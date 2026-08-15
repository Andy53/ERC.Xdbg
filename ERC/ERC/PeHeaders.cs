using System;
using System.Collections.Generic;

namespace ERC.Utilities
{
    /// <summary>
    /// One entry of a PE file's section table.
    /// </summary>
    public sealed class PeSection
    {
        internal PeSection(string name, uint virtualAddress, uint virtualSize,
                           uint pointerToRawData, uint sizeOfRawData)
        {
            Name = name;
            VirtualAddress = virtualAddress;
            VirtualSize = virtualSize;
            PointerToRawData = pointerToRawData;
            SizeOfRawData = sizeOfRawData;
        }

        /// <summary>Section name, for example ".text".</summary>
        public string Name { get; }

        /// <summary>Where the section starts once loaded, relative to the image base.</summary>
        public uint VirtualAddress { get; }

        /// <summary>How much space the section occupies once loaded.</summary>
        public uint VirtualSize { get; }

        /// <summary>Where the section's bytes start in the file.</summary>
        public uint PointerToRawData { get; }

        /// <summary>How many bytes the section occupies in the file.</summary>
        public uint SizeOfRawData { get; }
    }

    /// <summary>
    /// The parts of a PE file's headers that ERC uses, read safely.
    /// </summary>
    /// <remarks>
    /// Extracted from ModuleInfo, where the same fields were read by casting a raw
    /// pointer over a 4096 byte buffer inside an unsafe block. That code:
    ///
    ///   - ignored the return value of Read, so a file shorter than 4096 bytes was
    ///     parsed with the tail of the buffer left as zeros;
    ///   - never checked for the "MZ" or "PE\0\0" signatures, so any file at all was
    ///     treated as a module;
    ///   - never bounds-checked e_lfanew before adding it to the buffer pointer, so a
    ///     header claiming an offset of 0x7FFFFFFF read far outside the buffer. Inside
    ///     a fixed block that is an unchecked read of whatever happened to be at that
    ///     address.
    ///
    /// The bytes come from a file on disk that the debugged process loaded, which is
    /// not something ERC controls. Parsing it needs to be total: every input either
    /// produces headers or an explanation, and never an out-of-bounds read.
    ///
    /// Written with explicit offsets and BitConverter rather than struct overlays so
    /// that every read is bounds-checked by the runtime.
    /// </remarks>
    public sealed class PeHeaders
    {
        // Offsets within the DOS header.
        private const int DosHeaderSize = 64;
        private const int LfanewOffset = 60;
        private const ushort DosSignature = 0x5A4D;      // "MZ"
        private const uint NtSignature = 0x00004550;     // "PE\0\0"

        // Offsets within the COFF file header, which follows the NT signature.
        private const int FileHeaderSize = 20;
        private const int MachineOffset = 0;
        private const int SizeOfOptionalHeaderOffset = 16;

        // Offsets within the optional header. Identical in both forms up to
        // BaseOfCode; after that PE32+ widens ImageBase and drops BaseOfData.
        private const ushort Pe32Magic = 0x010B;
        private const ushort Pe32PlusMagic = 0x020B;
        private const int AddressOfEntryPointOffset = 16;

        // Indexes into the data directory.
        private const int ExportDirectoryIndex = 0;
        private const int LoadConfigDirectoryIndex = 10;
        private const int DataDirectoryEntrySize = 8;

        private PeHeaders()
        {
        }

        /// <summary>Architecture the image was built for.</summary>
        public MachineType MachineType { get; private set; }

        /// <summary>Whether the image uses the PE32+ (64-bit) optional header.</summary>
        public bool Is64Bit { get; private set; }

        /// <summary>Entry point, as an RVA.</summary>
        public uint AddressOfEntryPoint { get; private set; }

        /// <summary>Size of the image once loaded.</summary>
        public uint SizeOfImage { get; private set; }

        /// <summary>Address the image prefers to be loaded at.</summary>
        public ulong ImageBase { get; private set; }

        /// <summary>The DllCharacteristics field, holding the mitigation flags.</summary>
        public ushort DllCharacteristics { get; private set; }

        /// <summary>RVA of the load config directory, or 0 when the image has none.</summary>
        public uint LoadConfigTableRva { get; private set; }

        /// <summary>Size of the load config directory, or 0 when the image has none.</summary>
        public uint LoadConfigTableSize { get; private set; }

        /// <summary>RVA of the export directory, or 0 when the image exports nothing.</summary>
        public uint ExportTableRva { get; private set; }

        /// <summary>Size of the export directory, or 0 when the image exports nothing.</summary>
        public uint ExportTableSize { get; private set; }

        /// <summary>The image's sections, in the order the section table lists them.</summary>
        public IReadOnlyList<PeSection> Sections { get; private set; } = new PeSection[0];

        /// <summary>
        /// Translates an address relative to the image base into a file offset.
        /// </summary>
        /// <param name="rva">The address, relative to the image base.</param>
        /// <param name="fileOffset">Where those bytes sit in the file.</param>
        /// <returns>False when no section covers the address, or it has no bytes in the file.</returns>
        /// <remarks>
        /// Needed to read anything outside the headers - the load config directory,
        /// for instance - because a data directory records where its contents will be
        /// once loaded, not where they are in the file. The two differ because
        /// sections are aligned differently on disk and in memory.
        /// </remarks>
        public bool TryRvaToFileOffset(uint rva, out int fileOffset)
        {
            fileOffset = 0;

            if (rva == 0)
            {
                return false;
            }

            foreach (PeSection section in Sections)
            {
                // VirtualSize can exceed SizeOfRawData when a section has a
                // zero-filled tail that is not stored in the file, so the address has
                // to fall within the part that is.
                if (rva >= section.VirtualAddress &&
                    rva < section.VirtualAddress + Math.Max(section.VirtualSize, section.SizeOfRawData))
                {
                    uint offsetInSection = rva - section.VirtualAddress;

                    if (offsetInSection >= section.SizeOfRawData)
                    {
                        return false;
                    }

                    long absolute = section.PointerToRawData + offsetInSection;

                    if (absolute > int.MaxValue)
                    {
                        return false;
                    }

                    fileOffset = (int)absolute;
                    return true;
                }
            }

            return false;
        }

        /// <summary>Whether the image opts in to address space layout randomisation.</summary>
        public bool HasAslr { get { return PeCharacteristics.HasAslr(DllCharacteristics); } }

        /// <summary>Whether the image is compatible with data execution prevention.</summary>
        public bool HasNxCompat { get { return PeCharacteristics.HasNxCompat(DllCharacteristics); } }

        /// <summary>Whether the image declares that it uses no structured exception handling.</summary>
        public bool HasNoSeh { get { return PeCharacteristics.HasNoSeh(DllCharacteristics); } }

        /// <summary>
        /// Reads the headers of a PE image.
        /// </summary>
        /// <param name="image">
        /// The start of the file. Only the headers are needed, so a prefix is enough,
        /// but it must be a prefix rather than an arbitrary slice.
        /// </param>
        /// <param name="headers">The headers, when parsing succeeded.</param>
        /// <param name="error">Why parsing failed, when it did.</param>
        /// <returns>True when <paramref name="image"/> is a PE file ERC understands.</returns>
        public static bool TryParse(byte[]? image, out PeHeaders? headers, out string? error)
        {
            headers = null;
            error = null;

            if (image == null)
            {
                error = "No image data was supplied.";
                return false;
            }

            if (image.Length < DosHeaderSize)
            {
                error = "The file is too short to contain a DOS header (" + image.Length + " bytes).";
                return false;
            }

            if (BitConverter.ToUInt16(image, 0) != DosSignature)
            {
                error = "The file does not start with the \"MZ\" signature, so it is not a PE image.";
                return false;
            }

            int lfanew = BitConverter.ToInt32(image, LfanewOffset);

            // Checked against the buffer before it is used as an offset. This is the
            // read that was previously unbounded.
            if (lfanew < 0 || lfanew > image.Length - 4 - FileHeaderSize)
            {
                error = "The PE header offset in the DOS header (0x" + lfanew.ToString("X") +
                        ") lies outside the file, which is " + image.Length + " bytes.";
                return false;
            }

            if (BitConverter.ToUInt32(image, lfanew) != NtSignature)
            {
                error = "No \"PE\\0\\0\" signature was found at the offset the DOS header gives (0x" +
                        lfanew.ToString("X") + ").";
                return false;
            }

            int fileHeader = lfanew + 4;
            var result = new PeHeaders();

            result.MachineType = (MachineType)BitConverter.ToUInt16(image, fileHeader + MachineOffset);

            if (result.MachineType != MachineType.I386 && result.MachineType != MachineType.x64)
            {
                error = "Unsupported machine type: " + result.MachineType + ".";
                return false;
            }

            ushort sizeOfOptionalHeader =
                BitConverter.ToUInt16(image, fileHeader + SizeOfOptionalHeaderOffset);

            int optionalHeader = fileHeader + FileHeaderSize;

            if (sizeOfOptionalHeader < 2 || optionalHeader > image.Length - sizeOfOptionalHeader)
            {
                error = "The optional header runs past the end of the file.";
                return false;
            }

            ushort magic = BitConverter.ToUInt16(image, optionalHeader);

            if (magic != Pe32Magic && magic != Pe32PlusMagic)
            {
                error = "Unrecognised optional header magic: 0x" + magic.ToString("X4") + ".";
                return false;
            }

            result.Is64Bit = magic == Pe32PlusMagic;

            // The machine type and the optional header form have to agree. A file
            // claiming x64 with a PE32 optional header would otherwise be read with
            // the wrong field offsets throughout.
            if (result.Is64Bit != (result.MachineType == MachineType.x64))
            {
                error = "The machine type (" + result.MachineType + ") does not match the optional " +
                        "header form (" + (result.Is64Bit ? "PE32+" : "PE32") + ").";
                return false;
            }

            // Fields after BaseOfCode sit at different offsets in the two forms,
            // because PE32+ widens ImageBase to 8 bytes and drops BaseOfData.
            int imageBaseOffset = result.Is64Bit ? 24 : 28;
            int sizeOfImageOffset = result.Is64Bit ? 56 : 56;
            int dllCharacteristicsOffset = result.Is64Bit ? 70 : 70;
            int numberOfRvaAndSizesOffset = result.Is64Bit ? 108 : 92;
            int dataDirectoryOffset = numberOfRvaAndSizesOffset + 4;

            int required = dataDirectoryOffset;
            if (sizeOfOptionalHeader < required)
            {
                error = "The optional header is " + sizeOfOptionalHeader +
                        " bytes, too short to contain the fields ERC reads.";
                return false;
            }

            result.AddressOfEntryPoint = BitConverter.ToUInt32(image, optionalHeader + AddressOfEntryPointOffset);
            result.SizeOfImage = BitConverter.ToUInt32(image, optionalHeader + sizeOfImageOffset);
            result.DllCharacteristics = BitConverter.ToUInt16(image, optionalHeader + dllCharacteristicsOffset);

            result.ImageBase = result.Is64Bit
                ? BitConverter.ToUInt64(image, optionalHeader + imageBaseOffset)
                : BitConverter.ToUInt32(image, optionalHeader + imageBaseOffset);

            uint numberOfRvaAndSizes = BitConverter.ToUInt32(image, optionalHeader + numberOfRvaAndSizesOffset);

            // An image is allowed to declare fewer directories than the 16 the format
            // permits, and then simply has no load config. Reading entry 10 regardless
            // would read whatever follows the optional header - usually the section
            // table.
            uint loadConfigRva, loadConfigSize;
            if (TryReadDirectory(image, optionalHeader, dataDirectoryOffset, sizeOfOptionalHeader,
                                 numberOfRvaAndSizes, LoadConfigDirectoryIndex,
                                 out loadConfigRva, out loadConfigSize))
            {
                result.LoadConfigTableRva = loadConfigRva;
                result.LoadConfigTableSize = loadConfigSize;
            }

            uint exportRva, exportSize;
            if (TryReadDirectory(image, optionalHeader, dataDirectoryOffset, sizeOfOptionalHeader,
                                 numberOfRvaAndSizes, ExportDirectoryIndex,
                                 out exportRva, out exportSize))
            {
                result.ExportTableRva = exportRva;
                result.ExportTableSize = exportSize;
            }

            result.Sections = ReadSections(image, fileHeader, optionalHeader + sizeOfOptionalHeader);

            headers = result;
            return true;
        }

        /// <summary>
        /// Reads one entry of the data directory, if the image declares that many.
        /// </summary>
        private static bool TryReadDirectory(
            byte[] image, int optionalHeader, int dataDirectoryOffset, ushort sizeOfOptionalHeader,
            uint numberOfRvaAndSizes, int index, out uint rva, out uint size)
        {
            rva = 0;
            size = 0;

            if (numberOfRvaAndSizes <= index)
            {
                return false;
            }

            int entry = optionalHeader + dataDirectoryOffset + (index * DataDirectoryEntrySize);

            if (entry > image.Length - DataDirectoryEntrySize ||
                entry + DataDirectoryEntrySize > optionalHeader + sizeOfOptionalHeader)
            {
                return false;
            }

            rva = BitConverter.ToUInt32(image, entry);
            size = BitConverter.ToUInt32(image, entry + 4);
            return true;
        }

        /// <summary>
        /// Reads the section table, stopping at whatever the buffer actually holds.
        /// </summary>
        private static IReadOnlyList<PeSection> ReadSections(byte[] image, int fileHeader, int sectionTable)
        {
            const int NumberOfSectionsOffset = 2;
            const int SectionHeaderSize = 40;

            ushort count = BitConverter.ToUInt16(image, fileHeader + NumberOfSectionsOffset);

            var sections = new List<PeSection>();

            for (int i = 0; i < count; i++)
            {
                int entry = sectionTable + (i * SectionHeaderSize);

                // The caller may have handed us only the first few KB of the file, so
                // the table can be cut short. That is not an error: the sections that
                // were read are still usable.
                if (entry < 0 || entry > image.Length - SectionHeaderSize)
                {
                    break;
                }

                // The name is eight bytes, NUL padded rather than NUL terminated.
                int nameLength = 0;
                while (nameLength < 8 && image[entry + nameLength] != 0)
                {
                    nameLength++;
                }

                sections.Add(new PeSection(
                    System.Text.Encoding.ASCII.GetString(image, entry, nameLength),
                    BitConverter.ToUInt32(image, entry + 12),   // VirtualAddress
                    BitConverter.ToUInt32(image, entry + 8),    // VirtualSize
                    BitConverter.ToUInt32(image, entry + 20),   // PointerToRawData
                    BitConverter.ToUInt32(image, entry + 16))); // SizeOfRawData
            }

            return sections;
        }

        // Offsets within IMAGE_LOAD_CONFIG_DIRECTORY32.
        private const int SehHandlerTableOffset32 = 64;
        private const int SehHandlerCountOffset32 = 68;

        /// <summary>
        /// Reads the SafeSEH handler table fields out of a 32-bit load config directory.
        /// </summary>
        /// <param name="loadConfig">
        /// The load config directory's bytes, starting at its own first byte.
        /// </param>
        /// <param name="handlerTable">Address of the table of permitted handlers.</param>
        /// <param name="handlerCount">How many handlers that table holds.</param>
        /// <returns>False when the buffer is too short to contain these fields.</returns>
        /// <remarks>
        /// The directory grew over the years and the fields ERC wants sit at a fixed
        /// offset near the start, so a short directory simply predates them.
        ///
        /// The code this replaces read the same two fields at offsets 58 and 62. The
        /// correct offsets are 64 and 68, so it was reading the last two bytes of
        /// EditList and the whole of SecurityCookie. It made no difference in practice
        /// because the result was overwritten before anything used it.
        /// </remarks>
        public static bool TryReadSafeSehFields(byte[]? loadConfig, out uint handlerTable, out uint handlerCount)
        {
            handlerTable = 0;
            handlerCount = 0;

            if (loadConfig == null || loadConfig.Length < SehHandlerCountOffset32 + 4)
            {
                return false;
            }

            // A directory shorter than the fields, according to its own Size field,
            // does not contain them whatever the buffer holds.
            uint size = BitConverter.ToUInt32(loadConfig, 0);
            if (size != 0 && size < SehHandlerCountOffset32 + 4)
            {
                return false;
            }

            handlerTable = BitConverter.ToUInt32(loadConfig, SehHandlerTableOffset32);
            handlerCount = BitConverter.ToUInt32(loadConfig, SehHandlerCountOffset32);
            return true;
        }

        /// <summary>
        /// Reads the headers of a PE image, throwing when it cannot.
        /// </summary>
        /// <param name="image">The start of the file.</param>
        /// <returns>The headers.</returns>
        /// <exception cref="ERCException">The image could not be parsed.</exception>
        public static PeHeaders Parse(byte[]? image)
        {
            PeHeaders? headers;
            string? error;

            if (!TryParse(image, out headers, out error))
            {
                throw new ERCException(error!);
            }

            return headers!;
        }
    }
}
