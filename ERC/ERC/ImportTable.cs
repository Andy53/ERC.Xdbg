using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace ERC.Utilities
{
    /// <summary>
    /// One function imported by a module, and the IAT slot that holds its address.
    /// </summary>
    public sealed class ImportEntry
    {
        internal ImportEntry(string dll, string name, uint ordinal, bool byOrdinal, uint iatRva)
        {
            Dll = dll;
            Name = name;
            Ordinal = ordinal;
            ByOrdinal = byOrdinal;
            IatRva = iatRva;
        }

        /// <summary>The DLL the function is imported from, for example "kernel32.dll".</summary>
        public string Dll { get; }

        /// <summary>The imported name, or empty when the import is by ordinal.</summary>
        public string Name { get; }

        /// <summary>The ordinal, when <see cref="ByOrdinal"/> is true.</summary>
        public uint Ordinal { get; }

        /// <summary>True when the import is by ordinal rather than by name.</summary>
        public bool ByOrdinal { get; }

        /// <summary>
        /// RVA of the IAT slot. Added to the module base, this is a pointer to a
        /// pointer - the form a ROP chain actually dereferences.
        /// </summary>
        public uint IatRva { get; }

        /// <summary>A display name: the function name, or "#ordinal".</summary>
        public string DisplayName
        {
            get { return ByOrdinal ? ("#" + Ordinal.ToString()) : Name; }
        }
    }

    /// <summary>
    /// Reads a module's import address table from its file.
    /// </summary>
    /// <remarks>
    /// A ROP chain that calls VirtualProtect usually does so through an IAT slot:
    /// the slot is a pointer in a writable section that already holds the API
    /// address. --RopFunc lists export addresses; this lists the slots a chain
    /// actually writes or reuses. The two are not interchangeable.
    /// </remarks>
    public static class ImportTable
    {
        private const int DescriptorSize = 20;
        private const int OriginalFirstThunkOffset = 0;
        private const int NameOffset = 12;
        private const int FirstThunkOffset = 16;
        private const uint OrdinalFlag32 = 0x80000000;
        private const ulong OrdinalFlag64 = 0x8000000000000000UL;
        private const int MaxDescriptors = 4096;
        private const int MaxThunks = 100000;

        /// <summary>
        /// Reads every named and ordinal import of a module.
        /// </summary>
        /// <param name="modulePath">Path to the module file on disk.</param>
        /// <param name="is64Bit">
        /// Pointer width of the image. Taken from the PE headers when omitted.
        /// </param>
        /// <returns>One entry per IAT slot. Empty when the module imports nothing.</returns>
        public static IReadOnlyList<ImportEntry> Read(string modulePath, bool? is64Bit = null)
        {
            var imports = new List<ImportEntry>();

            byte[]? image = ReadFile(modulePath);
            if (image == null)
            {
                return imports;
            }

            PeHeaders? headers;
            string? error;
            if (!PeHeaders.TryParse(image, out headers, out error) || headers!.ImportTableRva == 0)
            {
                return imports;
            }

            bool wide = is64Bit ?? headers.Is64Bit;
            int pointerSize = wide ? 8 : 4;

            int directory;
            if (!headers.TryRvaToFileOffset(headers.ImportTableRva, out directory))
            {
                return imports;
            }

            for (int d = 0; d < MaxDescriptors; d++)
            {
                int descriptor = directory + (d * DescriptorSize);
                if (descriptor > image.Length - DescriptorSize)
                {
                    break;
                }

                uint originalFirstThunk = BitConverter.ToUInt32(image, descriptor + OriginalFirstThunkOffset);
                uint nameRva = BitConverter.ToUInt32(image, descriptor + NameOffset);
                uint firstThunk = BitConverter.ToUInt32(image, descriptor + FirstThunkOffset);

                if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0)
                {
                    break;
                }

                int nameOffset;
                string? dll = headers.TryRvaToFileOffset(nameRva, out nameOffset)
                    ? ReadAsciiString(image, nameOffset)
                    : null;

                if (string.IsNullOrEmpty(dll))
                {
                    continue;
                }

                uint thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
                int thunkFile;
                if (!headers.TryRvaToFileOffset(thunkRva, out thunkFile))
                {
                    continue;
                }

                for (int i = 0; i < MaxThunks; i++)
                {
                    int thunkAt = thunkFile + (i * pointerSize);
                    if (thunkAt > image.Length - pointerSize)
                    {
                        break;
                    }

                    ulong thunk = wide
                        ? BitConverter.ToUInt64(image, thunkAt)
                        : BitConverter.ToUInt32(image, thunkAt);

                    if (thunk == 0)
                    {
                        break;
                    }

                    uint iatRva = firstThunk + (uint)(i * pointerSize);
                    bool byOrdinal = wide
                        ? (thunk & OrdinalFlag64) != 0
                        : (thunk & OrdinalFlag32) != 0;

                    if (byOrdinal)
                    {
                        imports.Add(new ImportEntry(dll!, string.Empty, (uint)(thunk & 0xFFFF), true, iatRva));
                        continue;
                    }

                    int hintName;
                    if (!headers.TryRvaToFileOffset((uint)thunk, out hintName) ||
                        hintName > image.Length - 3)
                    {
                        continue;
                    }

                    // IMAGE_IMPORT_BY_NAME: 2-byte hint, then a null-terminated name.
                    string? function = ReadAsciiString(image, hintName + 2);
                    if (function == null)
                    {
                        continue;
                    }

                    imports.Add(new ImportEntry(dll!, function, 0, false, iatRva));
                }
            }

            return imports;
        }

        /// <summary>
        /// The address of an IAT slot once the module is loaded at
        /// <paramref name="moduleBase"/>.
        /// </summary>
        public static IntPtr SlotAddress(IntPtr moduleBase, uint iatRva)
        {
            return new IntPtr(moduleBase.ToInt64() + iatRva);
        }

        private static string? ReadAsciiString(byte[] image, int offset)
        {
            if (offset < 0 || offset >= image.Length)
            {
                return null;
            }

            int end = offset;
            while (end < image.Length && image[end] != 0)
            {
                end++;
            }

            if (end == offset || end - offset > 512)
            {
                return null;
            }

            return Encoding.ASCII.GetString(image, offset, end - offset);
        }

        private static byte[]? ReadFile(string path)
        {
            try
            {
                using (var file = new FileStream(path, FileMode.Open, FileAccess.Read,
                                                 FileShare.ReadWrite | FileShare.Delete))
                {
                    var buffer = new byte[file.Length];
                    int read = 0;

                    while (read < buffer.Length)
                    {
                        int got = file.Read(buffer, read, buffer.Length - read);
                        if (got == 0)
                        {
                            break;
                        }

                        read += got;
                    }

                    return read == buffer.Length ? buffer : null;
                }
            }
            catch (IOException)
            {
                return null;
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }
        }
    }
}
