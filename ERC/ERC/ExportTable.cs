using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace ERC.Utilities
{
    /// <summary>
    /// Reads the functions a module exports, and where they will be once loaded.
    /// </summary>
    /// <remarks>
    /// This exists because GetProcAddress cannot answer the question. It resolves an
    /// export in the *calling* process, and ERC is inspecting somebody else's - so a
    /// module handle from the target means nothing to it. That matters most in
    /// exactly the case exploit work cares about: a 32-bit target inspected from a
    /// 64-bit tool, where the target's kernel32 is not the one ERC is running on.
    ///
    /// The ROP chain generator worked around this by hard-coding offsets:
    ///
    ///     ApiAddresses.Add("VirtualAlloc", hModule + 0x166B0);
    ///
    /// Those offsets are correct for one build of kernel32 and wrong for every
    /// other, and nothing detects that they are wrong - the chain is produced, looks
    /// plausible, and jumps into the middle of some unrelated function.
    ///
    /// Reading the export directory out of the module's own file gives the right
    /// answer on any Windows version, and the section parsing needed to do it was
    /// already there for the load config.
    /// </remarks>
    public static class ExportTable
    {
        // Offsets within IMAGE_EXPORT_DIRECTORY.
        private const int OrdinalBaseOffset = 16;
        private const int NumberOfFunctionsOffset = 20;
        private const int NumberOfNamesOffset = 24;
        private const int AddressOfFunctionsOffset = 28;
        private const int AddressOfNamesOffset = 32;
        private const int AddressOfNameOrdinalsOffset = 36;
        private const int DirectorySize = 40;

        /// <summary>
        /// Reads every named export of a module.
        /// </summary>
        /// <param name="modulePath">Path to the module file on disk.</param>
        /// <returns>
        /// Export name to its address relative to the module's base. Empty when the
        /// module exports nothing or could not be read.
        /// </returns>
        public static IReadOnlyDictionary<string, uint> Read(string modulePath)
        {
            var exports = new Dictionary<string, uint>(StringComparer.Ordinal);

            byte[]? image = ReadFile(modulePath);
            if (image == null)
            {
                return exports;
            }

            PeHeaders? headers;
            string? error;

            if (!PeHeaders.TryParse(image, out headers, out error) || headers!.ExportTableRva == 0)
            {
                return exports;
            }

            int directory;
            if (!headers.TryRvaToFileOffset(headers.ExportTableRva, out directory) ||
                directory > image.Length - DirectorySize)
            {
                return exports;
            }

            uint ordinalBase = BitConverter.ToUInt32(image, directory + OrdinalBaseOffset);
            uint functionCount = BitConverter.ToUInt32(image, directory + NumberOfFunctionsOffset);
            uint nameCount = BitConverter.ToUInt32(image, directory + NumberOfNamesOffset);

            uint functionsRva = BitConverter.ToUInt32(image, directory + AddressOfFunctionsOffset);
            uint namesRva = BitConverter.ToUInt32(image, directory + AddressOfNamesOffset);
            uint ordinalsRva = BitConverter.ToUInt32(image, directory + AddressOfNameOrdinalsOffset);

            int functions, names, ordinals;
            if (!headers.TryRvaToFileOffset(functionsRva, out functions) ||
                !headers.TryRvaToFileOffset(namesRva, out names) ||
                !headers.TryRvaToFileOffset(ordinalsRva, out ordinals))
            {
                return exports;
            }

            // A module with a implausible export count is either corrupt or not what
            // it claims; either way there is nothing useful to read.
            if (nameCount > 100000 || functionCount > 100000)
            {
                return exports;
            }

            for (uint i = 0; i < nameCount; i++)
            {
                int namePointer = names + (int)(i * 4);
                int ordinalPointer = ordinals + (int)(i * 2);

                if (namePointer > image.Length - 4 || ordinalPointer > image.Length - 2)
                {
                    break;
                }

                uint nameRva = BitConverter.ToUInt32(image, namePointer);
                ushort ordinal = BitConverter.ToUInt16(image, ordinalPointer);

                if (ordinal >= functionCount)
                {
                    continue;
                }

                int functionPointer = functions + (ordinal * 4);
                int nameOffset;

                if (functionPointer > image.Length - 4 ||
                    !headers.TryRvaToFileOffset(nameRva, out nameOffset))
                {
                    continue;
                }

                string? name = ReadAsciiString(image, nameOffset);
                if (name == null)
                {
                    continue;
                }

                uint functionRva = BitConverter.ToUInt32(image, functionPointer);

                // An address inside the export directory is a forwarder: the bytes
                // there are a string like "NTDLL.RtlAllocateHeap" naming where the
                // export really lives. There is no code at that address, so offering
                // it as one would be worse than leaving it out.
                if (functionRva >= headers.ExportTableRva &&
                    functionRva < headers.ExportTableRva + headers.ExportTableSize)
                {
                    continue;
                }

                exports[name] = functionRva;

                // Ordinal base is part of the format even though the name lookup does
                // not need it; reading it keeps the parse honest about what it skipped.
                _ = ordinalBase;
            }

            return exports;
        }

        /// <summary>
        /// The address a named export will have once the module is loaded at
        /// <paramref name="moduleBase"/>.
        /// </summary>
        /// <param name="modulePath">Path to the module file on disk.</param>
        /// <param name="moduleBase">Where the module is loaded in the target process.</param>
        /// <param name="name">The export to resolve.</param>
        /// <param name="address">The address, when the export was found.</param>
        /// <returns>False when the module does not export that name.</returns>
        public static bool TryResolve(string modulePath, IntPtr moduleBase, string name, out IntPtr address)
        {
            address = IntPtr.Zero;

            IReadOnlyDictionary<string, uint> exports = Read(modulePath);

            uint rva;
            if (!exports.TryGetValue(name, out rva))
            {
                return false;
            }

            address = new IntPtr(moduleBase.ToInt64() + rva);
            return true;
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
                    // Whole file: the export directory and the name strings it points
                    // at can be anywhere in it, and system DLLs are a few hundred KB.
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
