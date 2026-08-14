using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace ERC.Net.Tests.TestSupport
{
    /// <summary>
    /// Builds a PE image in memory, field by field.
    /// </summary>
    /// <remarks>
    /// Header parsing could previously only be exercised against whatever DLLs happen
    /// to be on the machine, which makes the interesting cases - a module with ASLR
    /// off, a truncated file, a header claiming an offset past the end of the file -
    /// either unavailable or unrepeatable.
    ///
    /// This writes the bytes directly rather than linking a real binary, so no C++
    /// toolchain is needed and each test states exactly the header it wants.
    ///
    /// The result is a valid enough PE for ERC's purposes: correct signatures, a
    /// coherent optional header, a data directory and a section table. It is not
    /// loadable, and does not need to be.
    /// </remarks>
    public sealed class PeBuilder
    {
        /// <summary>DLL characteristic: image can be relocated at load time.</summary>
        public const ushort DynamicBase = 0x0040;

        /// <summary>DLL characteristic: image is compatible with DEP.</summary>
        public const ushort NxCompat = 0x0100;

        /// <summary>DLL characteristic: image uses no structured exception handling.</summary>
        public const ushort NoSeh = 0x0400;

        private const int DosHeaderSize = 64;
        private const int FileHeaderSize = 20;
        private const int SectionHeaderSize = 40;
        private const int DataDirectoryCount = 16;

        private sealed class Section
        {
            public string Name = string.Empty;
            public uint VirtualAddress;
            public byte[] Data = new byte[0];
            public uint Characteristics;
        }

        private readonly List<Section> _sections = new List<Section>();

        private bool _is64Bit;
        private ushort _machine = 0x014C;
        private ushort _dllCharacteristics;
        private ulong _imageBase = 0x00400000;
        private uint _addressOfEntryPoint = 0x1000;
        private uint _sizeOfImage = 0x4000;
        private uint _loadConfigRva;
        private uint _loadConfigSize;
        private uint _numberOfRvaAndSizes = DataDirectoryCount;
        private int _lfanew = DosHeaderSize;
        private ushort _dosSignature = 0x5A4D;
        private uint _ntSignature = 0x00004550;
        private ushort? _optionalHeaderMagic;
        private ushort? _sizeOfOptionalHeaderOverride;

        /// <summary>A 32-bit image with sensible defaults.</summary>
        public static PeBuilder X86()
        {
            return new PeBuilder { _is64Bit = false, _machine = 0x014C, _imageBase = 0x00400000 };
        }

        /// <summary>A 64-bit image with sensible defaults.</summary>
        public static PeBuilder X64()
        {
            return new PeBuilder { _is64Bit = true, _machine = 0x8664, _imageBase = 0x0000000140000000 };
        }

        /// <summary>Sets the DllCharacteristics field outright.</summary>
        public PeBuilder WithDllCharacteristics(ushort value)
        {
            _dllCharacteristics = value;
            return this;
        }

        /// <summary>Turns individual DllCharacteristics flags on.</summary>
        public PeBuilder With(params ushort[] flags)
        {
            foreach (ushort flag in flags)
            {
                _dllCharacteristics |= flag;
            }

            return this;
        }

        /// <summary>Sets the preferred load address.</summary>
        public PeBuilder WithImageBase(ulong imageBase)
        {
            _imageBase = imageBase;
            return this;
        }

        /// <summary>Sets the entry point RVA.</summary>
        public PeBuilder WithEntryPoint(uint rva)
        {
            _addressOfEntryPoint = rva;
            return this;
        }

        /// <summary>Sets SizeOfImage.</summary>
        public PeBuilder WithSizeOfImage(uint size)
        {
            _sizeOfImage = size;
            return this;
        }

        /// <summary>Points the load config data directory at an address.</summary>
        public PeBuilder WithLoadConfig(uint rva, uint size)
        {
            _loadConfigRva = rva;
            _loadConfigSize = size;
            return this;
        }

        /// <summary>Declares fewer data directories than the format's 16.</summary>
        public PeBuilder WithDataDirectoryCount(uint count)
        {
            _numberOfRvaAndSizes = count;
            return this;
        }

        /// <summary>Adds a section carrying <paramref name="data"/>.</summary>
        public PeBuilder WithSection(string name, uint virtualAddress, byte[] data, uint characteristics = 0x60000020)
        {
            _sections.Add(new Section
            {
                Name = name,
                VirtualAddress = virtualAddress,
                Data = data,
                Characteristics = characteristics
            });

            return this;
        }

        // ------------------------------------------------------- deliberate damage

        /// <summary>Writes a different machine type than the optional header form implies.</summary>
        public PeBuilder WithMachine(ushort machine)
        {
            _machine = machine;
            return this;
        }

        /// <summary>Writes something other than "MZ" at offset 0.</summary>
        public PeBuilder WithDosSignature(ushort signature)
        {
            _dosSignature = signature;
            return this;
        }

        /// <summary>Writes something other than "PE\0\0" at the NT header.</summary>
        public PeBuilder WithNtSignature(uint signature)
        {
            _ntSignature = signature;
            return this;
        }

        /// <summary>Writes an arbitrary value into the DOS header's e_lfanew field.</summary>
        public PeBuilder WithLfanew(int lfanew)
        {
            _lfanew = lfanew;
            return this;
        }

        /// <summary>Writes an arbitrary optional header magic.</summary>
        public PeBuilder WithOptionalHeaderMagic(ushort magic)
        {
            _optionalHeaderMagic = magic;
            return this;
        }

        /// <summary>Writes an arbitrary SizeOfOptionalHeader.</summary>
        public PeBuilder WithSizeOfOptionalHeader(ushort size)
        {
            _sizeOfOptionalHeaderOverride = size;
            return this;
        }

        // -------------------------------------------------------------------- build

        /// <summary>Produces the image.</summary>
        public byte[] Build()
        {
            int optionalHeaderSize = (_is64Bit ? 112 : 96) + (DataDirectoryCount * 8);

            using (var buffer = new MemoryStream())
            using (var w = new BinaryWriter(buffer))
            {
                // ---- DOS header. Only the signature and e_lfanew are meaningful.
                w.Write(_dosSignature);
                w.Write(new byte[LfanewOffsetFromStart - 2]);
                w.Write(_lfanew);

                // Pad to wherever the NT header is meant to start. A test that pushes
                // e_lfanew past the end of the file deliberately skips this.
                if (_lfanew > DosHeaderSize && _lfanew < 4096)
                {
                    w.Write(new byte[_lfanew - DosHeaderSize]);
                }

                long ntHeader = buffer.Position;

                w.Write(_ntSignature);

                // ---- COFF file header
                w.Write(_machine);
                w.Write((ushort)_sections.Count);
                w.Write((uint)0);                                   // TimeDateStamp
                w.Write((uint)0);                                   // PointerToSymbolTable
                w.Write((uint)0);                                   // NumberOfSymbols
                w.Write(_sizeOfOptionalHeaderOverride ?? (ushort)optionalHeaderSize);
                w.Write((ushort)0x2022);                            // Characteristics: DLL, large address aware

                // ---- Optional header
                w.Write(_optionalHeaderMagic ?? (ushort)(_is64Bit ? 0x020B : 0x010B));
                w.Write((byte)14);                                  // MajorLinkerVersion
                w.Write((byte)0);                                   // MinorLinkerVersion
                w.Write((uint)0x1000);                              // SizeOfCode
                w.Write((uint)0x1000);                              // SizeOfInitializedData
                w.Write((uint)0);                                   // SizeOfUninitializedData
                w.Write(_addressOfEntryPoint);
                w.Write((uint)0x1000);                              // BaseOfCode

                if (_is64Bit)
                {
                    w.Write(_imageBase);                            // 8 bytes, no BaseOfData
                }
                else
                {
                    w.Write((uint)0x2000);                          // BaseOfData
                    w.Write((uint)_imageBase);                      // 4 bytes
                }

                w.Write((uint)0x1000);                              // SectionAlignment
                w.Write((uint)0x200);                               // FileAlignment
                w.Write((ushort)6);                                 // MajorOperatingSystemVersion
                w.Write((ushort)0);                                 // MinorOperatingSystemVersion
                w.Write((ushort)0);                                 // MajorImageVersion
                w.Write((ushort)0);                                 // MinorImageVersion
                w.Write((ushort)6);                                 // MajorSubsystemVersion
                w.Write((ushort)0);                                 // MinorSubsystemVersion
                w.Write((uint)0);                                   // Win32VersionValue
                w.Write(_sizeOfImage);
                w.Write((uint)0x400);                               // SizeOfHeaders
                w.Write((uint)0);                                   // CheckSum
                w.Write((ushort)3);                                 // Subsystem: console
                w.Write(_dllCharacteristics);

                if (_is64Bit)
                {
                    w.Write((ulong)0x100000);                       // SizeOfStackReserve
                    w.Write((ulong)0x1000);                         // SizeOfStackCommit
                    w.Write((ulong)0x100000);                       // SizeOfHeapReserve
                    w.Write((ulong)0x1000);                         // SizeOfHeapCommit
                }
                else
                {
                    w.Write((uint)0x100000);
                    w.Write((uint)0x1000);
                    w.Write((uint)0x100000);
                    w.Write((uint)0x1000);
                }

                w.Write((uint)0);                                   // LoaderFlags
                w.Write(_numberOfRvaAndSizes);

                // ---- Data directory. Index 10 is the load config.
                for (int i = 0; i < DataDirectoryCount; i++)
                {
                    if (i == 10)
                    {
                        w.Write(_loadConfigRva);
                        w.Write(_loadConfigSize);
                    }
                    else
                    {
                        w.Write((uint)0);
                        w.Write((uint)0);
                    }
                }

                // ---- Section table
                long sectionData = Align(buffer.Position + (_sections.Count * SectionHeaderSize), 0x200);
                long cursor = sectionData;

                foreach (Section section in _sections)
                {
                    byte[] name = new byte[8];
                    byte[] encoded = Encoding.ASCII.GetBytes(section.Name);
                    Array.Copy(encoded, name, Math.Min(encoded.Length, 8));

                    w.Write(name);
                    w.Write((uint)section.Data.Length);              // VirtualSize
                    w.Write(section.VirtualAddress);
                    w.Write((uint)Align(section.Data.Length, 0x200)); // SizeOfRawData
                    w.Write((uint)cursor);                            // PointerToRawData
                    w.Write((uint)0);                                 // PointerToRelocations
                    w.Write((uint)0);                                 // PointerToLinenumbers
                    w.Write((ushort)0);                               // NumberOfRelocations
                    w.Write((ushort)0);                               // NumberOfLinenumbers
                    w.Write(section.Characteristics);

                    cursor += Align(section.Data.Length, 0x200);
                }

                // ---- Section contents
                foreach (Section section in _sections)
                {
                    w.Write(new byte[sectionData - buffer.Position]);
                    w.Write(section.Data);
                    sectionData += Align(section.Data.Length, 0x200);
                }

                w.Flush();
                return buffer.ToArray();
            }
        }

        /// <summary>Produces the image and writes it to a temporary file.</summary>
        /// <returns>The path written. The caller deletes it.</returns>
        public string BuildToFile(string directory, string fileName)
        {
            string path = Path.Combine(directory, fileName);
            File.WriteAllBytes(path, Build());
            return path;
        }

        private const int LfanewOffsetFromStart = 60;

        private static long Align(long value, long alignment)
        {
            long remainder = value % alignment;
            return remainder == 0 ? value : value + (alignment - remainder);
        }
    }
}
