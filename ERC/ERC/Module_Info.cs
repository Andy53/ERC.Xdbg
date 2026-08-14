using ERC.Structures;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

using ERC.Native;
namespace ERC
{
    /// <summary>
    /// Contains all information relating to a specific module.
    /// </summary>
    public class ModuleInfo
    {
        #region Class Variables
        /// <summary>
        /// Module name.
        /// </summary>
        public string ModuleName { get; private set; } = string.Empty;
        /// <summary>
        /// Module path.
        /// </summary>
        public string ModulePath { get; private set; } = string.Empty;
        /// <summary>
        /// Module version.
        /// </summary>
        public string ModuleVersion { get; private set; } = string.Empty;
        /// <summary>
        /// Module product.
        /// </summary>
        public string ModuleProduct { get; private set; } = string.Empty;

        /// <summary>
        /// Memory protection of this module.
        /// </summary>
        public uint ModuleProtection { get; private set; }

        /// <summary>
        /// Module base pointer.
        /// </summary>
        public IntPtr ModuleBase { get; private set; }
        /// <summary>
        /// Module entry point.
        /// </summary>
        public IntPtr ModuleEntry { get; private set; }
        /// <summary>
        /// Module image base.
        /// </summary>
        public IntPtr ModuleImageBase { get; private set; }
        /// <summary>
        /// Module size.
        /// </summary>
        public int ModuleSize { get; private set; }

        /// <summary>
        /// Module supports ASLR.
        /// </summary>
        public bool ModuleASLR { get; private set; }
        /// <summary>
        /// Module supports SafeSEH
        /// </summary>
        public bool ModuleSafeSEH { get; private set; }
        /// <summary>
        /// Module can be rebased.
        /// </summary>
        public bool ModuleRebase { get; private set; }
        /// <summary>
        /// Module is DEP enabled.
        /// </summary>
        public bool ModuleNXCompat { get; private set; }
        /// <summary>
        /// Module is an OS dll.
        /// </summary>
        public bool ModuleOsDll { get; private set; }
        /// <summary>
        /// Process where the module is loaded.
        /// </summary>
        public Process ModuleProcess { get; private set; }
        /// <summary>
        /// Associated ErcCore object.
        /// </summary>
        public ErcCore ModuleCore { get; private set; }

        /// <summary>
        /// Machine type of the module.
        /// </summary>
        public MachineType ModuleMachineType { get; private set; }

        /// <summary>
        /// The module's DllCharacteristics, which carry the mitigation flags.
        /// </summary>
        public ushort ModuleDllCharacteristics { get; private set; }

        /// <summary>
        /// RVA of the module's load config directory, or 0 when it has none.
        /// </summary>
        public uint ModuleLoadConfigRva { get; private set; }

        /// <summary>
        /// Address of the module's table of permitted SEH handlers, or 0 when it
        /// publishes none. 32-bit modules only.
        /// </summary>
        public uint SehHandlerTable { get; private set; }

        /// <summary>
        /// How many handlers that table holds. 32-bit modules only.
        /// </summary>
        public uint SehHandlerCount { get; private set; }

        /// <summary>
        /// An errpr was encountered whilst processing the module.
        /// </summary>
        public bool ModuleFailed = false;
        #endregion

        #region Constructor
        /// <summary>
        /// Constructor for the ModuleInfo object. Takes (string)modules filepath (IntPtr)module handle (Process)Process from which the module is loaded
        /// </summary>
        /// <param name="module">Filepath of the module</param>
        /// <param name="ptr">Handle to the module</param>
        /// <param name="process">Process where the module is loaded</param>
        /// <param name="core">An ErcCore object</param>
        internal ModuleInfo(string module, IntPtr ptr, Process process, ErcCore core)
        {
            ModuleCore = core;
            ModuleProcess = process;

            try
            {
                ModuleName = FileVersionInfo.GetVersionInfo(module).InternalName ?? string.Empty;
                ModulePath = FileVersionInfo.GetVersionInfo(module).FileName;
                ModuleBase = ptr;

                // Reads the headers, and sets MachineType, ImageBase, Entry, Size and
                // DllCharacteristics. It throws when the file is not a PE image ERC
                // understands, which the catch below records as a failed module.
                PopulateHeaderStructs(ModulePath);

                string? fileVersion = FileVersionInfo.GetVersionInfo(module).FileVersion;
                ModuleVersion = string.IsNullOrEmpty(fileVersion)
                    ? ""
                    : fileVersion!.Split(' ')[0];

                ModuleProduct = FileVersionInfo.GetVersionInfo(module).ProductName ?? string.Empty;

                // One derivation for both architectures. This was written out twice,
                // once per branch: the 64-bit copy was correct and the 32-bit copy
                // assigned inside a plain "else", so on a 32-bit target - the common
                // case for this tool - ASLR and NXCompat always read as false.
                ModuleASLR = Utilities.PeCharacteristics.HasAslr(ModuleDllCharacteristics);
                ModuleNXCompat = Utilities.PeCharacteristics.HasNxCompat(ModuleDllCharacteristics);

                ModuleSafeSEH = ModuleMachineType == MachineType.I386
                    ? Utilities.PeCharacteristics.HasSafeSeh(
                        ModuleDllCharacteristics, SehHandlerTable, SehHandlerCount)
                    // x64 has no SafeSEH: exception handling is table driven through
                    // .pdata, which an SEH overwrite cannot reach. Reported as
                    // protected rather than as "no SafeSEH", which would read as a
                    // missing mitigation.
                    : true;

                if (ModuleProduct == "Microsoft® Windows® Operating System")
                {
                    ModuleOsDll = true;
                }
                else
                {
                    ModuleOsDll = false;
                }

                if (ModuleImageBase != ptr)
                {
                    ModuleRebase = true;
                }
                else
                {
                    ModuleRebase = false;
                }

                long MaxAddress = 0x7fffffff;
                long address = (long)ModuleBase;

                if (!ProcessInfo.Is64Bit(process))
                {
                    List<ERC.Structures.MEMORY_BASIC_INFORMATION32> ProcessMemoryBasicInfo32 = new List<ERC.Structures.MEMORY_BASIC_INFORMATION32>();
                    long oldAddress = 0;
                    do
                    {
                        ERC.Structures.MEMORY_BASIC_INFORMATION32 m;
                        int result = ModuleCore.Native.VirtualQueryEx32(ModuleProcess.Handle, (IntPtr)address, out m, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION32)));
                        if (address == (long)m.BaseAddress + (long)m.RegionSize)
                            break;
                        address = (long)m.BaseAddress + (long)m.RegionSize;
                        if(oldAddress > address)
                        {
                            address = long.MaxValue;
                        }
                        oldAddress = address;
                        ModuleProtection = m.AllocationProtect;
                    } while (address <= MaxAddress);
                }
                else
                {
                    List<ERC.Structures.MEMORY_BASIC_INFORMATION64> ProcessMemoryBasicInfo64 = new List<ERC.Structures.MEMORY_BASIC_INFORMATION64>();
                    long oldAddress = 0;
                    do
                    {
                        ERC.Structures.MEMORY_BASIC_INFORMATION64 m;
                        int result = ModuleCore.Native.VirtualQueryEx64(ModuleProcess.Handle, (IntPtr)address, out m, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION64)));
                        if (address == (long)m.BaseAddress + (long)m.RegionSize)
                            break;
                        address = (long)m.BaseAddress + (long)m.RegionSize;
                        if (oldAddress > address)
                        {
                            address = long.MaxValue;
                        }
                        oldAddress = address;
                        ModuleProtection = m.AllocationProtect;
                    } while (address <= MaxAddress);
                }
            }
            catch (Exception e)
            {
                ErcResult<Exception> ExceptionLogger = new ErcResult<Exception>(ModuleCore);
                ExceptionLogger.Error = e;
                ExceptionLogger.LogEvent();
                ModuleFailed = true;
            }
        }

        /// <summary>
        /// Reads the module file's PE headers.
        /// </summary>
        /// <remarks>
        /// The parsing itself is in <see cref="Utilities.PeHeaders"/>, which is total
        /// and bounds-checked. This method only opens the file and copies the results
        /// onto the properties.
        ///
        /// What it replaces cast a pointer over a 4096 byte buffer inside an unsafe
        /// block: it ignored how many bytes Read actually returned, checked neither
        /// the "MZ" nor the "PE\0\0" signature, and added the file's own e_lfanew
        /// field to the buffer pointer without a bounds check, so a module whose
        /// header claimed an offset of 0x7FFFFFFF read whatever was at that address.
        ///
        /// It also read the load config out of the live process here and set
        /// ModuleSafeSEH from it, which the constructor then overwrote
        /// unconditionally - so that work never affected anything.
        /// </remarks>
        private void PopulateHeaderStructs(string modulePath)
        {
            // Only the headers are needed. 4096 covers the DOS stub, the NT headers
            // and the section table of anything a linker produces.
            byte[] data = ReadHeaderBytes(modulePath, 4096);

            Utilities.PeHeaders? headers;
            string? error;

            if (!Utilities.PeHeaders.TryParse(data, out headers, out error))
            {
                ModuleFailed = true;
                throw new ERCException("Could not read the PE headers of " + modulePath + ": " + error);
            }

            ModuleMachineType = headers!.MachineType;
            ModuleImageBase = (IntPtr)headers.ImageBase;
            ModuleEntry = (IntPtr)headers.AddressOfEntryPoint;
            ModuleSize = (int)headers.SizeOfImage;
            ModuleDllCharacteristics = headers.DllCharacteristics;
            ModuleLoadConfigRva = headers.LoadConfigTableRva;

            ReadSafeSehFields(modulePath, headers);
        }

        /// <summary>
        /// Reads SEHandlerTable and SEHandlerCount out of the module's load config.
        /// </summary>
        /// <remarks>
        /// Read from the file rather than through imagehlp's MapAndLoad and
        /// GetImageConfigInformation, which is what this replaces. Those mapped the
        /// whole image and loaded it a second time - two OS resources per module, per
        /// command, neither of which was ever released - and the values they produced
        /// were assigned to a local and discarded, so the SafeSEH test that reads them
        /// compared zero against zero and every module reported SafeSEH as false.
        ///
        /// The directory lives in a section rather than in the headers, so its address
        /// has to be translated from an RVA to a file offset first.
        /// </remarks>
        private void ReadSafeSehFields(string modulePath, Utilities.PeHeaders headers)
        {
            if (headers.MachineType != MachineType.I386 || headers.LoadConfigTableRva == 0)
            {
                return;
            }

            int offset;
            if (!headers.TryRvaToFileOffset(headers.LoadConfigTableRva, out offset))
            {
                return;
            }

            // 72 bytes reaches the end of SEHandlerCount. Reading the whole directory,
            // let alone the whole file, is unnecessary: ProcessInfo builds one of
            // these per loaded module on every command.
            byte[]? loadConfig = ReadAt(modulePath, offset, 72);

            uint handlerTable;
            uint handlerCount;

            if (Utilities.PeHeaders.TryReadSafeSehFields(loadConfig, out handlerTable, out handlerCount))
            {
                SehHandlerTable = handlerTable;
                SehHandlerCount = handlerCount;
            }
        }

        /// <summary>
        /// Reads <paramref name="count"/> bytes from <paramref name="offset"/>, or null.
        /// </summary>
        private static byte[]? ReadAt(string path, int offset, int count)
        {
            try
            {
                using (var file = new FileStream(path, FileMode.Open, FileAccess.Read,
                                                 FileShare.ReadWrite | FileShare.Delete))
                {
                    if (offset < 0 || offset + count > file.Length)
                    {
                        return null;
                    }

                    file.Seek(offset, SeekOrigin.Begin);

                    var buffer = new byte[count];
                    int read = 0;

                    while (read < count)
                    {
                        int got = file.Read(buffer, read, count - read);
                        if (got == 0)
                        {
                            break;
                        }

                        read += got;
                    }

                    return read == count ? buffer : null;
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

        /// <summary>
        /// Reads up to <paramref name="count"/> bytes from the start of a file.
        /// </summary>
        /// <remarks>
        /// Loops because Stream.Read is permitted to return fewer bytes than asked
        /// for, and returns exactly what it got rather than a fixed-size buffer with a
        /// zeroed tail. The original ignored the count entirely, so a file shorter
        /// than the buffer was parsed with zeros standing in for its headers.
        /// </remarks>
        private static byte[] ReadHeaderBytes(string path, int count)
        {
            using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                var buffer = new byte[count];
                int read = 0;

                while (read < count)
                {
                    int got = file.Read(buffer, read, count - read);
                    if (got == 0)
                    {
                        break;
                    }

                    read += got;
                }

                if (read == count)
                {
                    return buffer;
                }

                var exact = new byte[read];
                Array.Copy(buffer, exact, read);
                return exact;
            }
        }

        #endregion

        #region SearchModule
        /// <summary>
        /// Searches for a string of bytes within a specific module. Takes a byte array to be searched for. 
        /// </summary>
        /// <param name="searchBytes">A byte array to be searched for</param>
        /// <returns>Returns ERC_Result of pointers to the search term</returns>
        public ErcResult<List<IntPtr>> SearchModule(byte[] searchBytes)
        {
            ErcResult<List<IntPtr>> results = new ErcResult<List<IntPtr>>(ModuleCore);
            List<IntPtr> ptrs = new List<IntPtr>();

            IntPtr baseAddress = ModuleBase;
            byte[] buffer = new byte[ModuleSize];
            int bytesread = 0;

            ModuleCore.Native.ReadProcessMemory(ModuleProcess.Handle, ModuleBase, buffer, buffer.Length, out bytesread);
            List<int> positions = SearchBytePattern(searchBytes, buffer);

            for(int i = 0; i < positions.Count; i++)
            {
                ptrs.Add((IntPtr)(positions[i] + (long)ModuleBase));
            }
            
            results.ReturnValue = ptrs;
            return results;
        }

        private List<int> SearchBytePattern(byte[] pattern, byte[] bytes)
        {
            List<int> positions = new List<int>();
            int patternLength = pattern.Length;
            int totalLength = bytes.Length;
            byte firstMatchByte = pattern[0];
            for (int i = 0; i < totalLength; i++)
            {
                if (firstMatchByte == bytes[i] && totalLength - i >= patternLength)
                {
                    byte[] match = new byte[patternLength];
                    Array.Copy(bytes, i, match, 0, patternLength);
                    if (match.SequenceEqual<byte>(pattern))
                    {
                        positions.Add(i);
                        i += patternLength - 1;
                    }
                }
            }
            return positions;
        }
        #endregion

        #region ToString
        /// <summary>
        /// Override of the ToString method. Provides a data associated with the module.
        /// </summary>
        /// <returns>A string containing relevant data.</returns>
        public override string ToString()
        {
            string ret = "";
            ret += "Module Name        = " + ModuleName + Environment.NewLine;
            ret += "Module Path        = " + ModulePath + Environment.NewLine;
            ret += "Module Version     = " + ModuleVersion + Environment.NewLine;
            ret += "Module Produce     = " + ModuleProduct + Environment.NewLine;
            if (ModuleMachineType == MachineType.x64)
            {
                ret += "Module Handle      = " + "0x" + ModuleBase.ToString("x16") + Environment.NewLine;
                ret += "Module Entrypoint  = " + "0x" + ModuleEntry.ToString("x16") + Environment.NewLine;
                ret += "Module Image Base  = " + "0x" + ModuleImageBase.ToString("x16") + Environment.NewLine;
            }
            else
            {
                ret += "Module Handle      = " + "0x" + ModuleBase.ToString("x8") + Environment.NewLine;
                ret += "Module Entrypoint  = " + "0x" + ModuleEntry.ToString("x8") + Environment.NewLine;
                ret += "Module Image Base  = " + "0x" + ModuleImageBase.ToString("x8") + Environment.NewLine;
            }
            ret += "Module Size        = " + ModuleSize + Environment.NewLine;
            ret += "Module ASLR        = " + ModuleASLR + Environment.NewLine;
            ret += "Module SafeSEH     = " + ModuleSafeSEH + Environment.NewLine;
            ret += "Module Rebase      = " + ModuleRebase + Environment.NewLine;
            ret += "Module NXCompat    = " + ModuleNXCompat + Environment.NewLine;
            ret += "Module OS DLL      = " + ModuleOsDll + Environment.NewLine;
            return ret;
        }
        #endregion
    }
}
