using ERC.Structures;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

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
        public string ModuleName { get; private set; }
        /// <summary>
        /// Module path.
        /// </summary>
        public string ModulePath { get; private set; }
        /// <summary>
        /// Module version.
        /// </summary>
        public string ModuleVersion { get; private set; }
        /// <summary>
        /// Module product.
        /// </summary>
        public string ModuleProduct { get; private set; }

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

        internal IMAGE_DOS_HEADER ImageDosHeader = new IMAGE_DOS_HEADER();
        internal IMAGE_FILE_HEADER ImageFileHeader = new IMAGE_FILE_HEADER();
        internal IMAGE_NT_HEADERS32 ImageNTHeaders32 { get; private set; }
        internal IMAGE_NT_HEADERS64 ImageNTHeaders64 { get; private set; }
        internal IMAGE_OPTIONAL_HEADER32 ImageOptionalHeader32 { get; private set; }
        internal IMAGE_OPTIONAL_HEADER64 ImageOptionalHeader64 { get; private set; }
        internal IMAGE_LOAD_CONFIG_DIRECTORY32 ImageConfigDir32 { get; private set; }
        internal IMAGE_LOAD_CONFIG_DIRECTORY64 ImageConfigDir64 { get; private set; }
        internal LOADED_IMAGE loadedImage = new LOADED_IMAGE();

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
        internal unsafe ModuleInfo(string module, IntPtr ptr, Process process, ErcCore core)
        {
            try
            {
                ModuleCore = core;
                ModuleProcess = process;
                ModuleName = FileVersionInfo.GetVersionInfo(module).InternalName;
                ModulePath = FileVersionInfo.GetVersionInfo(module).FileName;
                ModuleBase = ptr;

                FileInfo fileInfo = new FileInfo(ModulePath);
                FileStream file = fileInfo.Open(FileMode.Open, FileAccess.Read, FileShare.Read);
                PopulateHeaderStructs(file);

                if (!string.IsNullOrEmpty(FileVersionInfo.GetVersionInfo(module).FileVersion))
                {
                    ModuleVersion = FileVersionInfo.GetVersionInfo(module).FileVersion.Split(' ')[0];
                }
                else
                {
                    ModuleVersion = "";
                }

                ModuleProduct = FileVersionInfo.GetVersionInfo(module).ProductName;
                
                if (ModuleMachineType == MachineType.I386)
                {
                    ModuleEntry = (IntPtr)ImageOptionalHeader32.AddressOfEntryPoint;
                    ModuleSize = (int)ImageOptionalHeader32.SizeOfImage;
                    ModuleImageBase = (IntPtr)ImageOptionalHeader32.ImageBase;
                    byte[] dllByte = BitConverter.GetBytes(ImageOptionalHeader32.DllCharacteristics);
                    BitArray bits = new BitArray(dllByte);
                    for (int i = 0; i < bits.Count; i++)
                    {
                        if (bits[i] == true && i == 6)
                        {
                            ModuleASLR = true;
                        }
                        else
                        {
                            ModuleASLR = false;
                        }

                        if (bits[i] == true && i == 8)
                        {
                            ModuleNXCompat = true;
                        }
                        else
                        {
                            ModuleNXCompat = false;
                        }
                    }

                    if(ModuleMachineType == MachineType.I386)
                    {
                        PopulateConfigStruct();

                        if (ImageConfigDir32.SEHandlerCount == 0 && ImageConfigDir32.SEHandlerTable == 0)
                        {
                            ModuleSafeSEH = false;
                        }
                        else
                        {
                            ModuleSafeSEH = true;
                        }
                    }
                    else
                    {
                        ModuleSafeSEH = true;
                    }
                    
                }
                else if (ModuleMachineType == MachineType.x64)
                {
                    ModuleEntry = (IntPtr)ImageOptionalHeader64.AddressOfEntryPoint;
                    ModuleSize = (int)ImageOptionalHeader64.SizeOfImage;
                    ModuleImageBase = (IntPtr)ImageOptionalHeader64.ImageBase;
                    byte[] dllByte = BitConverter.GetBytes(ImageOptionalHeader64.DllCharacteristics);
                    BitArray bits = new BitArray(dllByte);
                    for (int i = 0; i < bits.Count; i++)
                    {
                        if (bits[i] == true && i == 6)
                        {
                            ModuleASLR = true;
                        }
                        else if (bits[i] == false && i == 6)
                        {
                            ModuleASLR = false;
                        }

                        if (bits[i] == true && i == 8)
                        {
                            ModuleNXCompat = true;
                        }
                        else if (bits[i] == false && i == 8)
                        {
                            ModuleNXCompat = false;
                        }
                    }
                   
                    PopulateConfigStruct();
                    
                    if(ImageConfigDir64.SEHandlerCount == 0 && ImageConfigDir64.SEHandlerTable == 0)
                    {
                        ModuleSafeSEH = false;
                    }
                    else
                    {
                        ModuleSafeSEH = true;
                    }
                }
                else
                {
                    ModuleFailed = true;
                    throw new ERCException("Unsupported machine type: " + ModuleMachineType.ToString());
                }             

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
                        int result = ErcCore.VirtualQueryEx32(ModuleProcess.Handle, (IntPtr)address, out m, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION32)));
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
                        int result = ErcCore.VirtualQueryEx64(ModuleProcess.Handle, (IntPtr)address, out m, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION64)));
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

        private unsafe void PopulateHeaderStructs(FileStream fin)
        {
            byte[] Data = new byte[4096];
            int iRead = fin.Read(Data, 0, 4096);

            fin.Flush();
            fin.Close();

            fixed (byte* p_Data = Data)
            {
                IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)p_Data;
                IMAGE_NT_HEADERS32* inhs = (IMAGE_NT_HEADERS32*)(idh->nt_head_ptr + p_Data);
                ModuleMachineType = (MachineType)inhs->FileHeader.Machine;

                if (ModuleMachineType == MachineType.I386)
                {
                    IMAGE_NT_HEADERS32* inhs32 = (IMAGE_NT_HEADERS32*)(idh->nt_head_ptr + p_Data);
                    ImageFileHeader = inhs32->FileHeader;
                    ModuleMachineType = (MachineType)inhs32->FileHeader.Machine;
                    ImageOptionalHeader32 = inhs32->OptionalHeader;
                    ModuleImageBase = (IntPtr)inhs32->OptionalHeader.ImageBase;

                    ImageNTHeaders32 = new IMAGE_NT_HEADERS32
                    {
                        Signature = inhs32->Signature,
                        FileHeader = inhs32->FileHeader,
                        OptionalHeader = inhs32->OptionalHeader
                    };
                    
                    byte[] bytes = new byte[256];
                    var ret = ErcCore.ReadProcessMemory(ModuleProcess.Handle,
                        (IntPtr)((uint)ModuleBase + ImageOptionalHeader32.LoadConfigTable.VirtualAddress), bytes, 256, out int BytesRead);
                    if (BitConverter.ToUInt32(bytes, 58) > 0 || BitConverter.ToUInt32(bytes, 62) > 0)
                    {
                        ModuleSafeSEH = true;
                    }
                }
                else if (ModuleMachineType == MachineType.x64)
                {
                    IMAGE_NT_HEADERS64* inhs64 = (IMAGE_NT_HEADERS64*)(idh->nt_head_ptr + p_Data);
                    ImageFileHeader = inhs64->FileHeader;
                    ImageOptionalHeader64 = inhs64->OptionalHeader;
                    ModuleImageBase = (IntPtr)inhs64->OptionalHeader.ImageBase;

                    ImageNTHeaders64 = new IMAGE_NT_HEADERS64
                    {
                        Signature = inhs64->Signature,
                        FileHeader = inhs64->FileHeader,
                        OptionalHeader = inhs64->OptionalHeader
                    };

                    byte[] bytes = new byte[256];
                    var ret = ErcCore.ReadProcessMemory(ModuleProcess.Handle,
                        (IntPtr)((long)ModuleBase + (long)ImageOptionalHeader64.LoadConfigTable.VirtualAddress), bytes, 256, out int BytesRead);
                    if (BitConverter.ToUInt64(bytes, 88) > 0 || BitConverter.ToUInt64(bytes, 96) > 0)
                    {
                        ModuleSafeSEH = true;
                    }
                }
                else
                {
                    ModuleFailed = true;
                }
            }
        }

        private void PopulateConfigStruct()
        {
            string path = Path.GetDirectoryName(ModulePath);
            string name = Path.GetFileName(ModulePath);
            
            bool dll = true;

            
            if(Path.GetExtension(ModulePath) != ".dll" && Path.GetExtension(ModulePath) != ".DLL")
            {
                dll = false;
            }

            var MaLRet = ErcCore.MapAndLoad(name, path, out loadedImage, dll, true);
            var modPtr = ErcCore.ImageLoad(name, path);

            if (ModuleMachineType == MachineType.I386)
            {
                IMAGE_LOAD_CONFIG_DIRECTORY32 ImageConfigDir = new IMAGE_LOAD_CONFIG_DIRECTORY32();
                var check = ErcCore.GetImageConfigInformation32(ref loadedImage, ref ImageConfigDir);
            }
            else if (ModuleMachineType == MachineType.x64)
            {
                IMAGE_LOAD_CONFIG_DIRECTORY64 ImageConfigDir = new IMAGE_LOAD_CONFIG_DIRECTORY64();
                var check = ErcCore.GetImageConfigInformation64(ref loadedImage, ref ImageConfigDir);
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

            ErcCore.ReadProcessMemory(ModuleProcess.Handle, ModuleBase, buffer, buffer.Length, out bytesread);
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
