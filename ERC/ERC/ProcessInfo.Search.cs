using ERC.Structures;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

using ERC.Native;
namespace ERC
{
    /// <summary> Contains information needed for the associated functions relating to the process. </summary>
    public partial class ProcessInfo
    {
        #region Search_Functions

        #region Search_Process_Memory
        /// <summary>
        /// Private function called from Search_Memory. Searches memory regions populated by the process for specific patterns.
        /// </summary>
        /// <param name="searchBytes"> Takes a byte array as input to be searched for</param>
        /// <returns>Returns a list of IntPtr for each instance found.</returns>
        internal ErcResult<List<IntPtr>> SearchProcessMemory(byte[] searchBytes)
        {
            ErcResult<List<IntPtr>> resultAddresses = new ErcResult<List<IntPtr>>(ProcessCore);

            resultAddresses.ReturnValue = new List<IntPtr>();
            Process process = ProcessCurrent;

            if (ProcessMachineType == MachineType.I386)
            {
                for (int i = 0; i < MemoryRegions32.Count; i++)
                {
                    if((ulong)MemoryRegions32[i].RegionSize > int.MaxValue)
                    {
                        long startAddress = (long)MemoryRegions32[i].BaseAddress;
                        long endAddress = (long)MemoryRegions32[i].BaseAddress + (long)(MemoryRegions32[i].RegionSize - 1);
                        long region = (long)MemoryRegions32[i].RegionSize;
                        for (long j = startAddress; j < endAddress; j += (region / 100))
                        {
                            byte[] buffer = new byte[region / 100]; 
                            int bytesRead = 0;
                            Native.ReadProcessMemory(ProcessHandle, (IntPtr)j, buffer, buffer.Length, out bytesRead);

                            long pos = 0;
                            long index = 0;
                            do
                            {
                                byte[] buffer1Partial = new byte[buffer.Length - pos];
                                Array.Copy(buffer, pos, buffer1Partial, 0, buffer.Length - pos);
                                index = ByteIndexOf(buffer1Partial, searchBytes);

                                if (index != -1)
                                {
                                    resultAddresses.ReturnValue.Add((IntPtr)(index + (long)MemoryRegions32[i].BaseAddress + pos));
                                }
                                pos += index;
                                if (index == 0)
                                {
                                    pos += searchBytes.Length;
                                    index = 1;
                                }
                            } while (index != -1 && index != 0);
                        }
                    }
                    else
                    {
                        long bufferSize = (long)MemoryRegions32[i].RegionSize;
                        int bytesRead = 0;
                        IntPtr baseAddress = MemoryRegions32[i].BaseAddress;
                        byte[] buffer = new byte[bufferSize]; 

                        Native.ReadProcessMemory(ProcessHandle, baseAddress, buffer, buffer.Length, out bytesRead);

                        long pos = 0;
                        long index = 0;
                        do
                        {
                            byte[] buffer1Partial = new byte[buffer.Length - pos];
                            Array.Copy(buffer, pos, buffer1Partial, 0, buffer.Length - pos);
                            index = ByteIndexOf(buffer1Partial, searchBytes);

                            if (index != -1)
                            {
                                resultAddresses.ReturnValue.Add((IntPtr)(index + (long)MemoryRegions32[i].BaseAddress + pos));
                            }
                            pos += index;
                            if (index == 0)
                            {
                                pos += searchBytes.Length;
                                index = 1;
                            }
                        } while (index != -1 && index != 0);
                    }
                }
            }
            else if(ProcessMachineType == MachineType.x64)
            {
                byte[] buffer = new byte[int.MaxValue / 10];
                int bytesRead = 0;
                for (int i = 0; i < MemoryRegions64.Count; i++)
                {
                    if (MemoryRegions64[i].RegionSize > int.MaxValue)
                    {
                        ulong startAddress = MemoryRegions64[i].BaseAddress;
                        ulong endAddress = MemoryRegions64[i].BaseAddress + (MemoryRegions64[i].RegionSize - 1);
                        ulong region = MemoryRegions64[i].RegionSize;

                        for (ulong j = startAddress; j < endAddress; j += int.MaxValue / 10)
                        {
                            Native.ReadProcessMemory(ProcessHandle, (IntPtr)j, buffer, buffer.Length, out bytesRead);
                            long pos = 0;
                            long index = 0;
                            do
                            {
                                byte[] buffer1Partial = new byte[buffer.Length - pos];
                                Array.Copy(buffer, pos, buffer1Partial, 0, buffer.Length - pos);
                                index = ByteIndexOf(buffer1Partial, searchBytes);

                                if (index != -1)
                                {
                                    resultAddresses.ReturnValue.Add((IntPtr)(index + (long)MemoryRegions64[i].BaseAddress + pos));
                                }
                                pos += index;
                                if (index == 0)
                                {
                                    pos += searchBytes.Length;
                                    index = 1;
                                }
                            } while (index != -1 && index != 0);
                        }
                    }
                    else
                    {
                        long bufferSize = (long)MemoryRegions64[i].RegionSize;
                        bytesRead = 0;
                        IntPtr baseAddress = (IntPtr)MemoryRegions64[i].BaseAddress;
                        byte[] buffer1 = new byte[bufferSize]; 

                        Native.ReadProcessMemory(ProcessHandle, baseAddress, buffer1, buffer1.Length, out bytesRead);
                        long pos = 0;
                        long index = 0;
                        do
                        {
                            byte[] buffer1Partial = new byte[buffer1.Length - pos];
                            Array.Copy(buffer1, pos, buffer1Partial, 0, buffer1.Length - pos);
                            index = ByteIndexOf(buffer1Partial, searchBytes);

                            if (index != -1)
                            {
                                resultAddresses.ReturnValue.Add((IntPtr)(index + (long)MemoryRegions64[i].BaseAddress + pos));
                            }
                            pos += index;
                            if(index == 0)
                            {
                                pos += searchBytes.Length;
                                index = 1;
                            }
                        } while (index != -1 && index != 0);
                    }
                }
            }
            resultAddresses.ReturnValue = new HashSet<IntPtr>(resultAddresses.ReturnValue).ToList();
            return resultAddresses;  
        }

        /// <summary>
        /// Private function called from Search_Memory. Searches memory regions populated by the process for specific strings.
        /// </summary>
        /// <param name="searchBytes"> Takes a byte array as input to be searched for</param>
        /// <param name="ptrsToExclude"> Takes a byte array of values used to disqualify pointers</param>
        /// <returns>Returns a list of IntPtr for each instance found.</returns>
        internal ErcResult<List<IntPtr>> SearchProcessMemory(byte[] searchBytes, byte[] ptrsToExclude)
        {
            ErcResult<List<IntPtr>> resultAddresses = new ErcResult<List<IntPtr>>(ProcessCore);

            resultAddresses.ReturnValue = new List<IntPtr>();
            Process process = ProcessCurrent;

            if (ProcessMachineType == MachineType.I386)
            {
                for (int i = 0; i < MemoryRegions32.Count; i++)
                {
                    if ((ulong)MemoryRegions32[i].RegionSize > int.MaxValue)
                    {
                        long startAddress = (long)MemoryRegions32[i].BaseAddress;
                        long endAddress = (long)MemoryRegions32[i].BaseAddress + (long)(MemoryRegions32[i].RegionSize - 1);
                        long region = (long)MemoryRegions32[i].RegionSize;
                        for (long j = startAddress; j < endAddress; j += (region / 100))
                        {
                            byte[] buffer = new byte[region / 100];
                            int bytesRead = 0;
                            Native.ReadProcessMemory(ProcessHandle, (IntPtr)j, buffer, buffer.Length, out bytesRead);

                            long pos = 0;
                            long index = 0;
                            do
                            {
                                byte[] buffer1Partial = new byte[buffer.Length - pos];
                                Array.Copy(buffer, pos, buffer1Partial, 0, buffer.Length - pos);
                                index = ByteIndexOf(buffer1Partial, searchBytes);

                                if (index != -1)
                                {
                                    resultAddresses.ReturnValue.Add((IntPtr)(index + (long)MemoryRegions32[i].BaseAddress + pos));
                                }
                                pos += index;
                                if (index == 0)
                                {
                                    pos += searchBytes.Length;
                                    index = 1;
                                }
                            } while (index != -1 && index != 0);
                        }
                    }
                    else
                    {
                        long bufferSize = (long)MemoryRegions32[i].RegionSize;
                        int bytesRead = 0;
                        IntPtr baseAddress = MemoryRegions32[i].BaseAddress;
                        byte[] buffer = new byte[bufferSize];

                        Native.ReadProcessMemory(ProcessHandle, baseAddress, buffer, buffer.Length, out bytesRead);

                        long pos = 0;
                        long index = 0;
                        do
                        {
                            byte[] buffer1Partial = new byte[buffer.Length - pos];
                            Array.Copy(buffer, pos, buffer1Partial, 0, buffer.Length - pos);
                            index = ByteIndexOf(buffer1Partial, searchBytes);

                            if (index != -1)
                            {
                                resultAddresses.ReturnValue.Add((IntPtr)(index + (long)MemoryRegions32[i].BaseAddress + pos));
                            }
                            pos += index;
                            if (index == 0)
                            {
                                pos += searchBytes.Length;
                                index = 1;
                            }
                        } while (index != -1 && index != 0);
                    }
                }
            }
            else if (ProcessMachineType == MachineType.x64)
            {
                byte[] buffer = new byte[int.MaxValue / 10];
                int bytesRead = 0;
                for (int i = 0; i < MemoryRegions64.Count; i++)
                {
                    if (MemoryRegions64[i].RegionSize > int.MaxValue)
                    {
                        ulong startAddress = MemoryRegions64[i].BaseAddress;
                        ulong endAddress = MemoryRegions64[i].BaseAddress + (MemoryRegions64[i].RegionSize - 1);
                        ulong region = MemoryRegions64[i].RegionSize;

                        for (ulong j = startAddress; j < endAddress; j += int.MaxValue / 10)
                        {
                            Native.ReadProcessMemory(ProcessHandle, (IntPtr)j, buffer, buffer.Length, out bytesRead);
                            long pos = 0;
                            long index = 0;
                            do
                            {
                                byte[] buffer1Partial = new byte[buffer.Length - pos];
                                Array.Copy(buffer, pos, buffer1Partial, 0, buffer.Length - pos);
                                index = ByteIndexOf(buffer1Partial, searchBytes);

                                if (index != -1)
                                {
                                    resultAddresses.ReturnValue.Add((IntPtr)(index + (long)MemoryRegions64[i].BaseAddress + pos));
                                }
                                pos += index;
                                if (index == 0)
                                {
                                    pos += searchBytes.Length;
                                    index = 1;
                                }
                            } while (index != -1 && index != 0);
                        }
                    }
                    else
                    {
                        long bufferSize = (long)MemoryRegions64[i].RegionSize;
                        bytesRead = 0;
                        IntPtr baseAddress = (IntPtr)MemoryRegions64[i].BaseAddress;
                        byte[] buffer1 = new byte[bufferSize];

                        Native.ReadProcessMemory(ProcessHandle, baseAddress, buffer1, buffer1.Length, out bytesRead);
                        long pos = 0;
                        long index = 0;
                        do
                        {
                            byte[] buffer1Partial = new byte[buffer1.Length - pos];
                            Array.Copy(buffer1, pos, buffer1Partial, 0, buffer1.Length - pos);
                            index = ByteIndexOf(buffer1Partial, searchBytes);

                            if (index != -1)
                            {
                                resultAddresses.ReturnValue.Add((IntPtr)(index + (long)MemoryRegions64[i].BaseAddress + pos));
                            }
                            pos += index;
                            if (index == 0)
                            {
                                pos += searchBytes.Length;
                                index = 1;
                            }
                        } while (index != -1 && index != 0);
                    }
                }
            }
            resultAddresses.ReturnValue = new HashSet<IntPtr>(resultAddresses.ReturnValue).ToList();
            resultAddresses.ReturnValue = Utilities.PtrRemover.RemovePointers(ProcessMachineType, resultAddresses.ReturnValue, ptrsToExclude);
            return resultAddresses;
        }
        #endregion

        #region SearchAllMemoryPPR
        /// <summary>
        /// Searches all memory associated with a given process and associated modules for POP X POP X RET instructions. 
        /// Passing a list of module paths or names will exclude those modules from the search. 
        /// </summary>
        /// <param name="excludes">Takes a list of module names to be excluded from the search</param>
        /// <returns>Returns an ERC_Result containing a dictionary of pointers and the main module in which they were found</returns>
        public ErcResult<Dictionary<IntPtr, string>> SearchAllMemoryPPR(List<string>? excludes = null)
        {
            ErcResult<Dictionary<IntPtr, string>> ptrs = new ErcResult<Dictionary<IntPtr, string>>(ProcessCore);
            ptrs.ReturnValue = new Dictionary<IntPtr, string>();
            if (ProcessMachineType == MachineType.I386)
            {
                for (int i = 0; i < MemoryRegions32.Count; i++)
                {
                    if ((ulong)MemoryRegions32[i].RegionSize > int.MaxValue)
                    {
                        long start_address = (long)MemoryRegions32[i].BaseAddress;
                        long end_address = (long)MemoryRegions32[i].BaseAddress + (long)(MemoryRegions32[i].RegionSize - 1);
                        long region = (long)MemoryRegions32[i].RegionSize;
                        for (long j = start_address; j < end_address; j += (region / 100))
                        {
                            byte[] buffer = new byte[region / 100];
                            int bytesRead = 0;
                            Native.ReadProcessMemory(ProcessHandle, (IntPtr)j, buffer, buffer.Length, out bytesRead);
                            List<int> pprs = ERC.Utilities.Payloads.PopPopRet(buffer);
                            if (pprs.Count > 0)
                            {
                                for (int k = 0; k < pprs.Count; k++)
                                {
                                    if (!ptrs.ReturnValue.ContainsKey((IntPtr)((ulong)pprs[k] + (ulong)MemoryRegions32[i].BaseAddress)))
                                    {
                                        ptrs.ReturnValue.Add((IntPtr)((ulong)pprs[k] + (ulong)MemoryRegions32[i].BaseAddress), ProcessPath);
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        long bufferSize = (long)MemoryRegions32[i].RegionSize;
                        int bytesRead = 0;
                        IntPtr baseAddress = MemoryRegions32[i].BaseAddress;
                        byte[] buffer = new byte[bufferSize];

                        Native.ReadProcessMemory(ProcessHandle, baseAddress, buffer, buffer.Length, out bytesRead);
                        List<int> pprs = ERC.Utilities.Payloads.PopPopRet(buffer);
                        if (pprs.Count > 0)
                        {
                            for (int k = 0; k < pprs.Count; k++)
                            {
                                if (!ptrs.ReturnValue.ContainsKey((IntPtr)((ulong)pprs[k] + (ulong)MemoryRegions32[i].BaseAddress)))
                                {
                                    ptrs.ReturnValue.Add((IntPtr)((ulong)pprs[k] + (ulong)MemoryRegions32[i].BaseAddress), ProcessPath);
                                }
                            }
                        }
                    }
                }
            }
            else if (ProcessMachineType == MachineType.x64)
            {
                byte[] buffer = new byte[int.MaxValue / 10];
                int bytesRead = 0;
                for (int i = 0; i < MemoryRegions64.Count; i++)
                {
                    if (MemoryRegions64[i].RegionSize > int.MaxValue)
                    {
                        ulong startAddress = MemoryRegions64[i].BaseAddress;
                        ulong endAddress = MemoryRegions64[i].BaseAddress + (MemoryRegions64[i].RegionSize - 1);
                        ulong region = MemoryRegions64[i].RegionSize;

                        for (ulong j = startAddress; j < endAddress; j += int.MaxValue / 10)
                        {
                            Native.ReadProcessMemory(ProcessHandle, (IntPtr)j, buffer, buffer.Length, out bytesRead);
                            List<int> pprs = ERC.Utilities.Payloads.PopPopRet(buffer);
                            if (pprs.Count > 0)
                            {
                                for (int k = 0; k < pprs.Count; k++)
                                {
                                    if (!ptrs.ReturnValue.ContainsKey((IntPtr)((ulong)pprs[k] + MemoryRegions64[i].BaseAddress)))
                                    {
                                        ptrs.ReturnValue.Add((IntPtr)((ulong)pprs[k] + MemoryRegions64[i].BaseAddress), ProcessPath);
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        long bufferSize = (long)MemoryRegions64[i].RegionSize;
                        bytesRead = 0;
                        IntPtr baseAddress = (IntPtr)MemoryRegions64[i].BaseAddress;
                        byte[] buffer1 = new byte[bufferSize];

                        Native.ReadProcessMemory(ProcessHandle, baseAddress, buffer1, buffer1.Length, out bytesRead);
                        List<int> pprs = ERC.Utilities.Payloads.PopPopRet(buffer1);
                        if(pprs.Count > 0)
                        {
                            for (int k = 0; k < pprs.Count; k++)
                            {
                                if (!ptrs.ReturnValue.ContainsKey((IntPtr)((ulong)pprs[k] + MemoryRegions64[i].BaseAddress)))
                                {
                                    ptrs.ReturnValue.Add((IntPtr)((ulong)pprs[k] + MemoryRegions64[i].BaseAddress), ProcessPath);
                                }
                            }
                        }
                    }
                }
            }
            List<ModuleInfo> modules = new List<ModuleInfo>();
            for(int i = 0; i < ModulesInfo.Count; i++)
            {
                if (excludes != null)
                {
                    if (!excludes.Contains(ModulesInfo[i].ModuleName) && !excludes.Contains(ModulesInfo[i].ModulePath))
                    {
                        modules.Add(ModulesInfo[i]);
                    }
                }
                else
                {
                    modules.Add(ModulesInfo[i]);
                }
            }
            for(int i = 0; i < modules.Count; i++)
            {

                IntPtr baseAddress = modules[i].ModuleBase;
                byte[] buffer = new byte[modules[i].ModuleSize];
                int bytesread = 0;

                Native.ReadProcessMemory(ProcessHandle, modules[i].ModuleBase, buffer, buffer.Length, out bytesread);
                List<int> pprs = ERC.Utilities.Payloads.PopPopRet(buffer);
                if (pprs.Count > 0)
                {
                    for (int k = 0; k < pprs.Count; k++)
                    {
                        if (!ptrs.ReturnValue.ContainsKey((IntPtr)((ulong)pprs[k] + (ulong)modules[i].ModuleBase)))
                        {
                            ptrs.ReturnValue.Add((IntPtr)((ulong)pprs[k] + (ulong)modules[i].ModuleBase), modules[i].ModulePath);
                        }
                    }
                }
            }
            return ptrs;
        }

        /// <summary>
        /// Searches all memory associated with a given process and associated modules for POP X POP X RET instructions. 
        /// Passing a list of module paths or names will exclude those modules from the search. 
        /// </summary>
        /// <param name="excludes">Takes a list of module names to be excluded from the search</param>
        /// <param name="ptrsToExclude"> Takes a byte array of values used to disqualify pointers</param>
        /// <returns>Returns an ERC_Result containing a dictionary of pointers and the main module in which they were found</returns>
        public ErcResult<Dictionary<IntPtr, string>> SearchAllMemoryPPR(byte[] ptrsToExclude, List<string>? excludes = null)
        {
            ErcResult<Dictionary<IntPtr, string>> ptrs = new ErcResult<Dictionary<IntPtr, string>>(ProcessCore);
            ptrs.ReturnValue = new Dictionary<IntPtr, string>();
            if (ProcessMachineType == MachineType.I386)
            {
                for (int i = 0; i < MemoryRegions32.Count; i++)
                {
                    if ((ulong)MemoryRegions32[i].RegionSize > int.MaxValue)
                    {
                        long start_address = (long)MemoryRegions32[i].BaseAddress;
                        long end_address = (long)MemoryRegions32[i].BaseAddress + (long)(MemoryRegions32[i].RegionSize - 1);
                        long region = (long)MemoryRegions32[i].RegionSize;
                        for (long j = start_address; j < end_address; j += (region / 100))
                        {
                            byte[] buffer = new byte[region / 100];
                            int bytesRead = 0;
                            Native.ReadProcessMemory(ProcessHandle, (IntPtr)j, buffer, buffer.Length, out bytesRead);
                            List<int> pprs = ERC.Utilities.Payloads.PopPopRet(buffer);
                            if (pprs.Count > 0)
                            {
                                for (int k = 0; k < pprs.Count; k++)
                                {
                                    if (!ptrs.ReturnValue.ContainsKey((IntPtr)((ulong)pprs[k] + (ulong)MemoryRegions32[i].BaseAddress)))
                                    {
                                        ptrs.ReturnValue.Add((IntPtr)((ulong)pprs[k] + (ulong)MemoryRegions32[i].BaseAddress), ProcessPath);
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        long bufferSize = (long)MemoryRegions32[i].RegionSize;
                        int bytesRead = 0;
                        IntPtr baseAddress = MemoryRegions32[i].BaseAddress;
                        byte[] buffer = new byte[bufferSize];

                        Native.ReadProcessMemory(ProcessHandle, baseAddress, buffer, buffer.Length, out bytesRead);
                        List<int> pprs = ERC.Utilities.Payloads.PopPopRet(buffer);
                        if (pprs.Count > 0)
                        {
                            for (int k = 0; k < pprs.Count; k++)
                            {
                                if (!ptrs.ReturnValue.ContainsKey((IntPtr)((ulong)pprs[k] + (ulong)MemoryRegions32[i].BaseAddress)))
                                {
                                    ptrs.ReturnValue.Add((IntPtr)((ulong)pprs[k] + (ulong)MemoryRegions32[i].BaseAddress), ProcessPath);
                                }
                            }
                        }
                    }
                }
            }
            else if (ProcessMachineType == MachineType.x64)
            {
                byte[] buffer = new byte[int.MaxValue / 10];
                int bytesRead = 0;
                for (int i = 0; i < MemoryRegions64.Count; i++)
                {
                    if (MemoryRegions64[i].RegionSize > int.MaxValue)
                    {
                        ulong startAddress = MemoryRegions64[i].BaseAddress;
                        ulong endAddress = MemoryRegions64[i].BaseAddress + (MemoryRegions64[i].RegionSize - 1);
                        ulong region = MemoryRegions64[i].RegionSize;

                        for (ulong j = startAddress; j < endAddress; j += int.MaxValue / 10)
                        {
                            Native.ReadProcessMemory(ProcessHandle, (IntPtr)j, buffer, buffer.Length, out bytesRead);
                            List<int> pprs = ERC.Utilities.Payloads.PopPopRet(buffer);
                            if (pprs.Count > 0)
                            {
                                for (int k = 0; k < pprs.Count; k++)
                                {
                                    if (!ptrs.ReturnValue.ContainsKey((IntPtr)((ulong)pprs[k] + MemoryRegions64[i].BaseAddress)))
                                    {
                                        ptrs.ReturnValue.Add((IntPtr)((ulong)pprs[k] + MemoryRegions64[i].BaseAddress), ProcessPath);
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        long bufferSize = (long)MemoryRegions64[i].RegionSize;
                        bytesRead = 0;
                        IntPtr baseAddress = (IntPtr)MemoryRegions64[i].BaseAddress;
                        byte[] buffer1 = new byte[bufferSize];

                        Native.ReadProcessMemory(ProcessHandle, baseAddress, buffer1, buffer1.Length, out bytesRead);
                        List<int> pprs = ERC.Utilities.Payloads.PopPopRet(buffer1);
                        if (pprs.Count > 0)
                        {
                            for (int k = 0; k < pprs.Count; k++)
                            {
                                if (!ptrs.ReturnValue.ContainsKey((IntPtr)((ulong)pprs[k] + MemoryRegions64[i].BaseAddress)))
                                {
                                    ptrs.ReturnValue.Add((IntPtr)((ulong)pprs[k] + MemoryRegions64[i].BaseAddress), ProcessPath);
                                }
                            }
                        }
                    }
                }
            }
            List<ModuleInfo> modules = new List<ModuleInfo>();
            for (int i = 0; i < ModulesInfo.Count; i++)
            {
                if (excludes != null)
                {
                    if (!excludes.Contains(ModulesInfo[i].ModuleName) && !excludes.Contains(ModulesInfo[i].ModulePath))
                    {
                        modules.Add(ModulesInfo[i]);
                    }
                }
                else
                {
                    modules.Add(ModulesInfo[i]);
                }
            }
            for (int i = 0; i < modules.Count; i++)
            {

                IntPtr baseAddress = modules[i].ModuleBase;
                byte[] buffer = new byte[modules[i].ModuleSize];
                int bytesread = 0;

                Native.ReadProcessMemory(ProcessHandle, modules[i].ModuleBase, buffer, buffer.Length, out bytesread);
                List<int> pprs = ERC.Utilities.Payloads.PopPopRet(buffer);
                if (pprs.Count > 0)
                {
                    for (int k = 0; k < pprs.Count; k++)
                    {
                        if (!ptrs.ReturnValue.ContainsKey((IntPtr)((ulong)pprs[k] + (ulong)modules[i].ModuleBase)))
                        {
                            ptrs.ReturnValue.Add((IntPtr)((ulong)pprs[k] + (ulong)modules[i].ModuleBase), modules[i].ModulePath);
                        }
                    }
                }
            }
            ptrs.ReturnValue = Utilities.PtrRemover.RemovePointers(ProcessMachineType, ptrs.ReturnValue, ptrsToExclude);
            return ptrs;
        }
        #endregion

        #region SearchMemory
        /// <summary>
        /// Searches all memory (the process and associated DLLs) for a specific string or byte array. Strings can be passed as ASCII, Unicode, UTF7 or UTF8.
        /// Specific modules can be exclude through passing a Listof strings containing module names or paths.
        /// </summary>
        /// <param name="searchType">0 = search term is in bytes\n1 = search term is in unicode\n2 = search term is in ASCII\n3 = Search term is in UTF8\n4 = Search term is in UTF7\n5 = Search term is in UTF32</param>
        /// <param name="searchBytes">Byte array to be searched for (optional)</param>
        /// <param name="searchString">String to be searched for (optional)</param>
        /// <param name="excludes">Modules to be excluded from the search (optional)</param>
        /// <returns>Returns an ERC_Result containing pointers to all instances of the search query.</returns>
        public ErcResult<Dictionary<IntPtr, string>> SearchMemory(int searchType, byte[]? searchBytes = null, string? searchString = null, List<string>? excludes = null)
        {
            ErcResult<Dictionary<IntPtr, string>> resultAddresses = new ErcResult<Dictionary<IntPtr, string>>(ProcessCore);
            resultAddresses.ReturnValue = new Dictionary<IntPtr, string>();

            // Which argument is required depends on searchType; SearchTerm decides and
            // reports, rather than each caller reaching an encoder with a null string.
            ErcResult<byte[]> term = Utilities.SearchTerm.Resolve(ProcessCore, searchType, searchBytes, searchString);
            if (term.Error != null)
            {
                resultAddresses.Error = term.Error;
                resultAddresses.LogEvent();
                return resultAddresses;
            }

            searchBytes = term.ReturnValue;
            var processPtrs = SearchProcessMemory(searchBytes);
            if(processPtrs.Error != null)
            {
                resultAddresses.Error = new ERCException("Error passed from Search_Process_Memory: " + processPtrs.Error.ToString());
                resultAddresses.LogEvent();
                return resultAddresses;
            }

            for(int i = 0; i < processPtrs.ReturnValue.Count; i++)
            {
                if (!resultAddresses.ReturnValue.ContainsKey(processPtrs.ReturnValue[i]))
                {
                    resultAddresses.ReturnValue.Add(processPtrs.ReturnValue[i], ProcessPath);
                }
            }

            List<ModuleInfo> modules = new List<ModuleInfo>();
            for (int i = 0; i < ModulesInfo.Count; i++)
            {
                if (excludes != null)
                {
                    if (!excludes.Contains(ModulesInfo[i].ModuleName) && !excludes.Contains(ModulesInfo[i].ModulePath))
                    {
                        modules.Add(ModulesInfo[i]);
                    }
                }
                else
                {
                    modules.Add(ModulesInfo[i]);
                }
            }
            for(int i = 0; i < modules.Count; i++)
            {
                var modulePtrs = modules[i].SearchModule(searchBytes);
                if(modulePtrs.ReturnValue.Count > 0)
                {
                    for(int j = 0; j < modulePtrs.ReturnValue.Count; j++)
                    {
                        if (!resultAddresses.ReturnValue.ContainsKey(modulePtrs.ReturnValue[j]))
                        {
                            resultAddresses.ReturnValue.Add(modulePtrs.ReturnValue[j], modules[i].ModulePath);
                        }
                    }
                }
            }
            return resultAddresses;
        }

        /// <summary>
        /// Searches all memory (the process and associated DLLs) for a specific string or byte array. Strings can be passed as ASCII, Unicode, UTF7 or UTF8.
        /// Specific modules can be exclude through passing a Listof strings containing module names or paths.
        /// </summary>
        /// <param name="searchType">0 = search term is in bytes\n1 = search term is in unicode\n2 = search term is in ASCII\n3 = Search term is in UTF8\n4 = Search term is in UTF7\n5 = Search term is in UTF32</param>
        /// <param name="ptrsToExclude"> Takes a byte array of values used to disqualify pointers</param>
        /// <param name="searchBytes">Byte array to be searched for (optional)</param>
        /// <param name="searchString">String to be searched for (optional)</param>
        /// <param name="excludes">Modules to be excluded from the search (optional)</param>
        /// <returns>Returns an ERC_Result containing pointers to all instances of the search query.</returns>
        public ErcResult<Dictionary<IntPtr, string>> SearchMemory(int searchType, byte[] ptrsToExclude, byte[]? searchBytes = null, string? searchString = null, List<string>? excludes = null)
        {
            ErcResult<Dictionary<IntPtr, string>> resultAddresses = new ErcResult<Dictionary<IntPtr, string>>(ProcessCore);
            resultAddresses.ReturnValue = new Dictionary<IntPtr, string>();

            // Which argument is required depends on searchType; SearchTerm decides and
            // reports, rather than each caller reaching an encoder with a null string.
            ErcResult<byte[]> term = Utilities.SearchTerm.Resolve(ProcessCore, searchType, searchBytes, searchString);
            if (term.Error != null)
            {
                resultAddresses.Error = term.Error;
                resultAddresses.LogEvent();
                return resultAddresses;
            }

            searchBytes = term.ReturnValue;
            var processPtrs = SearchProcessMemory(searchBytes);
            if (processPtrs.Error != null)
            {
                resultAddresses.Error = new ERCException("Error passed from Search_Process_Memory: " + processPtrs.Error.ToString());
                resultAddresses.LogEvent();
                return resultAddresses;
            }

            for (int i = 0; i < processPtrs.ReturnValue.Count; i++)
            {
                if (!resultAddresses.ReturnValue.ContainsKey(processPtrs.ReturnValue[i]))
                {
                    resultAddresses.ReturnValue.Add(processPtrs.ReturnValue[i], ProcessPath);
                }
            }

            List<ModuleInfo> modules = new List<ModuleInfo>();
            for (int i = 0; i < ModulesInfo.Count; i++)
            {
                if (excludes != null)
                {
                    if (!excludes.Contains(ModulesInfo[i].ModuleName) && !excludes.Contains(ModulesInfo[i].ModulePath))
                    {
                        modules.Add(ModulesInfo[i]);
                    }
                }
                else
                {
                    modules.Add(ModulesInfo[i]);
                }
            }
            for (int i = 0; i < modules.Count; i++)
            {
                var modulePtrs = modules[i].SearchModule(searchBytes);
                if (modulePtrs.ReturnValue.Count > 0)
                {
                    for (int j = 0; j < modulePtrs.ReturnValue.Count; j++)
                    {
                        if (!resultAddresses.ReturnValue.ContainsKey(modulePtrs.ReturnValue[j]))
                        {
                            resultAddresses.ReturnValue.Add(modulePtrs.ReturnValue[j], modules[i].ModulePath);
                        }
                    }
                }
            }

            resultAddresses.ReturnValue = Utilities.PtrRemover.RemovePointers(ProcessMachineType, resultAddresses.ReturnValue, ptrsToExclude);
            
            return resultAddresses;
        }
        #endregion

        #region SearchModules
        /// <summary>
        /// Searches all modules loaded by a process for a specific string or byte array. Strings can be passed as ASCII, Unicode, UTF7 or UTF8.
        /// Search can be limited to specific modules through passing a List of strings containing module names or paths.
        /// </summary>
        /// <param name="searchType">0 = search term is in bytes\n1 = search term is in unicode\n2 = search term is in ASCII\n3 = Search term is in UTF8\n4 = Search term is in UTF7\n5 = Search term is in UTF32</param>
        /// <param name="ptrsToExclude"> Takes a byte array of values used to disqualify pointers</param>
        /// <param name="searchBytes">Byte array to be searched for (optional)</param>
        /// <param name="searchString">String to be searched for (optional)</param>
        /// <param name="includedModules">Modules to be included in the search (optional)</param>
        /// <param name="excludedModules">Modules to be excluded from the search (optional)</param>
        /// <returns>Returns an ERC_Result containing pointers to all instances of the search query.</returns>>
        public ErcResult<Dictionary<IntPtr, string>> SearchModules(int searchType, byte[]? ptrsToExclude = null, byte[]? searchBytes = null, string? searchString = null, List<string>? includedModules = null, List<string>? excludedModules = null)
        {
            ErcResult<Dictionary<IntPtr, string>> resultAddresses = new ErcResult<Dictionary<IntPtr, string>>(ProcessCore);
            resultAddresses.ReturnValue = new Dictionary<IntPtr, string>();

            // Which argument is required depends on searchType; SearchTerm decides and
            // reports, rather than each caller reaching an encoder with a null string.
            ErcResult<byte[]> term = Utilities.SearchTerm.Resolve(ProcessCore, searchType, searchBytes, searchString);
            if (term.Error != null)
            {
                resultAddresses.Error = term.Error;
                resultAddresses.LogEvent();
                return resultAddresses;
            }

            searchBytes = term.ReturnValue;

            List<ModuleInfo> modules = new List<ModuleInfo>();
            for (int i = 0; i < ModulesInfo.Count; i++)
            {
                if (includedModules != null)
                {
                    if (includedModules.Contains(ModulesInfo[i].ModuleName) || includedModules.Contains(ModulesInfo[i].ModulePath))
                    {
                        if(excludedModules != null)
                        {
                            if(!excludedModules.Contains(ModulesInfo[i].ModuleName) && !excludedModules.Contains(ModulesInfo[i].ModulePath))
                            {
                                modules.Add(ModulesInfo[i]);
                            }
                        }
                    }
                }
                else
                {
                    modules.Add(ModulesInfo[i]);
                }
            }
            for (int i = 0; i < modules.Count; i++)
            {
                var modulePtrs = modules[i].SearchModule(searchBytes);
                if (modulePtrs.ReturnValue.Count > 0)
                {
                    for (int j = 0; j < modulePtrs.ReturnValue.Count; j++)
                    {
                        if (!resultAddresses.ReturnValue.ContainsKey(modulePtrs.ReturnValue[j]))
                        {
                            resultAddresses.ReturnValue.Add(modulePtrs.ReturnValue[j], modules[i].ModulePath);
                        }
                    }
                }
            }

            if(ptrsToExclude != null)
            {
                resultAddresses.ReturnValue = Utilities.PtrRemover.RemovePointers(ProcessMachineType, resultAddresses.ReturnValue, ptrsToExclude);
            }
            return resultAddresses;
        }
        #endregion


        #endregion

        #region BoyerMoore Search ByteArrays
        /// <summary>
        /// Private function, BoyerMoore string search algorithm modified to search for sets of bytes in a byte array. 
        /// Takes two byte arrays, array to be searched and array to search for.
        /// </summary>
        private static int ByteIndexOf(byte[] haystack, byte[] needle)
        {
            if (needle.Length == 0)
            {
                return 0;
            }

            int[] charTable = MakeCharTable(needle);
            int[] offsetTable = MakeOffsetTable(needle);
            for (int i = needle.Length - 1; i < haystack.Length;)
            {
                int j;
                for (j = needle.Length - 1; needle[j] == haystack[i]; --i, --j)
                {
                    if (j == 0)
                    {
                        return i;
                    }
                }

                i += Math.Max(offsetTable[needle.Length - 1 - j], charTable[haystack[i]]);
            }
            return -1;
        }

        private static int[] MakeCharTable(byte[] needle)
        {
            const int ALPHABET_SIZE = 256;
            int[] table = new int[ALPHABET_SIZE];
            for (int i = 0; i < table.Length; ++i)
            {
                table[i] = needle.Length;
            }

            for (int i = 0; i < needle.Length - 1; ++i)
            {
                table[needle[i]] = needle.Length - 1 - i;
            }

            return table;
        }

        private static int[] MakeOffsetTable(byte[] needle)
        {
            int[] table = new int[needle.Length];
            int lastPrefixPosition = needle.Length;
            for (int i = needle.Length - 1; i >= 0; --i)
            {
                if (IsPrefix(needle, i + 1))
                {
                    lastPrefixPosition = i + 1;
                }

                table[needle.Length - 1 - i] = lastPrefixPosition - i + needle.Length - 1;
            }

            for (int i = 0; i < needle.Length - 1; ++i)
            {
                int slen = SuffixLength(needle, i);
                table[slen] = needle.Length - 1 - i + slen;
            }

            return table;
        }

        private static bool IsPrefix(byte[] needle, int p)
        {
            for (int i = p, j = 0; i < needle.Length; ++i, ++j)
            {
                if (needle[i] != needle[j])
                {
                    return false;
                }
            }

            return true;
        }

        private static int SuffixLength(byte[] needle, int p)
        {
            int len = 0;
            for (int i = p, j = needle.Length - 1; i >= 0 && needle[i] == needle[j]; --i, --j)
            {
                len += 1;
            }

            return len;
        }

        #endregion
    }
}
