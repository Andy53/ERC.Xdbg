using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using ERC.Structures;

namespace ERC
{
    public class HeapInfo
    {
        #region Variables
        internal List<HEAPENTRY32> HeapEntries = new List<HEAPENTRY32>();
        internal List<HEAPLIST32> HeapLists = new List<HEAPLIST32>();
        internal ProcessInfo HeapProcess;

        #endregion

        #region Constructor
        public HeapInfo(ProcessInfo info)
        {
            HeapProcess = info;
            HEAPLIST32 firstHeapList = new HEAPLIST32();
            firstHeapList.dwSize = (IntPtr)Marshal.SizeOf(typeof(HEAPLIST32));
            IntPtr Handle = ErcCore.CreateToolhelp32Snapshot(SnapshotFlags.HeapList, (uint)info.ProcessID);

            if ((int)Handle == -1)
            {
                throw new ERCException("CreateToolhelp32Snapshot returned an invalid handle value (-1)");
            }

            if (ErcCore.Heap32ListFirst(Handle, ref firstHeapList))
            {
                HeapLists.Add(firstHeapList);
                bool moreHeaps = false;
                do
                {
                    HEAPLIST32 currentHeap = new HEAPLIST32();
                    currentHeap.dwSize = (IntPtr)Marshal.SizeOf(typeof(HEAPLIST32));
                    moreHeaps = ErcCore.Heap32ListNext(Handle, ref currentHeap);
                    if(HeapEntries.Count == 0)
                    {
                        currentHeap = firstHeapList;
                    }

                    if (moreHeaps)
                    {
                        HeapLists.Add(currentHeap);
                        HEAPENTRY32 heapentry32 = new HEAPENTRY32();
                        heapentry32.dwSize = (IntPtr)Marshal.SizeOf(typeof(HEAPENTRY32));

                        if (ErcCore.Heap32First(ref heapentry32, (uint)HeapProcess.ProcessID, currentHeap.th32HeapID))
                        {
                            bool moreheapblocks = false;
                            do
                            {
                                HeapEntries.Add(heapentry32);
                                moreheapblocks = ErcCore.Heap32Next(ref heapentry32);
                            }
                            while (moreheapblocks);
                        }
                    }
                }
                while (moreHeaps);
            }
            else
            {
                throw new ERCException("Heap32ListFirst returned an invalid response. Error: " + Utilities.Win32Errors.GetLastWin32Error());
            }
        }

        #endregion

        #region Accessors
        /// <summary>
        /// Searches heap entries for a specified pattern. Returns pointers to all instances of the pattern. If heapID and startAddress are both supplied heapID takes precedence.
        /// </summary>
        /// <param name="searchBytes">byte array containing the pattern to search for</param>
        /// <param name="heapID">ID of the heap to be searched(Optional)</param>
        /// <param name="hexStartAddress">Start address of the heap entry to be searched in hexadecimal(Optional)</param>
        /// <returns>Returns an ERCResult of IntPtr containing pointers to all instances of the pattern found.</returns>
        public ErcResult<List<IntPtr>> SearchHeap(byte[] searchBytes, ulong heapID = 0, string hexStartAddress = "")
        {

            ErcResult<List<IntPtr>> result = new ErcResult<List<IntPtr>>(HeapProcess);
            result.ReturnValue = new List<IntPtr>();

            if (hexStartAddress.Contains("0x") || hexStartAddress.Contains("0x") || hexStartAddress.Contains("x") || hexStartAddress.Contains("X"))
            {
                hexStartAddress = hexStartAddress.Replace("0x", "");
                hexStartAddress = hexStartAddress.Replace("0X", "");
                hexStartAddress = hexStartAddress.Replace("X", "");
                hexStartAddress = hexStartAddress.Replace("x", "");
            }

            ulong startAddress = 0;
            if (HeapProcess.ProcessMachineType == MachineType.I386)
            {
                try
                {
                    startAddress = (uint)Convert.ToInt32(hexStartAddress, 16);
                }
                catch (Exception e)
                {
                    result.Error = e;
                }

            }
            else
            {
                try
                {
                    startAddress = (ulong)Convert.ToInt64(hexStartAddress, 16);
                }
                catch (Exception e)
                {
                    result.Error = e;
                }
            }

            if (searchBytes.Length < 3)
            {
                result.Error = new ERCException("Search pattern not long enough. Minimum length is 3 bytes");
                result.ReturnValue = null;
                return result;
            }

            if(heapID != 0)
            {
                foreach (HEAPENTRY32 he in HeapEntries)
                {
                    if((ulong)he.th32HeapID == heapID)
                    {
                        byte[] bytes = HeapProcess.DumpMemoryRegion(he.dwAddress, (int)he.dwBlockSize).ReturnValue;

                        int maxFirstCharSlot = bytes.Length - searchBytes.Length + 1;
                        for (int i = 0; i < maxFirstCharSlot; i++)
                        {
                            if (bytes[i] != searchBytes[0]) 
                                continue;

                            for (int j = searchBytes.Length - 1; j >= 1; j--)
                            {
                                if (bytes[i + j] != searchBytes[j]) break;
                                if (j == 1) result.ReturnValue.Add(he.dwAddress + i);
                            }
                        }
                    }
                }
            }
            else if(startAddress != 0)
            {
                foreach (HEAPENTRY32 he in HeapEntries)
                {
                    if ((ulong)he.dwAddress == startAddress)
                    {
                        byte[] bytes = HeapProcess.DumpMemoryRegion((IntPtr)startAddress, (int)he.dwBlockSize).ReturnValue;

                        int maxFirstCharSlot = bytes.Length - searchBytes.Length + 1;
                        for (int i = 0; i < maxFirstCharSlot; i++)
                        {
                            
                            if (bytes[i] != searchBytes[0])
                            {
                                continue;
                            }

                            for (int j = searchBytes.Length - 1; j >= 1; j--)
                            {
                                if (bytes[i + j] != searchBytes[j])
                                {
                                    break;
                                }

                                if (j == 1)
                                {
                                    result.ReturnValue.Add(he.dwAddress + i);
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                foreach(HEAPENTRY32 he in HeapEntries)
                {
                    byte[] bytes = HeapProcess.DumpMemoryRegion(he.dwAddress, (int)he.dwBlockSize).ReturnValue;

                    int maxFirstCharSlot = bytes.Length - searchBytes.Length + 1;
                    for (int i = 0; i < maxFirstCharSlot; i++)
                    {
                        if (bytes[i] != searchBytes[0])
                            continue;

                        for (int j = searchBytes.Length - 1; j >= 1; j--)
                        {
                            if (bytes[i + j] != searchBytes[j]) break;
                            if (j == 1) result.ReturnValue.Add(he.dwAddress + i);
                        }
                    }
                }
            }
            return result;
        }

        /// <summary>
        /// Returns a collections of stats related to the heap of the current process object. If both heapID and startAddress are specified heapID takes precedence.
        /// </summary>
        /// <param name="extended">display an extended set of </param>
        /// <param name="heapID">The ID of the heap to display stats for. (optional)</param>
        /// <param name="hexStartAddress">The start address of the specific heap block to display stats for in hexadecimal. (optional)</param>
        /// <returns>returns a List<string> object</returns>
        public ErcResult<List<string>> HeapStatistics(bool extended = false, ulong heapID = 0, string hexStartAddress = "")
        {
            ErcResult<List<string>> result = new ErcResult<List<string>>(HeapProcess);
            if (hexStartAddress.Contains("0x") || hexStartAddress.Contains("0x") || hexStartAddress.Contains("x") || hexStartAddress.Contains("X"))
            {
                hexStartAddress = hexStartAddress.Replace("0x", "");
                hexStartAddress = hexStartAddress.Replace("0X", "");
                hexStartAddress = hexStartAddress.Replace("X", "");
                hexStartAddress = hexStartAddress.Replace("x", "");
            }

            ulong startAddress = 0;
            if(HeapProcess.ProcessMachineType == MachineType.I386)
            {
                try
                {
                    startAddress = (uint)Convert.ToInt32(hexStartAddress, 16);
                }
                catch(Exception e)
                {
                    result.Error = e;
                }
                
            }
            else
            {
                try
                {
                    startAddress = (ulong)Convert.ToInt64(hexStartAddress, 16);
                }
                catch(Exception e)
                {
                    result.Error = e;
                }
            }
            
            List<string> heapStats = new List<string>();
            heapStats.Add("ProcessID = " + HeapProcess.ProcessID + Environment.NewLine);
            heapStats.Add("Number of heaps = " + HeapLists.Count + Environment.NewLine);
            
            if(heapID != 0)
            {
                heapStats.Add("    Heap ID = " + heapID + Environment.NewLine);
            }
            
            int count = 0;
            foreach(HEAPLIST32 hl in HeapLists)
            {
                count++;
                int heapEnts = 0;
                if(heapID == 0 && startAddress == 0)
                {
                    heapStats.Add("    Heap " + count + " ID = " + hl.th32HeapID + Environment.NewLine);
                }
                
                foreach(HEAPENTRY32 he in HeapEntries)
                {
                    if (heapID != 0)
                    {
                        if(he.th32HeapID == (IntPtr)heapID && hl.th32HeapID == (IntPtr)heapID)
                        {
                            if (HeapProcess.ProcessMachineType == MachineType.I386)
                            {
                                heapStats.Add("       Heap Start Address = 0x" + he.dwAddress.ToString("X8") + Environment.NewLine);
                                heapStats.Add("       Heap Entry size = " + he.dwBlockSize.ToString() + Environment.NewLine);
                                switch (he.dwFlags)
                                {
                                    case 1:
                                        heapStats.Add("       Heap flags = LF32_FIXED" + Environment.NewLine);
                                        break;
                                    case 2:
                                        heapStats.Add("       Heap flags = LF32_FREE" + Environment.NewLine);
                                        break;
                                    case 4:
                                        heapStats.Add("       Heap flags = LF32_MOVEABLE" + Environment.NewLine);
                                        break;
                                    default:
                                        break;
                                }
                            }
                            else
                            {
                                heapStats.Add("       Heap Start Address = " + he.dwAddress.ToString("X16") + Environment.NewLine);
                                heapStats.Add("       Heap Entry size = " + he.dwBlockSize.ToString() + Environment.NewLine);
                                switch (he.dwFlags)
                                {
                                    case 1:
                                        heapStats.Add("       Heap flags = LF32_FIXED" + Environment.NewLine);
                                        break;
                                    case 2:
                                        heapStats.Add("       Heap flags = LF32_FREE" + Environment.NewLine);
                                        break;
                                    case 4:
                                        heapStats.Add("       Heap flags = LF32_MOVEABLE" + Environment.NewLine);
                                        break;
                                    default:
                                        break;
                                }
                            }
                            heapEnts++;
                        }
                    }
                    else if (startAddress != 0)
                    {
                        if(he.dwAddress == (IntPtr)startAddress)
                        {
                            if (HeapProcess.ProcessMachineType == MachineType.I386)
                            {
                                heapStats.Add("    Heap ID = " + hl.th32HeapID + Environment.NewLine);
                                heapStats.Add("    Heap Start Address = " + he.dwAddress.ToString("X8") + Environment.NewLine);
                                heapStats.Add("    Heap Entry size = " + he.dwBlockSize.ToString() + Environment.NewLine);
                                switch (he.dwFlags)
                                {
                                    case 1:
                                        heapStats.Add("    Heap flags = LF32_FIXED" + Environment.NewLine);
                                        result.ReturnValue = heapStats;
                                        return result;
                                    case 2:
                                        heapStats.Add("    Heap flags = LF32_FREE" + Environment.NewLine);
                                        result.ReturnValue = heapStats;
                                        return result;
                                    case 4:
                                        heapStats.Add("    Heap flags = LF32_MOVEABLE" + Environment.NewLine);
                                        result.ReturnValue = heapStats;
                                        return result;
                                    default:
                                        break;
                                }
                            }
                            else
                            {
                                heapStats.Add("    Heap ID = " + hl.th32HeapID + Environment.NewLine);
                                heapStats.Add("    Heap Start Address = " + he.dwAddress.ToString("X16") + Environment.NewLine);
                                heapStats.Add("    Heap Entry size = " + he.dwBlockSize.ToString() + Environment.NewLine);
                                switch (he.dwFlags)
                                {
                                    case 1:
                                        heapStats.Add("    Heap flags = LF32_FIXED" + Environment.NewLine);
                                        result.ReturnValue = heapStats;
                                        return result;
                                    case 2:
                                        heapStats.Add("    Heap flags = LF32_FREE" + Environment.NewLine);
                                        result.ReturnValue = heapStats;
                                        return result;
                                    case 4:
                                        heapStats.Add("    Heap flags = LF32_MOVEABLE" + Environment.NewLine);
                                        result.ReturnValue = heapStats;
                                        return result;
                                    default:
                                        break;
                                }
                            }
                        }
                    }
                    else if (he.th32HeapID == hl.th32HeapID)
                    {
                        if(extended == true)
                        {
                            if (HeapProcess.ProcessMachineType == MachineType.I386)
                            {
                                heapStats.Add("       Heap Start Address = " + he.dwAddress.ToString("X8") + Environment.NewLine);
                                heapStats.Add("       Heap Entry size = " + he.dwBlockSize.ToString() + Environment.NewLine);
                                switch (he.dwFlags)
                                {
                                    case 1:
                                        heapStats.Add("       Heap flags = LF32_FIXED" + Environment.NewLine);
                                        break;
                                    case 2:
                                        heapStats.Add("       Heap flags = LF32_FREE" + Environment.NewLine);
                                        break;
                                    case 4:
                                        heapStats.Add("       Heap flags = LF32_MOVEABLE" + Environment.NewLine);
                                        break;
                                    default:
                                        break;
                                }
                            }
                            else
                            {
                                heapStats.Add("       Heap Start Address = " + he.dwAddress.ToString("X16") + Environment.NewLine);
                                heapStats.Add("       Heap Entry size = " + he.dwBlockSize.ToString() + Environment.NewLine);
                                switch (he.dwFlags)
                                {
                                    case 1:
                                        heapStats.Add("       Heap flags = LF32_FIXED" + Environment.NewLine);
                                        break;
                                    case 2:
                                        heapStats.Add("       Heap flags = LF32_FREE" + Environment.NewLine);
                                        break;
                                    case 4:
                                        heapStats.Add("       Heap flags = LF32_MOVEABLE" + Environment.NewLine);
                                        break;
                                    default:
                                        break;
                                }
                            }
                        }
                        heapEnts++;
                    }
                }
                if(heapID != 0 || startAddress != 0)
                {
                    if((IntPtr)heapID == hl.th32HeapID)
                    {
                        heapStats.Add("        Total number of entries in heap: " + heapEnts + Environment.NewLine);
                    }
                }
                else
                {
                    heapStats.Add("        Total number of entries in heap: " + heapEnts + Environment.NewLine);
                }
                
            }
            result.ReturnValue = heapStats;
            return result;
        }

        /// <summary>
        /// Lists all HeapIDs associated with a process.
        /// </summary>
        /// <returns>Returns an ErcResult<List<ulong>>"</returns>
        public ErcResult<List<ulong>> HeapIDs()
        {
            ErcResult<List<ulong>> result = new ErcResult<List<ulong>>(HeapProcess);
            result.ReturnValue = new List<ulong>();
            foreach(HEAPLIST32 hl in HeapLists)
            {
                result.ReturnValue.Add((ulong)hl.th32HeapID);
            }

            if(result.ReturnValue.Count == 0)
            {
                result.Error = new ERCException("Error: No heap ids found associated with this process.");
            }
            return result;
        }
        #endregion
    }
}
