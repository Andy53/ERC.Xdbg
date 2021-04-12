using System;
using System.Collections.Generic;
using System.Linq;

namespace ERC.Utilities
{
    /// <summary>
    /// Contains methods for identifying and removing pointers to unwanted data.
    /// </summary>
    public static class PtrRemover
    {
        /// <summary>
        /// Removes pointers which contain unwanted bytes. 
        /// </summary>
        /// <param name="mt">MachineType architecture of the associated process.</param>
        /// <param name="srcList">The list from which to remove the pointers</param>
        /// <param name="bytes">If a pointer contains any of these bytes it will be discarded</param>
        /// <returns>Returns a ErcResult of List IntPtr</returns>
        public static List<IntPtr> RemovePointers(MachineType mt, List<IntPtr> srcList, byte[] bytes)
        {
            bool nullByte = false;
            foreach (byte b in bytes)
            {
                if (b == 0x00)
                {
                    nullByte = true;
                }
            }

            for (int i = 0; i < srcList.Count; i++)
            {
                bool removed = false;
                byte[] ptr = null;
                if (mt == MachineType.I386)
                {
                   ptr = BitConverter.GetBytes((int)srcList[i]);
                }
                else
                {
                    ptr = BitConverter.GetBytes((long)srcList[i]);
                }
                for(int j = 0; j < ptr.Length; j++)
                {
                    for (int k = 0; k < bytes.Length; k++)
                    {
                        if (bytes[k] == ptr[j] && removed == false)
                        {
                            srcList.RemoveAt(i); 
                            removed = true;
                            i--;
                        }
                        if(mt == MachineType.I386 && removed == false && nullByte == true)
                        {
                            if(srcList[i].ToString("X").Length < 7)
                            {
                                srcList.RemoveAt(i);
                                removed = true;
                                i--;
                            }
                        }
                        else if(mt == MachineType.x64 && removed == false && nullByte == true)
                        {
                            if (srcList[i].ToString("X").Length < 15)
                            {
                                srcList.RemoveAt(i);
                                removed = true;
                                i--;
                            }
                        }
                    }
                }
            }
            Console.WriteLine("Srclist length = {0}", srcList.Count);
            return srcList;
        }

        /// <summary>
        /// Removes pointers which contain unwanted bytes. 
        /// </summary>
        /// <param name="mt">MachineType architecture of the associated process.</param>
        /// <param name="srcList">The list from which to remove the pointers</param>
        /// <param name="bytes">If a pointer contains any of these bytes it will be discarded</param>
        /// <returns>Returns a ErcResult of Dictionary IntPtr, String</returns>
        public static Dictionary<IntPtr, string> RemovePointers(MachineType mt, Dictionary<IntPtr, string> srcList, byte[] bytes)
        {
            bool nullByte = false;
            foreach(byte b in bytes)
            {
                if(b == 0x00)
                {
                    nullByte = true;
                }
            }

            for (int i = 0; i < srcList.Count; i++)
            {
                bool removed = false;
                var ptr = BitConverter.GetBytes((long)srcList.ElementAt(i).Key);
                for (int j = 0; j < ptr.Length; j++)
                {
                    for (int k = 0; k < bytes.Length; k++)
                    {
                        if (bytes[k] == ptr[j] && removed == false)
                        {
                            srcList.Remove(srcList.ElementAt(i).Key);
                            removed = true;
                            i--;
                        }
                        if (mt == MachineType.I386 && removed == false && nullByte == true)
                        {
                            if (srcList.ElementAt(i).Key.ToString("X").Length < 7)
                            {
                                srcList.Remove(srcList.ElementAt(i).Key);
                                removed = true;
                                i--;
                            }
                        }
                        else if (mt == MachineType.x64 && removed == false && nullByte == true)
                        {
                            if (srcList.ElementAt(i).Key.ToString("X").Length < 15)
                            {
                                srcList.Remove(srcList.ElementAt(i).Key);
                                removed = true;
                                i--;
                            }
                        }
                    }
                }
            }
            return srcList;
        }

        #region Remove Pointers Protection
        /// <summary>
        /// Removes pointers from a dictionary when pointers do not have the protection level specified.
        /// </summary>
        /// <param name="info">ProcessInfo object of the associated process.</param>
        /// <param name="srcList">List of pointers.</param>
        /// <param name="protection">Specified protection level of pointers.</param>
        /// <returns>Returns a Dictionary of Intptr, string</returns>
        public static List<IntPtr> RemovePointersProtection(ProcessInfo info, List<IntPtr> srcList, string protection = "exec")
        {
            string[] elements = protection.Split(',');
            if(elements.Length > 3)
            {
                throw new ERCException("Supplied protection string is not supported.");
            }

            bool read = false, write = false, exec = false, all = false;
            foreach(string s in elements)
            {
                if (s.Contains("read"))
                {
                    read = true;
                }
                else if (s.Contains("write"))
                {
                    write = true;
                }
                else if (s.Contains("exec"))
                {
                    exec = true;
                }
                else if (s.Contains("all"))
                {
                    all = true;
                }
            }

            protection = "";
            if(read == true)
            {
                protection += "read";
            }
            if(write == true)
            {
                if(protection.Length > 0)
                {
                    protection += ",";
                }
                protection += "write";
            }
            if (exec == true)
            {
                if (protection.Length > 0)
                {
                    protection += ",";
                }
                protection += "exec";
            }
            if(all == true)
            {
                protection = "all";
            }

            uint[] acceptedProtectionValues = new uint[0];
            switch (protection.ToLower())
            {
                case "all":
                    return srcList;
                case "read":
                    acceptedProtectionValues = new uint[4];
                    acceptedProtectionValues[0] = 0x02;
                    acceptedProtectionValues[1] = 0x04;
                    acceptedProtectionValues[2] = 0x20;
                    acceptedProtectionValues[3] = 0x40;
                    break;
                case "write":
                    acceptedProtectionValues = new uint[4];
                    acceptedProtectionValues[0] = 0x04;
                    acceptedProtectionValues[1] = 0x08;
                    acceptedProtectionValues[2] = 0x40;
                    acceptedProtectionValues[3] = 0x80;
                    break;
                case "exec":
                    acceptedProtectionValues = new uint[4];
                    acceptedProtectionValues[0] = 0x10;
                    acceptedProtectionValues[1] = 0x20;
                    acceptedProtectionValues[2] = 0x40;
                    acceptedProtectionValues[3] = 0x80;
                    break;
                case "read,write":
                    acceptedProtectionValues = new uint[6];
                    acceptedProtectionValues[0] = 0x02;
                    acceptedProtectionValues[1] = 0x04;
                    acceptedProtectionValues[2] = 0x08;
                    acceptedProtectionValues[3] = 0x20;
                    acceptedProtectionValues[4] = 0x40;
                    acceptedProtectionValues[5] = 0x80;
                    break;
                case "read,exec":
                    acceptedProtectionValues = new uint[6];
                    acceptedProtectionValues[0] = 0x02;
                    acceptedProtectionValues[1] = 0x04;
                    acceptedProtectionValues[2] = 0x10;
                    acceptedProtectionValues[3] = 0x20;
                    acceptedProtectionValues[4] = 0x40;
                    acceptedProtectionValues[5] = 0x80;
                    break;
                case "write,exec":
                    acceptedProtectionValues = new uint[6];
                    acceptedProtectionValues[0] = 0x04;
                    acceptedProtectionValues[1] = 0x08;
                    acceptedProtectionValues[2] = 0x10;
                    acceptedProtectionValues[3] = 0x20;
                    acceptedProtectionValues[4] = 0x40;
                    acceptedProtectionValues[5] = 0x80;
                    break;
                case "read,write,exec":
                    acceptedProtectionValues = new uint[7];
                    acceptedProtectionValues[0] = 0x02;
                    acceptedProtectionValues[1] = 0x04;
                    acceptedProtectionValues[2] = 0x08;
                    acceptedProtectionValues[3] = 0x10;
                    acceptedProtectionValues[4] = 0x20;
                    acceptedProtectionValues[5] = 0x40;
                    acceptedProtectionValues[6] = 0x80;
                    break;
                default:
                    throw new ERCException("Supplied protection string is not supported.");
            }

            for(int i = 0; i < srcList.Count; i++)
            {
                IntPtr ptr = srcList[i];
                if (info.ProcessMachineType == MachineType.I386)
                {
                    for (int j = 0; j < info.ProcessMemoryBasicInfo32.Count; j++)
                    {
                        ulong topAddress = (ulong)info.ProcessMemoryBasicInfo32[j].BaseAddress + (ulong)info.ProcessMemoryBasicInfo32[j].RegionSize;
                        if ((ulong)srcList[i] > (ulong)info.ProcessMemoryBasicInfo32[j].BaseAddress && (ulong)srcList[i] < topAddress)
                        {
                            if (!acceptedProtectionValues.Contains(info.ProcessMemoryBasicInfo32[j].AllocationProtect) && srcList.Contains(ptr))
                            {
                                srcList.Remove(ptr);
                            }
                        }
                    }
                }
                else
                {
                    for (int j = 0; j < info.ProcessMemoryBasicInfo64.Count; j++)
                    {
                        ulong topAddress = (ulong)info.ProcessMemoryBasicInfo64[j].BaseAddress + (ulong)info.ProcessMemoryBasicInfo64[j].RegionSize;
                        if ((ulong)srcList[i] > (ulong)info.ProcessMemoryBasicInfo64[j].BaseAddress && (ulong)srcList[i] < topAddress)
                        {
                            if (!acceptedProtectionValues.Contains(info.ProcessMemoryBasicInfo64[j].AllocationProtect) && srcList.Contains(ptr))
                            {
                                srcList.Remove(ptr);
                            }
                        }
                    }
                }
            }
            return srcList;
        }

        /// <summary>
        /// Removes pointers from a dictionary when pointers do not have the protection level specified.
        /// </summary>
        /// <param name="info">ProcessInfo object of the associated process.</param>
        /// <param name="srcList">List of pointers.</param>
        /// <param name="protection">Specified protection level of pointers.</param>
        /// <returns>Returns a Dictionary of Intptr, string</returns>
        public static List<IntPtr> RemovePointersProtection(ProcessInfo info, List<IntPtr> srcList, uint protection)
        {
            for (int i = 0; i < srcList.Count; i++)
            {
                IntPtr ptr = srcList[i];
                if (info.ProcessMachineType == MachineType.I386)
                {
                    for (int j = 0; j < info.ProcessMemoryBasicInfo32.Count; j++)
                    {
                        ulong topAddress = (ulong)info.ProcessMemoryBasicInfo32[j].BaseAddress + (ulong)info.ProcessMemoryBasicInfo32[j].RegionSize;
                        if ((ulong)srcList[i] > (ulong)info.ProcessMemoryBasicInfo32[j].BaseAddress && (ulong)srcList[i] < topAddress)
                        {
                            if (protection != info.ProcessMemoryBasicInfo32[j].AllocationProtect && srcList.Contains(ptr))
                            {
                                srcList.Remove(ptr);
                                i--;
                            }
                        }
                    }
                }
                else
                {
                    for (int j = 0; j < info.ProcessMemoryBasicInfo64.Count; j++)
                    {
                        ulong topAddress = (ulong)info.ProcessMemoryBasicInfo64[j].BaseAddress + (ulong)info.ProcessMemoryBasicInfo64[j].RegionSize;
                        if ((ulong)srcList[i] > (ulong)info.ProcessMemoryBasicInfo64[j].BaseAddress && (ulong)srcList[i] < topAddress)
                        {
                            if (protection != info.ProcessMemoryBasicInfo64[j].AllocationProtect && srcList.Contains(ptr))
                            {
                                srcList.Remove(ptr);
                                i--;
                            }
                        }
                    }
                }
            }
            return srcList;
        }
    }
    #endregion
}
