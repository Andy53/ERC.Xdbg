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
            if (bytes == null || bytes.Length == 0 || srcList == null)
            {
                return srcList;
            }

            int width = PointerWidth(mt);
            var kept = new List<IntPtr>(srcList.Count);

            foreach (IntPtr pointer in srcList)
            {
                if (!ContainsExcludedByte(pointer, width, bytes))
                {
                    kept.Add(pointer);
                }
            }

            return kept;
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
            if (bytes == null || bytes.Length == 0 || srcList == null)
            {
                return srcList;
            }

            int width = PointerWidth(mt);
            var kept = new Dictionary<IntPtr, string>(srcList.Count);

            foreach (KeyValuePair<IntPtr, string> entry in srcList)
            {
                if (!ContainsExcludedByte(entry.Key, width, bytes))
                {
                    kept.Add(entry.Key, entry.Value);
                }
            }

            return kept;
        }

        /// <summary>
        /// The number of bytes a pointer occupies in the target process.
        /// </summary>
        private static int PointerWidth(MachineType mt)
        {
            return mt == MachineType.x64 ? 8 : 4;
        }

        /// <summary>
        /// True when any byte of the pointer, as it would appear in the target's
        /// memory, is one of the excluded bytes.
        /// </summary>
        /// <remarks>
        /// Only the bytes the pointer actually occupies are examined, which is what
        /// the two previous implementations each got wrong in a different direction:
        ///
        /// The list overload narrowed with "(int)srcList[i]". IntPtr's conversion to
        /// int is checked, so on a 64-bit target every address above 0x7FFFFFFF threw
        /// an OverflowException instead of being filtered - the "-Bytes" option was
        /// unusable there.
        ///
        /// The dictionary overload widened every pointer to 8 bytes, so on a 32-bit
        /// target the four bytes of padding read as nulls. Excluding 0x00, the most
        /// common bad character there is, silently discarded every pointer and left
        /// the user believing no gadgets existed.
        /// </remarks>
        private static bool ContainsExcludedByte(IntPtr pointer, int width, byte[] excluded)
        {
            long value = pointer.ToInt64();

            for (int i = 0; i < width; i++)
            {
                byte current = (byte)(value >> (i * 8));

                for (int j = 0; j < excluded.Length; j++)
                {
                    if (excluded[j] == current)
                    {
                        return true;
                    }
                }
            }

            return false;
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
            if (protection == null)
            {
                return srcList;
            }

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
