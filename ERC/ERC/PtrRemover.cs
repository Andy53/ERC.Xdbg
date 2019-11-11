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
        /// <param name="srcList">The list from which to remove the pointers</param>
        /// <param name="bytes">If a pointer contains any of these bytes it will be discarded</param>
        /// <returns>Returns a ErcResult of List IntPtr</returns>
        public static List<IntPtr> RemovePointers(List<IntPtr> srcList, byte[] bytes)
        {
            for(int i = 0; i < srcList.Count; i++)
            {
                var ptr = BitConverter.GetBytes((long)srcList[i]);
                for(int j = 0; j < ptr.Length; j++)
                {
                    for(int k = 0; k < bytes.Length; k++)
                    {
                        if(bytes[k] == ptr[j])
                        {
                            srcList.RemoveAt(i);
                        }
                    }
                }
            }
            return srcList;
        }

        /// <summary>
        /// Removes pointers which contain unwanted bytes. 
        /// </summary>
        /// <param name="srcList">The list from which to remove the pointers</param>
        /// <param name="bytes">If a pointer contains any of these bytes it will be discarded</param>
        /// <returns>Returns a ErcResult of Dictionary IntPtr, String</returns>
        public static Dictionary<IntPtr, string> RemovePointers(Dictionary<IntPtr, string> srcList, byte[] bytes)
        {
            for (int i = 0; i < srcList.Count; i++)
            {
                var ptr = BitConverter.GetBytes((long)srcList.ElementAt(i).Key);
                for (int j = 0; j < ptr.Length; j++)
                {
                    for (int k = 0; k < bytes.Length; k++)
                    {
                        if (bytes[k] == ptr[j])
                        {
                            srcList.Remove(srcList.ElementAt(i).Key);
                        }
                    }
                }
            }
            return srcList;
        }
    }
}
