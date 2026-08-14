// <auto-documented>
// The declarations in this file mirror Win32 and its structures one for one. Their
// names, parameters and semantics are the ones Microsoft documents, and restating
// that here in XML comments would add nothing a reader could not get from MSDN
// while burying the parts of this library that do need explaining.
//
// CS1591 is disabled for this file only. Everywhere else in ERC.Net the warning is
// on, so a genuinely undocumented public member is reported.
// </auto-documented>
#pragma warning disable CS1591

using System;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace ERC
{
    namespace Structures
    {
        #region ToolHelp
        /// <summary>
        /// ToolHelp SnapshotFlags
        /// </summary>
        [Flags]
        public enum SnapshotFlags : uint
        {
            HeapList = 0x00000001,
            Process = 0x00000002,
            Thread = 0x00000004,
            Module = 0x00000008,
            Module32 = 0x00000010,
            Inherit = 0x80000000,
            All = 0x0000001F,
            NoHeaps = 0x40000000
        }

        /// <summary>
        /// ToolHelp PROCESSENTRY32
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESSENTRY32
        {
            const int MAX_PATH = 260;
            internal uint dwSize;
            internal uint cntUsage;
            internal uint th32ProcessID;
            internal IntPtr th32DefaultHeapID;
            internal uint th32ModuleID;
            internal uint cntThreads;
            internal uint th32ParentProcessID;
            internal int pcPriClassBase;
            internal uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            internal string szExeFile;
        }

        /// <summary>
        /// Describes one entry (block) of a heap that is being examined.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct HEAPLIST32
        {
            internal IntPtr dwSize;
            internal uint th32ProcessID;
            internal IntPtr th32HeapID;
            internal uint dwFlags;
        }

        /// <summary>
        /// Describes one entry (block) of a heap that is being examined.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct HEAPENTRY32
        {
            /** The size of the structure, in bytes **/
            internal IntPtr dwSize;
            /** A handle to the heap block **/
            internal IntPtr hHandle;
            /** The linear address of the start of the block **/
            internal IntPtr dwAddress;
            /** The size of the heap block, in bytes **/
            internal IntPtr dwBlockSize;
            /** This member can be one of the following values.
                LF32_FIXED    0x00000001
               LF32_FREE     0x00000002
               LF32_MOVEABLE 0x00000004 **/
            internal uint dwFlags;
            /** This member is no longer used and is always set to zero. **/
            internal uint dwLockCount;
            /** Reserved; do not use or alter **/
            internal uint dwResvd;
            /** The identifier of the process that uses the heap **/
            internal uint th32ProcessID;
            /** The heap identifier. This is not a handle, and has meaning only to the tool help functions **/
            internal IntPtr th32HeapID;
        }
        #endregion
    }
}
