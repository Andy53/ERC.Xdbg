using System;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace ERC
{
    namespace Structures
    {
        #region Process Memory Information

        #region AllocationProtect
        /// <summary>
        /// AllocationProtect.
        /// </summary>
        public enum AllocationProtect : uint
        {
            /// <summary>
            /// PAGE_EXECUTE
            /// </summary>
            PAGE_EXECUTE = 0x00000010,
            /// <summary>
            /// PAGE_EXECUTE_READ
            /// </summary>
            PAGE_EXECUTE_READ = 0x00000020,
            /// <summary>
            /// PAGE_EXECUTE_READWRITE
            /// </summary>
            PAGE_EXECUTE_READWRITE = 0x00000040,
            /// <summary>
            /// PAGE_EXECUTE_WRITECOPY
            /// </summary>
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            /// <summary>
            /// PAGE_NOACCESS
            /// </summary>
            PAGE_NOACCESS = 0x00000001,
            /// <summary>
            /// PAGE_READONLY
            /// </summary>
            PAGE_READONLY = 0x00000002,
            /// <summary>
            /// PAGE_READWRITE
            /// </summary>
            PAGE_READWRITE = 0x00000004,
            /// <summary>
            /// PAGE_WRITECOPY
            /// </summary>
            PAGE_WRITECOPY = 0x00000008,
            /// <summary>
            /// PAGE_GUARD
            /// </summary>
            PAGE_GUARD = 0x00000100,
            /// <summary>
            /// PAGE_NOCACHE
            /// </summary>
            PAGE_NOCACHE = 0x00000200,
            /// <summary>
            /// PAGE_WRITECOMBINE
            /// </summary>
            PAGE_WRITECOMBINE = 0x00000400
        }
        #endregion

        #region StateEnum
        /// <summary>
        /// StateEnum
        /// </summary>
        public enum StateEnum : uint
        {
            /// <summary>
            /// MEM_COMMIT
            /// </summary>
            MEM_COMMIT = 0x1000,
            /// <summary>
            /// MEM_FREE
            /// </summary>
            MEM_FREE = 0x10000,
            /// <summary>
            /// MEM_RESERVE
            /// </summary>
            MEM_RESERVE = 0x2000
        }
        #endregion

        #region TypeEnum
        /// <summary>
        /// TypeEnum
        /// </summary>
        public enum TypeEnum : uint
        {
            /// <summary>
            /// MEM_IMAGE
            /// </summary>
            MEM_IMAGE = 0x1000000,
            /// <summary>
            /// MEM_MAPPED
            /// </summary>
            MEM_MAPPED = 0x40000,
            /// <summary>
            /// MEM_PRIVATE
            /// </summary>
            MEM_PRIVATE = 0x20000
        }
        #endregion

        #region MEMORY_BASIC_INFORMATION32
        /// <summary>
        /// MEMORY_BASIC_INFORMATION32. See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-_memory_basic_information
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION32
        {
            /// <summary>
            /// BaseAddress
            /// </summary>
            public IntPtr BaseAddress;
            /// <summary>
            /// AllocationBase
            /// </summary>
            public IntPtr AllocationBase;
            /// <summary>
            /// AllocationProtec
            /// </summary>
            public uint AllocationProtect;
            /// <summary>
            /// RegionSize
            /// </summary>
            public IntPtr RegionSize;
            /// <summary>
            /// State
            /// </summary>
            public StateEnum State;
            /// <summary>
            /// Protect
            /// </summary>
            public uint Protect;
            /// <summary>
            /// Type
            /// </summary>
            public TypeEnum Type;
        }
        #endregion

        #region MEMORY_BASIC_INFORMATION64
        /// <summary>
        /// MEMORY_BASIC_INFORMATION32. See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-_memory_basic_information
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION64
        {
            /// <summary>
            /// BaseAddress
            /// </summary>
            public ulong BaseAddress;
            /// <summary>
            /// AllocationBase
            /// </summary>
            public ulong AllocationBase;
            /// <summary>
            /// AllocationProtect
            /// </summary>
            public uint AllocationProtect;
            /// <summary>
            /// __alignment1
            /// </summary>
            public int __alignment1;
            /// <summary>
            /// RegionSize
            /// </summary>
            public ulong RegionSize;
            /// <summary>
            /// State
            /// </summary>
            public StateEnum State;
            /// <summary>
            /// Protect
            /// </summary>
            public int Protect;
            /// <summary>
            /// Type
            /// </summary>
            public TypeEnum Type;
            /// <summary>
            /// __alignment2
            /// </summary>
            public int __alignment2;
        }
        #endregion

        #region ProcessAccessFlags
        /// <summary>
        /// ProcessAccessFlags
        /// </summary>
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            /// <summary>
            /// All
            /// </summary>
            All = 0x001F0FFF,
            /// <summary>
            /// Terminate
            /// </summary>
            Terminate = 0x00000001,
            /// <summary>
            /// CreateThread
            /// </summary>
            CreateThread = 0x00000002,
            /// <summary>
            /// VirtualMemoryOperation
            /// </summary>
            VirtualMemoryOperation = 0x00000008,
            /// <summary>
            /// VirtualMemoryRead
            /// </summary>
            VirtualMemoryRead = 0x00000010,
            /// <summary>
            /// VirtualMemoryWrite
            /// </summary>
            VirtualMemoryWrite = 0x00000020,
            /// <summary>
            /// DuplicateHandle
            /// </summary>
            DuplicateHandle = 0x00000040,
            /// <summary>
            /// CreateProcess
            /// </summary>
            CreateProcess = 0x000000080,
            /// <summary>
            /// SetQuota
            /// </summary>
            SetQuota = 0x00000100,
            /// <summary>
            /// SetInformation
            /// </summary>
            SetInformation = 0x00000200,
            /// <summary>
            /// QueryInformation
            /// </summary>
            QueryInformation = 0x00000400,
            /// <summary>
            /// QueryLimitedInformation
            /// </summary>
            QueryLimitedInformation = 0x00001000,
            /// <summary>
            /// Synchronize
            /// </summary>
            Synchronize = 0x00100000
        }
        #endregion

        #region LoadLibraryFlags
        /// <summary>
        /// LoadLibraryFlags
        /// </summary>
        [Flags]
        public enum LoadLibraryFlags : uint
        {
            /// <summary>
            /// None
            /// </summary>
            None = 0,
            /// <summary>
            /// DONT_RESOLVE_DLL_REFERENCES
            /// </summary>
            DONT_RESOLVE_DLL_REFERENCES = 0x00000001,
            /// <summary>
            /// LOAD_IGNORE_CODE_AUTHZ_LEVEL
            /// </summary>
            LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x00000010,
            /// <summary>
            /// LOAD_LIBRARY_AS_DATAFILE
            /// </summary>
            LOAD_LIBRARY_AS_DATAFILE = 0x00000002,
            /// <summary>
            /// LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE
            /// </summary>
            LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x00000040,
            /// <summary>
            /// LOAD_LIBRARY_AS_IMAGE_RESOURCE
            /// </summary>
            LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020,
            /// <summary>
            /// LOAD_LIBRARY_SEARCH_APPLICATION_DIR
            /// </summary>
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200,
            /// <summary>
            /// LOAD_LIBRARY_SEARCH_DEFAULT_DIRS
            /// </summary>
            LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000,
            /// <summary>
            /// LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
            /// </summary>
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100,
            /// <summary>
            /// LOAD_LIBRARY_SEARCH_SYSTEM32
            /// </summary>
            LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800,
            /// <summary>
            /// LOAD_LIBRARY_SEARCH_USER_DIRS
            /// </summary>
            LOAD_LIBRARY_SEARCH_USER_DIRS = 0x00000400,
            /// <summary>
            /// LOAD_WITH_ALTERED_SEARCH_PATH
            /// </summary>
            LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008
        }
        #endregion

        #endregion
    }
}
