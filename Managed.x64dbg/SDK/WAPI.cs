using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Managed.x64dbg.SDK
{
    public class WAPI
    {
        public const int MAX_PATH = 260;

        [DllImport("psapi.dll")]
        public static extern uint GetModuleBaseNameA(IntPtr hProcess, IntPtr hModule, StringBuilder lpBaseName, uint nSize);

        [DllImport("kernel32.dll", EntryPoint = "RtlZeroMemory")]
        public static extern void ZeroMemory(IntPtr dst, int length);

        public struct LOAD_DLL_DEBUG_INFO
        {
            public IntPtr hFile;
            public IntPtr lpBaseOfDll;
            public uint dwDebugInfoFileOffset;
            public uint nDebugInfoSize;
            public IntPtr lpImageName;
            public ushort fUnicode;
        }

        public delegate uint PTHREAD_START_ROUTINE(IntPtr lpThreadParameter);

        public struct CREATE_PROCESS_DEBUG_INFO
        {
            public IntPtr hFile;
            public IntPtr hProcess;
            public IntPtr hThread;
            public IntPtr lpBaseOfImage;
            public uint dwDebugInfoFileOffset;
            public uint nDebugInfoSize;
            public IntPtr lpThreadLocalBase;
            public IntPtr lpStartAddress; //PTHREAD_START_ROUTINE
            public IntPtr lpImageName;
            public ushort fUnicode;
        }

        public struct EXIT_PROCESS_DEBUG_INFO
        {
            public uint dwExitCode;
        }

        public struct IMAGEHLP_MODULE64
        {
            public uint SizeOfStruct;
            public ulong BaseOfImage;
            public uint ImageSize;
            public uint TimeDateStamp;
            public uint CheckSum;
            public uint NumSyms;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public SYM_TYPE[] SymType;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string ModuleName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string ImageName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string LoadedImageName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string LoadedPdbName;
            public uint CVSig;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 780)]
            public string CVData;
            public uint PdbSig;
            public GUID PdbSig70;
            public uint PdbAge;
            public int PdbUnmatched;
            public int DbgUnmatched;
            public int LineNumbers;
            public int GlobalSymbols;
            public int TypeInfo;
            public int SourceIndexed;
            public int Publics;
        }

        public enum SYM_TYPE
        {
            SymNone,
            SymCoff,
            SymCv,
            SymPdb,
            SymExport,
            SymDeferred,
            SymSym,
            SymDia,
            SymVirtual,
            NumSymTypes,
        }

        public struct GUID
        {
            public uint Data1;
            public ushort Data2;
            public ushort Data3;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
            public string Data4;
        }

        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
    }
}
