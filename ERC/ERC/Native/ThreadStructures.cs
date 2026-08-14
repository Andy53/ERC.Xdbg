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
        #region Thread Context

        #region ThreadAccess
        /// <summary>
        /// Enum to specify access level required when accessing a thread. 
        /// </summary>
        [Flags]
        public enum ThreadAccess : int
        {
            /// <summary>
            /// TERMINATE
            /// </summary>
            TERMINATE = (0x0001),
            /// <summary>
            /// SUSPEND_RESUME
            /// </summary>
            SUSPEND_RESUME = (0x0002),
            /// <summary>
            /// GET_CONTEXT
            /// </summary>
            GET_CONTEXT = (0x0008),
            /// <summary>
            /// SET_CONTEXT
            /// </summary>
            SET_CONTEXT = (0x0010),
            /// <summary>
            /// SET_INFORMATION
            /// </summary>
            SET_INFORMATION = (0x0020),
            /// <summary>
            /// QUERY_INFORMATION
            /// </summary>
            QUERY_INFORMATION = (0x0040),
            /// <summary>
            /// SET_THREAD_TOKEN
            /// </summary>
            SET_THREAD_TOKEN = (0x0080),
            /// <summary>
            /// IMPERSONATE
            /// </summary>
            IMPERSONATE = (0x0100),
            /// <summary>
            /// DIRECT_IMPERSONATION
            /// </summary>
            DIRECT_IMPERSONATION = (0x0200),
            /// <summary>
            /// All_ACCESS
            /// </summary>
            All_ACCESS = (0xFFFF)
        }
        #endregion

        #region CONTEXT_FLAGS
        /// <summary>
        /// CONTEXT_FLAGS
        /// </summary>
        public enum CONTEXT_FLAGS : uint
        {
            /// <summary>
            /// CONTEXT_i386
            /// </summary>
            CONTEXT_i386 = 0x10000,
            /// <summary>
            /// CONTEXT_i486
            /// </summary>
            CONTEXT_i486 = 0x10000,
            /// <summary>
            /// CONTEXT_CONTROL
            /// </summary>
            CONTEXT_CONTROL = CONTEXT_i386 | 0x01,
            /// <summary>
            /// CONTEXT_INTEGER
            /// </summary>
            CONTEXT_INTEGER = CONTEXT_i386 | 0x02,
            /// <summary>
            /// CONTEXT_SEGMENTS
            /// </summary>
            CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04,
            /// <summary>
            /// CONTEXT_FLOATING_POINT
            /// </summary>
            CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08,
            /// <summary>
            /// CONTEXT_DEBUG_REGISTERS
            /// </summary>
            CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10,
            /// <summary>
            /// CONTEXT_EXTENDED_REGISTERS
            /// </summary>
            CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20,
            /// <summary>
            /// CONTEXT_FULL
            /// </summary>
            CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
            /// <summary>
            /// CONTEXT_ALL
            /// </summary>
            CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
        }
        #endregion

        #region FLOATING_SAVE_AREA
        /// <summary>
        /// x86 Save area data. See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-_wow64_floating_save_area
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct FLOATING_SAVE_AREA
        {
            /// <summary>
            /// ControlWord
            /// </summary>
            public uint ControlWord;
            /// <summary>
            /// StatusWord
            /// </summary>
            public uint StatusWord;
            /// <summary>
            /// TagWord
            /// </summary>
            public uint TagWord;
            /// <summary>
            /// ErrorOffset
            /// </summary>
            public uint ErrorOffset;
            /// <summary>
            /// ErrorSelector
            /// </summary>
            public uint ErrorSelector;
            /// <summary>
            /// DataOffset
            /// </summary>
            public uint DataOffset;
            /// <summary>
            /// DataSelector
            /// </summary>
            public uint DataSelector;
            /// <summary>
            /// RegisterArea
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;
            /// <summary>
            /// Cr0NpxState
            /// </summary>
            public uint Cr0NpxState;
        }
        #endregion

        #region CONTEXT32
        /// <summary>
        /// Structure for holding x86 register values.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT32
        {
            /// <summary>
            /// ContextFlags
            /// </summary>
            public CONTEXT_FLAGS ContextFlags;
            /// <summary>
            /// Dr0
            /// </summary>
            public uint Dr0;
            /// <summary>
            /// Dr1
            /// </summary>
            public uint Dr1;
            /// <summary>
            /// Dr2
            /// </summary>
            public uint Dr2;
            /// <summary>
            /// Dr3
            /// </summary>
            public uint Dr3;
            /// <summary>
            /// Dr6
            /// </summary>
            public uint Dr6;
            /// <summary>
            /// Dr7
            /// </summary>
            public uint Dr7;
            /// <summary>
            /// FloatSave
            /// </summary>
            public FLOATING_SAVE_AREA FloatSave;
            /// <summary>
            /// SegGs
            /// </summary>
            public uint SegGs;
            /// <summary>
            /// SegFs
            /// </summary>
            public uint SegFs;
            /// <summary>
            /// SegEs
            /// </summary>
            public uint SegEs;
            /// <summary>
            /// SegDs
            /// </summary>
            public uint SegDs;
            /// <summary>
            /// Edi
            /// </summary>
            public uint Edi;
            /// <summary>
            /// Esi
            /// </summary>
            public uint Esi;
            /// <summary>
            /// Ebx
            /// </summary>
            public uint Ebx;
            /// <summary>
            /// Edx
            /// </summary>
            public uint Edx;
            /// <summary>
            /// Ecx
            /// </summary>
            public uint Ecx;
            /// <summary>
            /// Eax
            /// </summary>
            public uint Eax;
            /// <summary>
            /// Ebp
            /// </summary>
            public uint Ebp;
            /// <summary>
            /// Eip
            /// </summary>
            public uint Eip;
            /// <summary>
            /// SegCs
            /// </summary>
            public uint SegCs;
            /// <summary>
            /// EFlags
            /// </summary>
            public uint EFlags;
            /// <summary>
            /// Esp
            /// </summary>
            public uint Esp;
            /// <summary>
            /// SegSs
            /// </summary>
            public uint SegSs;
            /// <summary>
            /// ExtendedRegisters
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;

            /// <summary>
            /// Overridden ToString method, returns register values for the current thread.
            /// </summary>
            /// <returns>String</returns>
            public override string ToString()
            {
                string ret = "";
                ret += "EDI = " + Edi.ToString("X8") + Environment.NewLine;
                ret += "ESI = " + Esi.ToString("X8") + Environment.NewLine;
                ret += "EBX = " + Ebx.ToString("X8") + Environment.NewLine;
                ret += "EDX = " + Edx.ToString("X8") + Environment.NewLine;
                ret += "ECX = " + Ecx.ToString("X8") + Environment.NewLine;
                ret += "EAX = " + Eax.ToString("X8") + Environment.NewLine;
                ret += "EBP = " + Ebp.ToString("X8") + Environment.NewLine;
                ret += "ESP = " + Esp.ToString("X8") + Environment.NewLine;
                ret += "EIP = " + Eip.ToString("X8") + Environment.NewLine;
                return ret;
            }
        }
        #endregion

        #region M128A
        /// <summary>
        /// M128A
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            /// <summary>
            /// High
            /// </summary>
            public ulong High;
            /// <summary>
            /// Low
            /// </summary>
            public long Low;

            /// <summary>
            /// ToString Override
            /// </summary>
            /// <returns>Returns a String</returns>
            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", this.High, this.Low);
            }
        }
        #endregion

        #region XSAVE_FORMAT64
        /// <summary>
        /// x64 Save area data.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct XSAVE_FORMAT64
        {
            /// <summary>
            /// ControlWord
            /// </summary>
            public ushort ControlWord;
            /// <summary>
            /// StatusWord
            /// </summary>
            public ushort StatusWord;
            /// <summary>
            /// TagWord
            /// </summary>
            public byte TagWord;
            /// <summary>
            /// Reserved1
            /// </summary>
            public byte Reserved1;
            /// <summary>
            /// ErrorOpcode
            /// </summary>
            public ushort ErrorOpcode;
            /// <summary>
            /// ErrorOffset
            /// </summary>
            public uint ErrorOffset;
            /// <summary>
            /// ErrorSelector
            /// </summary>
            public ushort ErrorSelector;
            /// <summary>
            /// Reserved2
            /// </summary>
            public ushort Reserved2;
            /// <summary>
            /// DataOffset
            /// </summary>
            public uint DataOffset;
            /// <summary>
            /// DataSelector
            /// </summary>
            public ushort DataSelector;
            /// <summary>
            /// Reserved3
            /// </summary>
            public ushort Reserved3;
            /// <summary>
            /// MxCsr
            /// </summary>
            public uint MxCsr;
            /// <summary>
            /// MxCsr_Mask
            /// </summary>
            public uint MxCsr_Mask;
            /// <summary>
            /// FloatRegisters
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;
            /// <summary>
            /// XmmRegisters
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;
            /// <summary>
            /// Reserved4
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }
        #endregion

        #region CONTEXT64
        /// <summary>
        /// Structure for holding x64 register values.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64
        {
            /// <summary>
            /// P1Home
            /// </summary>
            public ulong P1Home;
            /// <summary>
            /// P2Home
            /// </summary>
            public ulong P2Home;
            /// <summary>
            /// P3Home
            /// </summary>
            public ulong P3Home;
            /// <summary>
            /// P4Home
            /// </summary>
            public ulong P4Home;
            /// <summary>
            /// P5Home
            /// </summary>
            public ulong P5Home;
            /// <summary>
            /// P6Home
            /// </summary>
            public ulong P6Home;

            /// <summary>
            /// ContextFlags
            /// </summary>
            public CONTEXT_FLAGS ContextFlags;
            /// <summary>
            /// MxCsr
            /// </summary>
            public uint MxCsr;

            /// <summary>
            /// SegCs
            /// </summary>
            public ushort SegCs;
            /// <summary>
            /// SegDs
            /// </summary>
            public ushort SegDs;
            /// <summary>
            /// SegEs
            /// </summary>
            public ushort SegEs;
            /// <summary>
            /// SegFs
            /// </summary>
            public ushort SegFs;
            /// <summary>
            /// SegGs
            /// </summary>
            public ushort SegGs;
            /// <summary>
            /// SegSs
            /// </summary>
            public ushort SegSs;
            /// <summary>
            /// EFlags
            /// </summary>
            public uint EFlags;

            /// <summary>
            /// Dr0
            /// </summary>
            public ulong Dr0;
            /// <summary>
            /// Dr1
            /// </summary>
            public ulong Dr1;
            /// <summary>
            /// Dr2
            /// </summary>
            public ulong Dr2;
            /// <summary>
            /// Dr3
            /// </summary>
            public ulong Dr3;
            /// <summary>
            /// Dr6
            /// </summary>
            public ulong Dr6;
            /// <summary>
            /// Dr7
            /// </summary>
            public ulong Dr7;

            /// <summary>
            /// Rax
            /// </summary>
            public ulong Rax;
            /// <summary>
            /// Rcx
            /// </summary>
            public ulong Rcx;
            /// <summary>
            /// Rdx
            /// </summary>
            public ulong Rdx;
            /// <summary>
            /// Rbx
            /// </summary>
            public ulong Rbx;
            /// <summary>
            /// Rsp
            /// </summary>
            public ulong Rsp;
            /// <summary>
            /// Rbp
            /// </summary>
            public ulong Rbp;
            /// <summary>
            /// Rsi
            /// </summary>
            public ulong Rsi;
            /// <summary>
            /// Rdi
            /// </summary>
            public ulong Rdi;
            /// <summary>
            /// R8
            /// </summary>
            public ulong R8;
            /// <summary>
            /// R9
            /// </summary>
            public ulong R9;
            /// <summary>
            /// R10
            /// </summary>
            public ulong R10;
            /// <summary>
            /// R11
            /// </summary>
            public ulong R11;
            /// <summary>
            /// R12
            /// </summary>
            public ulong R12;
            /// <summary>
            /// R13
            /// </summary>
            public ulong R13;
            /// <summary>
            /// R14
            /// </summary>
            public ulong R14;
            /// <summary>
            /// R15
            /// </summary>
            public ulong R15;
            /// <summary>
            /// Rip
            /// </summary>
            public ulong Rip;

            /// <summary>
            /// DUMMYUNIONNAME
            /// </summary>
            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            /// <summary>
            /// VectorRegister
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            /// <summary>
            /// VectorControl
            /// </summary>
            public ulong VectorControl;

            /// <summary>
            /// DebugControl
            /// </summary>
            public ulong DebugControl;
            /// <summary>
            /// LastBranchToRip
            /// </summary>
            public ulong LastBranchToRip;
            /// <summary>
            /// LastBranchFromRip
            /// </summary>
            public ulong LastBranchFromRip;
            /// <summary>
            /// LastExceptionToRip
            /// </summary>
            public ulong LastExceptionToRip;
            /// <summary>
            /// LastExceptionFromRip
            /// </summary>
            public ulong LastExceptionFromRip;

            /// <summary>
            /// Overridden ToString method, returns register values for the current thread.
            /// </summary>
            /// <returns>String</returns>
            public override string ToString()
            {
                string ret = "";
                ret += "RAX = " + Rax.ToString("X16") + Environment.NewLine;
                ret += "RCX = " + Rcx.ToString("X16") + Environment.NewLine;
                ret += "RDX = " + Rdx.ToString("X16") + Environment.NewLine;
                ret += "RBX = " + Rbx.ToString("X16") + Environment.NewLine;
                ret += "RSP = " + Rsp.ToString("X16") + Environment.NewLine;
                ret += "RBP = " + Rbp.ToString("X16") + Environment.NewLine;
                ret += "RSI = " + Rsi.ToString("X16") + Environment.NewLine;
                ret += "RDI = " + Rdi.ToString("X16") + Environment.NewLine;
                ret += "R08 = " + R8.ToString("X16") + Environment.NewLine;
                ret += "R09 = " + R9.ToString("X16") + Environment.NewLine;
                ret += "R10 = " + R10.ToString("X16") + Environment.NewLine;
                ret += "R11 = " + R11.ToString("X16") + Environment.NewLine;
                ret += "R12 = " + R12.ToString("X16") + Environment.NewLine;
                ret += "R13 = " + R13.ToString("X16") + Environment.NewLine;
                ret += "R14 = " + R14.ToString("X16") + Environment.NewLine;
                ret += "R15 = " + R15.ToString("X16") + Environment.NewLine;
                ret += "RIP = " + Rip.ToString("X16") + Environment.NewLine;
                return ret;
            }
        }
        #endregion

        #region RegisterInfo
        /// <summary>
        /// Register information
        /// </summary>
        public class RegisterInfo
        {
            /// <summary>
            /// Register name.
            /// </summary>
            public string Register { get; set; } = string.Empty;
            /// <summary>
            /// Register value.
            /// </summary>
            public IntPtr RegisterValue { get; set; }
            /// <summary>
            /// Register Offset.
            /// </summary>
            public int RegisterOffset { get; set; }
            /// <summary>
            /// String offset.
            /// </summary>
            public int StringOffset { get; set; }
            /// <summary>
            /// Buffer size.
            /// </summary>
            public int BufferSize { get; set; }
            /// <summary>
            /// Thread ID.
            /// </summary>
            public int ThreadID { get; set; }
            /// <summary>
            /// Overwritten.
            /// </summary>
            public bool overwritten { get; set; }
        }
        #endregion

        #endregion

        #region TEB

        /// <summary>
        /// ThreadBasicInformation
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct ThreadBasicInformation
        {
            /// <summary>
            /// ExitStatus
            /// </summary>
            public uint ExitStatus;
            /// <summary>
            /// TebBaseAdress
            /// </summary>
            public IntPtr TebBaseAdress;
            /// <summary>
            /// Identifiers
            /// </summary>
            public ClientID Identifiers;
            /// <summary>
            /// AffinityMask
            /// </summary>
            public uint AffinityMask;
            /// <summary>
            /// Priority
            /// </summary>
            public uint Priority;
            /// <summary>
            /// BasePriority
            /// </summary>
            public uint BasePriority;
        }

        /// <summary>
        /// ClientID
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct ClientID
        {
            /// <summary>
            /// ProcessID
            /// </summary>
            public IntPtr ProcessId;
            /// <summary>
            /// ThreadID
            /// </summary>
            public IntPtr ThreadId;
        }

        /// <summary>
        /// Thread Environment Block.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct TEB
        {
            /// <summary>
            /// CurrentSehFrame
            /// </summary>
            public IntPtr CurrentSehFrame;
            /// <summary>
            /// TopOfStack
            /// </summary>
            public IntPtr TopOfStack;
            /// <summary>
            /// BottomOfStack
            /// </summary>
            public IntPtr BottomOfStack;
            /// <summary>
            /// SubSystemTeb
            /// </summary>
            public IntPtr SubSystemTeb;
            /// <summary>
            /// FiberData
            /// </summary>
            public IntPtr FiberData;
            /// <summary>
            /// ArbitraryDataSlot
            /// </summary>
            public IntPtr ArbitraryDataSlot;
            /// <summary>
            /// Teb
            /// </summary>
            public IntPtr Teb;
            /// <summary>
            /// EnvironmentPointer
            /// </summary>
            public IntPtr EnvironmentPointer;
            /// <summary>
            /// Identifiers
            /// </summary>
            public ClientID Identifiers;
            /// <summary>
            /// RpcHandle
            /// </summary>
            public IntPtr RpcHandle;
            /// <summary>
            /// Tls
            /// </summary>
            public IntPtr Tls;
            /// <summary>
            /// Peb
            /// </summary>
            public IntPtr Peb;
            /// <summary>
            /// LastErrorNumber
            /// </summary>
            public int LastErrorNumber;
            /// <summary>
            /// CriticalSectionsCount
            /// </summary>
            public int CriticalSectionsCount;
            /// <summary>
            /// CsrClientThread
            /// </summary>
            public IntPtr CsrClientThread;
            /// <summary>
            /// Win32ThreadInfo
            /// </summary>
            public IntPtr Win32ThreadInfo;
            /// <summary>
            /// Win32ClientInfo
            /// </summary>
            public byte[] Win32ClientInfo;
            /// <summary>
            /// WoW64Reserved
            /// </summary>
            public IntPtr WoW64Reserved;
            /// <summary>
            /// CurrentLocale
            /// </summary>
            public IntPtr CurrentLocale;
            /// <summary>
            /// FpSoftwareStatusRegister
            /// </summary>
            public IntPtr FpSoftwareStatusRegister;
            /// <summary>
            /// SystemReserved1
            /// </summary>
            public byte[] SystemReserved1;
            /// <summary>
            /// ExceptionCode
            /// </summary>
            public IntPtr ExceptionCode;
            /// <summary>
            /// ActivationContextStack
            /// </summary>
            public byte[] ActivationContextStack;
            /// <summary>
            /// SpareBytes
            /// </summary>
            public byte[] SpareBytes;
            /// <summary>
            /// SystemReserved2
            /// </summary>
            public byte[] SystemReserved2;
            /// <summary>
            /// GdiTebBatch
            /// </summary>
            public byte[] GdiTebBatch;
            /// <summary>
            /// GdiRegion
            /// </summary>
            public IntPtr GdiRegion;
            /// <summary>
            /// GdiPen
            /// </summary>
            public IntPtr GdiPen;
            /// <summary>
            /// GdiBrush
            /// </summary>
            public IntPtr GdiBrush;
            /// <summary>
            /// RealProcessId
            /// </summary>
            public int RealProcessId;
            /// <summary>
            /// RealThreadId
            /// </summary>
            public int RealThreadId;
            /// <summary>
            /// GdiCachedProcessHandle
            /// </summary>
            public IntPtr GdiCachedProcessHandle;
            /// <summary>
            /// GdiClientProcessId
            /// </summary>
            public IntPtr GdiClientProcessId;
            /// <summary>
            /// GdiClientThreadId
            /// </summary>
            public IntPtr GdiClientThreadId;
            /// <summary>
            /// GdiThreadLocalInfo
            /// </summary>
            public IntPtr GdiThreadLocalInfo;
            /// <summary>
            /// UserReserved1
            /// </summary>
            public byte[] UserReserved1;
            /// <summary>
            /// GlReserved1
            /// </summary>
            public byte[] GlReserved1;
            /// <summary>
            /// LastStatusValue
            /// </summary>
            public int LastStatusValue;
            /// <summary>
            /// StaticUnicodeString
            /// </summary>
            public byte[] StaticUnicodeString;
            /// <summary>
            /// DeallocationStack
            /// </summary>
            public IntPtr DeallocationStack;
            /// <summary>
            /// TlsSlots
            /// </summary>
            public byte[] TlsSlots;
            /// <summary>
            /// TlsLinks
            /// </summary>
            public long TlsLinks;
            /// <summary>
            /// Vdm
            /// </summary>
            public IntPtr Vdm;
            /// <summary>
            /// RpcReserved
            /// </summary>
            public IntPtr RpcReserved;
            /// <summary>
            /// ThreadErrorMode
            /// </summary>
            public IntPtr ThreadErrorMode;
        }
        #endregion
    }
}
