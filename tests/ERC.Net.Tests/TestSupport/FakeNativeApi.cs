using System;
using System.Runtime.InteropServices;
using System.Text;
using ERC.Native;
using ERC.Structures;

namespace ERC.Net.Tests.TestSupport
{
    /// <summary>
    /// A stand-in for the operating system.
    /// </summary>
    /// <remarks>
    /// Every member throws by default, so a test overrides exactly the calls it
    /// expects and any unexpected call fails loudly instead of quietly returning
    /// zero and producing a plausible-looking wrong answer.
    ///
    /// This proves the <see cref="INativeApi"/> seam works. The synthetic memory maps
    /// and hand-built PE images that use it in earnest arrive with the tier-2 tests.
    /// </remarks>
    public class FakeNativeApi : INativeApi
    {
        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId)
        {
            throw new NotImplementedException(
                "OpenProcess was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual int ReadProcessMemory(IntPtr Handle, IntPtr Address, [Out] byte[] Arr, int Size, out int BytesRead)
        {
            throw new NotImplementedException(
                "ReadProcessMemory was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual int VirtualQueryEx32(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION32 lpBuffer, uint dwLength)
        {
            throw new NotImplementedException(
                "VirtualQueryEx32 was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual int VirtualQueryEx64(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION64 lpBuffer, uint dwLength)
        {
            throw new NotImplementedException(
                "VirtualQueryEx64 was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual bool IsWow64Process([In] IntPtr process, [Out] out bool wow64Process)
        {
            throw new NotImplementedException(
                "IsWow64Process was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId)
        {
            throw new NotImplementedException(
                "OpenThread was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual bool GetThreadContext32(IntPtr hThread, ref CONTEXT32 lpContext)
        {
            throw new NotImplementedException(
                "GetThreadContext32 was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual bool Wow64GetThreadContext(IntPtr hthread, ref CONTEXT32 lpContext)
        {
            throw new NotImplementedException(
                "Wow64GetThreadContext was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual bool GetThreadContext64(IntPtr hThread, ref CONTEXT64 lpContext)
        {
            throw new NotImplementedException(
                "GetThreadContext64 was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual int SuspendThread(IntPtr hThread)
        {
            throw new NotImplementedException(
                "SuspendThread was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual bool CloseHandle(IntPtr hObject)
        {
            throw new NotImplementedException(
                "CloseHandle was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual IntPtr GetProcAddress(IntPtr hModule, string procName)
        {
            throw new NotImplementedException(
                "GetProcAddress was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual IntPtr LoadLibraryEx(string lpFileName, IntPtr hReservedNull, LoadLibraryFlags dwFlags)
        {
            throw new NotImplementedException(
                "LoadLibraryEx was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual IntPtr FindResouce(IntPtr hModule, ref string resName, ref string resType)
        {
            throw new NotImplementedException(
                "FindResouce was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual IntPtr LoadResource(IntPtr hModule, IntPtr hResInfo)
        {
            throw new NotImplementedException(
                "LoadResource was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual uint GetProcessId(IntPtr handle)
        {
            throw new NotImplementedException(
                "GetProcessId was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual bool GetHandleInformation(IntPtr hObject, out uint lpdwFlags)
        {
            throw new NotImplementedException(
                "GetHandleInformation was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual IntPtr GetModuleHandle(string moduleName)
        {
            throw new NotImplementedException(
                "GetModuleHandle was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual uint ZwQueryInformationThread(IntPtr hwnd, int i, ref ThreadBasicInformation threadinfo, int length, IntPtr bytesread)
        {
            throw new NotImplementedException(
                "ZwQueryInformationThread was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual bool EnumProcessModulesEx(IntPtr hProcess, [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] IntPtr[] lphModule, int cb, [MarshalAs(UnmanagedType.U4)] out int lpcbNeeded, uint dwFilterFlag)
        {
            throw new NotImplementedException(
                "EnumProcessModulesEx was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, [In] [MarshalAs(UnmanagedType.U4)] int nSize)
        {
            throw new NotImplementedException(
                "GetModuleFileNameEx was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual IntPtr ImageLoad(string DllName, string DllPath)
        {
            throw new NotImplementedException(
                "ImageLoad was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual bool GetImageConfigInformation32(IntPtr dllptr, out IMAGE_LOAD_CONFIG_DIRECTORY32 ImageConfigDir32)
        {
            throw new NotImplementedException(
                "GetImageConfigInformation32 was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual bool GetImageConfigInformation64(IntPtr dllptr, out IMAGE_LOAD_CONFIG_DIRECTORY64 ImageConfigDir64)
        {
            throw new NotImplementedException(
                "GetImageConfigInformation64 was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual bool GetImageConfigInformation32(ref LOADED_IMAGE loadedImage, ref IMAGE_LOAD_CONFIG_DIRECTORY32 ImageConfigDir32)
        {
            throw new NotImplementedException(
                "GetImageConfigInformation32 was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual bool GetImageConfigInformation64(ref LOADED_IMAGE loadedImage, ref IMAGE_LOAD_CONFIG_DIRECTORY64 ImageConfigDir64)
        {
            throw new NotImplementedException(
                "GetImageConfigInformation64 was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual int MapAndLoad(string ImageName, string DllPath, out LOADED_IMAGE loadedImage, bool Dll, bool readOnly)
        {
            throw new NotImplementedException(
                "MapAndLoad was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual IntPtr CreateToolhelp32Snapshot([In] Structures.SnapshotFlags dwFlags, [In] uint th32ProcessID)
        {
            throw new NotImplementedException(
                "CreateToolhelp32Snapshot was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual bool Process32First([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe)
        {
            throw new NotImplementedException(
                "Process32First was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual bool Process32Next([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe)
        {
            throw new NotImplementedException(
                "Process32Next was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual bool Heap32ListFirst(IntPtr hSnapshot, ref HEAPLIST32 lphl)
        {
            throw new NotImplementedException(
                "Heap32ListFirst was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual bool Heap32ListNext(IntPtr hSnapshot, ref HEAPLIST32 lphl)
        {
            throw new NotImplementedException(
                "Heap32ListNext was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual bool Heap32First(ref HEAPENTRY32 heapentry32, uint processID, IntPtr heapID)
        {
            throw new NotImplementedException(
                "Heap32First was called. Override it in the test double if the test needs it.");
        }

        /// <summary>Not implemented. Override in a test that needs it.</summary>
        public virtual bool Heap32Next(ref HEAPENTRY32 heapentry32)
        {
            throw new NotImplementedException(
                "Heap32Next was called. Override it in the test double if the test needs it.");
        }
    }
}
