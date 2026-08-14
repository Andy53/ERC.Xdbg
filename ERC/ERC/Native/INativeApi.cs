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
using System.Text;
using ERC.Structures;

namespace ERC.Native
{
    /// <summary>
    /// The operating system calls the library makes.
    /// </summary>
    /// <remarks>
    /// Exists so the code that inspects a process - <see cref="ProcessInfo"/>,
    /// ModuleInfo, ThreadInfo, HeapInfo - can be driven by a substitute instead of
    /// the real Win32 API. Previously these were static externs on ErcCore, which
    /// meant every one of those types could only be exercised against a live target
    /// process, and most of the library was therefore untestable.
    ///
    /// Signatures mirror the P/Invoke declarations exactly, including parameter
    /// attributes, so marshalling behaviour is identical through the wrapper.
    /// </remarks>
    public interface INativeApi
    {
        IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        int ReadProcessMemory(IntPtr Handle, IntPtr Address, [Out] byte[] Arr, int Size, out int BytesRead);
        int VirtualQueryEx32(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION32 lpBuffer, uint dwLength);
        int VirtualQueryEx64(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION64 lpBuffer, uint dwLength);
        bool IsWow64Process([In] IntPtr process, [Out] out bool wow64Process);
        IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        bool GetThreadContext32(IntPtr hThread, ref CONTEXT32 lpContext);
        bool Wow64GetThreadContext(IntPtr hthread, ref CONTEXT32 lpContext);
        bool GetThreadContext64(IntPtr hThread, ref CONTEXT64 lpContext);
        int SuspendThread(IntPtr hThread);
        bool CloseHandle(IntPtr hObject);
        IntPtr GetProcAddress(IntPtr hModule, string procName);
        IntPtr LoadLibraryEx(string lpFileName, IntPtr hReservedNull, LoadLibraryFlags dwFlags);
        IntPtr FindResouce(IntPtr hModule, ref string resName, ref string resType);
        IntPtr LoadResource(IntPtr hModule, IntPtr hResInfo);
        uint GetProcessId(IntPtr handle);
        bool GetHandleInformation(IntPtr hObject, out uint lpdwFlags);
        IntPtr GetModuleHandle(string moduleName);
        uint ZwQueryInformationThread(IntPtr hwnd, int i, ref ThreadBasicInformation threadinfo, int length, IntPtr bytesread);
        bool EnumProcessModulesEx(IntPtr hProcess, [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] IntPtr[] lphModule, int cb, [MarshalAs(UnmanagedType.U4)] out int lpcbNeeded, uint dwFilterFlag);
        uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, [In] [MarshalAs(UnmanagedType.U4)] int nSize);
        IntPtr ImageLoad(string DllName, string DllPath);
        bool GetImageConfigInformation32(IntPtr dllptr, out IMAGE_LOAD_CONFIG_DIRECTORY32 ImageConfigDir32);
        bool GetImageConfigInformation64(IntPtr dllptr, out IMAGE_LOAD_CONFIG_DIRECTORY64 ImageConfigDir64);
        bool GetImageConfigInformation32(ref LOADED_IMAGE loadedImage, ref IMAGE_LOAD_CONFIG_DIRECTORY32 ImageConfigDir32);
        bool GetImageConfigInformation64(ref LOADED_IMAGE loadedImage, ref IMAGE_LOAD_CONFIG_DIRECTORY64 ImageConfigDir64);
        int MapAndLoad(string ImageName, string DllPath, out LOADED_IMAGE loadedImage, bool Dll, bool readOnly);
        IntPtr CreateToolhelp32Snapshot([In] Structures.SnapshotFlags dwFlags, [In] uint th32ProcessID);
        bool Process32First([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);
        bool Process32Next([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);
        bool Heap32ListFirst(IntPtr hSnapshot, ref HEAPLIST32 lphl);
        bool Heap32ListNext(IntPtr hSnapshot, ref HEAPLIST32 lphl);
        bool Heap32First(ref HEAPENTRY32 heapentry32, uint processID, IntPtr heapID);
        bool Heap32Next(ref HEAPENTRY32 heapentry32);
        bool UnMapAndLoad(ref LOADED_IMAGE loadedImage);
        bool ImageUnload(IntPtr loadedImage);
    }
}
