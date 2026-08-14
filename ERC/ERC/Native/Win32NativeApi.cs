using System;
using System.Runtime.InteropServices;
using System.Text;
using ERC.Structures;

namespace ERC.Native
{
    /// <summary>
    /// The real operating system, reached through P/Invoke.
    /// </summary>
    /// <remarks>
    /// A thin forwarding layer over <see cref="NativeMethods"/>. It holds no state,
    /// so a single shared instance is enough.
    /// </remarks>
    public sealed class Win32NativeApi : INativeApi
    {
        /// <summary>
        /// A shared instance, used as the default throughout the library.
        /// </summary>
        public static readonly Win32NativeApi Instance = new Win32NativeApi();

        public IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId)
        {
            return NativeMethods.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
        }

        public int ReadProcessMemory(IntPtr Handle, IntPtr Address, [Out] byte[] Arr, int Size, out int BytesRead)
        {
            return NativeMethods.ReadProcessMemory(Handle, Address, Arr, Size, out BytesRead);
        }

        public int VirtualQueryEx32(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION32 lpBuffer, uint dwLength)
        {
            return NativeMethods.VirtualQueryEx32(hProcess, lpAddress, out lpBuffer, dwLength);
        }

        public int VirtualQueryEx64(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION64 lpBuffer, uint dwLength)
        {
            return NativeMethods.VirtualQueryEx64(hProcess, lpAddress, out lpBuffer, dwLength);
        }

        public bool IsWow64Process([In] IntPtr process, [Out] out bool wow64Process)
        {
            return NativeMethods.IsWow64Process(process, out wow64Process);
        }

        public IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId)
        {
            return NativeMethods.OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
        }

        public bool GetThreadContext32(IntPtr hThread, ref CONTEXT32 lpContext)
        {
            return NativeMethods.GetThreadContext32(hThread, ref lpContext);
        }

        public bool Wow64GetThreadContext(IntPtr hthread, ref CONTEXT32 lpContext)
        {
            return NativeMethods.Wow64GetThreadContext(hthread, ref lpContext);
        }

        public bool GetThreadContext64(IntPtr hThread, ref CONTEXT64 lpContext)
        {
            return NativeMethods.GetThreadContext64(hThread, ref lpContext);
        }

        public int SuspendThread(IntPtr hThread)
        {
            return NativeMethods.SuspendThread(hThread);
        }

        public bool CloseHandle(IntPtr hObject)
        {
            return NativeMethods.CloseHandle(hObject);
        }

        public IntPtr GetProcAddress(IntPtr hModule, string procName)
        {
            return NativeMethods.GetProcAddress(hModule, procName);
        }

        public IntPtr LoadLibraryEx(string lpFileName, IntPtr hReservedNull, LoadLibraryFlags dwFlags)
        {
            return NativeMethods.LoadLibraryEx(lpFileName, hReservedNull, dwFlags);
        }

        public IntPtr FindResouce(IntPtr hModule, ref string resName, ref string resType)
        {
            return NativeMethods.FindResouce(hModule, ref resName, ref resType);
        }

        public IntPtr LoadResource(IntPtr hModule, IntPtr hResInfo)
        {
            return NativeMethods.LoadResource(hModule, hResInfo);
        }

        public uint GetProcessId(IntPtr handle)
        {
            return NativeMethods.GetProcessId(handle);
        }

        public bool GetHandleInformation(IntPtr hObject, out uint lpdwFlags)
        {
            return NativeMethods.GetHandleInformation(hObject, out lpdwFlags);
        }

        public IntPtr GetModuleHandle(string moduleName)
        {
            return NativeMethods.GetModuleHandle(moduleName);
        }

        public uint ZwQueryInformationThread(IntPtr hwnd, int i, ref ThreadBasicInformation threadinfo, int length, IntPtr bytesread)
        {
            return NativeMethods.ZwQueryInformationThread(hwnd, i, ref threadinfo, length, bytesread);
        }

        public bool EnumProcessModulesEx(IntPtr hProcess, [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] IntPtr[] lphModule, int cb, [MarshalAs(UnmanagedType.U4)] out int lpcbNeeded, uint dwFilterFlag)
        {
            return NativeMethods.EnumProcessModulesEx(hProcess, lphModule, cb, out lpcbNeeded, dwFilterFlag);
        }

        public uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, [In] [MarshalAs(UnmanagedType.U4)] int nSize)
        {
            return NativeMethods.GetModuleFileNameEx(hProcess, hModule, lpBaseName, nSize);
        }

        public IntPtr ImageLoad(string DllName, string DllPath)
        {
            return NativeMethods.ImageLoad(DllName, DllPath);
        }

        public bool GetImageConfigInformation32(IntPtr dllptr, out IMAGE_LOAD_CONFIG_DIRECTORY32 ImageConfigDir32)
        {
            return NativeMethods.GetImageConfigInformation32(dllptr, out ImageConfigDir32);
        }

        public bool GetImageConfigInformation64(IntPtr dllptr, out IMAGE_LOAD_CONFIG_DIRECTORY64 ImageConfigDir64)
        {
            return NativeMethods.GetImageConfigInformation64(dllptr, out ImageConfigDir64);
        }

        public bool GetImageConfigInformation32(ref LOADED_IMAGE loadedImage, ref IMAGE_LOAD_CONFIG_DIRECTORY32 ImageConfigDir32)
        {
            return NativeMethods.GetImageConfigInformation32(ref loadedImage, ref ImageConfigDir32);
        }

        public bool GetImageConfigInformation64(ref LOADED_IMAGE loadedImage, ref IMAGE_LOAD_CONFIG_DIRECTORY64 ImageConfigDir64)
        {
            return NativeMethods.GetImageConfigInformation64(ref loadedImage, ref ImageConfigDir64);
        }

        public int MapAndLoad(string ImageName, string DllPath, out LOADED_IMAGE loadedImage, bool Dll, bool readOnly)
        {
            return NativeMethods.MapAndLoad(ImageName, DllPath, out loadedImage, Dll, readOnly);
        }

        public IntPtr CreateToolhelp32Snapshot([In] Structures.SnapshotFlags dwFlags, [In] uint th32ProcessID)
        {
            return NativeMethods.CreateToolhelp32Snapshot(dwFlags, th32ProcessID);
        }

        public bool Process32First([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe)
        {
            return NativeMethods.Process32First(hSnapshot, ref lppe);
        }

        public bool Process32Next([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe)
        {
            return NativeMethods.Process32Next(hSnapshot, ref lppe);
        }

        public bool Heap32ListFirst(IntPtr hSnapshot, ref HEAPLIST32 lphl)
        {
            return NativeMethods.Heap32ListFirst(hSnapshot, ref lphl);
        }

        public bool Heap32ListNext(IntPtr hSnapshot, ref HEAPLIST32 lphl)
        {
            return NativeMethods.Heap32ListNext(hSnapshot, ref lphl);
        }

        public bool Heap32First(ref HEAPENTRY32 heapentry32, uint processID, IntPtr heapID)
        {
            return NativeMethods.Heap32First(ref heapentry32, processID, heapID);
        }

        public bool Heap32Next(ref HEAPENTRY32 heapentry32)
        {
            return NativeMethods.Heap32Next(ref heapentry32);
        }

        public bool UnMapAndLoad(ref LOADED_IMAGE loadedImage)
        {
            return NativeMethods.UnMapAndLoad(ref loadedImage);
        }

        public bool ImageUnload(IntPtr loadedImage)
        {
            return NativeMethods.ImageUnload(loadedImage);
        }
    }
}
