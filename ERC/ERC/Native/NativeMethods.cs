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
    /// Every P/Invoke declaration the library uses, in one place.
    /// </summary>
    /// <remarks>
    /// These used to sit directly on ErcCore, which meant anything that touched a
    /// process was welded to the real Win32 API and could only be exercised against
    /// a live target. They are gathered here so <see cref="INativeApi"/> can put an
    /// interface in front of them.
    ///
    /// Kept internal: this is an implementation detail, not part of the public API.
    /// </remarks>
    internal static class NativeMethods
    {
        /// <summary>
        /// Opens an existing local process object.
        /// </summary>
        /// <param name="dwDesiredAccess">The access to the process object. This access right is checked against the security descriptor for the process.</param>
        /// <param name="bInheritHandle">If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.</param>
        /// <param name="dwProcessId">The identifier of the local process to be opened.</param>
        /// <returns>If the function succeeds, the return value is an open handle to the specified process.</returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        /// <summary>
        /// Reads data from an area of memory in a specified process. The entire area to be read must be accessible or the operation fails.
        /// </summary>
        /// <param name="Handle">A handle to the process with memory that is being read.</param>
        /// <param name="Address">A pointer to the base address in the specified process from which to read.</param>
        /// <param name="Arr">A pointer to a buffer that receives the contents from the address space of the specified process.</param>
        /// <param name="Size">The number of bytes to be read from the specified process.</param>
        /// <param name="BytesRead">A pointer to a variable that receives the number of bytes transferred into the specified buffer.</param>
        /// <returns>If the function succeeds, the return value is nonzero.</returns>
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern int ReadProcessMemory(IntPtr Handle, IntPtr Address, [Out] byte[] Arr, int Size, out int BytesRead);

        /// <summary>
        /// Retrieves information about a range of pages within the virtual address space of a specified 32 bit process.
        /// </summary>
        /// <param name="hProcess">A handle to the process whose memory information is queried. </param>
        /// <param name="lpAddress">A pointer to the base address of the region of pages to be queried.</param>
        /// <param name="lpBuffer">A pointer to a MEMORY_BASIC_INFORMATION32 structure in which information about the specified page range is returned.</param>
        /// <param name="dwLength">The size of the buffer pointed to by the lpBuffer parameter, in bytes.</param>
        /// <returns>The return value is the actual number of bytes returned in the information buffer.</returns>
        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "VirtualQueryEx")]
        internal static extern int VirtualQueryEx32(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION32 lpBuffer, uint dwLength);

        /// <summary>
        /// Retrieves information about a range of pages within the virtual address space of a specified 64 bit process.
        /// </summary>
        /// <param name="hProcess">A handle to the process whose memory information is queried. </param>
        /// <param name="lpAddress">A pointer to the base address of the region of pages to be queried.</param>
        /// <param name="lpBuffer">A pointer to a MEMORY_BASIC_INFORMATION64 structure in which information about the specified page range is returned.</param>
        /// <param name="dwLength">The size of the buffer pointed to by the lpBuffer parameter, in bytes.</param>
        /// <returns>The return value is the actual number of bytes returned in the information buffer.</returns>
        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "VirtualQueryEx")]
        internal static extern int VirtualQueryEx64(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION64 lpBuffer, uint dwLength);

        /// <summary>
        /// Determines whether the specified process is running under WOW64 or an Intel64 of x64 processor.
        /// </summary>
        /// <param name="process">A handle to the process.</param>
        /// <param name="wow64Process">A pointer to a value that is set to TRUE if the process is running under WOW64 on an Intel64 or x64 processor.</param>
        /// <returns>If the function succeeds, the return value is a nonzero value.</returns>
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool IsWow64Process([In] IntPtr process, [Out] out bool wow64Process);

        /// <summary>
        /// Opens an existing thread object.
        /// </summary>
        /// <param name="dwDesiredAccess">The access to the thread object.</param>
        /// <param name="bInheritHandle">If this value is TRUE, processes created by this process will inherit the handle.</param>
        /// <param name="dwThreadId">The identifier of the thread to be opened.</param>
        /// <returns>If the function succeeds, the return value is an open handle to the specified thread.</returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        /// <summary>
        /// Retrieves the context of the specified 32 bit thread.
        /// </summary>
        /// <param name="hThread">A handle to the thread whose context is to be retrieved. </param>
        /// <param name="lpContext">A pointer to a CONTEXT structure that receives the appropriate context of the specified thread.</param>
        /// <returns>If the function succeeds, the return value is nonzero.</returns>
        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetThreadContext")]
        internal static extern bool GetThreadContext32(IntPtr hThread, ref CONTEXT32 lpContext);

        /// <summary>
        /// Retrieves the context of the specified WOW64 thread.
        /// </summary>
        /// <param name="hthread">A handle to the thread whose context is to be retrieved.</param>
        /// <param name="lpContext">A pointer to a CONTEXT structure that receives the appropriate context of the specified thread.</param>
        /// <returns>If the function succeeds, the return value is nonzero.</returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool Wow64GetThreadContext(IntPtr hthread, ref CONTEXT32 lpContext);

        /// <summary>
        /// Retrieves the context of the specified 64 bit thread.
        /// </summary>
        /// <param name="hThread">A handle to the thread whose context is to be retrieved. </param>
        /// <param name="lpContext">A pointer to a CONTEXT structure that receives the appropriate context of the specified thread.</param>
        /// <returns>If the function succeeds, the return value is nonzero.</returns>
        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetThreadContext")]
        internal static extern bool GetThreadContext64(IntPtr hThread, ref CONTEXT64 lpContext);

        /// <summary>
        /// Suspends the specified thread.
        /// </summary>
        /// <param name="hThread">A handle to the thread that is to be suspended.</param>
        /// <returns>If the function succeeds, the return value is the thread's previous suspend count. If the function fails the return value is -1.</returns>
        [DllImport("kernel32.dll", SetLastError= true)]
        internal static extern int SuspendThread(IntPtr hThread);

        /// <summary>
        /// Closes an open object handle.
        /// </summary>
        /// <param name="hObject">A valid handle to an open object.</param>
        /// <returns>If the function succeeds, the return value is nonzero.</returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr hObject);

        /// <summary>
        /// Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL).
        /// </summary>
        /// <param name="hModule">A handle to the DLL module that contains the function or variable.</param>
        /// <param name="procName">The function or variable name, or the function's ordinal value.</param>
        /// <returns>If the function succeeds, the return value is the address of the exported function or variable.</returns>
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        /// <summary>
        /// This function maps a specified executable module into the address space of the calling process. The executable module can be a .dll or an .exe file. The specified module may cause other modules to be mapped into the address space.
        /// </summary>
        /// <param name="lpFileName">Pointer to a null-terminated string that names the executable module.</param>
        /// <param name="hReservedNull">Must be null.</param>
        /// <param name="dwFlags">Specifies the action to take when loading the module.</param>
        /// <returns></returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hReservedNull, LoadLibraryFlags dwFlags);

        /// <summary>
        /// Determines the location of a resource with the specified type and name in the specified module.
        /// </summary>
        /// <param name="hModule">A handle to the module whose portable executable file or an accompanying MUI file contains the resource.</param>
        /// <param name="resName">The name of the resource.</param>
        /// <param name="resType">The resource type.</param>
        /// <returns>If the function succeeds, the return value is a handle to the specified resource's information block.</returns>
        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "FindResourceA")]
        internal static extern IntPtr FindResouce(IntPtr hModule, ref string resName, ref string resType);

        /// <summary>
        /// Retrieves a handle that can be used to obtain a pointer to the first byte of the specified resource in memory.
        /// </summary>
        /// <param name="hModule">A handle to the module whose executable file contains the resource.</param>
        /// <param name="hResInfo">A handle to the resource to be loaded. </param>
        /// <returns>If the function succeeds, the return value is a handle to the data associated with the resource.</returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr LoadResource(IntPtr hModule, IntPtr hResInfo);

        /// <summary>
        /// Retrieves the process identifier of the specified process.
        /// </summary>
        /// <param name="handle">A handle to the process. The handle must have the PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION access right.</param>
        /// <returns>Returns the identifier of the process as a Uint</returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint GetProcessId(IntPtr handle);

        /// <summary>
        /// Retrieves certain properties of an object handle.
        /// </summary>
        /// <param name="hObject">A handle to an object whose information is to be retrieved.</param>
        /// <param name="lpdwFlags">A pointer to a variable that receives a set of bit flags that specify properties of the object handle or 0. The following values are defined.</param>
        /// <returns>If the function succeeds, the return value is true.</returns>
        [DllImport("kernel32.dll")]
        public static extern bool GetHandleInformation(IntPtr hObject, out uint lpdwFlags);

        /// <summary>
        /// Retrieves a module handle for the specified module. The module must have been loaded by the calling process.
        /// </summary>
        /// <param name="moduleName">The name of the loaded module (either a .dll or .exe file).</param>
        /// <returns>If the function succeeds, the return value is a handle to the specified module.</returns>
        [DllImport("user32.dll", EntryPoint = "GetModuleHandleW", SetLastError = true)]
        internal static extern IntPtr GetModuleHandle(string moduleName);

        /// <summary>
        /// The ZwQueryInformationThread routine retrieves information about the specified thread.
        /// </summary>
        /// <param name="hwnd">Handle to the thread object.</param>
        /// <param name="i">The type of thread information to be retrieved. </param>
        /// <param name="threadinfo">Pointer to a buffer supplied by the caller.</param>
        /// <param name="length">The size, in bytes, of the buffer pointed to by threadinfo.</param>
        /// <param name="bytesread">A pointer to a variable in which the routine returns the size of the requested information.</param>
        /// <returns>ZwQueryInformationThread returns STATUS_SUCCESS on success, or the appropriate NTSTATUS error code on failure.</returns>
        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern uint ZwQueryInformationThread(IntPtr hwnd, int i, ref ThreadBasicInformation threadinfo, 
            int length, IntPtr bytesread);

        /// <summary>
        /// Retrieves a handle for each module in the specified process.
        /// </summary>
        /// <param name="hProcess">A handle to the process.</param>
        /// <param name="lphModule">An array that receives the list of module handles.</param>
        /// <param name="cb">The size of the lphModule array, in bytes.</param>
        /// <param name="lpcbNeeded">The number of bytes required to store all module handles in the lphModule array.</param>
        /// <param name="dwFilterFlag">The filter criteria. </param>
        /// <returns>If the function succeeds, the return value is nonzero.</returns>
        [DllImport("psapi.dll", SetLastError = true)]
        internal static extern bool EnumProcessModulesEx(IntPtr hProcess,
            [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] IntPtr[] lphModule,
            int cb, [MarshalAs(UnmanagedType.U4)] out int lpcbNeeded, uint dwFilterFlag);

        /// <summary>
        /// Retrieves the fully qualified path for the file containing the specified module.
        /// </summary>
        /// <param name="hProcess">A handle to the process that contains the module.</param>
        /// <param name="hModule">A handle to the module. </param>
        /// <param name="lpBaseName">A pointer to a buffer that receives the fully qualified path to the module.</param>
        /// <param name="nSize">The size of the lpFilename buffer, in characters.</param>
        /// <returns>If the function succeeds, the return value specifies the length of the string copied to the buffer.</returns>
        [DllImport("psapi.dll", SetLastError = true)]
        internal static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName,
            [In] [MarshalAs(UnmanagedType.U4)] int nSize);

        /// <summary>
        /// Maintains a list of loaded DLLs.
        /// </summary>
        /// <param name="DllName">The name of the image.</param>
        /// <param name="DllPath">The path used to locate the image if the name provided cannot be found.</param>
        /// <returns>If the function succeeds, the return value is a pointer to a LOADED_IMAGE structure.</returns>
        [DllImport("Imagehlp.dll", SetLastError = true)]
        internal static extern IntPtr ImageLoad(string DllName, string DllPath);

        /// <summary>
        /// Locates and returns the load configuration data of an image.
        /// </summary>
        /// <param name="dllptr">A pointer to a LOADED_IMAGE structure.</param>
        /// <param name="ImageConfigDir32">A pointer to an IMAGE_LOAD_CONFIG_DIRECTORY32</param>
        /// <returns>If the function succeeds, the return value is TRUE.</returns>
        [DllImport("Imagehlp.dll", SetLastError = true, EntryPoint = "GetImageConfigInformation")]
        internal static extern bool GetImageConfigInformation32(IntPtr dllptr, out IMAGE_LOAD_CONFIG_DIRECTORY32 ImageConfigDir32);

        /// <summary>
        /// Locates and returns the load configuration data of an image.
        /// </summary>
        /// <param name="dllptr">A pointer to a LOADED_IMAGE structure.</param>
        /// <param name="ImageConfigDir64">A pointer to an IMAGE_LOAD_CONFIG_DIRECTORY64</param>
        /// <returns>If the function succeeds, the return value is TRUE.</returns>
        [DllImport("Imagehlp.dll", SetLastError = true, EntryPoint = "GetImageConfigInformation")]
        internal static extern bool GetImageConfigInformation64(IntPtr dllptr, out IMAGE_LOAD_CONFIG_DIRECTORY64 ImageConfigDir64);

        /// <summary>
        /// Locates and returns the load configuration data of an image.
        /// </summary>
        /// <param name="loadedImage">A Loaded_Image structure.</param>
        /// <param name="ImageConfigDir32">A pointer to an IMAGE_LOAD_CONFIG_DIRECTORY32</param>
        /// <returns>If the function succeeds, the return value is TRUE.</returns>
        [DllImport("Imagehlp.dll", SetLastError = true, EntryPoint = "GetImageConfigInformation")]
        internal static extern bool GetImageConfigInformation32(ref LOADED_IMAGE loadedImage, ref IMAGE_LOAD_CONFIG_DIRECTORY32 ImageConfigDir32);

        /// <summary>
        /// Locates and returns the load configuration data of an image.
        /// </summary>
        /// <param name="loadedImage">A Loaded_Image structure.</param>
        /// <param name="ImageConfigDir64">A pointer to an IMAGE_LOAD_CONFIG_DIRECTORY64</param>
        /// <returns>If the function succeeds, the return value is TRUE.</returns>
        [DllImport("Imagehlp.dll", SetLastError = true, EntryPoint = "GetImageConfigInformation")]
        internal static extern bool GetImageConfigInformation64(ref LOADED_IMAGE loadedImage, ref IMAGE_LOAD_CONFIG_DIRECTORY64 ImageConfigDir64);

        /// <summary>
        /// Maps an image and preloads data from the mapped file.
        /// </summary>
        /// <param name="ImageName">The file name of the image (executable file or DLL) that is loaded.</param>
        /// <param name="DllPath">The path used to locate the image if the name provided cannot be found.</param>
        /// <param name="loadedImage">A pointer to a LOADED_IMAGE structure that receives information about the image after it is loaded.</param>
        /// <param name="Dll">True if the file is a DLL, false if the file is an EXE.</param>
        /// <param name="readOnly">Boolean for the access mode.</param>
        /// <returns>If the function succeeds, the return value is TRUE.</returns>
        [DllImport("Imagehlp.dll", SetLastError = true)]
        internal static extern int MapAndLoad(string ImageName, string DllPath, out LOADED_IMAGE loadedImage, bool Dll, bool readOnly);

        /// <summary>
        /// Takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes.
        /// </summary>
        /// <param name="dwFlags">The portions of the system to be included in the snapshot. </param>
        /// <param name="th32ProcessID">The process identifier of the process to be included in the snapshot. This parameter can be zero to indicate the current process. This parameter is used when the TH32CS_SNAPHEAPLIST, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, or TH32CS_SNAPALL value is specified. Otherwise, it is ignored and all processes are included in the snapshot.</param>
        /// <returns>If the function succeeds, it returns an open handle to the specified snapshot.</returns>
        [DllImport("kernel32", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern IntPtr CreateToolhelp32Snapshot([In] Structures.SnapshotFlags dwFlags, [In] uint th32ProcessID);

        /// <summary>
        /// Retrieves information about the first process encountered in a system snapshot.
        /// </summary>
        /// <param name="hSnapshot">A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.</param>
        /// <param name="lppe">A pointer to a PROCESSENTRY32 structure.</param>
        /// <returns>Returns TRUE if the first entry of the process list has been copied to the buffer or FALSE otherwise. </returns>
        [DllImport("kernel32", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern bool Process32First([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        /// <summary>
        /// Retrieves information about the next process recorded in a system snapshot.
        /// </summary>
        /// <param name="hSnapshot">A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.</param>
        /// <param name="lppe">A pointer to a PROCESSENTRY32 structure.</param>
        /// <returns>Returns TRUE if the next entry of the process list has been copied to the buffer or FALSE otherwise.</returns>
        [DllImport("kernel32", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern bool Process32Next([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        /// <summary>
        /// Retrieves information about the first heap that has been allocated by a specified process.
        /// </summary>
        /// <param name="hSnapshot">A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.</param>
        /// <param name="lphl">A pointer to a HEAPLIST32 structure.</param>
        /// <returns>Returns TRUE if the first entry of the heap list has been copied to the buffer or FALSE otherwise.</returns>
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern bool Heap32ListFirst(IntPtr hSnapshot, ref HEAPLIST32 lphl);

        /// <summary>
        /// Retrieves information about the next heap that has been allocated by a specified process.
        /// </summary>
        /// <param name="hSnapshot">A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.</param>
        /// <param name="lphl">A pointer to a HEAPLIST32 structure.</param>
        /// <returns>Returns TRUE if the first entry of the heap list has been copied to the buffer or FALSE otherwise.</returns>
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern bool Heap32ListNext(IntPtr hSnapshot, ref HEAPLIST32 lphl);

        /// <summary>
        /// Retrieves information about the first block of a heap that has been allocated by a process.
        /// </summary>
        /// <param name="heapentry32">A pointer to a HEAPENTRY32 structure.</param>
        /// <param name="processID">The identifier of the process context that owns the heap.</param>
        /// <param name="heapID">The identifier of the heap to be enumerated.</param>
        /// <returns>Returns TRUE if information for the first heap block has been copied to the buffer or FALSE otherwise. </returns>
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern bool Heap32First(ref HEAPENTRY32 heapentry32, uint processID, IntPtr heapID);

        /// <summary>
        /// Retrieves information about the next block of a heap that has been allocated by a process.
        /// </summary>
        /// <param name="heapentry32">A pointer to a HEAPENTRY32 structure.</param>
        /// <returns>Returns TRUE if information about the next block in the heap has been copied to the buffer or FALSE otherwise. </returns>
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern bool Heap32Next(ref HEAPENTRY32 heapentry32);

        /// <summary>
        /// Releases the resources of an image mapped with MapAndLoad.
        /// </summary>
        /// <param name="loadedImage">The image to release.</param>
        /// <returns>True on success.</returns>
        [DllImport("Imagehlp.dll", SetLastError = true)]
        internal static extern bool UnMapAndLoad(ref LOADED_IMAGE loadedImage);

        /// <summary>
        /// Releases an image loaded with ImageLoad.
        /// </summary>
        /// <param name="loadedImage">Pointer returned by ImageLoad.</param>
        /// <returns>True on success.</returns>
        [DllImport("Imagehlp.dll", SetLastError = true)]
        internal static extern bool ImageUnload(IntPtr loadedImage);
    }
}
