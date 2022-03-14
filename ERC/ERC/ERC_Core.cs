using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Xml;
using System.ComponentModel;
using ERC.Structures;

namespace ERC
{
    #region ErcCore
    /// <summary>
    /// A single instance of this object should be instantiated at a minimum. It is used for storing global variables such as the working directory etc.
    /// </summary>
    public class ErcCore
    {
        #region Class Variables
        /// <summary>
        /// The current version of the ERC.Net library
        /// </summary>
        public string ErcVersion { get; }
        /// <summary>
        /// The directory where output files will be saved.
        /// </summary>
        public string WorkingDirectory { get; internal set; }
        /// <summary>
        /// The Author to be credited in output files.
        /// </summary>
        public string Author { get; set; }
        /// <summary>
        /// Path of the current ERC_Config.xml file.
        /// </summary>
        private string ConfigPath { get; set; }
        /// <summary>
        /// Path where error details should be logged.
        /// </summary>
        public string SystemErrorLogPath { get; set; }
        /// <summary>
        /// Path to the file containing the standard pattern to be used.
        /// </summary>
        public string PatternStandardPath { get; set; }
        /// <summary>
        /// Path to the file containing the extended pattern to be used.
        /// </summary>
        public string PatternExtendedPath { get; set; }
        private Exception SystemError { get; set; }
        private XmlDocument ErcConfig = new XmlDocument();
        #endregion

        #region DLL Imports
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
        #endregion

        #region Constructor
        /// <summary>
        /// Constructor.
        /// </summary>
        public ErcCore()
        {
            WorkingDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().CodeBase);
            WorkingDirectory = WorkingDirectory.Remove(0, 6);
            WorkingDirectory += "\\";
            ConfigPath = Path.Combine(WorkingDirectory, "ERC_Config.XML");
            PatternStandardPath = "";
            PatternExtendedPath = "";
            SystemErrorLogPath = Path.Combine(WorkingDirectory, "System_Error.LOG");
            
            ErcVersion = "ERC.Xdbg_32-2.0"; //Uncomment for 32bit.
            //ErcVersion = "ERC.Xdbg_64-2.0"; //Uncomment for 32bit.

            bool configRead = false;
            while (configRead == false)
            {
                if (File.Exists(ConfigPath))
                {
                    try
                    {
                        ErcConfig.Load(ConfigPath);
                        var singleNode = ErcConfig.DocumentElement.SelectNodes("//Working_Directory");
                        WorkingDirectory = singleNode[0].InnerText;
                        singleNode = ErcConfig.DocumentElement.SelectNodes("//Author");
                        Author = singleNode[0].InnerText;
                        singleNode = ErcConfig.DocumentElement.SelectNodes("//Standard_Pattern");
                        PatternStandardPath = singleNode[0].InnerText;
                        singleNode = ErcConfig.DocumentElement.SelectNodes("//Extended_Pattern");
                        PatternExtendedPath = singleNode[0].InnerText;
                        singleNode = ErcConfig.DocumentElement.SelectNodes("//Error_Log_File");
                        SystemErrorLogPath = singleNode[0].InnerText;
                        configRead = true;
                        ErcConfig = null;
                        GC.Collect();
                    }
                    catch (Exception e)
                    {
                        SystemError = e;
                        BuildDefaultConfig();
                    }
                }
                else
                {
                    BuildDefaultConfig();
                }
            }

            if (PatternStandardPath == "")
            {
                PatternStandardPath = Path.Combine(WorkingDirectory, "Pattern_Standard");
                if (!File.Exists(PatternStandardPath))
                {
                    var patternExt = Utilities.PatternTools.PatternCreate(20277, this, false);
                    if (patternExt.Error != null)
                    {
                        patternExt.LogEvent();
                        Environment.Exit(1);
                    }
                    File.WriteAllText(PatternStandardPath, patternExt.ReturnValue);
                }
            }
            else
            {
                if (!File.Exists(PatternStandardPath))
                {
                    var patternExt = Utilities.PatternTools.PatternCreate(20277, this, false);
                    if (patternExt.Error != null)
                    {
                        patternExt.LogEvent();
                        Environment.Exit(1);
                    }
                    File.WriteAllText(PatternStandardPath, patternExt.ReturnValue);
                }
            }

            if (PatternExtendedPath == "")
            {
                PatternExtendedPath = Path.Combine(WorkingDirectory, "Pattern_Extended");
                if (!File.Exists(PatternExtendedPath))
                {
                    var patternExt = Utilities.PatternTools.PatternCreate(66923, this, true);
                    if (patternExt.Error != null)
                    {
                        patternExt.LogEvent();
                        Environment.Exit(1);
                    }
                    File.WriteAllText(PatternExtendedPath, patternExt.ReturnValue);
                }
            }
            else
            {
                if (!File.Exists(PatternExtendedPath))
                {
                    var patternExt = Utilities.PatternTools.PatternCreate(66923, this, true);
                    if (patternExt.Error != null)
                    {
                        patternExt.LogEvent();
                        Environment.Exit(1);
                    }
                    File.WriteAllText(PatternExtendedPath, patternExt.ReturnValue);
                }
            }
        }

        /// <summary>
        /// Constructor to be used when creating an object that inherits from an ErcCore object.
        /// </summary>
        /// <param name="parent">The ErcCore object to be inherited from.</param>
        protected ErcCore(ErcCore parent)
        {
            WorkingDirectory = parent.WorkingDirectory;
            Author = parent.Author;
        }

        private void BuildDefaultConfig()
        {
            string patternStandardPath = Path.Combine(WorkingDirectory, "Pattern_Standard");
            string patternExtendedPath = Path.Combine(WorkingDirectory, "Pattern_Extended");
            string systemErrorLogPath = Path.Combine(WorkingDirectory, "System_Error.LOG");

            XmlDocument defaultConfig = new XmlDocument();
            XmlDeclaration xmlDeclaration = defaultConfig.CreateXmlDeclaration("1.0", "UTF-8", null);
            XmlElement root = defaultConfig.DocumentElement;
            defaultConfig.InsertBefore(xmlDeclaration, root);

            XmlElement erc_xml = defaultConfig.CreateElement(string.Empty, "ERC.Net", Assembly.GetExecutingAssembly().GetName().Version.ToString());
            defaultConfig.AppendChild(erc_xml);

            XmlElement parameters = defaultConfig.CreateElement(string.Empty, "Parameters", string.Empty);
            erc_xml.AppendChild(parameters);

            XmlElement workingDir = defaultConfig.CreateElement(string.Empty, "Working_Directory", string.Empty);
            XmlText text1 = defaultConfig.CreateTextNode(WorkingDirectory);
            workingDir.AppendChild(text1);
            parameters.AppendChild(workingDir);

            XmlElement author = defaultConfig.CreateElement(string.Empty, "Author", string.Empty);
            text1 = defaultConfig.CreateTextNode("No_Author_Set");
            author.AppendChild(text1);
            parameters.AppendChild(author);

            XmlElement patternS = defaultConfig.CreateElement(string.Empty, "Standard_Pattern", string.Empty);
            text1 = defaultConfig.CreateTextNode(patternStandardPath);
            patternS.AppendChild(text1);
            parameters.AppendChild(patternS);

            XmlElement patternE = defaultConfig.CreateElement(string.Empty, "Extended_Pattern", string.Empty);
            text1 = defaultConfig.CreateTextNode(patternExtendedPath);
            patternE.AppendChild(text1);
            parameters.AppendChild(patternE);

            XmlElement errorlog = defaultConfig.CreateElement(string.Empty, "Error_Log_File", string.Empty);
            text1 = defaultConfig.CreateTextNode(systemErrorLogPath);
            errorlog.AppendChild(text1);
            parameters.AppendChild(errorlog);

            try
            {
                defaultConfig.Save(ConfigPath);
            }
            catch(Exception e)
            {
                SystemError = e;
                LogEvent(e);
            }
        }
        #endregion

        #region Variable Setters

        #region SetWorkingDirectory
        /// <summary>
        /// Changes the working directory in both the XML file and associated ErcCore object
        /// </summary>
        /// <param name="path"></param>
        public void SetWorkingDirectory(string path)
        {
            if (Directory.Exists(path))
            {
                if (!path.EndsWith("\\"))
                {
                    path += "\\";
                }
                XmlDocument xmldoc = new XmlDocument();
                xmldoc.Load(ConfigPath);
                var singleNode = xmldoc.DocumentElement.SelectSingleNode("//Working_Directory");
                singleNode.InnerText = path;
                xmldoc.Save(ConfigPath);
                WorkingDirectory = path;
            }
            else
            {
                throw new Exception("User Input Error: Value supplied for working directory is not a valid directory");
            }
        }
        #endregion

        #region SetPatternStandardPath
        /// <summary>
        /// Sets the standard pattern file path. Any pattern can replace the standard pattern when searching however the new pattern must be written to a file and the file path set here.
        /// </summary>
        /// <param name="path">The filepath of the new standard pattern file</param>
        public void SetPatternStandardPath(string path)
        {
            if (Directory.Exists(path))
            {
                if (!path.EndsWith("\\"))
                {
                    path += "\\";
                }
                XmlDocument xmldoc = new XmlDocument();
                xmldoc.Load(ConfigPath);
                var singleNode = xmldoc.DocumentElement.SelectSingleNode("//Standard_Pattern");
                singleNode.InnerText = path;
                xmldoc.Save(ConfigPath);
                PatternStandardPath = path;
            }
            else
            {
                throw new Exception("User Input Error: Value supplied for the standard pattern path is not a valid directory");
            }
        }
        #endregion

        #region SetPatternExtendedPath
        /// <summary>
        /// Sets the extended pattern file path. Any pattern can replace the extended pattern when searching however the new pattern must be written to a file and the file path set here.
        /// </summary>
        /// <param name="path">The filepath of the new extended pattern file</param>
        public void SetPatternExtendedPath(string path)
        {
            if (Directory.Exists(path))
            {
                if (!path.EndsWith("\\"))
                {
                    path += "\\";
                }
                XmlDocument xmldoc = new XmlDocument();
                xmldoc.Load(ConfigPath);
                var singleNode = xmldoc.DocumentElement.SelectSingleNode("//Extended_Pattern");
                singleNode.InnerText = path;
                xmldoc.Save(ConfigPath);
                PatternExtendedPath = path;
            }
            else
            {
                throw new Exception("User Input Error: Value supplied for the extended pattern path is not a valid directory");
            }
        }
        #endregion

        #region SetAuthor
        /// <summary>
        /// Sets the name of the author for use when outputing results to disk.
        /// </summary>
        /// <param name="author">String containing the name of the author</param>
        public void SetAuthor(string author)
        {
            XmlDocument xmldoc = new XmlDocument();
            xmldoc.Load(ConfigPath);
            var singleNode = xmldoc.DocumentElement.SelectSingleNode("//Author");
            singleNode.InnerText = author;
            xmldoc.Save(ConfigPath);
            Author = author;
        }
        #endregion

        #region SetSystemErrorLogFile
        /// <summary>
        /// Sets the error log file to a user specified filepath. 
        /// </summary>
        /// <param name="path">The new error log filepath.</param>
        public void SetErrorFile(string path)
        {
            if (File.Exists(path))
            {
                SystemErrorLogPath = path;
                XmlDocument xmldoc = new XmlDocument();
                xmldoc.Load(ConfigPath);
                var singleNode = xmldoc.DocumentElement.SelectSingleNode("//Error_Log_File");
                singleNode.InnerText = path;
                xmldoc.Save(ConfigPath);
                SystemErrorLogPath = path;
            } 
            else if (Directory.Exists(Path.GetDirectoryName(path)))
            {
                if (!path.EndsWith("\\"))
                {
                    path += "\\";
                }
                path += "System_Error.LOG";
                File.Create(path);
                XmlDocument xmldoc = new XmlDocument();
                xmldoc.Load(ConfigPath);
                var singleNode = xmldoc.DocumentElement.SelectSingleNode("//Error_Log_File");
                singleNode.InnerText = path;
                xmldoc.Save(ConfigPath);
            }
            else
            {
                File.Create(WorkingDirectory + "System_Error.LOG");
                XmlDocument xmldoc = new XmlDocument();
                xmldoc.Load(ConfigPath);
                var singleNode = xmldoc.DocumentElement.SelectSingleNode("//Error_Log_File");
                singleNode.InnerText = path;
                xmldoc.Save(ConfigPath);
                SystemErrorLogPath = path;
            }
        }
        #endregion

        #region LogEvent
        /// <summary>
        /// Logs events to the error log path in the XML file. This file is only appended to and never replaced.
        /// </summary>
        /// <param name="e">The exception to log</param>
        public void LogEvent(Exception e)
        {
            using (StreamWriter sw = File.AppendText(SystemErrorLogPath))
            {
                sw.WriteLine(e);
            }
        }
        #endregion

        #endregion

        #region X64toX32PointerModifier
        /// <summary>
        /// Converts a x64 pointer into a x86 pointer.
        /// </summary>
        /// <param name="ptr64">64bit pointer to be converted</param>
        /// <returns>Retruns a byte array 4 bytes long containing the modified pointer</returns>
        internal static byte[] X64toX32PointerModifier(byte[] ptr64)
        {
            byte[] ptr32 = new byte[4];
            Array.Copy(ptr64, 0, ptr32, 0, 4);
            return ptr32;
        }
        #endregion
    }
    #endregion

    #region ErcResult
    /// <summary>
    /// A basic object which contains a generic type and exception. 
    /// </summary>
    /// <typeparam name="T">A generic type</typeparam>
    public class ErcResult<T> : ErcCore
    {
        /// <summary>
        /// Generic Type.
        /// </summary>
        public T ReturnValue { get; set; }
        /// <summary>
        /// Exception to be logged by LogEvent().
        /// </summary>
        public Exception Error { get; set; }

        /// <summary>
        /// Base constructor.
        /// </summary>
        /// <param name="core">The ErcCore object to inherit from.</param>
        public ErcResult(ErcCore core) : base(core)
        {
            SystemErrorLogPath = core.SystemErrorLogPath;
        }

        /// <summary>
        /// Base constructor with a custom location for exceptions to be logged.
        /// </summary>
        /// <param name="core">The ErcCore object to inherit from.</param>
        /// <param name="errorFile">The location to log exceptions.</param>
        public ErcResult(ErcCore core, string errorFile) : base(core)
        {
            SystemErrorLogPath = errorFile;
        }

        /// <summary>
        /// Logs an event to the ErrorLogFile value.
        /// </summary>
        public void LogEvent()
        {
            using (StreamWriter sw = File.AppendText(base.SystemErrorLogPath))
            {
                sw.WriteLine(Error + " TimeStamp: " + DateTime.Now);
            }
        }

        /// <summary>
        /// Override of the ToString method. Returns a string containing values relevant to the object. 
        /// </summary>
        /// <returns>A string containing information about the object.</returns>
        public override string ToString()
        {
            string ret = "";
            ret += "ErcResult Type = " + ReturnValue.GetType() + Environment.NewLine;
            if (Error != null)
            {
                ret += "ErcResult.Error = " + Error.ToString() + Environment.NewLine;
            }
            else
            {
                ret += "ErcResult.Error = NULL" + Environment.NewLine;
            }
            ret += "ErcResult.ErrorLogFile = " + SystemErrorLogPath + Environment.NewLine;
            return base.ToString();
        }
    }
    #endregion

    #region Type Definitions

    #region MachineType
    /// <summary>
    /// Enum containing types of machine architectures.
    /// </summary>
    public enum MachineType
    {
        /// <summary>
        /// Native.
        /// </summary>
        [Description("Native")]
        Native = 0,
        /// <summary>
        /// x86.
        /// </summary>
        [Description("I386")]
        I386 = 0x014c,
        /// <summary>
        /// Itanium.
        /// </summary>
        [Description("Itanium")]
        Itanium = 0x0200,
        /// <summary>
        /// x64.
        /// </summary>
        [Description("x64")]
        x64 = 0x8664,
        /// <summary>
        /// Type is unknown or unset.
        /// </summary>
        [Description("Error")]
        error = -1
    }
    #endregion

    namespace Structures
    {
        #region DLL Headers

        #region IMAGE_DOS_HEADER
        /// <summary>
        /// IMAGE_DOS_HEADER.
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_DOS_HEADER
        {
            /// <summary>
            /// A pointer to the IMAGE_NT_HEADER.
            /// </summary>
            [FieldOffset(60)] public int nt_head_ptr;
        }
        #endregion

        #region IMAGE_FILE_HEADER
        /// <summary>
        /// IMAGE_FILE_HEADER. See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_FILE_HEADER
        {
            /// <summary>
            /// Machine
            /// </summary>
            [FieldOffset(0)] public ushort Machine;
            /// <summary>
            /// NumberOfSections
            /// </summary>
            [FieldOffset(2)] public ushort NumberOfSections;
            /// <summary>
            /// TimeDateStamp
            /// </summary>
            [FieldOffset(4)] public uint TimeDateStamp;
            /// <summary>
            /// PointerToSymbolTable
            /// </summary>
            [FieldOffset(8)] public uint PointerToSymbolTable;
            /// <summary>
            /// NumberOfSymbols
            /// </summary>
            [FieldOffset(12)] public uint NumberOfSymbols;
            /// <summary>
            /// SizeOfOptionalHeader
            /// </summary>
            [FieldOffset(16)] public ushort SizeOfOptionalHeader;
            /// <summary>
            /// Characteristics
            /// </summary>
            [FieldOffset(18)] public ushort Characteristics;
        }
        #endregion

        #region IMAGE_NT_HEADERS
        /// <summary>
        /// IMAGE_NT_HEADER 32 bit variant. See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-_image_nt_headers
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_NT_HEADERS32
        {
            /// <summary>
            /// Signature
            /// </summary>
            [FieldOffset(0)] public uint Signature;
            /// <summary>
            /// FileHeader
            /// </summary>
            [FieldOffset(4)] public IMAGE_FILE_HEADER FileHeader;
            /// <summary>
            /// OptionalHeader
            /// </summary>
            [FieldOffset(24)] public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        }

        /// <summary>
        /// IMAGE_NT_HEADER 64 bit variant. See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-_image_nt_headers
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_NT_HEADERS64
        {
            /// <summary>
            /// Signature
            /// </summary>
            [FieldOffset(0)] public uint Signature;
            /// <summary>
            /// FileHeader
            /// </summary>
            [FieldOffset(4)] public IMAGE_FILE_HEADER FileHeader;
            /// <summary>
            /// OptionalHeader
            /// </summary>
            [FieldOffset(24)] public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }
        #endregion

        #region IMAGE_DATA_DIRECTORY
        /// <summary>
        /// IMAGE_DATA_DIRECTORY. See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_DATA_DIRECTORY
        {
            /// <summary>
            /// VirtualAddress.
            /// </summary>
            [FieldOffset(0)] public uint VirtualAddress;
            /// <summary>
            /// Size.
            /// </summary>
            [FieldOffset(4)] public uint Size;
        }
        #endregion

        #region IMAGE_OPTIONAL_HEADER32
        /// <summary>
        /// IMAGE_OPTIONAL_HEADER 32 bit variant. See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-_image_optional_header
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            /// <summary>
            /// Magic
            /// </summary>
            [FieldOffset(0)] public MagicType Magic;
            /// <summary>
            /// MajorLinkerVersion
            /// </summary>
            [FieldOffset(2)] public byte MajorLinkerVersion;
            /// <summary>
            /// MinorLinkerVersion
            /// </summary>
            [FieldOffset(3)] public byte MinorLinkerVersion;
            /// <summary>
            /// SizeOfCode
            /// </summary>
            [FieldOffset(4)] public uint SizeOfCode;
            /// <summary>
            /// SizeOfInitializedData
            /// </summary>
            [FieldOffset(8)] public uint SizeOfInitializedData;
            /// <summary>
            /// SizeOfUninitializedData
            /// </summary>
            [FieldOffset(12)] public uint SizeOfUninitializedData;
            /// <summary>
            /// AddressOfEntryPoint
            /// </summary>
            [FieldOffset(16)] public uint AddressOfEntryPoint;
            /// <summary>
            /// BaseOfCode
            /// </summary>
            [FieldOffset(20)] public uint BaseOfCode;
            /// <summary>
            /// BaseOfData
            /// </summary>
            [FieldOffset(24)] public uint BaseOfData;
            /// <summary>
            /// ImageBase
            /// </summary>
            [FieldOffset(28)] public uint ImageBase;
            /// <summary>
            /// SectionAlignment
            /// </summary>
            [FieldOffset(32)] public uint SectionAlignment;
            /// <summary>
            /// FileAlignment
            /// </summary>
            [FieldOffset(36)] public uint FileAlignment;
            /// <summary>
            /// MajorOperatingSystemVersion
            /// </summary>
            [FieldOffset(40)] public ushort MajorOperatingSystemVersion;
            /// <summary>
            /// MinorOperatingSystemVersion
            /// </summary>
            [FieldOffset(42)] public ushort MinorOperatingSystemVersion;
            /// <summary>
            /// MajorImageVersion
            /// </summary>
            [FieldOffset(44)] public ushort MajorImageVersion;
            /// <summary>
            /// MinorImageVersion
            /// </summary>
            [FieldOffset(46)] public ushort MinorImageVersion;
            /// <summary>
            /// MajorSubsystemVersion
            /// </summary>
            [FieldOffset(48)] public ushort MajorSubsystemVersion;
            /// <summary>
            /// MinorSubsystemVersion
            /// </summary>
            [FieldOffset(50)] public ushort MinorSubsystemVersion;
            /// <summary>
            /// Win32VersionValue
            /// </summary>
            [FieldOffset(52)] public uint Win32VersionValue;
            /// <summary>
            /// SizeOfImage
            /// </summary>
            [FieldOffset(56)] public uint SizeOfImage;
            /// <summary>
            /// SizeOfHeaders
            /// </summary>
            [FieldOffset(60)] public uint SizeOfHeaders;
            /// <summary>
            /// CheckSum
            /// </summary>
            [FieldOffset(64)] public uint CheckSum;
            /// <summary>
            /// Subsystem
            /// </summary>
            [FieldOffset(68)] public SubSystemType Subsystem;
            /// <summary>
            /// DllCharacteristics
            /// </summary>
            [FieldOffset(70)] public ushort DllCharacteristics;
            /// <summary>
            /// SizeOfStackReserve
            /// </summary>
            [FieldOffset(72)] public uint SizeOfStackReserve;
            /// <summary>
            /// SizeOfStackCommit
            /// </summary>
            [FieldOffset(76)] public uint SizeOfStackCommit;
            /// <summary>
            /// SizeOfHeapReserve
            /// </summary>
            [FieldOffset(80)] public uint SizeOfHeapReserve;
            /// <summary>
            /// SizeOfHeapCommit
            /// </summary>
            [FieldOffset(84)] public uint SizeOfHeapCommit;
            /// <summary>
            /// LoaderFlags
            /// </summary>
            [FieldOffset(88)] public uint LoaderFlags;
            /// <summary>
            /// NumberOfRvaAndSizes
            /// </summary>
            [FieldOffset(92)] public uint NumberOfRvaAndSizes;
            /// <summary>
            /// ExportTable
            /// </summary>
            [FieldOffset(96)] public IMAGE_DATA_DIRECTORY ExportTable;
            /// <summary>
            /// ImportTable
            /// </summary>
            [FieldOffset(104)] public IMAGE_DATA_DIRECTORY ImportTable;
            /// <summary>
            /// ResourceTable
            /// </summary>
            [FieldOffset(112)] public IMAGE_DATA_DIRECTORY ResourceTable;
            /// <summary>
            /// ExceptionTable
            /// </summary>
            [FieldOffset(120)] public IMAGE_DATA_DIRECTORY ExceptionTable;
            /// <summary>
            /// CertificateTable
            /// </summary>
            [FieldOffset(128)] public IMAGE_DATA_DIRECTORY CertificateTable;
            /// <summary>
            /// BaseRelocationTable
            /// </summary>
            [FieldOffset(136)] public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            /// <summary>
            /// Debug
            /// </summary>
            [FieldOffset(144)] public IMAGE_DATA_DIRECTORY Debug;
            /// <summary>
            /// Architecture
            /// </summary>
            [FieldOffset(152)] public IMAGE_DATA_DIRECTORY Architecture;
            /// <summary>
            /// GlobalPtr
            /// </summary>
            [FieldOffset(160)] public IMAGE_DATA_DIRECTORY GlobalPtr;
            /// <summary>
            /// TLSTable
            /// </summary>
            [FieldOffset(168)] public IMAGE_DATA_DIRECTORY TLSTable;
            /// <summary>
            /// LoadConfigTable
            /// </summary>
            [FieldOffset(176)] public IMAGE_DATA_DIRECTORY LoadConfigTable;
            /// <summary>
            /// BoundImport
            /// </summary>
            [FieldOffset(184)] public IMAGE_DATA_DIRECTORY BoundImport;
            /// <summary>
            /// IAT
            /// </summary>
            [FieldOffset(192)] public IMAGE_DATA_DIRECTORY IAT;
            /// <summary>
            /// DelayImportDescriptor
            /// </summary>
            [FieldOffset(200)] public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            /// <summary>
            /// CLRRuntimeHeader
            /// </summary>
            [FieldOffset(208)] public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            /// <summary>
            /// Reserved
            /// </summary>
            [FieldOffset(216)] public IMAGE_DATA_DIRECTORY Reserved;
        }
        #endregion

        #region IMAGE_OPTIONAL_HEADER64
        /// <summary>
        /// IMAGE_OPTIONAL_HEADER 64 bit variant. See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-_image_optional_header
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            /// <summary>
            /// Magic
            /// </summary>
            [FieldOffset(0)] public MagicType Magic;
            /// <summary>
            /// MajorLinkerVersion
            /// </summary>
            [FieldOffset(2)] public byte MajorLinkerVersion;
            /// <summary>
            /// MinorLinkerVersion
            /// </summary>
            [FieldOffset(3)] public byte MinorLinkerVersion;
            /// <summary>
            /// SizeOfCode
            /// </summary>
            [FieldOffset(4)] public uint SizeOfCode;
            /// <summary>
            /// SizeOfInitializedData
            /// </summary>
            [FieldOffset(8)] public uint SizeOfInitializedData;
            /// <summary>
            /// SizeOfUninitializedData
            /// </summary>
            [FieldOffset(12)] public uint SizeOfUninitializedData;
            /// <summary>
            /// AddressOfEntryPoint
            /// </summary>
            [FieldOffset(16)] public uint AddressOfEntryPoint;
            /// <summary>
            /// BaseOfCode
            /// </summary>
            [FieldOffset(20)] public uint BaseOfCode;
            /// <summary>
            /// ImageBase
            /// </summary>
            [FieldOffset(24)] public ulong ImageBase;
            /// <summary>
            /// SectionAlignment
            /// </summary>
            [FieldOffset(32)] public uint SectionAlignment;
            /// <summary>
            /// FileAlignment
            /// </summary>
            [FieldOffset(36)] public uint FileAlignment;
            /// <summary>
            /// MajorOperatingSystemVersion
            /// </summary>
            [FieldOffset(40)] public ushort MajorOperatingSystemVersion;
            /// <summary>
            /// MinorOperatingSystemVersion
            /// </summary>
            [FieldOffset(42)] public ushort MinorOperatingSystemVersion;
            /// <summary>
            /// MajorImageVersion
            /// </summary>
            [FieldOffset(44)] public ushort MajorImageVersion;
            /// <summary>
            /// MinorImageVersion
            /// </summary>
            [FieldOffset(46)] public ushort MinorImageVersion;
            /// <summary>
            /// MajorSubsystemVersion
            /// </summary>
            [FieldOffset(48)] public ushort MajorSubsystemVersion;
            /// <summary>
            /// MinorSubsystemVersion
            /// </summary>
            [FieldOffset(50)] public ushort MinorSubsystemVersion;
            /// <summary>
            /// Win32VersionValue
            /// </summary>
            [FieldOffset(52)] public uint Win32VersionValue;
            /// <summary>
            /// SizeOfImage
            /// </summary>
            [FieldOffset(56)] public uint SizeOfImage;
            /// <summary>
            /// SizeOfHeaders
            /// </summary>
            [FieldOffset(60)] public uint SizeOfHeaders;
            /// <summary>
            /// CheckSum
            /// </summary>
            [FieldOffset(64)] public uint CheckSum;
            /// <summary>
            /// Subsystem
            /// </summary>
            [FieldOffset(68)] public SubSystemType Subsystem;
            /// <summary>
            /// DllCharacteristics
            /// </summary>
            [FieldOffset(70)] public ushort DllCharacteristics;
            /// <summary>
            /// SizeOfStackReserve
            /// </summary>
            [FieldOffset(72)] public ulong SizeOfStackReserve;
            /// <summary>
            /// SizeOfStackCommit
            /// </summary>
            [FieldOffset(80)] public ulong SizeOfStackCommit;
            /// <summary>
            /// SizeOfHeapReserve
            /// </summary>
            [FieldOffset(88)] public ulong SizeOfHeapReserve;
            /// <summary>
            /// SizeOfHeapCommit
            /// </summary>
            [FieldOffset(96)] public ulong SizeOfHeapCommit;
            /// <summary>
            /// LoaderFlags
            /// </summary>
            [FieldOffset(104)] public uint LoaderFlags;
            /// <summary>
            /// NumberOfRvaAndSizes
            /// </summary>
            [FieldOffset(108)] public uint NumberOfRvaAndSizes;
            /// <summary>
            /// ExportTable
            /// </summary>
            [FieldOffset(112)] public IMAGE_DATA_DIRECTORY ExportTable;
            /// <summary>
            /// ImportTable
            /// </summary>
            [FieldOffset(120)] public IMAGE_DATA_DIRECTORY ImportTable;
            /// <summary>
            /// ResourceTable
            /// </summary>
            [FieldOffset(128)] public IMAGE_DATA_DIRECTORY ResourceTable;
            /// <summary>
            /// ExceptionTable
            /// </summary>
            [FieldOffset(136)] public IMAGE_DATA_DIRECTORY ExceptionTable;
            /// <summary>
            /// CertificateTable
            /// </summary>
            [FieldOffset(144)] public IMAGE_DATA_DIRECTORY CertificateTable;
            /// <summary>
            /// BaseRelocationTable
            /// </summary>
            [FieldOffset(152)] public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            /// <summary>
            /// Debug
            /// </summary>
            [FieldOffset(160)] public IMAGE_DATA_DIRECTORY Debug;
            /// <summary>
            /// Architecture
            /// </summary>
            [FieldOffset(168)] public IMAGE_DATA_DIRECTORY Architecture;
            /// <summary>
            /// GlobalPtr
            /// </summary>
            [FieldOffset(176)] public IMAGE_DATA_DIRECTORY GlobalPtr;
            /// <summary>
            /// TLSTable
            /// </summary>
            [FieldOffset(184)] public IMAGE_DATA_DIRECTORY TLSTable;
            /// <summary>
            /// LoadConfigTable
            /// </summary>
            [FieldOffset(192)] public IMAGE_DATA_DIRECTORY LoadConfigTable;
            /// <summary>
            /// BoundImport
            /// </summary>
            [FieldOffset(200)] public IMAGE_DATA_DIRECTORY BoundImport;
            /// <summary>
            /// IAT
            /// </summary>
            [FieldOffset(208)] public IMAGE_DATA_DIRECTORY IAT;
            /// <summary>
            /// DelayImportDescriptor
            /// </summary>
            [FieldOffset(216)] public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            /// <summary>
            /// CLRRuntimeHeader
            /// </summary>
            [FieldOffset(224)] public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            /// <summary>
            /// Reserved
            /// </summary>
            [FieldOffset(232)] public IMAGE_DATA_DIRECTORY Reserved;
        }
        #endregion

        #region MagicType
        /// <summary>
        /// Image Option Header Magic Type.
        /// </summary>
        public enum MagicType : ushort
        {
            /// <summary>
            /// IMAGE_NT_OPTIONAL_HDR32_MAGIC
            /// </summary>
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            /// <summary>
            /// IMAGE_NT_OPTIONAL_HDR64_MAGIC
            /// </summary>
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }
        #endregion

        #region SubSystemType
        /// <summary>
        /// Image Option Header SubSystem Type.
        /// </summary>
        public enum SubSystemType : ushort
        {
            /// <summary>
            /// IMAGE_SUBSYSTEM_UNKNOWN
            /// </summary>
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            /// <summary>
            /// IMAGE_SUBSYSTEM_NATIVE
            /// </summary>
            IMAGE_SUBSYSTEM_NATIVE = 1,
            /// <summary>
            /// IMAGE_SUBSYSTEM_WINDOWS_GUI
            /// </summary>
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            /// <summary>
            /// IMAGE_SUBSYSTEM_WINDOWS_CUI
            /// </summary>
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            /// <summary>
            /// IMAGE_SUBSYSTEM_POSIX_CUI
            /// </summary>
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            /// <summary>
            /// IMAGE_SUBSYSTEM_WINDOWS_CE_GUI
            /// </summary>
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            /// <summary>
            /// IMAGE_SUBSYSTEM_EFI_APPLICATION
            /// </summary>
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            /// <summary>
            /// IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER
            /// </summary>
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            /// <summary>
            /// IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER
            /// </summary>
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            /// <summary>
            /// IMAGE_SUBSYSTEM_EFI_ROM
            /// </summary>
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            /// <summary>
            /// IMAGE_SUBSYSTEM_XBOX
            /// </summary>
            IMAGE_SUBSYSTEM_XBOX = 14
        }
        #endregion

        #region IMAGE_LOAD_CONFIG_DIRECTORY32
        /// <summary>
        /// IMAGE_LOAD_CONFIG_DIRECTORY32. See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-_image_load_config_directory32
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_LOAD_CONFIG_DIRECTORY32
        {
            /// <summary>
            /// Size
            /// </summary>
            public uint Size;
            /// <summary>
            /// TimeDateStamp
            /// </summary>
            public uint TimeDateStamp;
            /// <summary>
            /// MajorVersio
            /// </summary>
            public ushort MajorVersion;
            /// <summary>
            /// MinorVersion
            /// </summary>
            public ushort MinorVersion;
            /// <summary>
            /// GlobalFlagsClear
            /// </summary>
            public uint GlobalFlagsClear;
            /// <summary>
            /// GlobalFlagsSet
            /// </summary>
            public uint GlobalFlagsSet;
            /// <summary>
            /// CriticalSectionDefaultTimeout
            /// </summary>
            public uint CriticalSectionDefaultTimeout;
            /// <summary>
            /// DeCommitFreeBlockThreshold
            /// </summary>
            public uint DeCommitFreeBlockThreshold;
            /// <summary>
            /// DeCommitTotalFreeThreshold
            /// </summary>
            public uint DeCommitTotalFreeThreshold;
            /// <summary>
            /// LockPrefixTable
            /// </summary>
            public uint LockPrefixTable;
            /// <summary>
            /// MaximumAllocationSize
            /// </summary>
            public uint MaximumAllocationSize;
            /// <summary>
            /// VirtualMemoryThreshold
            /// </summary>
            public uint VirtualMemoryThreshold;
            /// <summary>
            /// ProcessHeapFlags
            /// </summary>
            public uint ProcessHeapFlags;
            /// <summary>
            /// ProcessAffinityMask
            /// </summary>
            public uint ProcessAffinityMask;
            /// <summary>
            /// CSDVersion
            /// </summary>
            public ushort CSDVersion;
            /// <summary>
            /// DependentLoadFlags
            /// </summary>
            public ushort DependentLoadFlags;
            /// <summary>
            /// EditList
            /// </summary>
            public uint EditList;
            /// <summary>
            /// SecurityCookie
            /// </summary>
            public uint SecurityCookie;
            /// <summary>
            /// SEHandlerTable
            /// </summary>
            public uint SEHandlerTable;
            /// <summary>
            /// SEHandlerCount
            /// </summary>
            public uint SEHandlerCount;
            /// <summary>
            /// GuardCFCheckFunctionPointer
            /// </summary>
            public uint GuardCFCheckFunctionPointer;
            /// <summary>
            /// GuardCFDispatchFunctionPointer
            /// </summary>
            public uint GuardCFDispatchFunctionPointer;
            /// <summary>
            /// GuardCFFunctionTable
            /// </summary>
            public uint GuardCFFunctionTable;
            /// <summary>
            /// GuardCFFunctionCount
            /// </summary>
            public uint GuardCFFunctionCount;
            /// <summary>
            /// GuardFlags
            /// </summary>
            public uint GuardFlags;
            /// <summary>
            /// CodeIntegrity
            /// </summary>
            public IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
            /// <summary>
            /// GuardAddressTakenIatEntryTable
            /// </summary>
            public uint GuardAddressTakenIatEntryTable;
            /// <summary>
            /// GuardAddressTakenIatEntryCount
            /// </summary>
            public uint GuardAddressTakenIatEntryCount;
            /// <summary>
            /// GuardLongJumpTargetTable
            /// </summary>
            public uint GuardLongJumpTargetTable;
            /// <summary>
            /// GuardLongJumpTargetCount
            /// </summary>
            public uint GuardLongJumpTargetCount;
            /// <summary>
            /// DynamicValueRelocTable
            /// </summary>
            public uint DynamicValueRelocTable;
            /// <summary>
            /// CHPEMetadataPointer
            /// </summary>
            public uint CHPEMetadataPointer;
            /// <summary>
            /// GuardRFFailureRoutine
            /// </summary>
            public uint GuardRFFailureRoutine;
            /// <summary>
            /// GuardRFFailureRoutineFunctionPointer
            /// </summary>
            public uint GuardRFFailureRoutineFunctionPointer;
            /// <summary>
            /// DynamicValueRelocTableOffset
            /// </summary>
            public uint DynamicValueRelocTableOffset;
            /// <summary>
            /// DynamicValueRelocTableSection
            /// </summary>
            public ushort DynamicValueRelocTableSection;
            /// <summary>
            /// Reserved2
            /// </summary>
            public ushort Reserved2;
            /// <summary>
            /// GuardRFVerifyStackPointerFunctionPointer
            /// </summary>
            public uint GuardRFVerifyStackPointerFunctionPointer;
            /// <summary>
            /// HotPatchTableOffset
            /// </summary>
            public uint HotPatchTableOffset;
            /// <summary>
            /// Reserved3
            /// </summary>
            public uint Reserved3;
            /// <summary>
            /// EnclaveConfigurationPointer
            /// </summary>
            public uint EnclaveConfigurationPointer;
            /// <summary>
            /// VolatileMetadataPointer
            /// </summary>
            public uint VolatileMetadataPointer;
        }
        #endregion

        #region IMAGE_LOAD_CONFIG_DIRECTORY64
        /// <summary>
        /// IMAGE_LOAD_CONFIG_DIRECTORY32. See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-_image_load_config_directory64
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_LOAD_CONFIG_DIRECTORY64
        {
            /// <summary>
            /// Size
            /// </summary>
            public uint Size;
            /// <summary>
            /// TimeDateStamp
            /// </summary>
            public uint TimeDateStamp;
            /// <summary>
            /// MajorVersion
            /// </summary>
            public ushort MajorVersion;
            /// <summary>
            /// MinorVersion
            /// </summary>
            public ushort MinorVersion;
            /// <summary>
            /// GlobalFlagsClear
            /// </summary>
            public uint GlobalFlagsClear;
            /// <summary>
            /// GlobalFlagsSet
            /// </summary>
            public uint GlobalFlagsSet;
            /// <summary>
            /// CriticalSectionDefaultTimeout
            /// </summary>
            public uint CriticalSectionDefaultTimeout;
            /// <summary>
            /// DeCommitFreeBlockThreshold
            /// </summary>
            public ulong DeCommitFreeBlockThreshold;
            /// <summary>
            /// DeCommitTotalFreeThreshold
            /// </summary>
            public ulong DeCommitTotalFreeThreshold;
            /// <summary>
            /// LockPrefixTable
            /// </summary>
            public ulong LockPrefixTable;
            /// <summary>
            /// MaximumAllocationSize
            /// </summary>
            public ulong MaximumAllocationSize;
            /// <summary>
            /// VirtualMemoryThreshold
            /// </summary>
            public ulong VirtualMemoryThreshold;
            /// <summary>
            /// ProcessAffinityMask
            /// </summary>
            public ulong ProcessAffinityMask;
            /// <summary>
            /// ProcessHeapFlags
            /// </summary>
            public uint ProcessHeapFlags;
            /// <summary>
            /// CSDVersion
            /// </summary>
            public ushort CSDVersion;
            /// <summary>
            /// DependentLoadFlags
            /// </summary>
            public ushort DependentLoadFlags;
            /// <summary>
            /// EditList
            /// </summary>
            public ulong EditList;
            /// <summary>
            /// SecurityCookie
            /// </summary>
            public ulong SecurityCookie;
            /// <summary>
            /// SEHandlerTable
            /// </summary>
            public ulong SEHandlerTable;
            /// <summary>
            /// SEHandlerCount
            /// </summary>
            public ulong SEHandlerCount;
            /// <summary>
            /// GuardCFCheckFunctionPointer
            /// </summary>
            public ulong GuardCFCheckFunctionPointer;
            /// <summary>
            /// GuardCFDispatchFunctionPointer
            /// </summary>
            public ulong GuardCFDispatchFunctionPointer;
            /// <summary>
            /// GuardCFFunctionTable
            /// </summary>
            public ulong GuardCFFunctionTable;
            /// <summary>
            /// GuardCFFunctionCount
            /// </summary>
            public ulong GuardCFFunctionCount;
            /// <summary>
            /// GuardFlags
            /// </summary>
            public uint GuardFlags;
            /// <summary>
            /// CodeIntegrity
            /// </summary>
            public IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
            /// <summary>
            /// GuardAddressTakenIatEntryTable
            /// </summary>
            public ulong GuardAddressTakenIatEntryTable;
            /// <summary>
            /// GuardAddressTakenIatEntryCount
            /// </summary>
            public ulong GuardAddressTakenIatEntryCount;
            /// <summary>
            /// GuardLongJumpTargetTable
            /// </summary>
            public ulong GuardLongJumpTargetTable;
            /// <summary>
            /// GuardLongJumpTargetCount
            /// </summary>
            public ulong GuardLongJumpTargetCount;
            /// <summary>
            /// DynamicValueRelocTable
            /// </summary>
            public ulong DynamicValueRelocTable;
            /// <summary>
            /// CHPEMetadataPointer
            /// </summary>
            public ulong CHPEMetadataPointer;
            /// <summary>
            /// GuardRFFailureRoutine
            /// </summary>
            public ulong GuardRFFailureRoutine;
            /// <summary>
            /// GuardRFFailureRoutineFunctionPointer
            /// </summary>
            public ulong GuardRFFailureRoutineFunctionPointer;
            /// <summary>
            /// DynamicValueRelocTableOffset
            /// </summary>
            public uint DynamicValueRelocTableOffset;
            /// <summary>
            /// DynamicValueRelocTableSection
            /// </summary>
            public ushort DynamicValueRelocTableSection;
            /// <summary>
            /// Reserved2
            /// </summary>
            public ushort Reserved2;
            /// <summary>
            /// GuardRFVerifyStackPointerFunctionPointer
            /// </summary>
            public ulong GuardRFVerifyStackPointerFunctionPointer;
            /// <summary>
            /// HotPatchTableOffset
            /// </summary>
            public uint HotPatchTableOffset;
            /// <summary>
            /// Reserved3
            /// </summary>
            public uint Reserved3;
            /// <summary>
            /// EnclaveConfigurationPointer
            /// </summary>
            public ulong EnclaveConfigurationPointer;
            /// <summary>
            /// VolatileMetadataPointer
            /// </summary>
            public ulong VolatileMetadataPointer;
        }
        #endregion

        #region IMAGE_LOAD_CONFIG_CODE_INTEGRITY
        /// <summary>
        /// IMAGE_LOAD_CONFIG_CODE_INTEGRITY.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY
        {
            /// <summary>
            /// Flags
            /// </summary>
            public ushort Flags;
            /// <summary>
            /// Catalog
            /// </summary>
            public ushort Catalog;
            /// <summary>
            /// CatalogOffset
            /// </summary>
            public uint CatalogOffset;
            /// <summary>
            /// Reserved
            /// </summary>
            public uint Reserved;
        };
        #endregion

        #region LOADED_IMAGE
        /// <summary>
        /// LOADED_IMAGE. See https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-_loaded_image
        /// </summary>
        public struct LOADED_IMAGE
        {
            /// <summary>
            /// ModuleName
            /// </summary>
            public IntPtr ModuleName;
            /// <summary>
            /// hFile
            /// </summary>
            public IntPtr hFile;
            /// <summary>
            /// MappedAddress
            /// </summary>
            public IntPtr MappedAddress;
            /// <summary>
            /// FileHeader
            /// </summary>
            public IntPtr FileHeader;
            /// <summary>
            /// LastRvaSection
            /// </summary>
            public IntPtr LastRvaSection;
            /// <summary>
            /// NumberOfSections
            /// </summary>
            public uint NumberOfSections;
            /// <summary>
            /// Sections
            /// </summary>
            public IntPtr Sections;
            /// <summary>
            /// Characteristics
            /// </summary>
            public uint Characteristics;
            /// <summary>
            /// fSystemImage
            /// </summary>
            public bool fSystemImage;
            /// <summary>
            /// fDOSImage
            /// </summary>
            public bool fDOSImage;
            /// <summary>
            /// fReadOnly
            /// </summary>
            public bool fReadOnly;
            /// <summary>
            /// Version
            /// </summary>
            public byte Version;
            /// <summary>
            /// Links
            /// </summary>
            public LIST_ENTRY Links;
            /// <summary>
            /// SizeOfImage
            /// </summary>
            public uint SizeOfImage;
        }
        #endregion

        #region List_Entry
        /// <summary>
        /// Describes an entry in a doubly linked list or serves as the header for such a list. See https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_list_entry
        /// </summary>
        public struct LIST_ENTRY
        {
            /// <summary>
            /// Flink points to the next entry in the list.
            /// </summary>
            public IntPtr Flink;
            /// <summary>
            /// Blink points to the previous entry in the list.
            /// </summary>
            public IntPtr Blink;
        }
        #endregion

        #endregion

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
            public string Register { get; set; }
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
    #endregion
}
