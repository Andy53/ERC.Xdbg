using ERC.Structures;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

using ERC.Native;
namespace ERC
{
    /// <summary> Contains information needed for the associated functions relating to the process. </summary>
    public partial class ProcessInfo : ErcCore, IDisposable
    {
        #region Class_Variables
        /// <summary> Name of the process. </summary>
        public string ProcessName { get; private set; }
        /// <summary> Process description. </summary>
        public string ProcessDescription { get; private set; }
        /// <summary> Path for the projects main module. </summary>
        public string ProcessPath { get; private set; }
        /// <summary> Process ID. </summary>
        public int ProcessID { get; private set; }

        /// <summary> Handle for the process. </summary>
        public IntPtr ProcessHandle { get; private set; }
        /// <summary> .Net Process object for this process </summary>
        public Process ProcessCurrent { get; private set; }
        /// <summary> The machine type the process runs on. Eg. x86 or x64 </summary>
        public MachineType ProcessMachineType { get; private set; }
        private Dictionary<string, IntPtr> ProcessModuleHandles = new Dictionary<string, IntPtr>();
        /// <summary> A list containing ModuleInfo objects associuted with the process. /// </summary>
        public  List<ModuleInfo> ModulesInfo = new List<ModuleInfo>();
        /// <summary> A list containing ThreadInfo objects associuted with the process. /// </summary>
        public List<ThreadInfo> ThreadsInfo = new List<ThreadInfo>();

        internal ErcCore ProcessCore;
        // Only one of these is ever filled in, decided by the target's
        // architecture, so both are genuinely nullable.
        internal List<MEMORY_BASIC_INFORMATION32>? ProcessMemoryBasicInfo32;
        internal List<MEMORY_BASIC_INFORMATION64>? ProcessMemoryBasicInfo64;

        /// <summary>
        /// The 32-bit memory regions, for code that has established the target is 32-bit.
        /// </summary>
        /// <remarks>
        /// LocateMemoryRegions fills in whichever list matches the architecture, so
        /// every caller reaches these from inside a machine-type branch. That
        /// connection is real but invisible to the compiler, and writing it out at
        /// each of the fourteen call sites would be noise. Asking through here keeps
        /// the assumption in one place and turns a mismatch into an explanation
        /// rather than a null reference somewhere further down.
        /// </remarks>
        internal List<MEMORY_BASIC_INFORMATION32> MemoryRegions32
        {
            get
            {
                if (ProcessMemoryBasicInfo32 == null)
                {
                    throw new ERCException(
                        "32 bit memory regions were requested for a process that is not 32 bit, " +
                        "or before its memory regions had been located.");
                }

                return ProcessMemoryBasicInfo32;
            }
        }

        /// <summary>
        /// The 64-bit memory regions, for code that has established the target is 64-bit.
        /// </summary>
        internal List<MEMORY_BASIC_INFORMATION64> MemoryRegions64
        {
            get
            {
                if (ProcessMemoryBasicInfo64 == null)
                {
                    throw new ERCException(
                        "64 bit memory regions were requested for a process that is not 64 bit, " +
                        "or before its memory regions had been located.");
                }

                return ProcessMemoryBasicInfo64;
            }
        }

        private const uint LIST_MODULES_ALL = 0x03;
        #endregion

        #region Constructor
        /// <summary>
        /// Constructor for the Process_Info object, requires an ERC_Core object and a Process.
        /// </summary>
        /// <param name="core">An ErcCore object</param>
        /// <param name="process">The process to gather information from</param>
        public ProcessInfo(ErcCore core, Process process) : base(core)
        {
            ProcessCore = core;

            if (Is64Bit(process))
            {
                ProcessMachineType = MachineType.x64;
            }
            else
            {
                ProcessMachineType = MachineType.I386;
            }

            ProcessName = process.ProcessName;

            // MainModule is unavailable for a process this build cannot fully open,
            // so say which process and why instead of failing with a null reference.
            ProcessModule mainModule = MainModuleOf(process);
            FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(mainModule.FileName);
            ProcessDescription = versionInfo.FileDescription ?? string.Empty;
            ProcessPath = versionInfo.FileName;
            ProcessID = process.Id;
            ProcessCurrent = process;
            ProcessHandle = process.Handle;
            ProcessModuleHandles = GetProcessModules().ReturnValue;

            if (ProcessModuleHandles.Count == 0)
            {
                for(int i = 0; i < process.Modules.Count; i++) 
                {
                    ProcessModuleHandles.Add(process.Modules[i].FileName, process.Modules[i].BaseAddress);
                }
            }
            foreach (KeyValuePair<string, IntPtr> s in ProcessModuleHandles)
            {
                ModuleInfo thisModuleInfo = new ModuleInfo(s.Key, s.Value, process, core);
                if(thisModuleInfo.ModuleFailed == false)
                {
                    ModulesInfo.Add(thisModuleInfo);
                }
            }
            for(int i = 0; i < process.Threads.Count; i++)
            {
                ThreadInfo thisThreadInfo = new ThreadInfo(process.Threads[i], ProcessCore, this);
                if(thisThreadInfo.ThreadFailed == false)
                {
                    ThreadsInfo.Add(thisThreadInfo);
                }
            }
            LocateMemoryRegions();
        }

        /// <summary>
        /// Constructor for the Process_Info object, requires an ERC_Core object and a Process.
        /// </summary>
        /// <param name="core">An ErcCore object</param>
        /// <param name="handle">The handle for the process to gather information from</param>
        public ProcessInfo(ErcCore core, IntPtr handle) : base(core)
        {
            uint flags = 0;
            bool result = Native.GetHandleInformation(handle, out flags);
            if(result == false)
            {
                throw new ERCException("The handle provided is not a valid process (GetHandleInformation returned false)");
            }
            uint processID = Native.GetProcessId(handle);
            
            Process process = Process.GetProcessById((int)processID);
            ProcessCore = core;

            if (Is64Bit(process))
            {
                ProcessMachineType = MachineType.x64;
            }
            else
            {
                ProcessMachineType = MachineType.I386;
            }

            ProcessName = process.ProcessName;

            // MainModule is unavailable for a process this build cannot fully open,
            // so say which process and why instead of failing with a null reference.
            ProcessModule mainModule = MainModuleOf(process);
            FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(mainModule.FileName);
            ProcessDescription = versionInfo.FileDescription ?? string.Empty;
            ProcessPath = versionInfo.FileName;
            ProcessID = process.Id;
            ProcessCurrent = process;
            ProcessHandle = process.Handle;
            ProcessModuleHandles = GetProcessModules().ReturnValue;

            if (ProcessModuleHandles.Count == 0)
            {
                for (int i = 0; i < process.Modules.Count; i++)
                {
                    ProcessModuleHandles.Add(process.Modules[i].FileName, process.Modules[i].BaseAddress);
                }
            }
            foreach (KeyValuePair<string, IntPtr> s in ProcessModuleHandles)
            {
                ModuleInfo thisModuleInfo = new ModuleInfo(s.Key, s.Value, process, core);
                if (thisModuleInfo.ModuleFailed == false)
                {
                    ModulesInfo.Add(thisModuleInfo);
                }
            }
            for (int i = 0; i < process.Threads.Count; i++)
            {
                ThreadInfo thisThreadInfo = new ThreadInfo(process.Threads[i], ProcessCore, this);
                if (thisThreadInfo.ThreadFailed == false)
                {
                    ThreadsInfo.Add(thisThreadInfo);
                }
            }
            LocateMemoryRegions();
        }

        /// <summary>
        /// Constructor to use when inheriting from ProcessInfo.
        /// </summary>
        /// <param name="parent">The object to inherit from</param>
        /// <remarks>
        /// The ": base(parent)" matters. Without it this fell through to the
        /// parameterless ErcCore constructor, so building an OpcodeAssembler or
        /// OpcodeDisassembler from a ProcessInfo quietly created a whole second
        /// ErcCore - re-reading the config from disk, and taking the default OS
        /// access and output sink instead of the parent's. Any substitute supplied
        /// for testing was silently discarded for those two types.
        /// </remarks>
        protected ProcessInfo(ProcessInfo parent) : base(parent)
        {
            ProcessName = parent.ProcessName;
            ProcessDescription = parent.ProcessDescription;
            ProcessPath = parent.ProcessPath;
            ProcessID = parent.ProcessID;

            ProcessHandle = parent.ProcessHandle;
            ProcessCurrent = parent.ProcessCurrent;
            ProcessMachineType = parent.ProcessMachineType;
            ProcessModuleHandles = parent.ProcessModuleHandles;
            ModulesInfo = parent.ModulesInfo;

            ProcessCore = parent.ProcessCore;
            ProcessMemoryBasicInfo32 = parent.ProcessMemoryBasicInfo32;
            ProcessMemoryBasicInfo64 = parent.ProcessMemoryBasicInfo64;

            WorkingDirectory = parent.WorkingDirectory;
            Author = parent.Author;
        }
        #endregion

        #region ListLocalProcesses
        /// <summary>
        /// Gets a list of running processes on the host and removes unusable processes (such as system processes etc)
        /// </summary>
        /// <param name="core">An ErcCore object</param>
        /// <returns>Returns an ErcResult containing a list of all supported processes</returns>
        public static ErcResult<Process[]> ListLocalProcesses(ErcCore core)
        {
            ErcResult<Process[]> result = new ErcResult<Process[]>(core);
            Process[] processes = Process.GetProcesses();
            List<int> processesToRemove = new List<int>();

            for(int i = 0; i < processes.Length; i++)
            {
                string? filename = null;
                try
                {
                    ProcessModule? mainModule = processes[i].MainModule;
                    if (mainModule == null)
                    {
                        processesToRemove.Add(i);
                        continue;
                    }

                    filename = mainModule.FileName;
                }
                catch(Exception)
                {
                    processesToRemove.Add(i);
                }
            }

            Process[] usableProcesses = new Process[processes.Length - processesToRemove.Count];
            int processCounter = 0;
            for (int i = 0; i < processes.Length; i++)
            {
                if (!processesToRemove.Contains(i))
                {
                    usableProcesses[processCounter] = processes[i];
                    processCounter++;
                }
            }
            
            result.ReturnValue = usableProcesses;
            return result;
        }
        #endregion

        #region ListRemoteProcesses
        /// <summary>
        /// Gets a list of running processes on the host and removes unusable processes.
        /// </summary>
        /// <param name="core">An ErcCore object</param>
        /// <param name="machineName">The computer from which to read the list of processes. Can be either the hostname or IP address.</param>
        /// <returns>Returns an ErcResult containing a list of all supported processes</returns>
        public static ErcResult<Process[]> ListRemoteProcesses(ErcCore core, string machineName)
        {
            ErcResult<Process[]> result = new ErcResult<Process[]>(core);

            IPAddress? machine = null;
            if(IPAddress.TryParse(machineName, out machine))
            {
                IPHostEntry hostEntry = Dns.GetHostEntry(machine);
                machineName = hostEntry.HostName;
            }
            
            Process[] processes = Process.GetProcesses(machineName);
            List<int> processesToRemove = new List<int>();

            for (int i = 0; i < processes.Length; i++)
            {
                string? filename = null;
                try
                {
                    ProcessModule? mainModule = processes[i].MainModule;
                    if (mainModule == null)
                    {
                        processesToRemove.Add(i);
                        continue;
                    }

                    filename = mainModule.FileName;
                }
                catch (Exception)
                {
                    processesToRemove.Add(i);
                }
            }

            Process[] usableProcesses = new Process[processes.Length - processesToRemove.Count];
            int processCounter = 0;
            for (int i = 0; i < processes.Length; i++)
            {
                if (!processesToRemove.Contains(i))
                {
                    usableProcesses[processCounter] = processes[i];
                    processCounter++;
                }
            }

            result.ReturnValue = usableProcesses;
            return result;
        }
        #endregion

        #region GetProcessModules
        /// <summary>
        /// Returns a list of files loaded by the current process as List String
        /// </summary>
        /// <returns>Returns an ErcResult containing a Dictionary of module names and the associated handles</returns>
        public ErcResult<Dictionary<string, IntPtr>> GetProcessModules()
        {
            IntPtr hProcess = ProcessHandle;
            ErcResult<Dictionary<string, IntPtr>> result = new ErcResult<Dictionary<string, IntPtr>>(ProcessCore);
            result.ReturnValue = new Dictionary<string, IntPtr>();
            Dictionary<string, IntPtr> modules = new Dictionary<string, IntPtr>();
            if (hProcess != IntPtr.Zero)
            {
                try
                {
                    IntPtr[] modhWnds = new IntPtr[0];
                    int lpcbNeeded = 0;

                    try
                    {
                        // -- call EnumProcessModules the first time to get the size of the array needed
                        Native.EnumProcessModulesEx(hProcess, modhWnds, 0, out lpcbNeeded, LIST_MODULES_ALL);

                        modhWnds = new IntPtr[lpcbNeeded / IntPtr.Size];
                        Native.EnumProcessModulesEx(hProcess, modhWnds, modhWnds.Length * IntPtr.Size, out lpcbNeeded, LIST_MODULES_ALL);
                    }
                    catch
                    {
                        result.ReturnValue = modules;
                        return result;
                    }

                    for (int i = 0; i < modhWnds.Length; i++)
                    {
                        StringBuilder modName = new StringBuilder(256);
                        if (Native.GetModuleFileNameEx(hProcess, modhWnds[i], modName, modName.Capacity) != 0)
                        {
                            if (!modules.ContainsKey(modName.ToString()))
                            {
                                modules.Add(modName.ToString(), modhWnds[i]);
                            }
                        }
                    }
                }
                catch (Exception e)
                {
                    result.Error = e;
                    result.LogEvent();
                    return result;
                }
            }
            result.ReturnValue = modules;
            return result;
        }
        #endregion

        #region Identify_Process_Architecture
        /// <summary>
        /// Identifies if a process is 64bit or 32 bit, returns true for 64bit and false for 32bit.
        /// </summary>
        /// <param name="process">The process to be used</param>
        /// <returns>Returns true if the process is 64bit and false if it is not.</returns>
        /// <summary>
        /// The process's main module, or a clear error explaining why it is absent.
        /// </summary>
        /// <remarks>
        /// Process.MainModule returns null or throws for a process the caller cannot
        /// open: a protected process, or a 64-bit target inspected from the 32-bit
        /// build of the plugin. Reporting that beats a NullReferenceException raised
        /// from inside a constructor.
        /// </remarks>
        private static ProcessModule MainModuleOf(Process process)
        {
            ProcessModule? mainModule;

            try
            {
                mainModule = process.MainModule;
            }
            catch (Exception e)
            {
                throw new ERCException(
                    "The main module of process " + process.ProcessName + " (" + process.Id +
                    ") could not be read. The process may be protected, or may be 64 bit " +
                    "while this build of the plugin is 32 bit. " + e.Message);
            }

            if (mainModule == null)
            {
                throw new ERCException(
                    "Process " + process.ProcessName + " (" + process.Id + ") reports no main module. " +
                    "The process may be protected, or may be 64 bit while this build of the " +
                    "plugin is 32 bit.");
            }

            return mainModule;
        }

        public static bool Is64Bit(Process? process)
        {
            return Is64Bit(process, Win32NativeApi.Instance);
        }

        /// <summary>
        /// Identifies if a process is 64bit or 32 bit, using the supplied OS access.
        /// </summary>
        /// <param name="process">The process to be used</param>
        /// <param name="native">The OS calls to use.</param>
        /// <returns>Returns true if the process is 64bit and false if it is not.</returns>
        /// <remarks>
        /// The overload exists because this method is static: it cannot reach the
        /// instance <see cref="ErcCore.Native"/>, and a test needs some way to
        /// substitute the call.
        /// </remarks>
        public static bool Is64Bit(Process? process, INativeApi native)
        {
            bool isWow64;

            if(process == null)
            {
                throw new ERCException("No process attached.");
            }

            if (native == null)
            {
                throw new ArgumentNullException("native");
            }

            if (!Environment.Is64BitOperatingSystem)
            {
                return false;
            }

            if (!native.IsWow64Process(process.Handle, out isWow64))
            {
                throw new ERCException("An error has occured in the IsWow64Process call from Process.Is64Bit()");
            }

            return !isWow64;
        }
        #endregion

        #region LocateMemoryRegions
        /// <summary>
        /// Identifies memory regions occupied by the current process and populates the associated list with the Process_Info object.
        /// </summary>
        private void LocateMemoryRegions()
        {
            
            Process process = ProcessCurrent;
            if (ProcessMachineType == MachineType.I386)
            {
                ProcessMemoryBasicInfo32 = new List<MEMORY_BASIC_INFORMATION32>();
                long MaxAddress = 0x7fffffff;
                long address = 0;
                long oldAddress = 0;

                do
                {
                    MEMORY_BASIC_INFORMATION32 m;
                    int result = Native.VirtualQueryEx32(process.Handle, (IntPtr)address, out m, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION32)));
                    if (address == (long)m.BaseAddress + (long)m.RegionSize)
                        break;
                    address = (long)m.BaseAddress + (long)m.RegionSize;
                    if (oldAddress > address)
                    {
                        address = long.MaxValue;
                    }
                    oldAddress = address;
                    if (m.State == StateEnum.MEM_COMMIT && (m.Type == TypeEnum.MEM_MAPPED || m.Type == TypeEnum.MEM_PRIVATE))
                    {
                        ProcessMemoryBasicInfo32.Add(m);
                    }
                } while (address <= MaxAddress);
            }
            else if (ProcessMachineType == MachineType.x64)
            {
                ProcessMemoryBasicInfo64 = new List<MEMORY_BASIC_INFORMATION64>();
                long MaxAddress = 0x000007FFFFFEFFFF;
                long address = 0;
                long oldAddress = 0;

                do
                {
                    MEMORY_BASIC_INFORMATION64 m;
                    int result = Native.VirtualQueryEx64(process.Handle, (IntPtr)address, out m, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION64)));
                    if (address == (long)m.BaseAddress + (long)m.RegionSize)
                        break;
                    address = (long)m.BaseAddress + (long)m.RegionSize;
                    if (oldAddress > address)
                    {
                        address = long.MaxValue;
                    }
                    oldAddress = address;
                    if (m.State == StateEnum.MEM_COMMIT && (m.Type == TypeEnum.MEM_MAPPED || m.Type == TypeEnum.MEM_PRIVATE))
                    {
                        ProcessMemoryBasicInfo64.Add(m);
                    }

                } while (address <= MaxAddress);
            }
            else
            {
                throw new ERCException("Machine type is invalid");
            }
        }
        #endregion

        #region CreateExcludesList
        /// <summary>
        /// Creates a list of modules to exclude from a search of memory.
        /// </summary>
        /// <returns>Returns an ErcResult containing a list of stringss</returns>
        public List<string> CreateExcludesList(bool aslr = false, bool safeseh = false, bool rebase = false, bool nxcompat = false, bool osdll = false)
        {
            List<string> excludedModules = new List<string>();
            for(int i = 0; i < ModulesInfo.Count; i++)
            {
                bool add = false;
                if(aslr == true && ModulesInfo[i].ModuleASLR == true)
                {
                    add = true;
                }
                if (safeseh == true && ModulesInfo[i].ModuleSafeSEH == true)
                {
                    add = true;
                }
                if (rebase == true && ModulesInfo[i].ModuleRebase == true)
                {
                    add = true;
                }
                if (nxcompat == true && ModulesInfo[i].ModuleNXCompat == true)
                {
                    add = true;
                }
                if (osdll == true && ModulesInfo[i].ModuleOsDll == true)
                {
                    add = true;
                }
                if(add == true)
                {
                    excludedModules.Add(ModulesInfo[i].ModulePath);
                }
            }
            return excludedModules;
        }
        #endregion

        #region Accessors

        #region ToString
        /// <summary>
        /// Override of the ToString method. Returns information about the process in a pleasantly formatted string
        /// </summary>
        /// <returns>A string</returns>
        public override string ToString()
        {
            string ret = "";
            ret += "Process Name = " + ProcessName + Environment.NewLine;
            ret += "Process Description = " + ProcessDescription + Environment.NewLine;
            ret += "Process Path = " + ProcessPath + Environment.NewLine;
            ret += "Process ID = " + ProcessID + Environment.NewLine;
            if(ProcessMachineType == MachineType.I386)
            {
                ret += "Process Handle = 0x" + ProcessHandle.ToString("X8") + Environment.NewLine;
            }
            else
            {
                ret += "Process Handle = 0x" + ProcessHandle.ToString("X16") + Environment.NewLine;
            }
            ret += "Process Machine Type = " + ProcessMachineType.ToString() + Environment.NewLine;

            return ret;
        }
        #endregion

        #region Get Modules Handles
        /// <summary>
        /// Returns a list of module handles associated with the process.
        /// </summary>
        /// <returns>Returns a dictionary containing the handle and path of each module</returns>
        public ErcResult<Dictionary<string, IntPtr>> GetModuleHandles()
        {
            ErcResult<Dictionary<string, IntPtr>> ret = new ErcResult<Dictionary<string, IntPtr>>(ProcessCore);
            if (ProcessModuleHandles.Count > 0)
            {
                ret.ReturnValue = ProcessModuleHandles;
                return ret;
            }
            else
            {
                ret.Error = new ERCException("Error: An unknown eroor has occured whilst populating the modules list for this process. Check the error log for more detailed information.");
                return ret;
            }
        }
        #endregion

        #region Get Module Information
        /// <summary>
        /// Gets the list of ModuleInfo objects associated with the current process.
        /// </summary>
        /// <returns>Returns an ErcResult containing a list of ModuleInfo objects</returns>
        public ErcResult<List<ModuleInfo>> GetProcessModuleInformation()
        {
            ErcResult<List<ModuleInfo>> ret = new ErcResult<List<ModuleInfo>>(ProcessCore);
            if(ModulesInfo.Count > 0)
            {
                ret.ReturnValue = ModulesInfo;
                return ret;
            }
            else
            {
                ret.Error = new ERCException("Error: An unknown eroor has occured whilst populating the modules list for this process. Check the error log for more detailed information.");
                return ret;
            }
        }
        #endregion

        #region Get Thread Information
        /// <summary>
        /// Gets the list of ThreadInfo objects associated with the current process.
        /// </summary>
        /// <returns>Returns an ErcResult containing a list of ThreadInfo objects</returns>
        public ErcResult<List<ThreadInfo>> GetProcessThreadInformation()
        {
            ErcResult<List<ThreadInfo>> ret = new ErcResult<List<ThreadInfo>>(ProcessCore);
            if (ThreadsInfo.Count > 0)
            {
                ret.ReturnValue = ThreadsInfo;
                return ret;
            }
            else
            {
                ret.Error = new ERCException("Error: An unknown eroor has occured whilst populating the threads list for this process. Check the error log for more detailed information.");
                return ret;
            }
        }
        #endregion

        #region Dump Memory Region
        /// <summary>
        /// Reads process memory from a specific address for a set number of bytes. 
        /// </summary>
        /// <param name="startAddress">The address to start reading from.</param>
        /// <param name="length">Number of bytes to read.</param>
        /// <returns>Returns a bytes array containing the specified contents of process memory.</returns>
        public ErcResult<byte[]> DumpMemoryRegion(IntPtr startAddress, int length)
        {
            ErcResult<byte[]> result = new ErcResult<byte[]>(ProcessCore);
            byte[] bytes = new byte[length];
            try
            {
                int retValue = Native.ReadProcessMemory(ProcessHandle, startAddress, bytes, length, out int bytesRead);
                if (retValue == 0)
                {
                    ERCException ex = new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    result.ReturnValue = bytes;
                    throw ex;
                }
                else
                {
                    result.ReturnValue = bytes;
                }
            }
            catch(Exception e)
            {
                result.Error = e;
            }
            
            return result;
        }
        #endregion

        #endregion

        #region IDisposable

        private bool _disposed;

        /// <summary>
        /// Releases the thread handles opened for this process.
        /// </summary>
        /// <remarks>
        /// ProcessHandle itself is deliberately not closed: it comes from the .NET
        /// Process object, which owns it. Only the handles this library opened are
        /// released here.
        /// </remarks>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            if (ThreadsInfo != null)
            {
                foreach (ThreadInfo thread in ThreadsInfo)
                {
                    if (thread != null)
                    {
                        thread.Dispose();
                    }
                }
            }

            _disposed = true;
            GC.SuppressFinalize(this);
        }

        #endregion
    }
}
