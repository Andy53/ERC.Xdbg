using ERC.Utilities;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace ERC
{
    /// <summary> Provides output in various human readable formats of data from the library. </summary>
    public static class DisplayOutput
    {

        #region GetFilePath
        /// <summary>
        /// Identifies output files previously created by a the Display_Modules function
        /// and identifies the last number used. Returns the next number to be used as a filename.
        /// </summary>
        /// <param name="directory">The directory to be used</param>
        /// <param name="prefix">A prefix for the file name e.g. "modules_" or "Pattern_" etc</param>
        /// <param name="extension">The file extension to be used e.g. ".txt" </param>
        /// <returns>Returns a string containing the full file path to be used when writing output to disk</returns>
        internal static string GetFilePath(string directory, string prefix, string extension)
        {
            string result = "";
            int fileNumber = 0;
            char[] delimiterChars = { '_', '.' };

            DirectoryInfo d = new DirectoryInfo(directory);
            FileInfo[] files = d.GetFiles(prefix + "*");

            foreach (FileInfo f in files)
            {
                string fileNumberString = Regex.Match(f.Name, @"\d+").Value;
                if (fileNumber < int.Parse(fileNumberString))
                {
                    fileNumber = int.Parse(fileNumberString);
                }
            }

            fileNumber++;
            result = directory + prefix + fileNumber.ToString() + extension;
            return result;
        }
        #endregion

        #region WriteToFile
        /// <summary>
        /// Writes a list of strings to a file. Takes a directory, filename and prefix along with a List of strings.
        /// </summary>
        /// <param name="directory">The directory to be used</param>
        /// <param name="prefix">A prefix for the file name e.g. "modules_" or "Pattern_" etc</param>
        /// <param name="extension">The file extension to be used e.g. ".txt" </param>
        /// <param name="content">A list of strings to be written to disk </param>

        public static void WriteToFile(string directory, string prefix, string extension, List<string> content)
        {
            string path = GetFilePath(directory, prefix, extension);
            TextWriter tw = new StreamWriter(path);

            foreach (String s in content)
                tw.WriteLine(s);

            tw.Close();
        }
        #endregion

        #region Generate Pattern
        /// <summary>
        /// Creates a file in the ErcCore working directory containing a string of non repeating characters. 
        /// </summary>
        /// <param name="length">The length of the string to be created</param>
        /// <param name="core">An ErcCore object</param>
        /// <param name="extended">A optional boolean specifying whether to use the extended character set. Default is false.</param>
        /// <returns>Returns a string containing the pattern generated.</returns>
        public static string GeneratePattern(int length, ErcCore core, bool extended = false)
        {
            var patternFilePath = GetFilePath(core.WorkingDirectory, "Pattern_Create_", ".txt");
            var pattern = PatternTools.PatternCreate(length, core, extended);
            if(pattern.Error != null)
            {
                throw pattern.Error;
            }
            var patternOutput = PatternOutputBuilder(pattern.ReturnValue, core);
            File.WriteAllText(patternFilePath, patternOutput);
            return patternOutput;
        }
        #endregion

        #region Pattern Output
        /// <summary>
        /// Private function, should not be called directly. Takes input from pattern_create and outputs in an easily readable format.
        /// </summary>
        /// <param name="pattern">The pattern to be used</param>
        /// <param name="core">An ErcCore object</param>
        /// <returns>Returns a string containing the human readable output of the pattern create method.</returns>
        private static string PatternOutputBuilder(string pattern, ErcCore core)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(pattern);
            string hexPattern = BitConverter.ToString(bytes);
            string asciiPattern = " ";
            string[] hexArray = hexPattern.Split('-');

            for (int i = 0; i < hexArray.Length; i++)
            {
                asciiPattern += pattern[i];

                if (i % 88 == 0 && i > 0)
                {
                    asciiPattern += "\"";
                    asciiPattern += Environment.NewLine;
                    asciiPattern += "\"";
                }
            }

            hexPattern = " ";
            for (int i = 0; i < hexArray.Length; i++)
            {
                hexPattern += "\\x" + hexArray[i];

                if (i % 22 == 0 && i > 0)
                {
                    hexPattern += Environment.NewLine;
                }
            }

            asciiPattern = asciiPattern.TrimStart(' ');
            hexPattern = hexPattern.TrimStart(' ');

            string output = "";
            output += "------------------------------------------------------------------------------------------" + Environment.NewLine;
            output += "Pattern created at: " + DateTime.Now + ". Pattern created by: " + core.Author + ". Pattern length: " + pattern.Length + Environment.NewLine;
            output += "------------------------------------------------------------------------------------------" + Environment.NewLine;
            output += Environment.NewLine;
            output += "Ascii:" + Environment.NewLine;
            output += "\"" + asciiPattern + "\"" + Environment.NewLine;
            output += Environment.NewLine;
            output += "Hexadecimal:" + Environment.NewLine;
            output += hexPattern;

            return output;
        }
        #endregion

        #region List Local Processes
        /// <summary>
        /// Lists usable processes running on the local machine.
        /// </summary>
        /// <returns>A string containing details of processes running on the local machine.</returns>
        public static string ListLocalProcesses()
        {
            var processes = ProcessInfo.ListLocalProcesses(new ErcCore());
            string processDetails = "";
            if (processes.Error != null)
            {
                return processes.Error.Message;
            }

            foreach(Process p in processes.ReturnValue)
            {
                processDetails += p.ProcessName + " ID: " + p.Id + " Filename: " + p.MainWindowTitle + Environment.NewLine;
            }
            return processDetails;
        }
        #endregion

        #region List Remote Processes
        /// <summary>
        /// Lists usable processes running on the remote machine.
        /// </summary>
        /// <returns>A string containing details of processes running on the remote machine.</returns>
        public static string ListRemoteProcesses(string machineName)
        {
            var processes = ProcessInfo.ListRemoteProcesses(new ErcCore(), machineName);
            string processDetails = "";
            if (processes.Error != null)
            {
                return processes.Error.Message;
            }

            foreach (Process p in processes.ReturnValue)
            {
                processDetails += p.ProcessName + " ID: " + p.Id + " Filename: " + p.MainWindowTitle + Environment.NewLine;
            }
            return processDetails;
        }
        #endregion

        #region DisplayProcessInfo
        /// <summary>
        /// Displays information related to the provided ProcessInfo object.
        /// </summary>
        /// <param name="info">The ProcessInfo object of which the module information will be displayed</param>
        /// <param name="outputToFile">Set to false to surpress file output.</param>
        /// <returns></returns>
        public static string DisplayProcessInfo(ProcessInfo info, bool outputToFile = true)
        {
            string information = "Process Information: " + info.ProcessName + Environment.NewLine;
            information += "------------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;
            information += info.ToString();
            information += Environment.NewLine;
            information += GenerateModuleInfoTable(info, false);
            information += Environment.NewLine;
            information += DisplayThreadInfo(info, false);

            if (outputToFile == true)
            {
                string processFilename = GetFilePath(info.WorkingDirectory, "process_info_", ".txt");
                File.WriteAllText(processFilename, information);
            }
            return information;
        }
        #endregion

        #region DisplayThreadInfo
        /// <summary>
        /// Displays information about all threads related to a specific process.
        /// </summary>
        /// <param name="info"></param>
        /// <param name="outputToFile"></param>
        /// <returns></returns>
        public static string DisplayThreadInfo(ProcessInfo info, bool outputToFile = true)
        {
            string information = "Thread Information for Process: " + info.ProcessName + Environment.NewLine;
            information += "------------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;
            var threads = info.GetProcessThreadInformation();
            foreach(ThreadInfo t in threads.ReturnValue)
            {
                information += "Thread ID = " + t.ThreadID + Environment.NewLine;
                var teb = t.GetTeb();
                if (t.X64 == MachineType.x64)
                {
                    information += "    Thread Handle = " + "0x" + t.ThreadHandle.ToString("x16") + Environment.NewLine;
                    information += "    Thread is running in a 64 bit process = true" + Environment.NewLine;
                    information += "    Top of stack = " + "0x" + teb.TopOfStack.ToString("x16") + Environment.NewLine;
                    information += "    Bottom of stack = " + "0x" + teb.BottomOfStack.ToString("x16") + Environment.NewLine;
                }
                else
                {
                    information += "    Thread Handle = " + "0x" + t.ThreadHandle.ToString("x8") + Environment.NewLine;
                    information += "    Thread is running in a 64 bit process = false" + Environment.NewLine;
                    information += "    Top of stack = " + "0x" + teb.TopOfStack.ToString("x8") + Environment.NewLine;
                    information += "    Bottom of stack = " + "0x" + teb.BottomOfStack.ToString("x8") + Environment.NewLine;
                }
                information += Environment.NewLine;
            }
            if(outputToFile == true)
            {
                string threadFilename = GetFilePath(info.WorkingDirectory, "threads_", ".txt");
                File.WriteAllText(threadFilename, information);
            }
            return information;
        }
        #endregion

        #region DisplayModuleInfo
        /// <summary>
        /// Displays a list of all modules and associated information from a specific process. Can output to stdout, a file or both.
        /// </summary>
        /// <param name="info">The ProcessInfo object of which the module information will be displayed</param>
        /// <returns>Returns a string containing all module info from a specific process</returns>
        internal static string DisplayModuleInfo(ProcessInfo info)
        {
            int ptrSegmentWidth = 16;
            int flagSegmentWidth = 10;
            string output = "";
            output += "------------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;

            if (info.Author != "No_Author_Set")
            {
                output += "Process Name: " + info.ProcessName + " Pattern created by: " + info.Author + " " +
                "Modules total: " + info.ModulesInfo.Count + Environment.NewLine;
            }
            else
            {
                output += "Process Name: " + info.ProcessName + " Modules total: " + info.ModulesInfo.Count + Environment.NewLine;
            }

            output += "------------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;
            output += " Base          | Entry point   | Size      | Rebase   | SafeSEH  | ASLR    | NXCompat | OS DLL  | Version, Name and Path" + Environment.NewLine;
            output += "------------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;
            foreach (ModuleInfo module in info.ModulesInfo)
            {
                string baseElement = " ";
                baseElement += "0x" + module.ModuleBase.ToString("x");
                for (int i = baseElement.Length; i < ptrSegmentWidth; i++)
                {
                    baseElement += " ";
                }

                string entryElement = " ";
                entryElement += "0x" + module.ModuleEntry.ToString("x");
                for (int i = entryElement.Length; i < ptrSegmentWidth; i++)
                {
                    entryElement += " ";
                }

                string sizeElement = " ";
                sizeElement += "0x" + module.ModuleSize.ToString("x");
                for (int i = sizeElement.Length; i < flagSegmentWidth; i++)
                {
                    sizeElement += " ";
                }

                string rebaseElement = "   ";
                if (module.ModuleRebase == true)
                {
                    rebaseElement += "True    ";
                }
                else
                {
                    rebaseElement += "False   ";
                }

                string sehElement = "   ";
                if (module.ModuleSafeSEH == true)
                {
                    sehElement += "True     ";
                }
                else
                {
                    sehElement += "False    ";
                }

                string aslrElement = "  ";
                if (module.ModuleASLR == true)
                {
                    aslrElement += "True     ";
                }
                else
                {
                    aslrElement += "False    ";
                }

                string nxElement = "  ";
                if (module.ModuleNXCompat == true)
                {
                    nxElement += "True     ";
                }
                else
                {
                    nxElement += "False    ";
                }

                string osElement = "  ";
                if (module.ModuleOsDll == true)
                {
                    osElement += "True     ";
                }
                else
                {
                    osElement += "False    ";
                }

                string fileElement = "  ";
                if (!string.IsNullOrEmpty(module.ModuleVersion))
                {
                    fileElement += module.ModuleVersion + ";";
                }
                if (!string.IsNullOrEmpty(module.ModuleName))
                {
                    fileElement += module.ModuleName + ";";
                }
                if (!string.IsNullOrEmpty(module.ModulePath))
                {
                    fileElement += module.ModulePath;
                }
                output += baseElement + entryElement + sizeElement + rebaseElement +
                    sehElement + aslrElement + nxElement + osElement + fileElement + Environment.NewLine;
            }
            return output;
        }
        #endregion

        #region GenerateModuleInfoTable
        /// <summary>
        /// Aquires filename and writes out all module data to the current working directory. Requires a Process_Info object to be passed as a parameter.
        /// </summary>
        /// <param name="info">The ProcessInfo object of which the module information will be displayed</param>
        /// <param name="outputToFile">Set to false to surpress file output.</param>
        /// <returns>Returns a formatted string of all results</returns>
        public static string GenerateModuleInfoTable(ProcessInfo info, bool outputToFile = true)
        {
            string modOutput = DisplayModuleInfo(info);
            string modFilename = GetFilePath(info.WorkingDirectory, "modules_", ".txt");
            if(outputToFile == true)
            {
                File.WriteAllText(modFilename, modOutput);
            }
            return modOutput;
        }
        #endregion

        #region SearhMemory
        /// <summary>
        /// Searches the memory of a process and it's loaded modules for a string or byte combination.
        /// </summary>
        /// <param name="info">The processInfo object for the process</param>
        /// <param name="searchType">The type of data to be searched for.</param>
        /// <param name="searchString">The string to search for.</param>
        /// <param name="aslr">Remove ASLR libraries.</param>
        /// <param name="safeseh">Remove SafeSEH libraries.</param>
        /// <param name="rebase">Remove rebasable libraries.</param>
        /// <param name="nxcompat">Remove NXCompat libraries.</param>
        /// <param name="osdll">Remove OS Dlls.</param>
        /// <param name="unwantedBytes">Addresses containing values in this byte array will be ignored.</param>
        /// <param name="protection">String containing protection level returned pointers will.</param>
        /// <returns></returns>
        public static List<string> SearchMemory(ProcessInfo info, int searchType, string searchString, bool aslr = false, 
            bool safeseh = false, bool rebase = false, bool nxcompat = false, bool osdll = false, 
            byte[] unwantedBytes = null, string protection = "exec")
        {
            List<string> excludedModules = info.CreateExcludesList(aslr, safeseh, rebase, nxcompat, osdll);
            Dictionary<IntPtr, string> results = new Dictionary<IntPtr, string>();

            if (searchType == 0)
            {
                byte[] searchBytes = StringToByteArray(searchString.Replace(" ", ""));
                results = info.SearchMemory(searchType, searchBytes, null, excludedModules).ReturnValue;
            }
            else
            {
                results = info.SearchMemory(searchType, null, searchString, excludedModules).ReturnValue;
            }

            if (unwantedBytes != null)
            {
                List<IntPtr> p = new List<IntPtr>();
                foreach (KeyValuePair<IntPtr, string> k in results)
                {
                    p.Add(k.Key);
                }
                var pt = ERC.Utilities.PtrRemover.RemovePointers(info.ProcessMachineType, p, unwantedBytes);
                pt = ERC.Utilities.PtrRemover.RemovePointersProtection(info, pt, protection);

                foreach (KeyValuePair<IntPtr, string> k in results.ToList())
                {
                    if (!pt.Contains(k.Key))
                    {
                        results.Remove(k.Key);
                    }
                }
            }
            else
            {
                List<IntPtr> p = new List<IntPtr>();
                foreach (KeyValuePair<IntPtr, string> k in results)
                {
                    p.Add(k.Key);
                }
                var pt = ERC.Utilities.PtrRemover.RemovePointersProtection(info, p, protection);

                foreach (KeyValuePair<IntPtr, string> k in results.ToList())
                {
                    if (!pt.Contains(k.Key))
                    {
                        results.Remove(k.Key);
                    }
                }
            }

            List<string> output = new List<string>();
            output.Add(String.Format("List created on {0} by {1}. Search string: {2}", DateTime.Now, info.Author, searchString));
            output.Add("----------------------------------------------------------------------");
            if (info.ProcessMachineType == ERC.MachineType.I386)
            {
                output.Add("  Address  | ASLR | SafeSEH | Rebase | NXCompat | OsDLL | Module Path");
            }
            else
            {
                output.Add("      Address      | ASLR | SafeSEH  | Rebase | NXCompat | OsDLL | Module Path");
            }
            output.Add("----------------------------------------------------------------------");
            foreach (KeyValuePair<IntPtr, string> v in results)
            {
                for (int i = 0; i < info.ModulesInfo.Count; i++)
                {
                    if (info.ProcessMachineType == ERC.MachineType.I386)
                    {
                        if (info.ModulesInfo[i].ModulePath == v.Value)
                        {
                            output.Add(String.Format("0x{0} | {1} |  {2}   |  {3}  |   {4}   |  {5} | {6}",
                                v.Key.ToString("X8"), info.ModulesInfo[i].ModuleASLR, info.ModulesInfo[i].ModuleSafeSEH,
                                info.ModulesInfo[i].ModuleRebase, info.ModulesInfo[i].ModuleNXCompat, info.ModulesInfo[i].ModuleOsDll,
                                info.ModulesInfo[i].ModulePath));
                        }
                    }
                    else
                    {
                        if (info.ModulesInfo[i].ModulePath == v.Value)
                        {
                            output.Add(String.Format("0x{0} | {1} |  {2}   |  {3}  |   {4}   |  {5} | {6}",
                                v.Key.ToString("X16"), info.ModulesInfo[i].ModuleASLR, info.ModulesInfo[i].ModuleSafeSEH,
                                info.ModulesInfo[i].ModuleRebase, info.ModulesInfo[i].ModuleNXCompat, info.ModulesInfo[i].ModuleOsDll,
                                info.ModulesInfo[i].ModulePath));
                        }
                    }
                }
            }
            WriteToFile(info.WorkingDirectory, "MemorySearch", ".txt", output);
            return output;
        }
        #endregion

        #region SearchModules
        /// <summary>
        /// Searches the loaded modules of a process for a string or byte combination.
        /// </summary>
        /// <param name="info">The processInfo object for the process</param>
        /// <param name="searchType">The type of data to be searched for.</param>
        /// <param name="searchString">The string to search for.</param>
        /// <param name="aslr">Remove ASLR libraries.</param>
        /// <param name="safeseh">Remove SafeSEH libraries.</param>
        /// <param name="rebase">Remove rebasable libraries.</param>
        /// <param name="nxcompat">Remove NXCompat libraries.</param>
        /// <param name="osdll">Remove OS Dlls.</param>
        /// <param name="unwantedBytes">Addresses containing values in this byte array will be ignored.</param>
        /// <param name="modules">List of modules to be searched</param>
        /// <param name="protection">String containing protection level returned pointers will.</param>
        /// <returns></returns>
        public static List<string> SearchModules(ProcessInfo info, int searchType, string searchString, bool aslr = false,
            bool safeseh = false, bool rebase = false, bool nxcompat = false, bool osdll = false,
            byte[] unwantedBytes = null, List<string> modules = null, string protection = "exec")
        {
            List<string> excludedModules = info.CreateExcludesList(aslr, safeseh, rebase, nxcompat, osdll);
            Dictionary<IntPtr, string> results = new Dictionary<IntPtr, string>();

            if (searchType == 0)
            {
                byte[] searchBytes = StringToByteArray(searchString.Replace(" ", ""));
                results = info.SearchModules(searchType, unwantedBytes, searchBytes, null, modules, excludedModules).ReturnValue;
            }
            else
            {
                results = info.SearchModules(searchType, unwantedBytes, null, searchString, modules, excludedModules).ReturnValue;
            }

            if (unwantedBytes != null)
            {
                List<IntPtr> p = new List<IntPtr>();
                foreach (KeyValuePair<IntPtr, string> k in results)
                {
                    p.Add(k.Key);
                }
                var pt = ERC.Utilities.PtrRemover.RemovePointers(info.ProcessMachineType, p, unwantedBytes);
                pt = ERC.Utilities.PtrRemover.RemovePointersProtection(info, pt, protection);

                foreach (KeyValuePair<IntPtr, string> k in results.ToList())
                {
                    if (!pt.Contains(k.Key))
                    {
                        results.Remove(k.Key);
                    }
                }
            }
            else
            {
                List<IntPtr> p = new List<IntPtr>();
                foreach (KeyValuePair<IntPtr, string> k in results)
                {
                    p.Add(k.Key);
                }
                var pt = ERC.Utilities.PtrRemover.RemovePointersProtection(info, p, protection);

                foreach (KeyValuePair<IntPtr, string> k in results.ToList())
                {
                    if (!pt.Contains(k.Key))
                    {
                        results.Remove(k.Key);
                    }
                }
            }
            List<string> output = new List<string>();
            output.Add(String.Format("List created on {0} by {1}. Search string: {2}", DateTime.Now, info.Author, searchString));
            output.Add("----------------------------------------------------------------------");
            if (info.ProcessMachineType == ERC.MachineType.I386)
            {
                output.Add("  Address  | ASLR | SafeSEH | Rebase | NXCompat | OsDLL | Module Path");
            }
            else
            {
                output.Add("      Address      | ASLR | SafeSEH  | Rebase | NXCompat | OsDLL | Module Path");
            }
            output.Add("----------------------------------------------------------------------");
            foreach (KeyValuePair<IntPtr, string> v in results)
            {
                for (int i = 0; i < info.ModulesInfo.Count; i++)
                {
                    if (info.ProcessMachineType == ERC.MachineType.I386)
                    {
                        if (info.ModulesInfo[i].ModulePath == v.Value)
                        {
                            output.Add(String.Format("0x{0} | {1} |  {2}   |  {3}  |   {4}   |  {5} | {6}",
                                v.Key.ToString("X8"), info.ModulesInfo[i].ModuleASLR, info.ModulesInfo[i].ModuleSafeSEH,
                                info.ModulesInfo[i].ModuleRebase, info.ModulesInfo[i].ModuleNXCompat, info.ModulesInfo[i].ModuleOsDll,
                                info.ModulesInfo[i].ModulePath));
                        }
                    }
                    else
                    {
                        if (info.ModulesInfo[i].ModulePath == v.Value)
                        {
                            output.Add(String.Format("0x{0} | {1} |  {2}   |  {3}  |   {4}   |  {5} | {6}",
                                v.Key.ToString("X16"), info.ModulesInfo[i].ModuleASLR, info.ModulesInfo[i].ModuleSafeSEH,
                                info.ModulesInfo[i].ModuleRebase, info.ModulesInfo[i].ModuleNXCompat, info.ModulesInfo[i].ModuleOsDll,
                                info.ModulesInfo[i].ModulePath));
                        }
                    }
                }
            }
            WriteToFile(info.WorkingDirectory, "ModuleSearch", ".txt", output);
            return output;
        }

        #endregion

        #region GetSEHJumps
        /// <summary>
        /// Searches all memory associated with a given process and associated modules for POP X POP X RET instructions. 
        /// Passing a list of module paths or names will exclude those modules from the search. 
        /// Similar to Search_All_Memory_PPR however provides output in an easily readable format.
        /// </summary>
        /// <param name="info">The ProcessInfo object which will be searched for POP POP RET instructions.</param>
        /// <param name="aslr">Remove ASLR libraries.</param>
        /// <param name="safeseh">Remove SafeSEH libraries.</param>
        /// <param name="rebase">Remove rebasable libraries.</param>
        /// <param name="nxcompat">Remove NXCompat libraries.</param>
        /// <param name="osdll">Remove OS Dlls.</param>
        /// <param name="unwantedBytes">Addresses containing values in this byte array will be ignored.</param>
        /// <param name="protection">String containing protection level returned pointers will.</param>
        /// <returns>Returns an ErcResult containing a list of strings detailing the pointers, opcodes and base files of suitable instruction sets.</returns>
        public static List<string> GetSEHJumps(ProcessInfo info, bool aslr = false,
            bool safeseh = false, bool rebase = false, bool nxcompat = false, bool osdll = false,
            byte[] unwantedBytes = null, string protection = "exec")
        {
            List<string> ret = new List<string>();
            List<string> excludedModules = info.CreateExcludesList(aslr, safeseh, rebase, nxcompat, osdll);
            ErcResult<Dictionary<IntPtr, string>> ptrs = info.SearchAllMemoryPPR(excludedModules);

            if (unwantedBytes != null)
            {
                List<IntPtr> p = new List<IntPtr>();
                foreach(KeyValuePair<IntPtr, string> k in ptrs.ReturnValue)
                {
                    p.Add(k.Key);
                }
                var pt = ERC.Utilities.PtrRemover.RemovePointers(info.ProcessMachineType, p, unwantedBytes);
                pt = ERC.Utilities.PtrRemover.RemovePointersProtection(info, pt, protection);

                foreach (KeyValuePair<IntPtr, string> k in ptrs.ReturnValue.ToList())
                {
                    if (!pt.Contains(k.Key))
                    {
                        ptrs.ReturnValue.Remove(k.Key);
                    }
                }
            }
            else
            {
                List<IntPtr> p = new List<IntPtr>();
                foreach (KeyValuePair<IntPtr, string> k in ptrs.ReturnValue)
                {
                    p.Add(k.Key);
                }
                var pt = ERC.Utilities.PtrRemover.RemovePointersProtection(info, p, protection);

                foreach (KeyValuePair<IntPtr, string> k in ptrs.ReturnValue.ToList())
                {
                    if (!pt.Contains(k.Key))
                    {
                        ptrs.ReturnValue.Remove(k.Key);
                    }
                }
            }

            string sehFilename = GetFilePath(info.WorkingDirectory, "SEH_jumps_", ".txt");
            ret.Add("---------------------------------------------------------------------------------------");
            if (info.Author != "No_Author_Set")
            {
                ret.Add("Process Name: " + info.ProcessName + " Created by: " + info.Author + " " +
                "Total Results: " + ptrs.ReturnValue.Count);
            }
            else
            {
                ret.Add("Process Name: " + info.ProcessName + " Total Results: " + ptrs.ReturnValue.Count);
            }
            ret.Add("---------------------------------------------------------------------------------------");

            if (ptrs.Error != null)
            {
                throw new Exception("Error passed from Search_All_Memory_PPR: " + ptrs.Error.ToString());
            }
            if (info.ProcessMachineType == ERC.MachineType.I386)
            {
                ret.Add("  Address  |      Instructions     | ASLR | SafeSEH  | Rebase  | NXCompat |  OsDLL | Module Path");
            }
            else
            {
                ret.Add("      Address      |      Instructions     | ASLR | SafeSEH  | Rebase  | NXCompat |  OsDLL | Module Path");
            }
            byte[] ppr = new byte[5];
            int bytesread = 0;

            if(ptrs.ReturnValue.Count > 0)
            {
                foreach (KeyValuePair<IntPtr, string> s in ptrs.ReturnValue)
                {
                    string holder = "";
                    List<byte> opcodes = new List<byte>();
                    try
                    {
                        ErcCore.ReadProcessMemory(info.ProcessHandle, s.Key, ppr, ppr.Length, out bytesread);
                        for (int i = 0; i < 5; i++)
                        {
                            if (ppr[i].Equals(0xC3))
                            {
                                for (int j = 0; j <= i; j++)
                                {
                                    opcodes.Add(ppr[j]);
                                }
                                ERC.Utilities.OpcodeDisassembler disas = new ERC.Utilities.OpcodeDisassembler(info);
                                var result = disas.Disassemble(opcodes.ToArray());
                                if (info.ProcessMachineType == ERC.MachineType.I386)
                                {
                                    holder = result.ReturnValue.Replace(Environment.NewLine, ", ");
                                    int index = holder.IndexOf("ret");
                                    holder = holder.Substring(0, index + 3);
                                    holder = "0x" + s.Key.ToString("x8") + " | " + holder + " ";

                                }
                                else
                                {
                                    holder = result.ReturnValue.Replace(Environment.NewLine, ", ");
                                    int index = holder.IndexOf("ret");
                                    holder = holder.Substring(0, index + 3);
                                    holder = "0x" + s.Key.ToString("x16") + " | " + holder + " ";
                                }
                                opcodes.Clear();
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        throw e;
                    }

                    for (int i = 0; i < info.ModulesInfo.Count; i++)
                    {
                        if (info.ModulesInfo[i].ModulePath == s.Value)
                        {
                            holder += String.Format("| {0} |  {1}   |  {2}   |   {3}   |  {4}  |  {5} ",
                                info.ModulesInfo[i].ModuleASLR, info.ModulesInfo[i].ModuleSafeSEH,
                                info.ModulesInfo[i].ModuleRebase, info.ModulesInfo[i].ModuleNXCompat, info.ModulesInfo[i].ModuleOsDll,
                                info.ModulesInfo[i].ModulePath);
                        }
                    }
                    ret.Add(holder);
                }
            }
            else
            {
                ret.Add("No compliant POP POP RET instuctions were found.");
            }
            
            File.WriteAllLines(sehFilename, ret);
            return ret;
        }

        /// <summary>
        /// Searches all memory associated with a given process and associated modules for POP X POP X RET instructions. 
        /// Passing a list of module paths or names will exclude those modules from the search. 
        /// Similar to Search_All_Memory_PPR however provides output in an easily readable format.
        /// </summary>
        /// <param name="info">The ProcessInfo object which will be searched for POP POP RET instructions</param>
        /// <param name="ptrsToExclude">Ptrs containing these byte values will be discarded.</param>
        /// <param name="excludes">Modules to be ignored when searching for the instruction sets.</param>
        /// <returns>Returns an ErcResult containing a list of strings detailing the pointers, opcodes and base files of suitable instruction sets.</returns>
        public static List<string> GetSEHJumps(ProcessInfo info, byte[] ptrsToExclude, List<string> excludes = null)
        {
            List<string> ret = new List<string>();
            ErcResult<Dictionary<IntPtr, string>> ptrs = info.SearchAllMemoryPPR(ptrsToExclude, excludes);

            string sehFilename = GetFilePath(info.WorkingDirectory, "SEH_jumps_", ".txt");
            ret.Add("---------------------------------------------------------------------------------------");
            if (info.Author != "No_Author_Set")
            {
                ret.Add("Process Name: " + info.ProcessName + " Created by: " + info.Author + " " +
                "Total Jumps: " + ptrs.ReturnValue.Count);
            }
            else
            {
                ret.Add("Process Name: " + info.ProcessName + " Total Jumps: " + ptrs.ReturnValue.Count);
            }
            ret.Add("---------------------------------------------------------------------------------------");

            if (ptrs.Error != null)
            {
                throw new Exception("Error passed from Search_All_Memory_PPR: " + ptrs.Error.ToString());
            }
            if (info.ProcessMachineType == ERC.MachineType.I386)
            {
                ret.Add("  Address  |      Instructions     | ASLR | SafeSEH  | Rebase  | NXCompat |  OsDLL | Module Path");
            }
            else
            {
                ret.Add("      Address      |      Instructions     | ASLR | SafeSEH  | Rebase  | NXCompat |  OsDLL | Module Path");
            }
            byte[] ppr = new byte[5];
            int bytesread = 0;

            if(ptrs.ReturnValue.Count > 0)
            {
                foreach (KeyValuePair<IntPtr, string> s in ptrs.ReturnValue)
                {
                    string holder = "";
                    List<byte> opcodes = new List<byte>();
                    try
                    {
                        ErcCore.ReadProcessMemory(info.ProcessHandle, s.Key, ppr, ppr.Length, out bytesread);
                        for (int i = 0; i < 5; i++)
                        {
                            if (ppr[i].Equals(0xC3))
                            {
                                for (int j = 0; j <= i; j++)
                                {
                                    opcodes.Add(ppr[j]);
                                }
                                ERC.Utilities.OpcodeDisassembler disas = new ERC.Utilities.OpcodeDisassembler(info);
                                var result = disas.Disassemble(opcodes.ToArray());
                                if (info.ProcessMachineType == ERC.MachineType.I386)
                                {
                                    holder = result.ReturnValue.Replace(Environment.NewLine, ", ");
                                    int index = holder.IndexOf("ret");
                                    holder = holder.Substring(0, index + 3);
                                    holder = "0x" + s.Key.ToString("x8") + " | " + holder + " ";

                                }
                                else
                                {
                                    holder = result.ReturnValue.Replace(Environment.NewLine, ", ");
                                    int index = holder.IndexOf("ret");
                                    holder = holder.Substring(0, index + 3);
                                    holder = "0x" + s.Key.ToString("x16") + " | " + holder + " ";
                                }
                                opcodes.Clear();
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        throw e;
                    }
                    for (int i = 0; i < info.ModulesInfo.Count; i++)
                    {
                        if (info.ModulesInfo[i].ModulePath == s.Value)
                        {
                            holder += String.Format("| {0} |  {1}   |  {2}   |   {3}   |  {4}  |  {5} ",
                                info.ModulesInfo[i].ModuleASLR, info.ModulesInfo[i].ModuleSafeSEH,
                                info.ModulesInfo[i].ModuleRebase, info.ModulesInfo[i].ModuleNXCompat, info.ModulesInfo[i].ModuleOsDll,
                                info.ModulesInfo[i].ModulePath);
                        }
                    }
                    ret.Add(holder);
                }
            }
            else
            {
                ret.Add("No compliant POP POP RET instuctions were found.");
            }
            
            File.WriteAllLines(sehFilename, ret);
            return ret;
        }

        /// <summary>
        /// Searches all memory associated with a given process and associated modules for POP X POP X RET instructions. 
        /// Passing a list of module paths or names will exclude those modules from the search. 
        /// Similar to Search_All_Memory_PPR however provides output in an easily readable format. This version only returns unicode compliant pointers.
        /// </summary>
        /// <param name="info">The ProcessInfo object which will be searched for POP POP RET instructions.</param>
        /// <param name="aslr">Remove ASLR libraries.</param>
        /// <param name="safeseh">Remove SafeSEH libraries.</param>
        /// <param name="rebase">Remove rebasable libraries.</param>
        /// <param name="nxcompat">Remove NXCompat libraries.</param>
        /// <param name="osdll">Remove OS Dlls.</param>
        /// <param name="unwantedBytes">Addresses containing values in this byte array will be ignored.</param>
        /// <param name="protection">String containing protection level returned pointers will.</param>
        /// <returns>Returns an ErcResult containing a list of strings detailing the pointers, opcodes and base files of suitable instruction sets.</returns>
        public static List<string> GetSEHJumpsUnicode(ProcessInfo info, bool aslr = false,
            bool safeseh = false, bool rebase = false, bool nxcompat = false, bool osdll = false,
            byte[] unwantedBytes = null, string protection = "exec")
        {
            List<string> ret = new List<string>();
            List<string> excludedModules = info.CreateExcludesList(aslr, safeseh, rebase, nxcompat, osdll);
            ErcResult<Dictionary<IntPtr, string>> ptrs = info.SearchAllMemoryPPR(excludedModules);

            if (unwantedBytes != null)
            {
                List<IntPtr> p = new List<IntPtr>();
                foreach (KeyValuePair<IntPtr, string> k in ptrs.ReturnValue)
                {
                    p.Add(k.Key);
                }
                var pt = ERC.Utilities.PtrRemover.RemovePointers(info.ProcessMachineType, p, unwantedBytes);
                pt = ERC.Utilities.PtrRemover.RemovePointersProtection(info, pt, protection);

                foreach (KeyValuePair<IntPtr, string> k in ptrs.ReturnValue.ToList())
                {
                    if (!pt.Contains(k.Key))
                    {
                        ptrs.ReturnValue.Remove(k.Key);
                    }
                }
            }
            else
            {
                List<IntPtr> p = new List<IntPtr>();
                foreach (KeyValuePair<IntPtr, string> k in ptrs.ReturnValue)
                {
                    p.Add(k.Key);
                }
                var pt = ERC.Utilities.PtrRemover.RemovePointersProtection(info, p, protection);

                foreach (KeyValuePair<IntPtr, string> k in ptrs.ReturnValue.ToList())
                {
                    if (!pt.Contains(k.Key))
                    {
                        ptrs.ReturnValue.Remove(k.Key);
                    }
                }
            }

            byte[] managedArray = new byte[IntPtr.Size];
            
            foreach (KeyValuePair<IntPtr, string> entry in ptrs.ReturnValue.ToList())
            {
                managedArray = BitConverter.GetBytes((uint)entry.Key);
                if (!(managedArray[0] == 0x00 && managedArray[2] == 0x00) && !(managedArray[1] == 0x00 && managedArray[3] == 0x00))
                {
                    ptrs.ReturnValue.Remove(entry.Key);
                }
            }

            string sehFilename = GetFilePath(info.WorkingDirectory, "SEH_jumps_", ".txt");
            ret.Add("---------------------------------------------------------------------------------------");
            if (info.Author != "No_Author_Set")
            {
                ret.Add("Process Name: " + info.ProcessName + " Created by: " + info.Author + " " +
                "Total Results: " + ptrs.ReturnValue.Count);
            }
            else
            {
                ret.Add("Process Name: " + info.ProcessName + " Total Results: " + ptrs.ReturnValue.Count);
            }
            ret.Add("---------------------------------------------------------------------------------------");

            if (ptrs.Error != null)
            {
                throw new Exception("Error passed from Search_All_Memory_PPR: " + ptrs.Error.ToString());
            }
            if (info.ProcessMachineType == ERC.MachineType.I386)
            {
                ret.Add("  Address  |      Instructions     | ASLR | SafeSEH  | Rebase  | NXCompat |  OsDLL | Module Path");
            }
            else
            {
                ret.Add("      Address      |      Instructions     | ASLR | SafeSEH  | Rebase  | NXCompat |  OsDLL | Module Path");
            }
            byte[] ppr = new byte[5];
            int bytesread = 0;

            if(ptrs.ReturnValue.Count > 0)
            {
                foreach (KeyValuePair<IntPtr, string> s in ptrs.ReturnValue)
                {
                    string holder = "";
                    List<byte> opcodes = new List<byte>();
                    try
                    {
                        ErcCore.ReadProcessMemory(info.ProcessHandle, s.Key, ppr, ppr.Length, out bytesread);
                        for (int i = 0; i < 5; i++)
                        {
                            if (ppr[i].Equals(0xC3))
                            {
                                for (int j = 0; j <= i; j++)
                                {
                                    opcodes.Add(ppr[j]);
                                }
                                ERC.Utilities.OpcodeDisassembler disas = new ERC.Utilities.OpcodeDisassembler(info);
                                var result = disas.Disassemble(opcodes.ToArray());
                                if (info.ProcessMachineType == ERC.MachineType.I386)
                                {
                                    holder = result.ReturnValue.Replace(Environment.NewLine, ", ");
                                    int index = holder.IndexOf("ret");
                                    holder = holder.Substring(0, index + 3);
                                    holder = "0x" + s.Key.ToString("x8") + " | " + holder + " ";

                                }
                                else
                                {
                                    holder = result.ReturnValue.Replace(Environment.NewLine, ", ");
                                    int index = holder.IndexOf("ret");
                                    holder = holder.Substring(0, index + 3);
                                    holder = "0x" + s.Key.ToString("x16") + " | " + holder + " ";
                                }
                                opcodes.Clear();
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        throw e;
                    }

                    for (int i = 0; i < info.ModulesInfo.Count; i++)
                    {
                        if (info.ModulesInfo[i].ModulePath == s.Value)
                        {
                            holder += String.Format("| {0} |  {1}   |  {2}   |   {3}   |  {4}  |  {5} ",
                                info.ModulesInfo[i].ModuleASLR, info.ModulesInfo[i].ModuleSafeSEH,
                                info.ModulesInfo[i].ModuleRebase, info.ModulesInfo[i].ModuleNXCompat, info.ModulesInfo[i].ModuleOsDll,
                                info.ModulesInfo[i].ModulePath);
                        }
                    }
                    ret.Add(holder);
                }
            }
            else
            {
                ret.Add("No Unicode compliant POP POP RET instructions were found.");
            }
            
            File.WriteAllLines(sehFilename, ret);
            return ret;
        }
        #endregion

        #region GenerateByteArray
        /// <summary>
        /// Generates an array of all possible bytes for use when identifying bad characters. Writes the output to disk in the working directory.
        /// </summary>
        /// <param name="unwantedBytes">An array of bytes to be excluded from the final byte array</param>
        /// <param name="core">An ErcCore object</param>
        /// <returns>Returns a byte array of all possible bytes.</returns>
        public static byte[] GenerateByteArray(ErcCore core, byte[] unwantedBytes = null)
        {
            string byteFilename = GetFilePath(core.WorkingDirectory, "ByteArray_", ".bin");
            byte[] byteArray = Payloads.ByteArrayConstructor(unwantedBytes);
            FileStream fs1 = new FileStream(byteFilename, FileMode.Create, FileAccess.Write);
            fs1.Write(byteArray, 0, byteArray.Length);
            fs1.Close();

            string outputString = "---------------------------------------------------------------------------------------" + Environment.NewLine;
            if(unwantedBytes != null)
            {
                outputString += "Byte Array generated at:" + DateTime.Now + "  Omitted values: " + BitConverter.ToString(unwantedBytes).Replace("-", ", ") + Environment.NewLine;
            }
            else
            {
                outputString += "Byte Array generated at:" + DateTime.Now + Environment.NewLine;
            }
            outputString += "---------------------------------------------------------------------------------------" + Environment.NewLine;
            outputString += Environment.NewLine;
            outputString += "Raw:" + Environment.NewLine;

            string raw = "\\x" + BitConverter.ToString(byteArray).Replace("-", "\\x");
            string formattedHex = "";
            for(int i = 0; i < raw.Length; i++)
            {
                if(i == 0)
                {
                    formattedHex += raw[i];
                }
                else if(i % 48 == 0)
                {
                    formattedHex += "\n" + raw[i];
                }
                else
                {
                    formattedHex += raw[i];
                }
                
            }

            outputString += formattedHex;

            outputString += Environment.NewLine + Environment.NewLine + "C#:" + Environment.NewLine;
            string CSharp = "byte[] buf = new byte[]" + Environment.NewLine + "{" + Environment.NewLine;
            string CSharpTemp = "0x" + BitConverter.ToString(byteArray).Replace("-", ", 0x");
            string CSharpFormatted = "";
            int counter = 0;
            for(int i = 0; i < CSharpTemp.Length; i++)
            {
                if(i == 0)
                {
                    CSharpFormatted += "    " + CSharpTemp[i];
                    counter++;
                }
                else if(CSharpTemp[i] == ',' && counter % 8 == 0 && counter != 0)
                {
                    CSharpFormatted += CSharpTemp[i] + "\n    ";
                    i++;
                    counter++;
                }
                else if (CSharpTemp[i] == ',')
                {
                    counter++;
                    CSharpFormatted += CSharpTemp[i];
                }
                else
                {
                    CSharpFormatted += CSharpTemp[i];
                }
            }
            outputString += CSharp + CSharpFormatted + Environment.NewLine + "}";
            File.WriteAllText(byteFilename.Substring(0, (byteFilename.Length - 4)) + ".txt", outputString);

            return byteArray;
        }
        #endregion

        #region CompareByteArrays
        /// <summary>
        /// Compares a the values contained in a memory region to the values in the supplied byte array.
        /// </summary>
        /// <param name="info">The processInfo object that contains the memory region.</param>
        /// <param name="startAddress">The memory address to start the search at.</param>
        /// <param name="byteArray">The byte array the region will be compared against.</param>
        /// <returns>Returns a string detailing differences between the two.</returns>
        public static string[] CompareByteArrayToMemoryRegion(ProcessInfo info, IntPtr startAddress, byte[] byteArray)
        {
            List<string> output = new List<string>();
            byte[] memoryRegion = new byte[byteArray.Length];
            int bytesRead = 0;
            output.Add("                   ----------------------------------------------------");
            string fromArray  = "        From Array | ";
            string fromRegion = "From Memory Region | "; 
            ErcCore.ReadProcessMemory(info.ProcessHandle, startAddress, memoryRegion, byteArray.Length, out bytesRead);
            int counter = 0;
            for(int i = 0; i <= byteArray.Length; i++)
            {
                if (i == byteArray.Length)
                {
                    counter = 0;
                    fromArray += " | ";
                    fromRegion += " | ";
                    string newLine = "                   |                                                  | ";
                    output.Add(fromArray);
                    output.Add(fromRegion);
                    output.Add(newLine);
                    fromArray = "        From Array | ";
                    fromRegion = "From Memory Region | ";
                }
                else
                {
                    if (counter == 16)
                    {
                        counter = 0;
                        fromArray += " | ";
                        fromRegion += " | ";
                        string newLine = "                   |                                                  | ";
                        output.Add(fromArray);
                        output.Add(fromRegion);
                        output.Add(newLine);
                        fromArray = "        From Array | ";
                        fromRegion = "From Memory Region | ";
                    }
                    byte[] thisByte = new byte[1];
                    thisByte[0] = byteArray[i];
                    fromArray += BitConverter.ToString(thisByte);
                    fromArray += " ";

                    thisByte[0] = memoryRegion[i];
                    fromRegion += BitConverter.ToString(thisByte);
                    fromRegion += " ";
                    counter++;
                }
            }
            output.Add("                   ----------------------------------------------------");
            return output.ToArray();
        }
        #endregion

        #region GenerateEggHunters
        /// <summary>
        /// Generates a collection of EggHunter payloads.
        /// </summary>
        /// <param name="core">(Optional) If an ErcCore object is provided the output will also be written out to the working directory </param>
        /// <param name="tag">(Optional) If a tag is provided the payloads will be altered to search for that tag, the default tag is ERCD</param>
        /// <returns>Returns a string containing all EggHunters </returns>
        public static string GenerateEggHunters(ErcCore core = null, string tag = null)
        {
            var eggHunters = Payloads.EggHunterConstructor(tag);
            string eggFilename = "";
            if (core != null)
            {
                eggFilename = GetFilePath(core.WorkingDirectory, "Egg_Hunters_", ".txt");
            }

            string eggTag = "";
            if (tag != null)
            {
                eggTag = tag;
            }
            else
            {
                eggTag = "ERCD";
            }

            string outputString = "";
            outputString = "---------------------------------------------------------------------------------------" + Environment.NewLine;
            outputString += "EggHunters generated at:" + DateTime.Now + " Tag: " + eggTag + Environment.NewLine;
            outputString += "---------------------------------------------------------------------------------------" + Environment.NewLine;
            outputString += Environment.NewLine;
            foreach (KeyValuePair<string, byte[]> k in eggHunters)
            {
                outputString += k.Key + Environment.NewLine;
                outputString += "Raw:" + Environment.NewLine;
                string raw = "\\x" + BitConverter.ToString(k.Value).Replace("-", "\\x");
                var rawlist = Enumerable
                    .Range(0, raw.Length / 48)
                    .Select(i => raw.Substring(i * 48, 48))
                    .ToList();
                raw = string.Join(Environment.NewLine, rawlist);
                outputString += raw;

                outputString += Environment.NewLine + Environment.NewLine + "C#:" + Environment.NewLine;
                string CSharp = "byte[] buf = new byte[]" + Environment.NewLine + "{" + Environment.NewLine;
                string CSharpTemp = "0x" + BitConverter.ToString(k.Value).Replace("-", ", 0x");
                var list = Enumerable
                    .Range(0, CSharpTemp.Length / 48)
                    .Select(i => CSharpTemp.Substring(i * 48, 48))
                    .ToList();
                for (int i = 0; i < list.Count; i++)
                {
                    list[i] = "    " + list[i];
                }
                CSharp += string.Join(Environment.NewLine, list) + Environment.NewLine + "}" + Environment.NewLine + Environment.NewLine;
                outputString += CSharp;
            }
            if (core != null)
            {
                File.WriteAllText(eggFilename, outputString);
            }
            return outputString;
        }
        #endregion

        #region GenerateFindNRPTable
        /// <summary>
        /// Searches the memory of a process for a non repeating pattern.
        /// </summary>
        /// <param name="info">The ProcessInfo object of the process to be searched</param>
        /// <param name="searchType">Integer specifiying the format of the string: 0 = search term is in bytes\n1 = search term is in unicode\n2 = search term is in ASCII\n3 = Search term is in UTF8\n4 = Search term is in UTF7\n5 = Search term is in UTF32</param>
        /// <param name="extended">Whether the extended character range is to be used when searching for the non repeating pattern</param>
        /// <returns>Returns a List of strings containing the locations the repeating pattern was identified</returns>
        public static List<string> GenerateFindNRPTable(ProcessInfo info, int searchType = 0, bool extended = false)
        {
            List<string> output = new List<string>();
            string fnrpFilename = GetFilePath(info.WorkingDirectory, "Find_NRP_", ".txt");
            output.Add("---------------------------------------------------------------------------------------");
            if (info.Author != "No_Author_Set")
            {
                output.Add("Process Name: " + info.ProcessName + " Created by: " + info.Author + " FindNRP table generated at: " + DateTime.Now);
            }
            else
            {
                output.Add("Process Name: " + info.ProcessName + " FindNRP table generated at: " + DateTime.Now);
            }
            output.Add("---------------------------------------------------------------------------------------");
            var fnrp = info.FindNRP(searchType, extended);
            if (fnrp.Error != null)
            {
                output.Add(fnrp.Error.ToString());
                File.WriteAllLines(fnrpFilename, output);
                return output;
            }

            for (int i = 0; i < fnrp.ReturnValue.Count; i++)
            {
                string registerInfoText = "";
                if (fnrp.ReturnValue[i].StringOffset >= 0 && !fnrp.ReturnValue[i].Register.Contains("IP") && !fnrp.ReturnValue[i].Register.Contains("SP")
                    && !fnrp.ReturnValue[i].Register.Contains("SEH"))
                {
                    if(fnrp.ReturnValue[i].overwritten == false)
                    {
                        registerInfoText += "Register " + fnrp.ReturnValue[i].Register + " points into pattern at position " + fnrp.ReturnValue[i].StringOffset 
                            + " for " + fnrp.ReturnValue[i].BufferSize + " bytes." + " in thread " + fnrp.ReturnValue[i].ThreadID;
                        output.Add(registerInfoText);
                    }
                    else
                    {
                        registerInfoText += "Register " + fnrp.ReturnValue[i].Register + " is overwritten with pattern at position " + fnrp.ReturnValue[i].StringOffset + " in thread " + fnrp.ReturnValue[i].ThreadID;
                        output.Add(registerInfoText);
                    }
                }
                else if (fnrp.ReturnValue[i].StringOffset > 0 && fnrp.ReturnValue[i].Register.Contains("SP"))
                {
                    registerInfoText += "Register " + fnrp.ReturnValue[i].Register + " points into pattern at position " + fnrp.ReturnValue[i].StringOffset;
                    if (fnrp.ReturnValue[i].RegisterOffset > 0)
                    {
                        registerInfoText += " at " + fnrp.ReturnValue[i].Register + " +" + fnrp.ReturnValue[i].RegisterOffset + " length of pattern found is " +
                            fnrp.ReturnValue[i].BufferSize + " characters" + " in thread " + fnrp.ReturnValue[i].ThreadID;
                        output.Add(registerInfoText);
                    }
                    else
                    {
                        registerInfoText += " length of pattern found is " + fnrp.ReturnValue[i].BufferSize + " characters" + " in thread " + fnrp.ReturnValue[i].ThreadID;
                        output.Add(registerInfoText);
                    }
                }
                else if (fnrp.ReturnValue[i].StringOffset > 0 && fnrp.ReturnValue[i].Register.Contains("IP"))
                {
                    registerInfoText += "Register " + fnrp.ReturnValue[i].Register + " is overwritten with pattern at position " + fnrp.ReturnValue[i].StringOffset + " in thread " + fnrp.ReturnValue[i].ThreadID;
                    output.Add(registerInfoText);
                }
                else if (fnrp.ReturnValue[i].StringOffset > 0 && fnrp.ReturnValue[i].Register.Contains("SEH"))
                {
                    registerInfoText += "SEH register is overwritten with pattern at position " + fnrp.ReturnValue[i].StringOffset + " in thread " + fnrp.ReturnValue[i].ThreadID;
                    output.Add(registerInfoText);
                }
            }

            output = output.Distinct().ToList();
            File.WriteAllLines(fnrpFilename, output);
            return output;
        }
        #endregion

        #region RopChainGadgets32
        /// <summary>
        /// Produces output files containing information about the associated ROP chain, produces files containing ROP gadgets and the associated ROP chain.
        /// </summary>
        /// <param name="rcg">The ROP chain generator object</param>
        /// <returns>Returns a List of strings</returns>
        public static List<string> RopChainGadgets32(RopChainGenerator32 rcg)
        {
            string output = "";
            List<string> totalGadgets = new List<string>();
            List<string> curatedGadgets = new List<string>();
            string totalGadgetsPath = GetFilePath(rcg.RcgInfo.WorkingDirectory, "total_gadgest_", ".txt");
            string curatedGadgetsPath = GetFilePath(rcg.RcgInfo.WorkingDirectory, "curated_gadgest_", ".txt");
            string ropChainPath = GetFilePath(rcg.RcgInfo.WorkingDirectory, "rop_chain_", ".txt");

            output += "-------------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;
            if (rcg.RcgInfo.Author != "No_Author_Set")
            {
                output += "Process Name: " + rcg.RcgInfo.ProcessName + " Gadget list created by: " + rcg.RcgInfo.Author + " " + Environment.NewLine;
            }
            else
            {
                output += "Process Name: " + rcg.RcgInfo.ProcessName + " ROP chain gadget list" + Environment.NewLine;
            }

            if (rcg.RcgInfo.ProcessMachineType == MachineType.I386)
            {
                totalGadgets.Add("pushEax: ");
                curatedGadgets.Add("pushEax: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEax)
                {
                    if(k.Value.Contains("push eax") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if(!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                        
                }
                totalGadgets.Add("pushEbx: ");
                curatedGadgets.Add("pushEbx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEbx)
                {
                    if (k.Value.Contains("push ebx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("pushEcx: ");
                curatedGadgets.Add("pushEcx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEcx)
                {
                    if (k.Value.Contains("push ecx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("pushEdx: ");
                curatedGadgets.Add("pushEdx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEdx)
                {
                    if (k.Value.Contains("push edx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("pushEsp: ");
                curatedGadgets.Add("pushEsp: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEsp)
                {
                    if (k.Value.Contains("push esp") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("pushEbp: ");
                curatedGadgets.Add("pushEbp: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEbp)
                {
                    if (k.Value.Contains("push ebp") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("pushEsi: ");
                curatedGadgets.Add("pushEsi: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEsi)
                {
                    if (k.Value.Contains("push esi") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("pushEdi: ");
                curatedGadgets.Add("pushEdi: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEdi)
                {
                    if (k.Value.Contains("push edi") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("JmpEsp: ");
                curatedGadgets.Add("JmpEsp: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.jmpEsp)
                {
                    if (k.Value.Contains("jmp esp"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("CallEsp: ");
                curatedGadgets.Add("CallEsp: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.callEsp)
                {
                    if (k.Value.Contains("call esp"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("xorEax: ");
                curatedGadgets.Add("xorEax: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.xorEax)
                {
                    if (k.Value.Contains("xor eax") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("xorEbx: ");
                curatedGadgets.Add("xorEbx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.xorEbx)
                {
                    if (k.Value.Contains("xor ebx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("xorEcx: ");
                curatedGadgets.Add("xorEcx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.xorEcx)
                {
                    if (k.Value.Contains("xor ecx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("xorEdx: ");
                curatedGadgets.Add("xorEdx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.xorEdx)
                {
                    if (k.Value.Contains("xor edx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("xorEsi: ");
                curatedGadgets.Add("xorEsi: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.xorEsi)
                {
                    if (k.Value.Contains("xor esi") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("xorEdi: ");
                curatedGadgets.Add("xorEdi: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.xorEdi)
                {
                    if (k.Value.Contains("xor edi") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("popEax: ");
                curatedGadgets.Add("popEax: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEax)
                {
                    if (k.Value.Contains("pop eax") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("popEbx: ");
                curatedGadgets.Add("popEbx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEbx)
                {
                    if (k.Value.Contains("pop ebx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("popEcx: ");
                curatedGadgets.Add("popEcx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEcx)
                {
                    if (k.Value.Contains("pop ecx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("popEdx: ");
                curatedGadgets.Add("popEdx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEdx)
                {
                    if (k.Value.Contains("pop edx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("popEsp: ");
                curatedGadgets.Add("popEsp: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEsp)
                {
                    if (k.Value.Contains("pop esp") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("popEbp: ");
                curatedGadgets.Add("popEbp: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEbp)
                {
                    if (k.Value.Contains("pop ebp") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("popEsi: ");
                curatedGadgets.Add("popEsi: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEsi)
                {
                    if (k.Value.Contains("pop esi") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("popEdi: ");
                curatedGadgets.Add("popEdi: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEdi)
                {
                    if (k.Value.Contains("pop edo") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("incEax: ");
                curatedGadgets.Add("incEax: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEax)
                {
                    if (k.Value.Contains("inc eax") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("decEax: ");
                curatedGadgets.Add("decEax: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEax)
                {
                    if (k.Value.Contains("dec eax") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("incEbx: ");
                curatedGadgets.Add("incEbx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEbx)
                {
                    if (k.Value.Contains("inc ebx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("decEbx: ");
                curatedGadgets.Add("decEbx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEbx)
                {
                    if (k.Value.Contains("dec ebx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("incEcx: ");
                curatedGadgets.Add("incEcx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEcx)
                {
                    if (k.Value.Contains("inc ecx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("decEcx: ");
                curatedGadgets.Add("decEcx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEcx)
                {
                    if (k.Value.Contains("dec ecx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("incEdx: ");
                curatedGadgets.Add("incEdx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEdx)
                {
                    if (k.Value.Contains("inc edx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("decEdx: ");
                curatedGadgets.Add("decEdx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEdx)
                {
                    if (k.Value.Contains("dec edx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("incEbp: ");
                curatedGadgets.Add("incEbp: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEbp)
                {
                    if (k.Value.Contains("inc ebp") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }

                }
                totalGadgets.Add("decEbp: ");
                curatedGadgets.Add("decEbp: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEbp)
                {
                    if (k.Value.Contains("dec ebp") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("incEsp: ");
                curatedGadgets.Add("incEsp: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEsp)
                {
                    if (k.Value.Contains("inc esp") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("decEsp: ");
                curatedGadgets.Add("decEsp: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEsp)
                {
                    if (k.Value.Contains("dec esp") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("incEsi: ");
                curatedGadgets.Add("incEsi: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEsi)
                {
                    if (k.Value.Contains("inc esi") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("decEsi: ");
                curatedGadgets.Add("decEsi: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEsi)
                {
                    if (k.Value.Contains("dec esi") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("incEdi: ");
                curatedGadgets.Add("incEdi: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEdi)
                {
                    if (k.Value.Contains("inc edi") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("decEdi: ");
                curatedGadgets.Add("decEdi: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEdi)
                {
                    if (k.Value.Contains("dec edi") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("Add: ");
                curatedGadgets.Add("Add: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.add)
                {
                    if (k.Value.Contains("add") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("Sub: ");
                curatedGadgets.Add("Sub: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.sub)
                {
                    if (k.Value.Contains("sub") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("Mov: ");
                curatedGadgets.Add("Mov: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.mov)
                {
                    if (k.Value.Contains("mov") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("And: ");
                curatedGadgets.Add("And: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.and)
                {
                    if (k.Value.Contains("and") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
            }
            totalGadgets.Add("pushad: ");
            curatedGadgets.Add("pushad: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushad)
            {
                if (k.Value.Contains("pushad") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                    }
                }
            }
            File.WriteAllLines(totalGadgetsPath, totalGadgets);
            File.WriteAllLines(curatedGadgetsPath, curatedGadgets);


            List<string> ropChain = new List<string>();
            foreach(Tuple<byte[], string> k in rcg.VirtualAllocChain)
            {
                ropChain.Add(BitConverter.ToString(k.Item1).Replace("-", "\\x") + " | " + k.Item2);
            }
            File.WriteAllLines(ropChainPath, ropChain);
 
            return totalGadgets;
        }
        #endregion

        #region RopChainGadgets64
        /// <summary>
        /// Produces output files containing information about the associated ROP chain, produces files containing ROP gadgets and the associated ROP chain.
        /// </summary>
        /// <param name="rcg">The ROP chain generator object</param>
        /// <returns>Returns a List of strings</returns>
        public static List<string> RopChainGadgets64(RopChainGenerator64 rcg)
        {
            string output = "";
            List<string> totalGadgets = new List<string>();
            List<string> curatedGadgets = new List<string>();
            string totalGadgetsPath = GetFilePath(rcg.RcgInfo.WorkingDirectory, "total_gadgest_64_", ".txt");
            string curatedGadgetsPath = GetFilePath(rcg.RcgInfo.WorkingDirectory, "curated_gadgest_64_", ".txt");
            string ropChainPath = GetFilePath(rcg.RcgInfo.WorkingDirectory, "rop_chain_64_", ".txt");

            output += "-------------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;
            if (rcg.RcgInfo.Author != "No_Author_Set")
            {
                output += "Process Name: " + rcg.RcgInfo.ProcessName + " Gadget list created by: " + rcg.RcgInfo.Author + " " + Environment.NewLine;
            }
            else
            {
                output += "Process Name: " + rcg.RcgInfo.ProcessName + " ROP chain gadget list" + Environment.NewLine;
            }

            totalGadgets.Add("pushRax: ");
            curatedGadgets.Add("pushRax: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.pushRax)
            {
                if (k.Value.Contains("push rax") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }

            }
            totalGadgets.Add("pushRbx: ");
            curatedGadgets.Add("pushRbx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.pushRbx)
            {
                if (k.Value.Contains("push rbx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("pushRcx: ");
            curatedGadgets.Add("pushRcx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.pushRcx)
            {
                if (k.Value.Contains("push rcx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("pushRdx: ");
            curatedGadgets.Add("pushRdx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.pushRdx)
            {
                if (k.Value.Contains("push rdx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("pushRsp: ");
            curatedGadgets.Add("pushRsp: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.pushRsp)
            {
                if (k.Value.Contains("push rsp") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("pushRbp: ");
            curatedGadgets.Add("pushRbp: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.pushRbp)
            {
                if (k.Value.Contains("push rbp") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("pushRsi: ");
            curatedGadgets.Add("pushRsi: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.pushRsi)
            {
                if (k.Value.Contains("push rsi") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("pushRdi: ");
            curatedGadgets.Add("pushRdi: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.pushRdi)
            {
                if (k.Value.Contains("push rdi") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("JmpRsp: ");
            curatedGadgets.Add("JmpRsp: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.jmpRsp)
            {
                if (k.Value.Contains("jmp rsp"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("CallRsp: ");
            curatedGadgets.Add("CallRsp: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.callRsp)
            {
                if (k.Value.Contains("call rsp"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("xorEax: ");
            curatedGadgets.Add("xorEax: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.xorRax)
            {
                if (k.Value.Contains("xor eax") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("xorRbx: ");
            curatedGadgets.Add("xorRbx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.xorRbx)
            {
                if (k.Value.Contains("xor rbx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("xorRcx: ");
            curatedGadgets.Add("xorRcx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.xorRcx)
            {
                if (k.Value.Contains("xor rcx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("xorRdx: ");
            curatedGadgets.Add("xorRdx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.xorRdx)
            {
                if (k.Value.Contains("xor rdx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("xorRsi: ");
            curatedGadgets.Add("xorRsi: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.xorRsi)
            {
                if (k.Value.Contains("xor rsi") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("xorRdi: ");
            curatedGadgets.Add("xorRdi: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.xorRdi)
            {
                if (k.Value.Contains("xor rdi") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("popRax: ");
            curatedGadgets.Add("popRax: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.popRax)
            {
                if (k.Value.Contains("pop rax") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("popRbx: ");
            curatedGadgets.Add("popRbx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.popRbx)
            {
                if (k.Value.Contains("pop rbx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("popRcx: ");
            curatedGadgets.Add("popRcx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.popRcx)
            {
                if (k.Value.Contains("pop rcx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("popRdx: ");
            curatedGadgets.Add("popRdx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.popRdx)
            {
                if (k.Value.Contains("pop rdx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("popRsp: ");
            curatedGadgets.Add("popRsp: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.popRsp)
            {
                if (k.Value.Contains("pop rsp") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("popRbp: ");
            curatedGadgets.Add("popRbp: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.popRbp)
            {
                if (k.Value.Contains("pop rbp") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("popRsi: ");
            curatedGadgets.Add("popRsi: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.popRsi)
            {
                if (k.Value.Contains("pop rsi") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("popRdi: ");
            curatedGadgets.Add("popRdi: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.popRdi)
            {
                if (k.Value.Contains("pop rdi") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("incRax: ");
            curatedGadgets.Add("incRax: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.incRax)
            {
                if (k.Value.Contains("inc rax") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("decRax: ");
            curatedGadgets.Add("decRax: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.decRax)
            {
                if (k.Value.Contains("dec eax") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("incRbx: ");
            curatedGadgets.Add("incRbx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.incRbx)
            {
                if (k.Value.Contains("inc rbx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("decRbx: ");
            curatedGadgets.Add("decRbx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.decRbx)
            {
                if (k.Value.Contains("dec ebx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("incRcx: ");
            curatedGadgets.Add("incRcx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.incRcx)
            {
                if (k.Value.Contains("inc rcx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("decRcx: ");
            curatedGadgets.Add("decRcx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.decRcx)
            {
                if (k.Value.Contains("dec ecx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("incRdx: ");
            curatedGadgets.Add("incRdx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.incRdx)
            {
                if (k.Value.Contains("inc rdx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("decRdx: ");
            curatedGadgets.Add("decRdx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.decRdx)
            {
                if (k.Value.Contains("dec edx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("incRbp: ");
            curatedGadgets.Add("incRbp: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.incRbp)
            {
                if (k.Value.Contains("inc rbp") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }

            }
            totalGadgets.Add("decRbp: ");
            curatedGadgets.Add("decRbp: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.decRbp)
            {
                if (k.Value.Contains("dec ebp") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("incRsp: ");
            curatedGadgets.Add("incRsp: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.incRsp)
            {
                if (k.Value.Contains("inc rsp") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("decRsp: ");
            curatedGadgets.Add("decRsp: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.decRsp)
            {
                if (k.Value.Contains("dec esp") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("incRsi: ");
            curatedGadgets.Add("incRsi: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.incRsi)
            {
                if (k.Value.Contains("inc rsi") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("decRsi: ");
            curatedGadgets.Add("decRsi: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.decRsi)
            {
                if (k.Value.Contains("dec esi") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("incRdi: ");
            curatedGadgets.Add("incRdi: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.incRdi)
            {
                if (k.Value.Contains("inc rdi") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("decRdi: ");
            curatedGadgets.Add("decRdi: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.decRdi)
            {
                if (k.Value.Contains("dec edi") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("Add: ");
            curatedGadgets.Add("Add: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.add)
            {
                if (k.Value.Contains("add") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("Mov: ");
            curatedGadgets.Add("Mov: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.mov)
            {
                if (k.Value.Contains("mov") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            
            File.WriteAllLines(totalGadgetsPath, totalGadgets);
            File.WriteAllLines(curatedGadgetsPath, curatedGadgets);

            List<string> ropChain = new List<string>();
            foreach (Tuple<byte[], string> k in rcg.VirtualAllocChain)
            {
                ropChain.Add(BitConverter.ToString(k.Item1).Replace("-", "\\x") + " | " + k.Item2);
            }
            File.WriteAllLines(ropChainPath, ropChain);
            return totalGadgets;
        }

        private static string ConvertRopElementToString(Tuple<IntPtr, string> element)
        {
            string ret = "0x" + element.Item1.ToString("X16") + " | " + element.Item2;
            return ret;
        }
        #endregion

        #region Assemble Opcodes
        /// <summary>
        /// Converts a collection of instructions into the associated opcodes.
        /// </summary>
        /// <param name="instructions">An array containing either x86 or x64 instructions.</param>
        /// <param name="machine">Uint representing the machine type (x86 = 0, x64 = 1)</param>
        /// <returns>Returns null if the method fails.</returns>
        public static string[] AssembleOpcodes(string[] instructions, uint machine)
        {
            string[] opcodeArray = null;
            MachineType mt;
            if(machine == 0)
            {
                mt = MachineType.I386;
            }
            else if(machine == 1)
            {
                mt = MachineType.x64;
            }
            else
            {
                throw new ERCException("Invalid machine type provided. Value provided = " + machine + ". Uint 0 = x86, 1 = x64");
            }
            var instructionsList = instructions.ToList();
            var asmResult = OpcodeAssembler.AssembleOpcodes(instructionsList, mt);
            if (asmResult.Error != null)
            {
                throw asmResult.Error;
            }
            string opcodes = BitConverter.ToString(asmResult.ReturnValue).Replace("-", " ");
            opcodeArray = opcodes.Split(' ');
            return opcodeArray;
        }

        /// <summary>
        /// Converts a collection of instructions into the associated opcodes.
        /// </summary>
        /// <param name="instructions">An array containing either x86 or x64 instructions.</param>
        /// <param name="machine">MachineType of the instruction set to be assembled.</param>
        /// <returns>Returns null if the method fails.</returns>
        public static string[] AssembleOpcodes(string[] instructions, MachineType machine)
        {
            string[] opcodeArray = null;
            if(machine != MachineType.I386 && machine != MachineType.x64)
            {
                throw new ERCException("Invalid machine type provided.");
            }
            var instructionsList = instructions.ToList();
            var asmResult = OpcodeAssembler.AssembleOpcodes(instructionsList, machine);
            if(asmResult.Error != null)
            {
                throw asmResult.Error;
            }
            string opcodes = BitConverter.ToString(asmResult.ReturnValue).Replace("-", " ");
            opcodeArray = opcodes.Split(' ');
            return opcodeArray;
        }
        #endregion

        #region Disassemble Opcodes
        /// <summary>
        /// Converts a collection of opcodes into the associated instructions.
        /// </summary>
        /// <param name="opcodes">An array containing either x86 or x64 opcodes.</param>
        /// <param name="machine">Uint representing the machine type (x86 = 0, x64 = 1)</param>
        /// <returns>Returns null if the method fails.</returns>
        public static string[] DisassembleOpcodes(byte[] opcodes, uint machine)
        {
            string[] instructionArray = null;
            MachineType mt;
            if (machine == 0)
            {
                mt = MachineType.I386;
            }
            else if (machine == 1)
            {
                mt = MachineType.x64;
            }
            else
            {
                throw new ERCException("Invalid machine type provided. Value provided = " + machine + ". Uint 0 = x86, 1 = x64");
            }
            
            var disassembledInstructions = OpcodeDisassembler.Disassemble(opcodes, mt);
            if (disassembledInstructions.Error != null)
            {
                throw disassembledInstructions.Error;
            }
            instructionArray = disassembledInstructions.ReturnValue.Split('\n');
            return instructionArray;
        }

        /// <summary>
        /// Converts a collection of opcodes into the associated instructions.
        /// </summary>
        /// <param name="opcodes">An array containing either x86 or x64 opcodes.</param>
        /// <param name="machine">MachineType of the instruction set to be assembled.</param>
        /// <returns>Returns null if the method fails.</returns>
        public static string[] DisassembleOpcodes(byte[] opcodes, MachineType machine)
        {
            string[] instructionArray = null;
            if (machine != MachineType.I386 && machine != MachineType.x64)
            {
                throw new ERCException("Invalid machine type provided.");
            }
            var disassembledInstructions = OpcodeDisassembler.Disassemble(opcodes, machine);
            if(disassembledInstructions.Error != null)
            {
                throw disassembledInstructions.Error;
            }
            instructionArray = disassembledInstructions.ReturnValue.Split('\n');
            return instructionArray;
        }
        #endregion

        #region StringToByteArray
        /// <summary>
        /// Converts a string of hex characters to a byte array of the associated values.
        /// </summary>
        /// <param name="hex">A string containing hex characters.</param>
        /// <returns>Returns a byte array.</returns>
        private static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => System.Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
        #endregion

        #region Dump Memory
        /// <summary>
        /// Reads a set of bytes from process memory and provides a string contianing the results.
        /// </summary>
        /// <param name="info">ProcessInfo object</param>
        /// <param name="startAddress">The address to start reading from.</param>
        /// <param name="length">The number of bytes to read.</param>
        /// <returns>A string containing the bytes read from memroy</returns>
        public static ErcResult<string> DumpMemory(ProcessInfo info, IntPtr startAddress, int length)
        {
            string dumpFilename = GetFilePath(info.WorkingDirectory, "MemoryDump_", ".txt");
            ErcResult<byte[]> result = info.DumpMemoryRegion(startAddress, length);
            ErcResult<string> output = new ErcResult<string>(info.ProcessCore);

            int bytesPerLine = 0;

            if (info.ProcessMachineType == MachineType.I386)
            {
                bytesPerLine = 8;
            }
            else if (info.ProcessMachineType == MachineType.x64)
            {
                bytesPerLine = 16;
            }
            else
            {
                output.Error = new ERCException("Unsupported MachineType. MachineType must be I386 or x64");
                output.ReturnValue = "ERROR: Check exception.";
                return output;
            }

            output.ReturnValue += "----------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;
            output.ReturnValue += "Contents of memory region 0x" + startAddress.ToString("X" + bytesPerLine) + " - 0x" + (startAddress + length).ToString("X" + bytesPerLine) 
                + " Created at: " + DateTime.Now + ". Created by: " + info.Author + Environment.NewLine;
            output.ReturnValue += "----------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;

            for(int i = 0; i < result.ReturnValue.Length; i++)
            {
                if(i == 0)
                {
                    output.ReturnValue += startAddress.ToString("X" + bytesPerLine) + ": " + result.ReturnValue[i].ToString("X2") + " ";
                }
                else if(i % bytesPerLine == 0)
                {
                    output.ReturnValue += Environment.NewLine;
                    output.ReturnValue += (startAddress + ((i / bytesPerLine) * bytesPerLine)).ToString("X" + bytesPerLine) + ": " + result.ReturnValue[i].ToString("X2") + " ";
                }
                else
                {
                    output.ReturnValue += result.ReturnValue[i].ToString("X2") + " ";
                }
            }

            File.WriteAllText(dumpFilename, output.ReturnValue);
            return output;
        }
        #endregion
    }
}
