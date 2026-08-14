using ERC.Utilities;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Convert = ERC.Utilities.Convert;

using ERC.Native;
namespace ERC
{
    /// <summary> Provides output in various human readable formats of data from the library. </summary>
    public static partial class DisplayOutput
    {

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
                info.Output.WriteText(processFilename, information);
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
                info.Output.WriteText(threadFilename, information);
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
                info.Output.WriteText(modFilename, modOutput);
            }
            return modOutput;
        }
        #endregion
    }
}
