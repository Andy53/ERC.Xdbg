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
        /// <param name="protection">String array containing protection level returned pointers will.</param>
        /// <returns></returns>
        public static string[] SearchMemory(ProcessInfo info, int searchType, string searchString, bool aslr = false, 
            bool safeseh = false, bool rebase = false, bool nxcompat = false, bool osdll = false, 
            byte[]? unwantedBytes = null, string protection = "exec")
        {
            List<string> excludedModules = info.CreateExcludesList(aslr, safeseh, rebase, nxcompat, osdll);
            Dictionary<IntPtr, string> result = new Dictionary<IntPtr, string>();

            if (searchType == 0)
            {
                byte[] searchBytes = StringToByteArray(searchString.Replace(" ", ""));
                result = info.SearchMemory(searchType, searchBytes, null, excludedModules).ReturnValue;
            }
            else
            {
                result = info.SearchMemory(searchType, null, searchString, excludedModules).ReturnValue;
            }

            if (unwantedBytes != null)
            {
                List<IntPtr> p = new List<IntPtr>();
                foreach (KeyValuePair<IntPtr, string> k in result)
                {
                    p.Add(k.Key);
                }
                List<string> outText = new List<string>();

                var pt = PtrRemover.RemovePointers(info.ProcessMachineType, p, unwantedBytes);
                pt = PtrRemover.RemovePointersProtection(info, pt, protection);

                foreach (KeyValuePair<IntPtr, string> k in result.ToList())
                {
                    if (!pt.Contains(k.Key))
                    {
                        result.Remove(k.Key);
                    }
                }
            }
            else
            {
                List<IntPtr> p = new List<IntPtr>();
                foreach (KeyValuePair<IntPtr, string> k in result)
                {
                    p.Add(k.Key);
                }
                var pt = PtrRemover.RemovePointersProtection(info, p, protection);

                foreach (KeyValuePair<IntPtr, string> k in result.ToList())
                {
                    if (!pt.Contains(k.Key))
                    {
                        result.Remove(k.Key);
                    }
                }
            }

            List<string> output = new List<string>();
            output.Add(String.Format("List created on {0} by {1}. Search string: {2}", DateTime.Now, info.Author, searchString));
            output.Add("----------------------------------------------------------------------");
            if (info.ProcessMachineType == MachineType.I386)
            {
                output.Add("  Address  | ASLR | SafeSEH | Rebase | NXCompat | OsDLL | Module Path");
            }
            else
            {
                output.Add("      Address      | ASLR | SafeSEH  | Rebase | NXCompat | OsDLL | Module Path");
            }
            output.Add("----------------------------------------------------------------------");
            foreach (KeyValuePair<IntPtr, string> v in result)
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
            return output.ToArray();
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
        /// <param name="protection">String array containing protection level returned pointers will.</param>
        /// <returns></returns>
        public static string[] SearchModules(ProcessInfo info, int searchType, string searchString, bool aslr = false,
            bool safeseh = false, bool rebase = false, bool nxcompat = false, bool osdll = false,
            byte[]? unwantedBytes = null, List<string>? modules = null, string protection = "exec")
        {
            List<string> excludedModules = info.CreateExcludesList(aslr, safeseh, rebase, nxcompat, osdll);
            Dictionary<IntPtr, string> result = new Dictionary<IntPtr, string>();

            if (searchType == 0)
            {
                byte[] searchBytes = StringToByteArray(searchString.Replace(" ", ""));
                result = info.SearchModules(searchType, unwantedBytes, searchBytes, null, modules, excludedModules).ReturnValue;
            }
            else
            {
                result = info.SearchModules(searchType, unwantedBytes, null, searchString, modules, excludedModules).ReturnValue;
            }

            if (unwantedBytes != null)
            {
                List<IntPtr> p = new List<IntPtr>();
                foreach (KeyValuePair<IntPtr, string> k in result)
                {
                    p.Add(k.Key);
                }
                var pt = PtrRemover.RemovePointers(info.ProcessMachineType, p, unwantedBytes);
                pt = PtrRemover.RemovePointersProtection(info, pt, protection);

                foreach (KeyValuePair<IntPtr, string> k in result.ToList())
                {
                    if (!pt.Contains(k.Key))
                    {
                        result.Remove(k.Key);
                    }
                }
            }
            else
            {
                List<IntPtr> p = new List<IntPtr>();
                foreach (KeyValuePair<IntPtr, string> k in result)
                {
                    p.Add(k.Key);
                }
                var pt = PtrRemover.RemovePointersProtection(info, p, protection);

                foreach (KeyValuePair<IntPtr, string> k in result.ToList())
                {
                    if (!pt.Contains(k.Key))
                    {
                        result.Remove(k.Key);
                    }
                }
            }
            List<string> output = new List<string>();
            output.Add(String.Format("List created on {0} by {1}. Search string: {2}", DateTime.Now, info.Author, searchString));
            output.Add("----------------------------------------------------------------------");
            if (info.ProcessMachineType == MachineType.I386)
            {
                output.Add("  Address  | ASLR | SafeSEH | Rebase | NXCompat | OsDLL | Module Path");
            }
            else
            {
                output.Add("      Address      | ASLR | SafeSEH  | Rebase | NXCompat | OsDLL | Module Path");
            }
            output.Add("----------------------------------------------------------------------");
            foreach (KeyValuePair<IntPtr, string> v in result)
            {
                for (int i = 0; i < info.ModulesInfo.Count; i++)
                {
                    if (info.ProcessMachineType == MachineType.I386)
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
            return output.ToArray();
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
        /// <returns>Returns an array of strings detailing the pointers, opcodes and base files of suitable instruction sets.</returns>
        public static string[] GetSEHJumps(ProcessInfo info, bool aslr = false,
            bool safeseh = false, bool rebase = false, bool nxcompat = false, bool osdll = false,
            byte[]? unwantedBytes = null, string protection = "exec")
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
                        info.Native.ReadProcessMemory(info.ProcessHandle, s.Key, ppr, ppr.Length, out bytesread);
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
                    catch (Exception)
                    {
                        throw;   // "throw;" keeps the original stack trace; "throw e;" reset it
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
            
            info.Output.WriteLines(sehFilename, ret);
            return ret.ToArray();
        }

        /// <summary>
        /// Searches all memory associated with a given process and associated modules for POP X POP X RET instructions. 
        /// Passing a list of module paths or names will exclude those modules from the search. 
        /// Similar to Search_All_Memory_PPR however provides output in an easily readable format.
        /// </summary>
        /// <param name="info">The ProcessInfo object which will be searched for POP POP RET instructions</param>
        /// <param name="ptrsToExclude">Ptrs containing these byte values will be discarded.</param>
        /// <param name="excludes">Modules to be ignored when searching for the instruction sets.</param>
        /// <returns>Returns an array of strings detailing the pointers, opcodes and base files of suitable instruction sets.</returns>
        public static string[] GetSEHJumps(ProcessInfo info, byte[] ptrsToExclude, List<string>? excludes = null)
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
                        info.Native.ReadProcessMemory(info.ProcessHandle, s.Key, ppr, ppr.Length, out bytesread);
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
                    catch (Exception)
                    {
                        throw;   // "throw;" keeps the original stack trace; "throw e;" reset it
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
            
            info.Output.WriteLines(sehFilename, ret);
            return ret.ToArray();
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
        /// <returns>Returns an array of strings detailing the pointers, opcodes and base files of suitable instruction sets.</returns>
        public static string[] GetSEHJumpsUnicode(ProcessInfo info, bool aslr = false,
            bool safeseh = false, bool rebase = false, bool nxcompat = false, bool osdll = false,
            byte[]? unwantedBytes = null, string protection = "exec")
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
                        info.Native.ReadProcessMemory(info.ProcessHandle, s.Key, ppr, ppr.Length, out bytesread);
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
                    catch (Exception)
                    {
                        throw;   // "throw;" keeps the original stack trace; "throw e;" reset it
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
            
            info.Output.WriteLines(sehFilename, ret);
            return ret.ToArray();
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
        public static string[] GenerateFindNRPTable(ProcessInfo info, int searchType = 0, bool extended = false)
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
                info.Output.WriteLines(fnrpFilename, output);
                return output.ToArray();
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
            info.Output.WriteLines(fnrpFilename, output);
            return output.ToArray();
        }
        #endregion
    }
}
