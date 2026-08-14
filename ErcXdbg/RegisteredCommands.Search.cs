using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text.RegularExpressions;
using Managed.x64dbg.SDK;
using System.Management;
using System.Threading;
using ERC.Cli;

namespace ErcXdbg
{
    /// <summary>
    /// The commands for searching memory.
    /// </summary>
    /// <remarks>
    /// Searching process memory and modules, and the searches built on top of them.
    ///
    /// One part of RegisteredCommands, which was a single 2,100 line file holding
    /// every command. Splitting it by command group leaves the dispatcher in
    /// RegisteredCommands.cs and each group beside the others it shares helpers with.
    /// </remarks>
    public static partial class RegisteredCommands
    {
        private static void SearchMemory(ERC.ProcessInfo info, List<string> parameters, SessionState session)
        {
            // Strip the switches, keeping the positional arguments.
            //
            // This was a forward loop calling parameters.Remove(parameters[i]),
            // which shifted the next element into the current index and skipped it,
            // so a switch immediately following another switch survived and was then
            // treated as a positional argument. The same loop was copy-pasted into
            // nearly every command handler.
            parameters.RemoveAll(p => p.Contains("--"));

            int searchType = 0;
            string searchString = "";

            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i] == "0" || parameters[i] == "1" || parameters[i] == "2" ||
                    parameters[i] == "3" || parameters[i] == "4" || parameters[i] == "5")
                {
                    searchType = Int32.Parse(parameters[i]);
                    parameters.Remove(parameters[i]);
                    i--;
                }
            }

            searchString = string.Join("", parameters);

            var output = ERC.DisplayOutput.SearchMemory(info, searchType, searchString, session.Aslr, session.SafeSeh, session.Rebase, session.NxCompat,
                session.OsDll, session.Bytes, session.Protection);
            foreach(string s in output)
            {
                PLog.WriteLine(s);
            }
        }

        private static void SearchModules(ERC.ProcessInfo info, List<string> parameters, SessionState session)
        {
            // Strip the switches, keeping the positional arguments.
            //
            // This was a forward loop calling parameters.Remove(parameters[i]),
            // which shifted the next element into the current index and skipped it,
            // so a switch immediately following another switch survived and was then
            // treated as a positional argument. The same loop was copy-pasted into
            // nearly every command handler.
            parameters.RemoveAll(p => p.Contains("--"));

            int searchType = 0;
            string searchString = "";

            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i] == "0" || parameters[i] == "1" || parameters[i] == "2" ||
                    parameters[i] == "3" || parameters[i] == "4" || parameters[i] == "5")
                {
                    searchType = Int32.Parse(parameters[i]);
                    parameters.Remove(parameters[i]);
                    i--;
                }
            }

            // Nulled below to mean "no module filter", which is what SearchModules expects.
            List<string>? includedModules = new List<string>();

            foreach(string s in parameters)
            {
                bool hex = true;
                foreach(char c in s)
                {
                    if(!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F'))
                    {
                        hex = false;
                    }
                }
                if(hex == false)
                {
                    includedModules.Add(s);
                    parameters.Remove(s);
                }
            }

            if (includedModules.Count <= 0)
            {
                includedModules = null;
            }

            searchString = string.Join("", parameters);
            var output = ERC.DisplayOutput.SearchModules(info, searchType, searchString, session.Aslr, session.SafeSeh, session.Rebase, session.NxCompat,
                session.OsDll, session.Bytes, includedModules, session.Protection);
            foreach (string s in output)
            {
                PLog.WriteLine(s);
            }
        }

        private static void DumpMemory(ERC.ProcessInfo info, List<string> parameters, SessionState session)
        {
            // Strip the switches, keeping the positional arguments.
            //
            // This was a forward loop calling parameters.Remove(parameters[i]),
            // which shifted the next element into the current index and skipped it,
            // so a switch immediately following another switch survived and was then
            // treated as a positional argument. The same loop was copy-pasted into
            // nearly every command handler.
            parameters.RemoveAll(p => p.Contains("--"));

            if(parameters.Count != 2)
            {
                PrintHelp("Incorrect parameters passed to DumpMemory. 2 values must be passed, first being start address, second being length.");
            }

            long[] values = new long[2];

            for(int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].StartsWith("0x") || parameters[i].StartsWith("x")
                || parameters[i].StartsWith("\\x") || parameters[i].StartsWith("X"))
                {
                    parameters[i] = parameters[i].Replace("0x", "");
                    parameters[i] = parameters[i].Replace("\\x", "");
                    parameters[i] = parameters[i].Replace("X", "");
                    parameters[i] = parameters[i].Replace("x", "");
                }
                values[i] = System.Convert.ToInt64(parameters[i], 16);
            }

            PLog.WriteLine(ERC.DisplayOutput.DumpMemory(info, (IntPtr)values[0], (int)values[1]));
        }

        private static void SEH(List<string> parameters, ERC.ProcessInfo info, SessionState session) 
        {
            // Strip the switches, keeping the positional arguments.
            //
            // This was a forward loop calling parameters.Remove(parameters[i]),
            // which shifted the next element into the current index and skipped it,
            // so a switch immediately following another switch survived and was then
            // treated as a positional argument. The same loop was copy-pasted into
            // nearly every command handler.
            parameters.RemoveAll(p => p.Contains("--"));

            if(info.ProcessMachineType == ERC.MachineType.x64)
            {
                PLog.WriteLine("WARNING: This function will find pop pop ret instructions however please be aware that SEH overflows will not work on the 64bit architecture.");
            }

            List<string> sehJumpAddresses = new List<string>();

            bool aslr = session.Aslr, safeseh = session.SafeSeh, rebase = session.Rebase, nxcompat = session.NxCompat, osdll = session.OsDll;

            if(session.Bytes.Length > 0)
            {
                if(session.Encode == SearchEncoding.Unicode)
                {
                    sehJumpAddresses = ERC.DisplayOutput.GetSEHJumpsUnicode(info, aslr, safeseh, rebase, nxcompat, osdll, session.Bytes, session.Protection).ToList();
                }
                else
                {
                    sehJumpAddresses = ERC.DisplayOutput.GetSEHJumps(info, aslr, safeseh, rebase, nxcompat, osdll, session.Bytes, session.Protection).ToList();
                }
            }
            else
            {
                if (session.Encode == SearchEncoding.Unicode)
                {
                    sehJumpAddresses = ERC.DisplayOutput.GetSEHJumpsUnicode(info, aslr, safeseh, rebase, nxcompat, osdll, null, session.Protection).ToList();
                }
                else
                {
                    sehJumpAddresses = ERC.DisplayOutput.GetSEHJumps(info, aslr, safeseh, rebase, nxcompat, osdll, null, session.Protection).ToList();
                } 
            }

            foreach(string s in sehJumpAddresses)
            {
                PLog.WriteLine(s);
            }
            
            //return sehJumpAddresses;
            return;
        }

        private static void EggHunters(SessionState session, ERC.ErcCore? core = null, string? tag = null)
        {
            string holder = ERC.DisplayOutput.GenerateEggHunters(core, tag);
            Plugins._plugin_logputs(holder);
        }
    }
}
