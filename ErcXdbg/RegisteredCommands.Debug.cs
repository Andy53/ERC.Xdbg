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
    /// The commands for diagnostics.
    /// </summary>
    /// <remarks>
    /// Reporting the plugin's own state, for diagnosing the plugin rather than a target.
    ///
    /// One part of RegisteredCommands, which was a single 2,100 line file holding
    /// every command. Splitting it by command group leaves the dispatcher in
    /// RegisteredCommands.cs and each group beside the others it shares helpers with.
    /// </remarks>
    public static partial class RegisteredCommands
    {
        private static void Debug(ERC.ProcessInfo info, List<string> parameters, SessionState session)
        {
            List<string> arg = new List<string>();
            arg.Add("ERC");
            PLog.WriteLine("\n");

            bool showGlobals = false;
            bool showArgs = false;
            bool showProcess = false;
            bool showSystem = false;
            bool showConfig = false;

            foreach (string s in parameters)
            {
                arg.Add(s);
            }

            // Strip the switches, keeping the positional arguments.
            //
            // This was a forward loop calling parameters.Remove(parameters[i]),
            // which shifted the next element into the current index and skipped it,
            // so a switch immediately following another switch survived and was then
            // treated as a positional argument. The same loop was copy-pasted into
            // nearly every command handler.
            parameters.RemoveAll(p => p.Contains("--"));

            if (parameters.Count == 0)
            {
                showGlobals = true;
                showArgs = true;
                showProcess = true;
                showSystem = true;
                showConfig = true;
            }

            for (int i = 0; i < parameters.Count && i >= 0; i++)
            {
                if (parameters.Count > i && i >= 0)
                {
                    if (parameters[i].ToLower() == "showSystem")
                    {
                        showSystem = true;
                        parameters.Remove(parameters[i]);
                        i--;
                    }
                }

                if (parameters.Count > i && i >= 0)
                {
                    if (parameters[i].ToLower() == "showglobals")
                    {
                        showGlobals = true;
                        parameters.Remove(parameters[i]);
                        i--;
                    }
                }

                if (parameters.Count > i && i >= 0)
                {
                    if (parameters[i].ToLower() == "showargs")
                    {
                        showArgs = true;
                        parameters.Remove(parameters[i]);
                        i--;
                    }
                }

                if (parameters.Count > i && i >= 0)
                {
                    if (parameters[i].ToLower() == "showprocess")
                    {
                        showProcess = true;
                        parameters.Remove(parameters[i]);
                        i--;
                    }
                }
            }

            if(showSystem == true)
            {
                ManagementObjectSearcher mos = new ManagementObjectSearcher("select * from Win32_OperatingSystem");

                PLog.WriteLine("DEBUG: System Information");
                PLog.WriteLine("--------------------------------------------");
                foreach (ManagementObject managementObject in mos.Get())
                {
                    if (managementObject["Caption"] != null)
                    {
                        PLog.WriteLine("Operating System Name  :  " + managementObject["Caption"].ToString());
                    }
                    if (managementObject["OSArchitecture"] != null)
                    {
                        PLog.WriteLine("Operating System Architecture  :  " + managementObject["OSArchitecture"].ToString());
                    }
                    if (managementObject["CSDVersion"] != null)
                    {
                        PLog.WriteLine("Operating System Service Pack   :  " + managementObject["CSDVersion"].ToString());
                    }
                }
                PLog.WriteLine("");
            }

            if (showArgs == false && showGlobals == false)
            {
                showArgs = true;
                PLog.WriteLine("\n");
            }

            if (showProcess == true)
            {
                PLog.WriteLine("DEBUG: Process ");
                PLog.WriteLine("--------------------------------------------");
                PLog.WriteLine("Process Name         = {0}", info.ProcessName);
                PLog.WriteLine("Process Description  = {0}", info.ProcessDescription);
                PLog.WriteLine("Process Path         = {0}", info.ProcessPath);
                PLog.WriteLine("Process ID           = {0}", info.ProcessID);
                PLog.WriteLine("Process Handle       = {0}", info.ProcessHandle.ToString("X"));
                PLog.WriteLine("Process Architecture = {0}\n", info.ProcessMachineType.ToString());
            }

            if (showGlobals == true)
            {
                PLog.WriteLine("DEBUG: Globals ");
                PLog.WriteLine("--------------------------------------------");
                PLog.WriteLine("ASLR       = {0}", session.Aslr.ToString());
                PLog.WriteLine("SafeSEH    = {0}", session.SafeSeh.ToString());
                PLog.WriteLine("Rebase     = {0}", session.Rebase.ToString());
                PLog.WriteLine("NXCompat   = {0}", session.NxCompat.ToString());
                PLog.WriteLine("OSDll      = {0}", session.OsDll.ToString());
                PLog.WriteLine("Bytes      = {0}", ByteArrayToString(session.Bytes));
                PLog.WriteLine("Protection = {0}", session.Protection);
                PLog.WriteLine("Extended   = {0}", session.Extended.ToString());
                PLog.WriteLine("Encoding   = {0}\n", session.Encode.ToString());
            }

            if (showArgs == true)
            {
                PLog.WriteLine("DEBUG: Args ");
                PLog.WriteLine("--------------------------------------------");
                PLog.WriteLine("Args = {0}\n", string.Join(" ", arg.ToArray()));
            }

            if(showConfig == true)
            {
                List<string> nullParams = new List<string>();
                Config(nullParams, info, session);
            }
        }

        private static void Debug(List<string> parameters, SessionState session)
        {
            List<string> arg = new List<string>();
            arg.Add("ERC");
            PLog.WriteLine("\n");

            bool showGlobals = false;
            bool showArgs = false;
            bool showSystem = false;

            foreach (string s in parameters)
            {
                arg.Add(s);
            }

            // Strip the switches, keeping the positional arguments.
            //
            // This was a forward loop calling parameters.Remove(parameters[i]),
            // which shifted the next element into the current index and skipped it,
            // so a switch immediately following another switch survived and was then
            // treated as a positional argument. The same loop was copy-pasted into
            // nearly every command handler.
            parameters.RemoveAll(p => p.Contains("--"));

            if (parameters.Count == 0)
            {
                showGlobals = true;
                showArgs = true;
                showSystem = true;
            }

            for (int i = 0; i < parameters.Count && i >= 0; i++)
            {
                if (parameters.Count > i && i >= 0)
                {
                    if (parameters[i].ToLower() == "showSystem")
                    {
                        showSystem = true;
                        parameters.Remove(parameters[i]);
                        i--;
                    }
                }

                if (parameters.Count > i && i >= 0)
                {
                    if (parameters[i].ToLower() == "showglobals")
                    {
                        showGlobals = true;
                        parameters.Remove(parameters[i]);
                        i--;
                    }
                }

                if (parameters.Count > i && i >= 0)
                {
                    if (parameters[i].ToLower() == "showargs")
                    {
                        showArgs = true;
                        parameters.Remove(parameters[i]);
                        i--;
                    }
                }
            }

            if (showSystem == true)
            {
                ManagementObjectSearcher mos = new ManagementObjectSearcher("select * from Win32_OperatingSystem");

                PLog.WriteLine("DEBUG: System Information");
                PLog.WriteLine("--------------------------------------------");
                foreach (ManagementObject managementObject in mos.Get())
                {
                    if (managementObject["Caption"] != null)
                    {
                        PLog.WriteLine("Operating System Name  :  " + managementObject["Caption"].ToString());
                    }
                    if (managementObject["OSArchitecture"] != null)
                    {
                        PLog.WriteLine("Operating System Architecture  :  " + managementObject["OSArchitecture"].ToString());
                    }
                    if (managementObject["CSDVersion"] != null)
                    {
                        PLog.WriteLine("Operating System Service Pack   :  " + managementObject["CSDVersion"].ToString());
                    }
                }
                PLog.WriteLine("");
            }

            if (showArgs == false && showGlobals == false)
            {
                showArgs = true;
            }

            if (showGlobals == true)
            {
                PLog.WriteLine("DEBUG: Globals ");
                PLog.WriteLine("--------------------------------------------");
                PLog.WriteLine("ASLR       = {0}", session.Aslr.ToString());
                PLog.WriteLine("SafeSEH    = {0}", session.SafeSeh.ToString());
                PLog.WriteLine("Rebase     = {0}", session.Rebase.ToString());
                PLog.WriteLine("NXCompat   = {0}", session.NxCompat.ToString());
                PLog.WriteLine("OSDll      = {0}", session.OsDll.ToString());
                PLog.WriteLine("Bytes      = {0}", ByteArrayToString(session.Bytes));
                PLog.WriteLine("Protection = {0}", session.Protection);
                PLog.WriteLine("Extended   = {0}", session.Extended.ToString());
                PLog.WriteLine("Encoding   = {0}\n", session.Encode.ToString());
            }

            if (showArgs == true)
            {
                PLog.WriteLine("DEBUG: Args ");
                PLog.WriteLine("--------------------------------------------");
                PLog.WriteLine("Args = {0}\n", string.Join(" ", arg.ToArray()));
            }
        }
    }
}
