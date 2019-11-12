using System;
using System.Collections.Generic;
using System.Text;
using Managed.x64dbg.SDK;


namespace ErcXdbg
{
    public static class RegisteredCommands
    {
        public static bool ErcCommand(int argc, string[] argv)
        {
            try
            {
                //Get the handle of the attached process
                var hProcess = Bridge.DbgValFromString("$hProcess");

                //Confirm that at least some options were passed.
                if (argc <= 1)
                {
                    PrintHelp();
                    return true;
                }

                //Check a process is attached.
                if (hProcess == IntPtr.Zero)
                {
                    PrintHelp("The debugger must be attached to a process to use ERC");
                    return true;
                }

                ERC.ErcCore core = new ERC.ErcCore();
                ERC.ProcessInfo info = new ERC.ProcessInfo(new ERC.ErcCore(), hProcess);

                //Check the command was properly formed.
                List<string> command = ParseCommand(argv[0], core, info);
                if (command == null)
                {
                    return true;
                }

                //This is the code for a popup box
                /*
                string Left = Interaction.InputBox("Enter value pls", "NetTest", "", -1, -1);
                if (Left == null | Operators.CompareString(Left, "", false) == 0)
                    PLog.WriteLine("[TEST] cancel pressed!");
                else
                    PLog.WriteLine("[TEST] line: {0}", Left);
                */
                ErcXdbg.PluginStop();
                ErcXdbg.PluginStart();
                PLog.WriteLine("Exiting plugin");
            }
            catch(Exception e)
            {
                PLog.WriteLine(e.Message);
                return true;
            }
            return true;
        }

        private static void PrintHelp(string errorMessage = null)
        {
            PLog.WriteLine("    __________   ______  ");
            PLog.WriteLine("   / ____ / __\\ / ____/ ");
            PLog.WriteLine("  / __ / / /_/ / /       ");
            PLog.WriteLine(" / /___ / _, _/ /___     ");
            PLog.WriteLine("/_____ /_/ |_|\\____/    ");
            PLog.WriteLine("-------------------------");
            if (errorMessage != null)
            {
                PLog.WriteLine("Error: {0}", errorMessage);
            }
            string help = "";
            help += "Global Options:\n";
            help += "   - \n";
            help += "Usage:       \n";
            help += "   --Config        |\n";
            help += "   --Pattern       |\n";
            help += "   --Bytearray     |\n";
            help += "   --Compare       |\n";
            help += "   --Assemble      |\n";
            help += "   --Disassemble   |\n";
            help += "   --ListProcesses |\n";
            help += "   --ProcessInfo   |\n";
            help += "   --ModuleInfo    |\n";
            help += "   --ThreadInfo    |\n";
            help += "   --SEH           |\n";
            help += "   --EggHunters    |\n";
            help += "   --FindNrp       |\n";
            help += "   --Rop           |\n";
            PLog.WriteLine(help);
        }

        private static List<string> ParseCommand(string command, ERC.ErcCore core, ERC.ProcessInfo info)
        {
            List<string> parameters = new List<string>(command.Split(' '));
            parameters.RemoveAt(0);

            int commands = 0;
            string option = "";
            
            //check how many options were passed to ERC
            foreach(string s in parameters)
            {
                if (s.Contains("--"))
                {
                    commands++;
                    option = s.ToLower();
                }
            }

            //Confirm the option is valid.
            if(commands != 1)
            {
                PrintHelp("One option and it's parameters must be executed at a time (options start with --)");
                return null;
            }
            else
            {
                switch (option)
                {
                    case "--config":
                        OptionConfig(parameters, core);
                        break;
                    case "--pattern":
                        break;
                    case "--bytearray":
                        break;
                    case "--compare":
                        break;
                    case "--assemble":
                        break;
                    case "--disassemble":
                        break;
                    case "--listprocesses":
                        break;
                    case "--processinfo":
                        break;
                    case "--moduleinfo":
                        break;
                    case "--threadinfo":
                        break;
                    case "--seh":
                        break;
                    case "--egghunters":
                        break;
                    case "--findnrp":
                        break;
                    case "--rop":
                        break;
                    default:
                        PrintHelp("The command was not structured correctly: Option is not supported. ERC <option> <parameters>");
                        return null;
                }
            }
            return parameters;
        }

        private static string OptionConfig(List<string> parameters, ERC.ErcCore core)
        {
            for(int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].Contains("--"))
                {
                    parameters.Remove(parameters[i]);
                }
            }

            switch (parameters[0].ToLower())
            {
                case "getworkingdirectory":
                    PLog.WriteLine("Working Directory = {0}", core.WorkingDirectory);
                    return core.WorkingDirectory;
                case "getversion":
                    PLog.WriteLine("ERC Version = {0}", core.ErcVersion);
                    return core.ErcVersion;
                case "getauthor":
                    PLog.WriteLine("Author = {0}", core.Author);
                    return core.Author;
                case "geterrorlogpath":
                    PLog.WriteLine("Error Log File = {0}", core.SystemErrorLogPath);
                    return core.SystemErrorLogPath;
                case "getstandardpattern":
                    PLog.WriteLine("Standard Pattern Location = {0}", core.PatternStandardPath);
                    return core.PatternStandardPath;
                case "getextendedpattern":
                    PLog.WriteLine("Standard Pattern Location = {0}", core.PatternExtendedPath);
                    return core.PatternExtendedPath;
                case "setworkingdirectory":
                    if(parameters.Count == 2)
                    {
                        core.SetWorkingDirectory(parameters[1]);
                        PLog.WriteLine("New Working Directory = {0}", core.WorkingDirectory);
                    }
                    else
                    {
                        PLog.WriteLine("Error incorrect number of arguments. Use ERC --config SetWorkingDirectory <PATH>");
                    }
                    return core.WorkingDirectory;
                case "setauthor":
                    if (parameters.Count == 2)
                    {
                        core.SetAuthor(parameters[1]);
                        PLog.WriteLine("New Author = {0}", core.Author);
                    }
                    else
                    {
                        PLog.WriteLine("Error incorrect number of arguments. Use ERC --config SetAuthor <Author>");
                    }
                    return core.Author;
                case "seterrorlogpath":
                    if (parameters.Count == 2)
                    {
                        core.SetErrorFile(parameters[1]);
                        PLog.WriteLine("New Error Log File = {0}", core.SystemErrorLogPath);
                    }
                    else
                    {
                        PLog.WriteLine("Error incorrect number of arguments. Use ERC --config SetErrorLogPath <PATH>");
                    }
                    return core.SystemErrorLogPath;
                case "setstandardpattern":
                    if (parameters.Count == 2)
                    {
                        core.SetPatternStandardPath(parameters[1]);
                        PLog.WriteLine("New standard pattern from file = {0}", core.PatternStandardPath);
                    }
                    else
                    {
                        PLog.WriteLine("Error incorrect number of arguments. Use ERC --config SetStandardPattern <PATH>");
                    }
                    return core.PatternStandardPath;
                case "setextendedpattern":
                    if (parameters.Count == 2)
                    {
                        core.SetPatternExtendedPath(parameters[1]);
                        PLog.WriteLine("New extended pattern from file = {0}", core.PatternExtendedPath);
                    }
                    else
                    {
                        PLog.WriteLine("Error incorrect number of arguments. Use ERC --config SetExtendedPattern <PATH>");
                    }
                    return core.PatternExtendedPath;
                default:
                    return null;
            }
        }
    }
}
