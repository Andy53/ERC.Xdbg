using System;
using System.Collections.Generic;
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

                //Check the command was properly formed.
                List<string> command = ParseCommand(argv[0]);
                if (command == null)
                {
                    return true;
                }
                ERC.ErcCore core = new ERC.ErcCore();
                ERC.ProcessInfo pi = new ERC.ProcessInfo(core, hProcess);

                //This is the code for a popup box
                /*
                string Left = Interaction.InputBox("Enter value pls", "NetTest", "", -1, -1);
                if (Left == null | Operators.CompareString(Left, "", false) == 0)
                    PLog.WriteLine("[TEST] cancel pressed!");
                else
                    PLog.WriteLine("[TEST] line: {0}", Left);
                */
                PLog.WriteLine("Exiting plugin");
                return true;
            }
            catch(Exception e)
            {
                PLog.WriteLine(e.Message);
                return true;
            }
        }

        public static void PrintHelp(string errorMessage = null)
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

        public static List<string> ParseCommand(string command)
        {
            List<string> parameters = new List<string>(command.Split(' '));
            PLog.WriteLine("Parameters lenght = {0}", parameters.Count);
            foreach(string s in parameters)
            {
                PLog.WriteLine(s);
            }
            parameters.RemoveAt(0);
            PLog.WriteLine("Parameters lenght = {0}", parameters.Count);
            foreach (string s in parameters)
            {
                PLog.WriteLine(s);
            }
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
    }
}
