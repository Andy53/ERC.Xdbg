using System;
using System.Collections.Generic;
using Managed.x64dbg.SDK;


namespace ErcXdbg
{
    public static class RegisteredCommands
    {
        enum Command
        {
            Config,
            Pattern,
            Bytearray,
            Compare,
            Assemble,
            Disassemble,
            ListProcesses,
            ProcessInfo,
            ModuleInfo,
            ThreadInfo,
            SEH,
            EggHunters,
            FindNrp,
            Rop 
        }

        public static bool ErcCommand(int argc, string[] argv)
        {
            var hProcess = Bridge.DbgValFromString("$hProcess");
            if(argc <= 1)
            {
                PrintHelp();
                return true;
            }

            if(hProcess == IntPtr.Zero)
            {
                PrintHelp("The debugger must be attached to a process to use ERC");
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
            return true;
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
            help += "Usage: \n";
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
            
            return null;
        }
    }
}
