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

namespace ErcXdbg
{
    public static class RegisteredCommands
    {
        public static bool ErcCommand(int argc, string[] argv)
        {
            string sessionFile = Path.GetDirectoryName(Assembly.GetExecutingAssembly().CodeBase) + "\\Session.xml";
            sessionFile = sessionFile.Replace("file:\\", "");

            try
            {
                DeleteOldPlugins();
                
                //Get the handle of the attached process
                var hProcess = Bridge.DbgValFromString("$hProcess");
                
                //Confirm that at least some options were passed.
                if (argc <= 1)
                {
                    PrintHelp("Arguments must be provided. Use --help for detailed information.");
                    ErcXdbg.PluginStart();
                    return true; 
                }

                if (argv[0].ToLower().Contains("--reset"))
                {
                    Reset();
                    ErcXdbg.PluginStart();
                    return true;
                }

                //Check a process is attached.
                if (hProcess == IntPtr.Zero)
                {
                    bool exitWithError = true;
                    bool update = false;
                    bool config = false;
                    bool debug = false;
                    ERC.ErcCore coreTemp = new ERC.ErcCore();

                    foreach (string s in argv[0].Split(' '))
                    {
                        if (s.Contains("--"))
                        {
                            switch (s.ToLower())
                            {
                                case "--update":
                                    exitWithError = false;
                                    if (update == false)
                                    {
                                        update = true;
                                        List<string> args = argv[0].Split(' ').ToList<string>();
                                        args.RemoveAt(0);
                                        Update(args);
                                    }
                                    break;
                                case "--config":
                                    exitWithError = false;
                                    if (config == false)
                                    {
                                        config = true;
                                        List<string> args = argv[0].Split(' ').ToList<string>();
                                        args.RemoveAt(0);
                                        Config(args, coreTemp);
                                    }
                                    break;
                                case "--debug":
                                    exitWithError = false;
                                    if (debug == false)
                                    {
                                        debug = true;
                                        List<string> args = argv[0].Split(' ').ToList<string>();
                                        args.RemoveAt(0);
                                        Debug(args);
                                    }
                                    break;
                                default:
                                    break;
                            }
                        }
                    }

                    if(exitWithError == true)
                    {
                        PrintHelp("The debugger must be attached to a process to use ERC");
                    }
                    
                    ErcXdbg.PluginStart();
                    return true;
                }
                PLog.WriteLine("");
                GC.Collect();

                ERC.ErcCore core = new ERC.ErcCore();
                ERC.ProcessInfo info = new ERC.ProcessInfo(new ERC.ErcCore(), hProcess);

                ParseCommand(argv[0], core, info);
            }
            catch (Exception e)
            {
                PrintHelp(e.Message);
                ErcXdbg.PluginStart();
                return true;
            }

            ErcXdbg.PluginStart();
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
            help += "Globals:\n";
            help += "   Global arguments can be appended to any command and will persist for the length of the session until X64dbg is next\n";
            help += "   restarted.\n";
            help += "   -Aslr           |\n";
            help += "       Excludes ASLR enabled modules from all searches. Can be disabled by passing \"false\". -Aslr false\n";
            help += "   -SafeSEH        |\n";
            help += "       Excludes SafeSEH enabled modules from all searches. Can be disabled by passing \"false\". -SafeSEH false\n";
            help += "   -Rebase         |\n";
            help += "       Excludes Rebase enabled modules from all searches. Can be disabled by passing \"false\". -Rebase false\n";
            help += "   -NXCompat       |\n";
            help += "       Excludes NXCompat enabled modules from all searches. Can be disabled by passing \"false\". -NXCompat false\n";
            help += "   -OSDLL          |\n";
            help += "       Excludes OSDLL enabled modules from all searches. Can be disabled by passing \"false\". -OSDLL false\n";
            help += "   -Bytes          |\n";
            help += "       Excludes bytes from pointers returned in searches and from being added to bytearrays. Disabled by passing\n"; 
            help += "       without any bytes.\n";
            help += "   -Protection     |\n";
            help += "       Defines the protection level of pointers to be included search results. Default is exec. This\n";
            help += "       allows only executable pointers to be returned in search results. A value must be provided with this switch,\n";
            help += "       options are read,write,exec. Options must be comma seperated without spaces.\n";
            help += "Usage:       \n";
            help += "   --Help          |\n";
            help += "       Displays this message. Further help can be found at: https://github.com/Andy53/ERC.Xdbg/tree/master/ErcXdbg \n";
            help += "   --Update        |\n";
            help += "       Can be used to update the plugin to the latest version. Can be passed a ip:port combination to specify the\n";
            help += "       proxy server to use.\n";
            help += "   --Config        |\n";
            help += "       Takes any of the following arguments, Get requests take no additional parameters, Set requests take a directory\n";
            help += "       which will be set as the new value.\n";
            help += "           GetWorkingDirectory (ERC --config GetWorkingDirectory)\n";
            help += "           GetStandardPattern  (ERC --config GetStandardPatter)\n";
            help += "           GetExtendedPattern  (ERC --config GetExtendedPattern)\n";
            help += "           GetVersion          (ERC --config GetVersion)\n";
            help += "           GetAuthor           (ERC --config GetAuthor)\n";
            help += "           GetErrorFilePath    (ERC --config GetErrorFilePath)\n";
            help += "           SetWorkingDirectory (ERC --config SetWorkingDirectory directory)\n";
            help += "           SetStandardPattern  (ERC --config SetStandardPattern file)\n";
            help += "           SetExtendedPattern  (ERC --config SetExtendedPattern file)\n";
            help += "           SetAuthor           (ERC --config SetAuthor author)\n";
            help += "           SetErrorFilePath    (ERC --config SetErrorFilePath file)\n";
            help += "       Passed without parameters will print all Get requests.\n";
            help += "   --Pattern       |\n";
            help += "       Generates a non repeating pattern. A pattern of pure ASCII characters can be generated up to 20277 and up to  \n";
            help += "       66923 if special characters are used. The offset of a particular string can be found inside the pattern by \n";
            help += "       providing a search string (must be at least 3 chars long).\n";
            help += "           Pattern create: ERC --pattern <create | c> <length>\n";
            help += "           Pattern offset: ERC --pattern <offset | o> <search string>\n";
            help += "   --Bytearray     |\n";
            help += "       Generates a bytearray which is saved to the working directory and displayed in the application log tab. A set \n";
            help += "       of hex characters can be provided to the -byte global which will be excluded from the bytearray.\n";
            help += "   --Compare       |\n";
            help += "       Generates a table with a byte by byte comparison of an area of memory and the bytes from a file. Takes a memory \n";
            help += "       from which to start the search and a filepath for the binary file\n";
            help += "   --Convert       |\n";
            help += "       Converts input from one form to another such as ASCII to hex, Unicode to hex, ASCII to bytes. \n";
            help += "       Valid conversion types:\n           Ascii to Hex = AtoH\n           Unicdoe to Hex = UtoH\n           UTF-7 to Hex = 7toH\n";
            help += "           UTF-8 to Hex = 8toH\n           UTF-32 to Hex = 32toH\n";
            help += "   --Assemble      |\n";
            help += "       Takes a collection of assembley instructions and outputs the associated opcodes. Takes a boolean of 0 for x32 or\n";
            help += "        1 for x64 can be used to force the architecture of the opcodes returned, if neither is passed the architecture \n";
            help += "       of the process will be used.\n";
            help += "   --Disassemble   |\n";
            help += "       Takes a collection of opcodes and outputs the associated assembley instructions. Takes a boolean of 0 for x32 or\n";
            help += "        1 for x64 can be used to force the architecture of the opcodes returned, if neither is passed the architecture \n";
            help += "       of the process will be used.\n";
            help += "   --SearchMemory   |\n";
            help += "       Takes a search string of either bytes or a string to search for. Takes an (optional) integer to specify search \n";
            help += "       type (0 = bytes, 1 = Unicode, 2 = ASCII, 4 = UTF7, 5 = UTF8).\n";        
            help += "       Example: ERC --SearchMemory FF E4. Search for bytes FF E4 including all dll's \n";
            help += "       Example: ERC --SearchMemory HelloWorld 1. Search for the string \"HelloWorld in Unicode\"\n";
            help += "   --SearchModules   |\n";
            help += "       Takes a search string of either bytes or a string to search for in a processes loaded modules. Takes an \n";
            help += "       (optional) integer to specify search \n";
            help += "       type (0 = bytes, 1 = Unicode, 2 = ASCII, 4 = UTF7, 5 = UTF8).\n";
            help += "       Example: ERC --SearchModules FF E4. Search for bytes FF E4 including all dll's \n";
            help += "       Example: ERC --SearchModules FF E4 module1.dll module2.dll. Search for bytes FF E4 only in module1.dll and module2.dll\n";
            help += "   --Dump |\n";
            help += "       Dump contents of memory to a file. Takes an address to start at and a hex number of bytes to be read.\n"; 
            help += "   --ListProcesses |\n";
            help += "       Displays a list of processes running on the local machine.\n";
            help += "   --ProcessInfo   |\n";
            help += "       Displays info about the attached process, loaded modules and threads. Can be passed a boolen to indicate if the\n"; 
            help += "       output should be written to disk.\n";
            help += "   --ModuleInfo    |\n";
            help += "       Displays info about the modules loaded by the attached process. Can be passed a boolen to indicate if the output\n"; 
            help += "       should be written to disk.\n";
            help += "   --ThreadInfo    |\n";
            help += "       Displays info about threads associated with the attached process. Can be passed a boolen to indicate if the\n"; 
            help += "       output should be written to disk.\n";
            help += "   --SEH           |\n";
            help += "       Displays a list of addresses for pop pop ret instructions.\n"; 
            help += "       in the search.\n";
            help += "       Example: ERC --SEH Search for POP, POP, RET instructions in memory. \n";
            help += "   --EggHunters    |\n";
            help += "       Prints a list of egghunters which can be used for various machine types. Can be passed 4 character string to be\n"; 
            help += "       used as the egghunter search tag. Default tag is ERCD.\n";
            help += "   --FindNrp       |\n";
            help += "       Generates a table detailing whether a repeating pattern has been found in the memory space of the process and\n";
            help += "       if any registers pointed into the pattern. Takes an integer for the text to look for (1 = Unicode, 2 = ASCII,\n";
            help += "       3 = UTF8, 4 = UTF7, 5 = UTF32, default = ASCII). Additionally if the value \"True\" is provided the extended \n";
            help += "       pattern will be used which includes special characters.\n";
            help += "   --HeapInfo      |\n";
            help += "       Displays information about the heap. Takes commands search, stats, ids, and dump. Takes an integer to\n";
            help += "       represent the ID of the heap to utilize. Takes a hex value to specify the address of the heap entry to utilize.\n";
            help += "       If both heap ID and start address are specified heap ID takes precedence, if start address and a byte pattern to.\n";
            help += "       search for are specified start address must be provided first. Takes a boolean value of true/false/1/0\n";
            help += "       to specify if output should be written to disk.\n";
            help += "       Example: ERC --HeapInfo stats. Display statistics about all heaps associated with the process.\n";
            help += "       Example: ERC --HeapInfo 0x00453563 search FFE4. Search for FFE4 in the Heap entry starting at 0x00453563\n";
            help += "       Example: ERC --HeapInfo 0x00453563 dump. Dump all memory from heap entry starting at 0x00453563\n";
            help += "   --Rop           |\n";
            help += "       Attempts to build a ROP chain for the current process. Current implementation utilizes VirtualAlloc, HeapCreate\n";
            help += "       and VirtualProtect.\n";
            help += "   --RopGadgets    |\n";
            help += "       Generates lists of ROP gadgets from within the current process. Lists are saved to the working directory.\n";
            help += "   --Reset         |\n";
            help += "       Clears all global variables and user defined configurations.";
            PLog.WriteLine(help);
        }

        private static void ParseCommand(string command, ERC.ErcCore core, ERC.ProcessInfo info)
        {
            List<string> parameters = new List<string>(command.Split(' '));
            parameters.RemoveAt(0);

            int commands = 0;
            string option = "";

            parameters = ParseGlobals(parameters);

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
                return;
            }
            else
            {
                bool writeToFile = true;
                switch (option)
                {
                    case "--help":
                        PrintHelp();
                        return;
                    case "--update":
                        Update(parameters);
                        return;
                    case "--config":
                        Config(parameters, core);
                        return;
                    case "--pattern":
                        Pattern(core, parameters);
                        return;
                    case "--bytearray":
                        ByteArray(parameters, core);
                        return;
                    case "--compare":
                        Compare(info, parameters);
                        return;
                    case "--convert":
                        Convert(info, parameters);
                        return;
                    case "--assemble":
                        Assemble(info, parameters);
                        return;
                    case "--disassemble":
                        Disassemble(info, parameters);
                        return;
                    case "--searchmemory":
                        SearchMemory(info, parameters);
                        return;
                    case "--searchmodules":
                        SearchModules(info, parameters);
                        return;
                    case "--dump":
                        DumpMemory(info, parameters);
                        return;
                    case "--listprocesses":
                        PLog.WriteLine(ERC.DisplayOutput.ListLocalProcesses());
                        return;
                    case "--processinfo":
                        if(parameters.Count == 2)
                        {
                            if(parameters[1].ToLower() == "false" || parameters[1].ToLower() == "0")
                            {
                                writeToFile = false;
                            }
                        }
                        PLog.WriteLine("\n" + ERC.DisplayOutput.DisplayProcessInfo(info, writeToFile));
                        return;
                    case "--moduleinfo":
                        if (parameters.Count == 2)
                        {
                            if (parameters[1].ToLower() == "false" || parameters[1].ToLower() == "0")
                            {
                                writeToFile = false;
                            }
                        }
                        PLog.WriteLine("\n" + ERC.DisplayOutput.GenerateModuleInfoTable(info, writeToFile));
                        return;
                    case "--threadinfo":
                        if (parameters.Count == 2)
                        {
                            if (parameters[1].ToLower() == "false" || parameters[1].ToLower() == "0")
                            {
                                writeToFile = false;
                            }
                        }
                        PLog.WriteLine("\n" + ERC.DisplayOutput.DisplayThreadInfo(info, writeToFile));
                        return;
                    case "--seh":
                        SEH(parameters, info);
                        break;
                    case "--egghunters":
                        if(parameters.Count <= 2)
                        {
                            if(parameters.Count == 1)
                            {
                                EggHunters(core);
                            }
                            else
                            {
                                EggHunters(core, parameters[1]);
                            }
                        }
                        return;
                    case "--findnrp":
                        FindNRP(info, parameters);
                        return;
                    case "--heapinfo":
                        HeapInfo(info, parameters);
                        return;
                    case "--ropgadgets":
                        rop(info, true);
                        return;
                    case "--rop":
                        rop(info);
                        return;
                    case "--debug":
                        Debug(info, parameters);
                        return;
                    case "--reset":
                        Reset(info, parameters);
                        return;
                    default:
                        PrintHelp("The command was not structured correctly: Option is not supported. ERC <option> <parameters>");
                        return;
                }
            }
            return;
        }

        private static List<string> ParseGlobals(List<string> parameters)
        {
            try
            {
                for (int i = 0; i < parameters.Count; i++)
                {
                    if (parameters.Count > i + 1)
                    {
                        if (parameters[i].ToLower() == "-aslr" && (parameters[i + 1].ToLower() == "true" || parameters[i + 1].ToLower() == "false"))
                        {
                            if (parameters[i + 1].ToLower() == "true")
                            {
                                Globals.aslr = true;
                                parameters.RemoveAt(i + 1);
                                parameters.RemoveAt(i);
                                i--;
                            }
                            else
                            {
                                Globals.aslr = false;
                                parameters.RemoveAt(i + 1);
                                parameters.RemoveAt(i);
                                i--;
                            }
                        }
                        else if (parameters[i].ToLower() == "-aslr")
                        {
                            Globals.aslr = true;
                            parameters.RemoveAt(i);
                            i--;
                        }
                    }
                    else if (parameters[i].ToLower() == "-aslr")
                    {
                        Globals.aslr = true;
                        parameters.RemoveAt(i);
                        i--;
                    }

                    if (parameters.Count > i + 1)
                    {
                        if (parameters[i].ToLower() == "-safeseh" && (parameters[i + 1].ToLower() == "true" || parameters[i + 1].ToLower() == "false"))
                        {
                            if (parameters[i + 1].ToLower() == "true")
                            {
                                Globals.safeseh = true;
                                parameters.RemoveAt(i + 1);
                                parameters.RemoveAt(i);
                                i--;
                            }
                            else
                            {
                                Globals.safeseh = false;
                                parameters.RemoveAt(i + 1);
                                parameters.RemoveAt(i);
                                i--;
                            }
                        }
                        else if (parameters[i].ToLower() == "-safeseh")
                        {
                            Globals.safeseh = true;
                            parameters.RemoveAt(i);
                            i--;
                        }
                    }
                    else if (parameters[i].ToLower() == "-safeseh")
                    {
                        Globals.safeseh = true;
                        parameters.RemoveAt(i);
                        i--;
                    }

                    if (parameters.Count > i + 1)
                    {
                        if (parameters[i].ToLower() == "-rebase" && (parameters[i + 1].ToLower() == "true" || parameters[i + 1].ToLower() == "false"))
                        {
                            if (parameters[i + 1].ToLower() == "true")
                            {
                                Globals.rebase = true;
                                parameters.RemoveAt(i + 1);
                                parameters.RemoveAt(i);
                                i--;
                            }
                            else
                            {
                                Globals.rebase = false;
                                parameters.RemoveAt(i + 1);
                                parameters.RemoveAt(i);
                                i--;
                            }
                        }
                        else if (parameters[i].ToLower() == "-rebase")
                        {
                            Globals.rebase = true;
                            parameters.RemoveAt(i);
                            i--;
                        }
                    }
                    else if (parameters[i].ToLower() == "-rebase")
                    {
                        Globals.rebase = true;
                        parameters.RemoveAt(i);
                        i--;
                    }

                    if (parameters.Count > i + 1)
                    {
                        if (parameters[i].ToLower() == "-nxcompat" && (parameters[i + 1].ToLower() == "true" || parameters[i + 1].ToLower() == "false"))
                        {
                            if (parameters[i + 1].ToLower() == "true")
                            {
                                Globals.nxcompat = true;
                                parameters.RemoveAt(i + 1);
                                parameters.RemoveAt(i);
                                i--;
                            }
                            else
                            {
                                Globals.nxcompat = false;
                                parameters.RemoveAt(i + 1);
                                parameters.RemoveAt(i);
                                i--;
                            }
                        }
                        else if (parameters[i].ToLower() == "-nxcompat")
                        {
                            Globals.nxcompat = true;
                            parameters.RemoveAt(i);
                            i--;
                        }
                    }
                    else if (parameters[i].ToLower() == "-nxcompat")
                    {
                        Globals.nxcompat = true;
                        parameters.RemoveAt(i);
                        i--;
                    }

                    if (parameters.Count > i + 1)
                    {
                        if (parameters[i].ToLower() == "-osdll" && (parameters[i + 1].ToLower() == "true" || parameters[i + 1].ToLower() == "false"))
                        {
                            if (parameters[i + 1].ToLower() == "true")
                            {
                                Globals.osdll = true;
                                parameters.RemoveAt(i + 1);
                                parameters.RemoveAt(i);
                                i--;
                            }
                            else
                            {
                                Globals.osdll = false;
                                parameters.RemoveAt(i + 1);
                                parameters.RemoveAt(i);
                                i--;
                            }
                        }
                        else if (parameters[i].ToLower() == "-osdll")
                        {
                            Globals.osdll = true;
                            parameters.RemoveAt(i);
                            i--;
                        }
                    }
                    else if (parameters[i].ToLower() == "-osdll")
                    {
                        Globals.osdll = true;
                        parameters.RemoveAt(i);
                        i--;
                    }

                    if (parameters.Count > i + 1)
                    {
                        
                        if (parameters[i].ToLower() == "-bytes" && !parameters[i + 1].ToLower().Contains("-"))
                        {
                            string allowedChars = "abcdefABCDEF1234567890";
                            parameters[i + 1] = parameters[i + 1].Replace("\\x", "");
                            parameters[i + 1] = parameters[i + 1].Replace("0x", "");
                            string hexChars = "";

                            for (int j = 0; j < parameters[i + 1].Length; j++)
                            {
                                if (allowedChars.Contains(parameters[i + 1][j].ToString()))
                                {
                                    hexChars = hexChars + parameters[i + 1][j];
                                }
                            }

                            if (hexChars.Length % 2 != 0)
                            {
                                hexChars += "0";
                            }

                            byte[] bytes = StringToByteArray(hexChars);
                            Globals.bytes = bytes;
                            parameters.RemoveAt(i + 1);
                            parameters.RemoveAt(i);
                            i--;
                        }
                        else if (parameters[i].ToLower() == "-bytes")
                        {
                            
                            Globals.bytes = new byte[0];
                            parameters.RemoveAt(i);
                            i--;
                        }
                    }
                    else if (parameters[i].ToLower() == "-bytes")
                    {
                        Globals.bytes = new byte[0];
                        parameters.RemoveAt(i);
                        i--;
                    }

                    if (parameters.Count > i + 1)
                    {
                        if (parameters[i].ToLower() == "-protection")
                        {
                            Globals.protection = parameters[i + 1].ToLower();
                            parameters.RemoveAt(i + 1);
                            parameters.RemoveAt(i);
                            i--;
                        }
                    }
                    else if (parameters[i].ToLower() == "-protection")
                    {
                        parameters.RemoveAt(i);
                        i--;
                    }

                    if (parameters.Count > i + 1)
                    {
                        if (parameters[i].ToLower() == "-extended" && (parameters[i + 1].ToLower() == "true" || parameters[i + 1].ToLower() == "false"))
                        {
                            if (parameters[i + 1].ToLower() == "true")
                            {
                                Globals.extended = true;
                                parameters.RemoveAt(i + 1);
                                parameters.RemoveAt(i);
                                i--;
                            }
                            else
                            {
                                Globals.extended = false;
                                parameters.RemoveAt(i + 1);
                                parameters.RemoveAt(i);
                                i--;
                            }
                        }
                        else if (parameters[i].ToLower() == "-extended")
                        {
                            Globals.extended = true;
                            parameters.RemoveAt(i);
                            i--;
                        }
                    }
                    else if (parameters[i].ToLower() == "-extended")
                    {
                        Globals.extended = true;
                        parameters.RemoveAt(i);
                        i--;
                    }

                    if (parameters[i].ToLower() == "-ascii")
                    {
                        Globals.encode = Encoding.ASCII;
                        parameters.RemoveAt(i);
                        i--;
                    }

                    if (parameters[i].ToLower() == "-unicode")
                    {
                        Globals.encode = Encoding.Unicode;
                        parameters.RemoveAt(i);
                        i--;
                    }

                    if (parameters[i].ToLower() == "-utf7")
                    {
                        Globals.encode = Encoding.UTF7;
                        parameters.RemoveAt(i);
                        i--;
                    }

                    if (parameters[i].ToLower() == "-utf8")
                    {
                        Globals.encode = Encoding.UTF8;
                        parameters.RemoveAt(i);
                        i--;
                    }

                    if (parameters[i].ToLower() == "-utf32")
                    {
                        Globals.encode = Encoding.UTF32;
                        parameters.RemoveAt(i);
                        i--;
                    }
                }
            }
            catch (Exception e)
            {
                PLog.WriteLine("ERROR: " + e.Message + "\n");
            }
            
            return parameters;
        }

        private static void Update(List<string> parameters)
        {
            PLog.WriteLine("ERC --Update");
            PLog.WriteLine("----------------------------------------------------------------------");

            
            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].Contains("--"))
                {
                    parameters.Remove(parameters[i]);
                }
            }

            bool proxy = false;
            string proxyIpAddress = "";
            string proxyPort = "";
            IPAddress address = null;

            if (parameters.Count > 1)
            {
                PrintHelp("Too many parameters provided. Update must be called as \"ERC --update <proxyIP:port>\"");
            }
            else if (parameters.Count == 1)
            {
                if (parameters[0].Split('.').Length == 4)
                {
                    if (parameters[0].Contains(":") == true && parameters[0].Split(':').Length == 2
                        && IPAddress.TryParse(parameters[0].Split(':')[0], out address) == true)
                    {
                        proxyIpAddress = parameters[0].Split(':')[0];
                        proxyPort = parameters[0].Split(':')[1];
                        proxy = true;
                    }
                }
                else
                {
                    PrintHelp("Proxy IP address:Port not formatted correctly. Update must be called as \"ERC --update <proxyIP:port>\"");
                }
            }

            try
            {
                //Get plugins directory for X64dbg.
                string updatePath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

                var wClient = new WebClient();
                ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
                System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;

                string releases = "";
                string[] releasesArray = null;
                string fileurl = "";
                string[] urlSegments = null;
                string filename = "";
                string zipPath = "";
                string[] files = null;
                bool oldPluginRenamed = false;

                if (Environment.Is64BitOperatingSystem) { 
                    wClient.Headers.Add("Accept", "text/html, application/xhtml+xml,application/xml;q=0.9,image/ webp,*/*;q=0.8");
                    wClient.Headers.Add("User-Agent", "ERC-Plugin");

                    //Set proxy if specified.
                    if (proxy == true)
                    {
                        WebProxy wProxy = new WebProxy(proxyIpAddress + ":" + proxyPort);
                        wClient.Proxy = wProxy;
                    }

                    if (!updatePath.Contains("\\x64\\"))
                    {
                        updatePath = updatePath.Replace("\\x32\\", "\\x64\\");
                    }

                    releases = wClient.DownloadString("https://api.github.com/repos/andy53/erc.xdbg/releases/tags/64");

                    releasesArray = releases.Split(',');
                    fileurl = "";
                    foreach (string s in releasesArray)
                    {
                        if (s.Contains("browser_download_url"))
                        {
                            fileurl = s.Split('\"')[3];
                        }
                    }

                    urlSegments = fileurl.Split('/');
                    filename = urlSegments[urlSegments.Length - 1];
                    zipPath = updatePath + "\\" + filename;
                    wClient.DownloadFile(fileurl, zipPath);

                    // Ensures that the last character on the extraction path
                    // is the directory separator char. 
                    // Without this, a malicious zip file could try to traverse outside of the expected
                    // extraction path.
                    if (!updatePath.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal))
                    {
                        updatePath += Path.DirectorySeparatorChar;
                    }

                    files = Directory.GetFiles(updatePath);
                    oldPluginRenamed = false;

                    foreach (string s in files)
                    {
                        if (s.Contains("Erc.Xdbg.dp64-OLD") && oldPluginRenamed == false)
                        {
                            int i = 0;
                            var holder = s.Split('_')[1];
                            int.TryParse(holder[0].ToString(), out i);
                            System.IO.File.Move(updatePath + "Erc.Xdbg.dp64", updatePath + "Erc.Xdbg.dp64-OLD_" + i.ToString() + ".txt");
                            oldPluginRenamed = true;
                        }
                    }

                    if (oldPluginRenamed == false)
                    {
                        if (File.Exists(updatePath + "Erc.Xdbg.dp64"))
                        {
                            System.IO.File.Move(updatePath + "Erc.Xdbg.dp64", updatePath + "Erc.Xdbg.dp64-OLD_0.txt");
                        }
                    }

                    //unzip update package 
                    using (ZipArchive archive = ZipFile.OpenRead(zipPath))
                    {
                        foreach (ZipArchiveEntry entry in archive.Entries)
                        {
                            string destinationPath = Path.GetFullPath(Path.Combine(updatePath, entry.FullName));
                            entry.ExtractToFile(destinationPath, true);
                        }
                    }

                    //Delete the zip archive.
                    File.Delete(zipPath);
                }

                wClient.Headers.Add("Accept", "text/html, application/xhtml+xml,application/xml;q=0.9,image/ webp,*/*;q=0.8");
                wClient.Headers.Add("User-Agent", "ERC-Plugin");

                updatePath = updatePath.Replace("\\x64\\", "\\x32\\");
                releases = wClient.DownloadString("https://api.github.com/repos/andy53/erc.xdbg/releases/tags/32");

                releasesArray = releases.Split(',');
                fileurl = "";
                foreach (string s in releasesArray)
                {
                    if (s.Contains("browser_download_url"))
                    {
                        fileurl = s.Split('\"')[3];
                    }
                }

                urlSegments = fileurl.Split('/');
                filename = urlSegments[urlSegments.Length - 1];
                zipPath = updatePath + "\\" + filename;
                wClient.DownloadFile(fileurl, zipPath);

                // Ensures that the last character on the extraction path
                // is the directory separator char. 
                // Without this, a malicious zip file could try to traverse outside of the expected
                // extraction path.
                if (!updatePath.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal))
                {
                    updatePath += Path.DirectorySeparatorChar;
                }

                files = Directory.GetFiles(updatePath);
                oldPluginRenamed = false;

                foreach (string s in files)
                {
                    if (s.Contains("Erc.Xdbg.dp32-OLD") && oldPluginRenamed == false)
                    {
                        int i = 0;
                        var holder = s.Split('_')[1];
                        int.TryParse(holder[0].ToString(), out i);
                        System.IO.File.Move(updatePath + "Erc.Xdbg.dp32", updatePath + "Erc.Xdbg.dp32-OLD_" + i.ToString() + ".txt");
                        oldPluginRenamed = true;
                    }
                }

                if (oldPluginRenamed == false)
                {
                    if (File.Exists(updatePath + "Erc.Xdbg.dp32"))
                    {
                        System.IO.File.Move(updatePath + "Erc.Xdbg.dp32", updatePath + "Erc.Xdbg.dp32-OLD_0.txt");
                    }
                }

                //unzip update package 
                using (ZipArchive archive = ZipFile.OpenRead(zipPath))
                {
                    foreach (ZipArchiveEntry entry in archive.Entries)
                    {
                        string destinationPath = Path.GetFullPath(Path.Combine(updatePath, entry.FullName));
                        entry.ExtractToFile(destinationPath, true);
                    }
                }

                //Delete the zip archive.
                File.Delete(zipPath);

                PLog.WriteLine("\nUpdate was downloaded successfully.");
                PLog.WriteLine("In order to use the updated binary you will need to restart X64dbg.");
                PLog.WriteLine("----------------------------------------------------------------------");
            }
            catch (Exception e)
            {
                PrintHelp(e.Message + "\n" + e.InnerException);
            }
        }

        private static void Config(List<string> parameters, ERC.ErcCore core)
        {
            PLog.WriteLine("ERC --Config");
            PLog.WriteLine("--------------------------------------------");
            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].Contains("--"))
                {
                    parameters.Remove(parameters[i]);
                }
            }

            if(parameters.Count == 0)
            {
                PLog.WriteLine("Configuration Settings:");
                PLog.WriteLine("Working Directory = {0}", core.WorkingDirectory);
                PLog.WriteLine("ERC Version = {0}", core.ErcVersion);
                PLog.WriteLine("Author = {0}", core.Author);
                PLog.WriteLine("Error Log File = {0}", core.SystemErrorLogPath);
                PLog.WriteLine("Standard Pattern Location = {0}", core.PatternStandardPath);
                PLog.WriteLine("Standard Pattern Location = {0}", core.PatternExtendedPath);
                //return null;
                PLog.WriteLine("--------------------------------------------");
                return;
            }
            
            switch (parameters[0].ToLower())
            {
                case "getworkingdirectory":
                    PLog.WriteLine("Working Directory = {0}", core.WorkingDirectory);
                    //return core.WorkingDirectory;
                    PLog.WriteLine("--------------------------------------------");
                    return;
                case "getversion":
                    PLog.WriteLine("ERC Version = {0}", core.ErcVersion);
                    //return core.ErcVersion;
                    PLog.WriteLine("--------------------------------------------");
                    return;
                case "getauthor":
                    PLog.WriteLine("Author = {0}", core.Author);
                    //return core.Author;
                    PLog.WriteLine("--------------------------------------------");
                    return;
                case "geterrorlogpath":
                    PLog.WriteLine("Error Log File = {0}", core.SystemErrorLogPath);
                    //return core.SystemErrorLogPath;
                    PLog.WriteLine("--------------------------------------------");
                    return;
                case "getstandardpattern":
                    PLog.WriteLine("Standard Pattern Location = {0}", core.PatternStandardPath);
                    //return core.PatternStandardPath;
                    PLog.WriteLine("--------------------------------------------");
                    return;
                case "getextendedpattern":
                    PLog.WriteLine("Standard Pattern Location = {0}", core.PatternExtendedPath);
                    //return core.PatternExtendedPath;
                    PLog.WriteLine("--------------------------------------------");
                    return;
                case "setworkingdirectory":
                    if(parameters.Count == 2)
                    {
                        if (Directory.Exists(parameters[1]))
                        {
                            core.SetWorkingDirectory(parameters[1]);
                            PLog.WriteLine("New Working Directory = {0}", core.WorkingDirectory);
                            PLog.WriteLine("--------------------------------------------");
                            return;
                        }
                        else
                        {
                            PrintHelp("Please provide a valid directory.");
                            PLog.WriteLine("--------------------------------------------");
                        }
                    }
                    else
                    {
                        PLog.WriteLine("Error incorrect number of arguments. Use ERC --config SetWorkingDirectory <PATH>");
                        PLog.WriteLine("--------------------------------------------");
                    }
                    //return core.WorkingDirectory;
                    return;
                case "setauthor":
                    for (int i = 0; i < parameters.Count; i++)
                    {
                        if (parameters[i].ToLower().Contains("setauthor"))
                        {
                            parameters.Remove(parameters[i]);
                        }
                    }
                    if (parameters.Count >= 1)
                    {
                        core.SetAuthor(String.Join(" ", parameters.ToArray()));
                        PLog.WriteLine("New Author = {0}", core.Author);
                    }
                    else
                    {
                        PLog.WriteLine("Error incorrect number of arguments. Use ERC --config SetAuthor <Author>");
                    }
                    //return core.Author;
                    PLog.WriteLine("--------------------------------------------");
                    return;
                case "seterrorlogpath":
                    if (parameters.Count == 2)
                    {
                        if (Directory.Exists(parameters[1]))
                        {
                            PrintHelp("A directory name was provided, value provided must be a filename.");
                            return;
                        }
                        core.SetErrorFile(parameters[1]);
                        PLog.WriteLine("New Error Log File = {0}", core.SystemErrorLogPath);
                    }
                    else
                    {
                        PLog.WriteLine("Error incorrect number of arguments. Use ERC --config SetErrorLogPath <PATH>");
                    }
                    //return core.SystemErrorLogPath;
                    PLog.WriteLine("--------------------------------------------");
                    return;
                case "setstandardpattern":
                    if (parameters.Count == 2)
                    {
                        if (!File.Exists(parameters[1]))
                        {
                            PrintHelp("The file does not exist, the value provided must be a filename.");
                            return;
                        }
                        core.SetPatternStandardPath(parameters[1]);
                        PLog.WriteLine("New standard pattern from file = {0}", core.PatternStandardPath);
                    }
                    else
                    {
                        PLog.WriteLine("Error incorrect number of arguments. Use ERC --config SetStandardPattern <PATH>");
                    }
                    //return core.PatternStandardPath;
                    PLog.WriteLine("--------------------------------------------");
                    return;
                case "setextendedpattern":
                    if (parameters.Count == 2)
                    {
                        if (!File.Exists(parameters[1]))
                        {
                            PrintHelp("The file does not exist, the value provided must be a filename.");
                            return;
                        }
                        core.SetPatternExtendedPath(parameters[1]);
                        PLog.WriteLine("New extended pattern from file = {0}", core.PatternExtendedPath);
                    }
                    else
                    {
                        PLog.WriteLine("Error incorrect number of arguments. Use ERC --config SetExtendedPattern <PATH>");
                    }
                    //return core.PatternExtendedPath;
                    PLog.WriteLine("--------------------------------------------");
                    return;
                default:
                    PLog.WriteLine("Configuration Settings:");
                    PLog.WriteLine("Working Directory = {0}", core.WorkingDirectory);
                    PLog.WriteLine("ERC Version = {0}", core.ErcVersion);
                    PLog.WriteLine("Author = {0}", core.Author);
                    PLog.WriteLine("Error Log File = {0}", core.SystemErrorLogPath);
                    PLog.WriteLine("Standard Pattern Location = {0}", core.PatternStandardPath);
                    PLog.WriteLine("Standard Pattern Location = {0}", core.PatternExtendedPath);
                    //return null;
                    PLog.WriteLine("--------------------------------------------");
                    return;
            }
        }

        private static void Pattern(ERC.ErcCore core, List<string> parameters)
        {
            PLog.WriteLine("ERC --Pattern");
            PLog.WriteLine("----------------------------------------------------------------------");
            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].Contains("--"))
                {
                    parameters.Remove(parameters[i]);
                }
            }

            int patternLength = 0;
            string search = "";
            bool extended = Globals.extended;
            bool offset = false;
            bool create = false;

            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].ToLower() == "create" || parameters[i].ToLower() == "c")
                {
                    create = true;
                }
                else if(parameters[i].ToLower() == "offset" || parameters[i].ToLower() == "o")
                {
                    offset = true;
                }
            }

            if(create == true && offset == true)
            {
                PrintHelp("A pattern create and pattern offset operation can not be executed at the same time. Please choose one or the other.");
                return;
            }

            if (create == false && offset == false)
            {
                PrintHelp("A create or offset operation must be specified as part of the pattern command. ERC --pattern <create(c) or offset(o)> <parameters>");
                return;
            }

            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i] == "create" || parameters[i] == "offset" 
                    || parameters[i] == "c" || parameters[i] == "o")
                {
                    parameters.Remove(parameters[i]);
                }
            }

            if(parameters.Count > 2)
            {
                PrintHelp("Too many parameters provided.");
                return;
            }

            if (create == true)
            {
                for (int i = 0; i < parameters.Count; i++)
                {
                    if (parameters[i] == "true")
                    {
                        extended = true;
                        if (parameters.Count == 1)
                        {
                            PrintHelp("A valid integer must be provided for the pattern length.");
                            return;
                        }
                    }
                    else
                    {
                        if (int.TryParse(parameters[i], out patternLength))
                        {
                            if (patternLength > 20277 && patternLength < 66923)
                            {
                                extended = true;
                            }
                            else if (patternLength > 66923)
                            {
                                PrintHelp("Maximum length of the pattern is 66923.");
                                return;
                            }
                        }  
                        else
                        {
                            PrintHelp("A valid integer must be provided for the pattern length.");
                            return;
                        }
                    }
                }
                var result = ERC.DisplayOutput.GeneratePattern(patternLength, core, extended);
                PLog.Write(result + "\n");
            }
            else if(offset == true)
            {
                for(int i = 0; i < parameters.Count; i++)
                {
                    if(parameters[i] == "true")
                    {
                        extended = true;
                        if (parameters.Count == 1)
                        {
                            PrintHelp("A search string must be provided.");
                            return;
                        }
                    }
                    else
                    {
                        search = parameters[i];
                    }
                }
                string extendedCharSet = ": ,.;+= -_! & ()#@'*^[]%$?";
                foreach (char c in search)
                {
                    if (extendedCharSet.Contains(c))
                    {
                        extended = true;
                    }
                }
                var result = ERC.Utilities.PatternTools.PatternOffset(search, core, extended);
                PLog.WriteLine(result.ReturnValue);
            }
            PLog.WriteLine("----------------------------------------------------------------------");
            return;
        }

        private static void ByteArray(List<string> parameters, ERC.ErcCore core)
        {
            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].Contains("--"))
                {
                    parameters.Remove(parameters[i]);
                }
            }

            byte[] byteArray = ERC.DisplayOutput.GenerateByteArray(core, Globals.bytes);

            if(Globals.bytes.Length > 0)
            {
                PLog.WriteLine("Byte Array excluding: " + BitConverter.ToString(Globals.bytes).Replace('-', ' '));
            }
            else
            {
                PLog.WriteLine("Byte Array: ");
            }

            PLog.WriteLine("--------------------------------");
            PLog.Write("|");
            string[] hexBytes = BitConverter.ToString(byteArray).Replace('-', ' ').Split(' ');
            int lineLength = 0;
            for(int i = 0; i < hexBytes.Length; i++)
            {
                if(i % 10 == 0 && i > 1)
                {
                    PLog.Write(" |\n| " + hexBytes[i]);
                    lineLength = 3;
                }
                else
                {
                    PLog.Write(" " + hexBytes[i]);
                    lineLength += 3;
                }
            }

            for(int i = lineLength; i < 32; i++)
            {
                if(i != 31)
                {
                    PLog.Write(" ");
                }
                else
                {
                    PLog.Write("|\n");
                }
            }
            PLog.WriteLine("--------------------------------");
            //return hexBytes;
            return;
        }

        private static void Compare(ERC.ProcessInfo info, List<string> parameters)
        {
            string allowedChars = "abcdefABCDEF1234567890";
            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].Contains("--"))
                {
                    parameters.Remove(parameters[i]);
                }
            }

            if (parameters.Count != 2)
            {
                PrintHelp("Incorrect parameters provided. Compare must be run as \"ERC --compare <start address> <file containing bytes>");
                return;
            }

            if(parameters[0].StartsWith("0x") || parameters[0].StartsWith("x") 
                || parameters[0].StartsWith("\\x") || parameters[0].StartsWith("X"))
            {
                parameters[0] = parameters[0].Replace("0x", "");
                parameters[0] = parameters[0].Replace("\\x", "");
                parameters[0] = parameters[0].Replace("X", "");
                parameters[0] = parameters[0].Replace("x", "");
            }

            if (parameters[1].StartsWith("0x") || parameters[1].StartsWith("x")
                || parameters[1].StartsWith("\\x") || parameters[1].StartsWith("X"))
            {
                parameters[1] = parameters[1].Replace("0x", "");
                parameters[1] = parameters[1].Replace("\\x", "");
                parameters[1] = parameters[1].Replace("X", "");
                parameters[1] = parameters[1].Replace("x", "");
            }

            bool validAddress = true;
            string path = "";
            IntPtr address = IntPtr.Zero;
            double addrHolder = 0;
            string memAddress = "";

            if (File.Exists(parameters[0]))
            {
                path = parameters[0];
                if (parameters[1].Length <= 16)
                {
                    foreach (char c in parameters[1])
                    {
                        if (!allowedChars.Contains(c))
                        {
                            validAddress = false;
                        }
                    }
                    if(parameters[1].Length < 16)
                    { 
                        for(int i = parameters[1].Length; i < 16; i++)
                        {
                            memAddress += 0;
                        }
                        parameters[1] = memAddress + parameters[1];
                    }
                    addrHolder = (double)System.Convert.ToInt64(parameters[1], 16);
                    address = (IntPtr)addrHolder;
                }
                else
                {
                    validAddress = false;
                }
            }
            else if(File.Exists(parameters[1]))
            {
                path = parameters[1];
                if (parameters[0].Length <= 16)
                {
                    foreach (char c in parameters[0])
                    {
                        if (!allowedChars.Contains(c))
                        {
                            validAddress = false;
                        }
                    }
                    if (parameters[0].Length < 16)
                    {
                        for (int i = parameters[0].Length; i < 16; i++)
                        {
                            memAddress += 0;
                        }
                        parameters[0] = memAddress + parameters[0];
                    }
                    addrHolder = (double)System.Convert.ToInt64(parameters[0], 16);
                    address = (IntPtr)addrHolder;
                }
                else
                {
                    validAddress = false;
                }
            }
            else
            {
                PrintHelp("Must provide a valid file path for byte array. Compare must be run as \"ERC --compare <start address> <file containing bytes>");
                return;
            }

            if(validAddress == false)
            {
                PrintHelp("Start address may only contain hex characters and must be less than 16 characters. Compare must be run as \"ERC --compare <start address> <file containing bytes>");
                return;
            }

            byte[] bytes = File.ReadAllBytes(path);
            string[] output = ERC.DisplayOutput.CompareByteArrayToMemoryRegion(info, address, bytes);

            /* Race condition: Order of logged items is not guaranteed to be the order presented due to fault in x64dbg. */
            // Dirty thread sleep - ideally wouldn't have to do this.
            Thread.Sleep(500);
            PLog.WriteLine("Comparing memory region starting at 0x{0} to bytes in file {1}", 
                address.ToString("X"), path);
            Thread.Sleep(200);
            /* There is a maximum length of accepted string on x64dbg side, so let's output line-by-line */
            foreach (string l in output)
            {
                PLog.WriteLineHtml(l);
            }
            /* Sleep upon completion so ERC register/unregister messages don't collide with above */
            Thread.Sleep(200);
            return;
        }

        private static void Convert(ERC.ProcessInfo info, List<string> parameters)
        {
            PLog.WriteLine("ERC --Convert");
            PLog.WriteLine("----------------------------------------------------------------------");
            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].Contains("--"))
                {
                    parameters.Remove(parameters[i]);
                }
            }

            string output = "";

            switch (parameters[0].ToLower())
            {
                case "atoh":
                    parameters.Remove(parameters[0]);
                    output = "The string " + String.Join(" ", parameters) + " encoded as ASCII has the following byte sequence:\n";
                    output += "0x" + ERC.Utilities.Convert.AsciiToHex(String.Join(" ", parameters)).Replace(" ", " 0x");
                    PLog.WriteLine(output);
                    break;
                case "utoh":
                    parameters.Remove(parameters[0]);
                    output = "The string " + String.Join(" ", parameters) + " encoded as Unicode has the following byte sequence:\n";
                    output += "0x" + ERC.Utilities.Convert.UnicodeToHex(String.Join(" ", parameters)).Replace(" ", " 0x");
                    PLog.WriteLine(output);
                    break;
                case "7toh":
                    parameters.Remove(parameters[0]);
                    output = "The string " + String.Join(" ", parameters) + " encoded as UTF-7 has the following byte sequence:\n";
                    output += "0x" + ERC.Utilities.Convert.UTF7ToHex(String.Join(" ", parameters)).Replace(" ", " 0x");
                    PLog.WriteLine(output);
                    break;
                case "8toh":
                    parameters.Remove(parameters[0]);
                    output = "The string " + String.Join(" ", parameters) + " encoded as UTF-8 has the following byte sequence:\n";
                    output += "0x" + ERC.Utilities.Convert.UTF8ToHex(String.Join(" ", parameters)).Replace(" ", " 0x");
                    PLog.WriteLine(output);
                    break;
                case "32toh":
                    parameters.Remove(parameters[0]);
                    output = "The string " + String.Join(" ", parameters) + " encoded as UTF-32 has the following byte sequence:\n";
                    output += "0x" + ERC.Utilities.Convert.UTF32ToHex(String.Join(" ", parameters)).Replace(" ", " 0x");
                    PLog.WriteLine(output);
                    break;
                default:
                    PLog.WriteLine("Incorrect parameters provided. Convert must be run as \"ERC --convert <conversion type> <input>");
                    PLog.WriteLine("Valid conversion types:\n    Ascii to Hex = AtoH\n    Unicdoe to Hex = UtoH\n    UTF-7 to Hex = 7toH\n" +
                        "    UTF-8 to Hex = 8toH\n    UTF-32 to Hex = 32toH\n");
                    PLog.WriteLine("----------------------------------------------------------------------");
                    return;
            }
            PLog.WriteLine("----------------------------------------------------------------------");
        }

        private static void Assemble(ERC.ProcessInfo info, List<string> parameters)
        {
            PLog.WriteLine("ERC --Assemble");
            PLog.WriteLine("----------------------------------------------------------------------");
            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].Contains("--"))
                {
                    parameters.Remove(parameters[i]);
                }
            }

            if (parameters.Count == 0)
            {
                PLog.WriteLine("No parameters provided. Assemble must be run: ERC --Assemble [1:0] <mnemonics>");
                //return null;
                return;
            }

            int n = -1;
            List<int> elementsToRemove = new List<int>();
            for (int i = 0; i < parameters.Count; i++)
            {
                if (i <= parameters.Count)
                {
                    if (Regex.IsMatch(parameters[i], @"^\d+$"))
                    {
                        if(parameters[i] == "0")
                        {
                            elementsToRemove.Add(i);
                            n = 0;
                        }
                        else if(parameters[i] == "1")
                        {
                            elementsToRemove.Add(i);
                            n = 1;
                        }
                    }
                }               
            }

            foreach(int i in elementsToRemove)
            {
                parameters.Remove(parameters[i]);
            }

            if(n == -1)
            {
                if(info.ProcessMachineType == ERC.MachineType.I386)
                {
                    n = 0;
                }
                else
                {
                    n = 1;
                }
            }

            try
            {
                List<string> instructions = string.Join(" ", parameters).Split(',').ToList();
                foreach (string s in instructions)
                {
                    List<string> instruction = new List<string>();
                    instruction.Add(s.Trim());
                    var asmResult = ERC.Utilities.OpcodeAssembler.AssembleOpcodes(instruction, info.ProcessMachineType);
                    PLog.WriteLine(instruction[0] + " = " + BitConverter.ToString(asmResult.ReturnValue).Replace("-", " "));
                }
                PLog.WriteLine("Assembly completed at {0} by {1}", DateTime.Now, info.Author);
            }
            catch (Exception e)
            {
                PLog.WriteLine("An error occured calling the assemble method. Error: {0}\nThe command should be structured ERC --assemble [1|0] <mnemonics>.", e.Message);
            }
            //return new List<string>(assembled);
            PLog.WriteLine("----------------------------------------------------------------------");
            return;
        }

        private static void Disassemble(ERC.ProcessInfo info, List<string> parameters)
        {
            PLog.WriteLine("ERC --Disassemble");
            PLog.WriteLine("----------------------------------------------------------------------");
            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].Contains("--"))
                {
                    parameters.Remove(parameters[i]);
                }
            }

            if (parameters.Count <= 0)
            {
                PLog.WriteLine("No parameters provided. Disassemble must be run: ERC --Disassemble [1|0] <opcodes>");
                //return null;
                return;
            }

            int n = -1;
            List<int> elementsToRemove = new List<int>();
            for (int i = 0; i < parameters.Count; i++)
            {
                if (i <= parameters.Count)
                {
                    if (Regex.IsMatch(parameters[i], @"^\d+$"))
                    {
                        if (parameters[i] == "0")
                        {
                            elementsToRemove.Add(i);
                            n = 0;
                        }
                        else if (parameters[i] == "1")
                        {
                            elementsToRemove.Add(i);
                            n = 1;
                        }
                    }
                }
            }

            foreach (int i in elementsToRemove)
            {
                parameters.Remove(parameters[i]);
            }

            if (n == -1)
            {
                if (info.ProcessMachineType == ERC.MachineType.I386)
                {
                    n = 0;
                }
                else
                {
                    n = 1;
                }
            }

            string opcodeChars = string.Join("", parameters.ToArray());
            string allowedChars = "abcdefABCDEF1234567890";
            opcodeChars = opcodeChars.Replace("\\x", "");
            opcodeChars = opcodeChars.Replace("0x", "");
            opcodeChars = opcodeChars.Replace(" ", "");
            string hexChars = "";
            for(int i = 0; i < opcodeChars.Length; i++)
            {
                if (allowedChars.Contains(opcodeChars[i].ToString()))
                {
                    hexChars = hexChars + opcodeChars[i];
                }
            }
            if(hexChars.Length % 2 != 0)
            {
                hexChars += "0";
            }

            List<string> opcodes = new List<string>();

            var bytes = StringToByteArray(hexChars);

            foreach(string s in opcodes)
            {
                PLog.WriteLine(s);
            }

            var disassembled = ERC.DisplayOutput.DisassembleOpcodes(bytes, (uint)n);
            PLog.WriteLine("ERC Disassebled Instructions:");
            foreach (string s in disassembled)
            {
                PLog.WriteLine(s);
            }
            PLog.WriteLine("Disassembly completed at {0} by {1}", DateTime.Now, info.Author);
            //return new List<string>(disassembled);
            PLog.WriteLine("----------------------------------------------------------------------");
            return;
        }
        
        private static void SearchMemory(ERC.ProcessInfo info, List<string> parameters)
        {
            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].Contains("--"))
                {
                    parameters.Remove(parameters[i]);
                }
            }

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
            var output = ERC.DisplayOutput.SearchMemory(info, searchType, searchString, Globals.aslr, Globals.safeseh, Globals.rebase, Globals.nxcompat,
                Globals.osdll, Globals.bytes, Globals.protection) ;
            foreach(string s in output)
            {
                PLog.WriteLine(s);
            }
        }

        private static void SearchModules(ERC.ProcessInfo info, List<string> parameters)
        {
            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].Contains("--"))
                {
                    parameters.Remove(parameters[i]);
                }
            }

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

            List<string> includedModules = new List<string>();

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
            var output = ERC.DisplayOutput.SearchModules(info, searchType, searchString, Globals.aslr, Globals.safeseh, Globals.rebase, Globals.nxcompat,
                Globals.osdll, Globals.bytes, includedModules, Globals.protection);
            foreach (string s in output)
            {
                PLog.WriteLine(s);
            }
        }

        private static void DumpMemory(ERC.ProcessInfo info, List<string> parameters)
        {
            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].Contains("--"))
                {
                    parameters.Remove(parameters[i]);
                }
            }

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

        private static void SEH(List<string> parameters, ERC.ProcessInfo info) 
        {
            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].Contains("--"))
                {
                    parameters.Remove(parameters[i]);
                }
            }

            if(info.ProcessMachineType == ERC.MachineType.x64)
            {
                PLog.WriteLine("WARNING: This function will find pop pop ret instructions however please be aware that SEH overflows will not work on the 64bit architecture.");
            }

            List<string> sehJumpAddresses = new List<string>();

            bool aslr = Globals.aslr, safeseh = Globals.safeseh, rebase = Globals.rebase, nxcompat = Globals.nxcompat, osdll = Globals.osdll;

            if(Globals.bytes.Length > 0)
            {
                if(Globals.encode == Encoding.Unicode)
                {
                    sehJumpAddresses = ERC.DisplayOutput.GetSEHJumpsUnicode(info, aslr, safeseh, rebase, nxcompat, osdll, Globals.bytes, Globals.protection).ToList();
                }
                else
                {
                    sehJumpAddresses = ERC.DisplayOutput.GetSEHJumps(info, aslr, safeseh, rebase, nxcompat, osdll, Globals.bytes, Globals.protection).ToList();
                }
            }
            else
            {
                if (Globals.encode == Encoding.Unicode)
                {
                    sehJumpAddresses = ERC.DisplayOutput.GetSEHJumpsUnicode(info, aslr, safeseh, rebase, nxcompat, osdll, null, Globals.protection).ToList();
                }
                else
                {
                    sehJumpAddresses = ERC.DisplayOutput.GetSEHJumps(info, aslr, safeseh, rebase, nxcompat, osdll, null, Globals.protection).ToList();
                } 
            }

            foreach(string s in sehJumpAddresses)
            {
                PLog.WriteLine(s);
            }
            
            //return sehJumpAddresses;
            return;
        }

        private static void EggHunters(ERC.ErcCore core = null, string tag = null)
        {
            string holder = ERC.DisplayOutput.GenerateEggHunters(core, tag);
            Plugins._plugin_logputs(holder);
        }

        private static void FindNRP(ERC.ProcessInfo info, List<string> parameters)
        {
            if((int)Globals.encode < 0 || (int)Globals.encode > 5)
            {
                Globals.encode = Encoding.ASCII;
            }

            List<string> nrpInfo = new List<string>();
            nrpInfo = ERC.DisplayOutput.GenerateFindNRPTable(info, (int)Globals.encode, Globals.extended).ToList();

            foreach (string s in nrpInfo)
            {
                PLog.WriteLine(s);
            }
            //return nrpInfo;
            return;
        }

        private static void HeapInfo(ERC.ProcessInfo info, List<string> parameters)
        {
            bool heapids = false;
            bool dumpheap = false;
            bool heapstats = false;
            bool searchheap = false;

            string hexStartAddress = "";
            ulong heapID = 0;
            bool writeToFile = true;
            byte[] bytes = null;

            ERC.HeapInfo hi = new ERC.HeapInfo(info);

            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].Contains("--"))
                {
                    parameters.Remove(parameters[i]);
                }
            }

            if (parameters.Count == 0)
            {
                heapstats = true;
            }

            for (int i = 0; i < parameters.Count && i >= 0; i++)
            {
                if (parameters[i].ToLower() == "ids")
                {
                    heapids = true;
                    parameters.Remove(parameters[i]);
                    i--;
                }
                else if (parameters[i].ToLower() == "stats")
                {
                    heapstats = true;
                    parameters.Remove(parameters[i]);
                    i--;
                }
                else if (parameters[i].ToLower() == "dump")
                {
                    dumpheap = true;
                    parameters.Remove(parameters[i]);
                    i--;
                }
                else if (parameters[i].ToLower() == "search")
                {
                    searchheap = true;
                    parameters.Remove(parameters[i]);
                    i--;
                }
                else if (parameters[i].ToLower() == "true" || parameters[i].ToLower() == "false")
                {
                    writeToFile = parameters[i].ToLower() == "true";
                    parameters.Remove(parameters[i]);
                    i--;
                }
                else if (parameters[i].ToLower() == "1" || parameters[i].ToLower() == "0")
                {
                    writeToFile = parameters[i].ToLower() == "1";
                    parameters.Remove(parameters[i]);
                    i--;
                }
                else if(ulong.TryParse(parameters[i].ToLower(), out heapID))
                {
                    parameters.Remove(parameters[i]);
                    i--;
                }
                else if(Regex.IsMatch(parameters[i], @"\A\b[0-9a-fA-F]+\b\Z"))
                {
                    string searchString = string.Join("", parameters);
                    if (hexStartAddress == "")
                    {
                        hexStartAddress = parameters[i];
                        parameters.Remove(parameters[i]);
                        i--;
                    }
                    else
                    {
                        bytes = ERC.Utilities.Convert.HexToBytes(searchString);
                    }
                }
                else
                {
                    string searchString = string.Join("", parameters);
                    bytes = StringToByteArray(searchString);
                }
            }

            if (searchheap == true)
            {
                if(hexStartAddress != "" && bytes == null)
                {
                    bytes = ERC.Utilities.Convert.HexToBytes(hexStartAddress);
                    hexStartAddress = "";
                }

                var result = ERC.DisplayOutput.SearchHeap(hi, bytes, heapID, hexStartAddress, writeToFile);
                foreach (string s in result)
                {
                    PLog.Write(s);
                }
                PLog.Write(Environment.NewLine);
            }

            if (heapids == true)
            {
                foreach(string s in ERC.DisplayOutput.ListHeapIDs(hi))
                {
                    PLog.Write(s);
                }
                PLog.Write(Environment.NewLine);
            }

            if (heapstats == true)
            {
                var result = ERC.DisplayOutput.HeapStats(hi);
                foreach (string s in result)
                {
                    PLog.Write(s);
                }
                PLog.Write(Environment.NewLine);
            }

            if(dumpheap == true)
            {
                var result = ERC.DisplayOutput.DumpHeap(hi, heapID, hexStartAddress, writeToFile);
                foreach (string s in result)
                {
                    PLog.Write(s);
                }
                PLog.Write(Environment.NewLine);
            }
        }

        private static void rop(ERC.ProcessInfo info, bool gadgetsOnly = false)
        {
            PLog.WriteLine("Starting to build ROP Chains.");
            ERC.Utilities.RopChainGenerator32 RCG = new ERC.Utilities.RopChainGenerator32(info);
            //ERC.Utilities.RopChainGenerator64 RCG = new ERC.Utilities.RopChainGenerator64(info);
            List<string> excludes = new List<string>();
            foreach(ERC.ModuleInfo mi in info.ModulesInfo)
            {
                if(!mi.ModuleASLR == Globals.aslr || !mi.ModuleNXCompat == Globals.nxcompat || !mi.ModuleOsDll == Globals.osdll || !mi.ModuleSafeSEH == Globals.safeseh
                    || !mi.ModuleRebase == Globals.rebase)
                {
                    excludes.Add(mi.ModulePath);
                }
            }

            try
            {
                if(gadgetsOnly == true)
                {
                    PLog.WriteLine("Generating ROP chain files...");
                    if (Globals.bytes.Length > 0 || excludes.Count > 0)
                    {
                        RCG.GenerateRopGadgets32(Globals.bytes, excludes);           //Uncomment if 32 bit
                        //RCG.GenerateRopGadgets64(Globals.bytes, excludes);           //Uncomment if 64 bit
                    }
                    else
                    {
                        RCG.GenerateRopGadgets32();           //Uncomment if 32 bit
                        //RCG.GenerateRopGadgets64();           //Uncomment if 64 bit
                    }
                    PLog.WriteLine("ROP chain generation completed. Files can be found in {0}", info.WorkingDirectory);
                }
                else
                {
                    PLog.WriteLine("Generating ROP chain files...");
                    if(Globals.bytes.Length > 0 || excludes.Count > 0)
                    {
                        var ropHolder = RCG.GenerateRopChain32(Globals.bytes, excludes); //Uncomment if 32 bit
                        //var ropHolder = RCG.GenerateRopChain64(Globals.bytes, excludes);             //Uncomment if 64 bit
                        PLog.WriteLine(ropHolder.ReturnValue);

                    }
                    else
                    {
                        var ropHolder = RCG.GenerateRopChain32();             //Uncomment if 32 bit
                        //var ropHolder = RCG.GenerateRopChain64();              //Uncomment if 64 bit
                        PLog.WriteLine(ropHolder.ReturnValue);
                    }
                    PLog.WriteLine("ROP chain generation completed. Files can be found in {0}", info.WorkingDirectory);
                }
            }
            catch(Exception e)
            {
                PrintHelp(e.Message);
            }
            finally
            {
                RCG = null;
                GC.Collect();
            }
            
            return;
        }

        private static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => System.Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        private static string ByteArrayToString(byte[] ba)
        {
            return BitConverter.ToString(ba).Replace("-", "");
        }

        private static void DeleteOldPlugins()
        {
            //Get list of files in the plugins directory. Delete old versions of the plugin.
            try
            {
                string path = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                if (path.Contains("\\x32\\"))
                {
                    path = path.Replace("\\x32\\", "\\x64\\");
                }
                string[] files = Directory.GetFiles(path);
                foreach (string s in files)
                {
                    if (s.Contains("Erc.Xdbg.dp64-OLD") || s.Contains("Erc.Xdbg.dp32-OLD") || s.Contains(".zip"))
                    {
                        File.Delete(s);
                    }
                }
                path = path.Replace("\\x64\\", "\\x32\\");
                files = Directory.GetFiles(path);
                foreach (string s in files)
                {
                    if (s.Contains("Erc.Xdbg.dp64-OLD") || s.Contains("Erc.Xdbg.dp32-OLD") || s.Contains(".zip"))
                    {
                        File.Delete(s);
                    }
                }
            }
            catch (Exception e)
            {
                PLog.WriteLine("ERROR: " + e.Message);
            }
        }

        private static void Debug(ERC.ProcessInfo info, List<string> parameters)
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

            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].Contains("--"))
                {
                    parameters.Remove(parameters[i]);
                }
            }

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
                PLog.WriteLine("ASLR       = {0}", Globals.aslr.ToString());
                PLog.WriteLine("SafeSEH    = {0}", Globals.safeseh.ToString());
                PLog.WriteLine("Rebase     = {0}", Globals.rebase.ToString());
                PLog.WriteLine("NXCompat   = {0}", Globals.nxcompat.ToString());
                PLog.WriteLine("OSDll      = {0}", Globals.osdll.ToString());
                PLog.WriteLine("Bytes      = {0}", ByteArrayToString(Globals.bytes));
                PLog.WriteLine("Protection = {0}", Globals.protection);
                PLog.WriteLine("Extended   = {0}", Globals.extended.ToString());
                PLog.WriteLine("Encoding   = {0}\n", Globals.encode.ToString());
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
                Config(nullParams, info);
            }
        }

        private static void Debug(List<string> parameters)
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

            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].Contains("--"))
                {
                    parameters.Remove(parameters[i]);
                }
            }

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
                PLog.WriteLine("ASLR       = {0}", Globals.aslr.ToString());
                PLog.WriteLine("SafeSEH    = {0}", Globals.safeseh.ToString());
                PLog.WriteLine("Rebase     = {0}", Globals.rebase.ToString());
                PLog.WriteLine("NXCompat   = {0}", Globals.nxcompat.ToString());
                PLog.WriteLine("OSDll      = {0}", Globals.osdll.ToString());
                PLog.WriteLine("Bytes      = {0}", ByteArrayToString(Globals.bytes));
                PLog.WriteLine("Protection = {0}", Globals.protection);
                PLog.WriteLine("Extended   = {0}", Globals.extended.ToString());
                PLog.WriteLine("Encoding   = {0}\n", Globals.encode.ToString());
            }

            if (showArgs == true)
            {
                PLog.WriteLine("DEBUG: Args ");
                PLog.WriteLine("--------------------------------------------");
                PLog.WriteLine("Args = {0}\n", string.Join(" ", arg.ToArray()));
            }
        }

        private static void Reset(ERC.ProcessInfo info, List<string> parameters)
        {
            Globals.aslr = false;
            Globals.safeseh = false;
            Globals.rebase = false;
            Globals.nxcompat = false;
            Globals.osdll = false;
            Globals.extended = false;
            Globals.encode = Encoding.ASCII;
            Globals.bytes = new byte[0];
            Globals.protection = "read,write";

            string path = Path.GetDirectoryName(Assembly.GetExecutingAssembly().CodeBase);
            path = path.Replace("file:\\", "");
            File.Delete(path + "ERC_Config.xml");

            PLog.WriteLine("ERC Rests: All configuration settings have been reset to the default values.");
            PLog.WriteLine("--------------------------------------------");
        }

        private static void Reset()
        {
            Globals.aslr = false;
            Globals.safeseh = false;
            Globals.rebase = false;
            Globals.nxcompat = false;
            Globals.osdll = false;
            Globals.extended = false;
            Globals.encode = Encoding.ASCII;
            Globals.bytes = new byte[0];
            Globals.protection = "read,write";

            string path = Path.GetDirectoryName(Assembly.GetExecutingAssembly().CodeBase);
            path = path.Replace("file:\\", "");
            File.Delete(path + "ERC_Config.xml");

            PLog.WriteLine("ERC Rests: All configuration settings have been reset to the default values.");
            PLog.WriteLine("--------------------------------------------");
        }
    }
}
