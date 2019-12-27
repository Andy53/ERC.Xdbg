using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
                    PrintHelp("Arguments must be provided. Use --help for detailed information.");
                    return true;
                }

                //Check a process is attached.
                if (hProcess == IntPtr.Zero)
                {
                    PrintHelp("The debugger must be attached to a process to use ERC");
                    return true;
                }
                PLog.WriteLine("");
                GC.Collect();

                ERC.ErcCore core = new ERC.ErcCore();
                ERC.ProcessInfo info = new ERC.ProcessInfo(new ERC.ErcCore(), hProcess);

                ParseCommand(argv[0], core, info);
            }
            catch(Exception e)
            {
                PrintHelp(e.Message);
                ErcXdbg.PluginStop();
                ErcXdbg.PluginStart();
                PLog.WriteLine("Operation Completed");
                return true;
            }
            ErcXdbg.PluginStop();
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
            help += "Usage:       \n";
            help += "   --Help          |\n";
            help += "       Displays this message. Further help can be found at: https://github.com/Andy53/ERC.Xdbg/tree/master/ErcXdbg \n";
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
            help += "   --Pattern       |\n";
            help += "       Generates a non repeating pattern. A pattern of pure ASCII characters can be generated up to 20277 and up to  \n";
            help += "       66923 if special characters are used. The offset of a particular string can be found inside the pattern by \n";
            help += "       providing a search string (must be at least 3 chars long).\n";
            help += "           Pattern create: ERC --pattern <create | c> <length>\n";
            help += "           Pattern offset: ERC --pattern <offset | o> <search string>\n";
            help += "   --Bytearray     |\n";
            help += "       Generates a bytearray which is saved to the working directory and displayed in the application log tab. An set \n";
            help += "       hex characters can be provided which will be excluded from the bytearray.";
            help += "   --Compare       |\n";
            help += "       Generates a table with a byte by byte comparison of an area of memory and the bytes from a file. Takes a memory \n";
            help += "       from which to start the search and a filepath for the binary file\n"; 
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
            help += "       type (0 = bytes, 1 = Unicode, 2 = ASCII, 4 = UTF7, 5 = UTF8. Additionally boolean values of true or false can \n";
            help += "       be used to exclude modules from the search with certain characteristics. The values are optional however if \n";
            help += "       you wish to exclude a later value all previous ones must be included. Order is ASLR, SAFESEH, REBASE, NXCOMPAT, \n";
            help += "       OSDLL.\n";       
            help += "       Example: ERC --SearchMemory FF E4 false false false false true. Search for bytes FF E4 excluding only OS dll's\n";
            help += "       Example: ERC --SearchMemory FF E4. Search for bytes FF E4 including all dll's \n";
            help += "       Example: ERC --SearchMemory FF E4 true true. Search for bytes FF E4 excluding only dll's with ASLR and SafeSEH\n"; 
            help += "       enabled\n";
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
            help += "       Displays a list of addresses for pop pop ret instructions. Can be passed a list of module paths to be ignored\n"; 
            help += "       in the search.\n";
            help += "   --EggHunters    |\n";
            help += "       Prints a list of egghunters which can be used for various machine types. Can be passed 4 character string to be\n"; 
            help += "       used as the egghunter search tag. Default tag is ERCD.\n";
            help += "   --FindNrp       |\n";
            help += "       Generates a table detailing whether a repeating pattern has been found in the memory space of the process and\n";
            help += "       if any registers pointed into the pattern. Takes an integer for the text to look for (1 = Unicode, 2 = ASCII,\n";
            help += "       3 = UTF8, 4 = UTF7, 5 = UTF32, default = ASCII). Additionally if the value \"True\" is provided the extended \n";
            help += "       pattern will be used which includes special characters.\n";
            help += "   --Rop           |\n";
            help += "       Much like the lottery you can try your luck and your life may get much easier, however it probably wont...\n";
            PLog.WriteLine(help);
        }

        private static void ParseCommand(string command, ERC.ErcCore core, ERC.ProcessInfo info)
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
                    case "--assemble":
                        Assemble(info, parameters);
                        return;
                    case "--disassemble":
                        Disassemble(info, parameters);
                        return;
                    case "--searchmemory":
                        SearchMemory(info, parameters);
                        return;
                    case "--listprocesses":
                        PLog.WriteLine(ERC.DisplayOutput.ListLocalProcesses());
                        return;
                    case "--processinfo":
                        if(parameters.Count == 2)
                        {
                            if(parameters[1].ToLower() == "false")
                            {
                                writeToFile = false;
                            }
                        }
                        PLog.WriteLine("\n" + ERC.DisplayOutput.DisplayProcessInfo(info, writeToFile));
                        return;
                    case "--moduleinfo":
                        if (parameters.Count == 2)
                        {
                            if (parameters[1].ToLower() == "false")
                            {
                                writeToFile = false;
                            }
                        }
                        PLog.WriteLine("\n" + ERC.DisplayOutput.GenerateModuleInfoTable(info, writeToFile));
                        return;
                    case "--threadinfo":
                        if (parameters.Count == 2)
                        {
                            if (parameters[1].ToLower() == "false")
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
                    case "--rop":
                        rop(info);
                        return;
                    default:
                        PrintHelp("The command was not structured correctly: Option is not supported. ERC <option> <parameters>");
                        return;
                }
            }
            return;
        }

        private static void Config(List<string> parameters, ERC.ErcCore core)
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
                    //return core.WorkingDirectory;
                    return;
                case "getversion":
                    PLog.WriteLine("ERC Version = {0}", core.ErcVersion);
                    //return core.ErcVersion;
                    return;
                case "getauthor":
                    PLog.WriteLine("Author = {0}", core.Author);
                    //return core.Author;
                    return;
                case "geterrorlogpath":
                    PLog.WriteLine("Error Log File = {0}", core.SystemErrorLogPath);
                    //return core.SystemErrorLogPath;
                    return;
                case "getstandardpattern":
                    PLog.WriteLine("Standard Pattern Location = {0}", core.PatternStandardPath);
                    //return core.PatternStandardPath;
                    return;
                case "getextendedpattern":
                    PLog.WriteLine("Standard Pattern Location = {0}", core.PatternExtendedPath);
                    //return core.PatternExtendedPath;
                    return;
                case "setworkingdirectory":
                    if(parameters.Count == 2)
                    {
                        if (Directory.Exists(parameters[1]))
                        {
                            core.SetWorkingDirectory(parameters[1]);
                            PLog.WriteLine("New Working Directory = {0}", core.WorkingDirectory);
                            
                            return;
                        }
                        else
                        {
                            PrintHelp("Please provide a valid directory.");
                        }
                    }
                    else
                    {
                        PLog.WriteLine("Error incorrect number of arguments. Use ERC --config SetWorkingDirectory <PATH>");
                    }
                    //return core.WorkingDirectory;
                    return;
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
                    //return core.Author;
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
                    return;
                default:
                    PrintHelp("A syntax error was encountered when parsing the config command. Please review the documentation");
                    //return null;
                    return;
            }
        }

        private static void Pattern(ERC.ErcCore core, List<string> parameters)
        {
            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].Contains("--"))
                {
                    parameters.Remove(parameters[i]);
                }
            }

            int patternLength = 0;
            string search = "";
            bool extended = false;
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
                PLog.WriteLine("Pattern found at offset {0}", result.ReturnValue);
            }
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

            string opcodeChars = string.Join("", parameters.ToArray());
            string allowedChars = "abcdefABCDEF1234567890";
            opcodeChars = opcodeChars.Replace("\\x", "");
            opcodeChars = opcodeChars.Replace("0x", "");
            opcodeChars = opcodeChars.Replace(" ", "");
            string hexChars = "";
            for (int i = 0; i < opcodeChars.Length; i++)
            {
                if (allowedChars.Contains(opcodeChars[i].ToString()))
                {
                    hexChars = hexChars + opcodeChars[i];
                }
            }
            if (hexChars.Length % 2 != 0)
            {
                hexChars += "0";
            }

            byte[] bytes = StringToByteArray(hexChars);
            byte[] byteArray = ERC.DisplayOutput.GenerateByteArray(core, bytes);

            if(bytes.Length > 0)
            {
                PLog.WriteLine("Byte Array excluding: " + BitConverter.ToString(bytes).Replace('-', ' '));
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
                    addrHolder = (double)Convert.ToInt64(parameters[1], 16);
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
                    addrHolder = (double)Convert.ToInt64(parameters[0], 16);
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
            PLog.WriteLine("Comparing memory region starting at 0x{0} to bytes in file {1}", 
                address.ToString("X"), path);
            PLog.WriteLine(string.Join("\n", output));
            //return string.Join("\n", output);
            return;
        }

        private static void Assemble(ERC.ProcessInfo info, List<string> parameters)
        {
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
            for (int i = 0; i < parameters.Count; i++)
            {
                if(i >= parameters.Count)
                {
                    int.TryParse(parameters[1], out n);
                    if (n == 0 || n == 1)
                    {
                        parameters.Remove(parameters[i]);
                    }
                    else
                    {
                        n = -1;
                    }
                }               
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
            return;
        }

        private static void Disassemble(ERC.ProcessInfo info, List<string> parameters)
        {
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
            for (int i = 0; i < parameters.Count; i++)
            {
                if(i >= parameters.Count)
                {
                    int.TryParse(parameters[1], out n);
                    if (n == 0 || n == 1)
                    {
                        parameters.Remove(parameters[i]);
                    }
                }
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

            bool aslr = false, safeseh = false, rebase = false, nxcompat = false, osdll = false;
            int searchType = 0;
            string searchString = "";
            int counter = 0;
            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].ToLower().Contains("true") || parameters[i].ToLower().Contains("false"))
                {
                    bool modifier = false;
                    if (parameters[i].ToLower().Contains("true"))
                    {
                        modifier = true;
                    }
                    switch (counter)
                    {
                        case 0:
                            aslr = modifier;
                            break;
                        case 1:
                            safeseh = modifier;
                            break;
                        case 2:
                            rebase = modifier;
                            break;
                        case 3:
                            nxcompat = modifier;
                            break;
                        case 4:
                            osdll = modifier;
                            break;
                        default:
                            break;
                    }
                    counter++;
                    parameters.Remove(parameters[i]);
                    i--;
                }
                else if (parameters[i] == "0" || parameters[i] == "1" || parameters[i] == "2" ||
                    parameters[i] == "3" || parameters[i] == "4" || parameters[i] == "5")
                {
                    searchType = Int32.Parse(parameters[i]);
                    parameters.Remove(parameters[i]);
                    i--;
                }
            }

            searchString = string.Join("", parameters);
            var output = ERC.DisplayOutput.SearchMemory(info, searchType, searchString, aslr, safeseh, rebase, nxcompat,
                osdll);
            foreach(string s in output)
            {
                PLog.WriteLine(s);
            }
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

            if(parameters.Count >= 1)
            {
                sehJumpAddresses = ERC.DisplayOutput.GetSEHJumps(info, parameters);
                foreach(string s in sehJumpAddresses)
                {
                    PLog.WriteLine(s);
                }
            }
            else
            {
                sehJumpAddresses = ERC.DisplayOutput.GetSEHJumps(info);
                foreach (string s in sehJumpAddresses)
                {
                    PLog.WriteLine(s);
                }
            }
            //return sehJumpAddresses;
            return;
        }

        private static void EggHunters(ERC.ErcCore core = null, string tag = null)
        {
            string holder = ERC.DisplayOutput.GenerateEggHunters(core, tag);
            string[] lines = holder.Split(
                new[] { Environment.NewLine },
                StringSplitOptions.None
            );
            foreach(string s in lines)
            {
                if (!s.Contains("{") && !s.Contains("}"))
                {
                    PLog.WriteLine("{");
                    PLog.WriteLine(s);
                }
            }
        }

        private static void FindNRP(ERC.ProcessInfo info, List<string> parameters)
        {
            List<string> nrpInfo = new List<string>();
            if (parameters.Count >= 10)
            {
                if (parameters.Count == 3)
                {
                    if (int.TryParse(parameters[1], out int n))
                    {
                        if (parameters[2] == "true")
                        {
                            nrpInfo = ERC.DisplayOutput.GenerateFindNRPTable(info, n, true);
                        }
                        else
                        {
                            nrpInfo = ERC.DisplayOutput.GenerateFindNRPTable(info, n);
                        }
                    }
                    else if (int.TryParse(parameters[2], out int m))
                    {
                        if (parameters[1] == "true")
                        {
                            nrpInfo = ERC.DisplayOutput.GenerateFindNRPTable(info, m, true);
                        }
                        else
                        {
                            nrpInfo = ERC.DisplayOutput.GenerateFindNRPTable(info, m);
                        }
                    }
                }
                else
                {
                    bool isNumeric = int.TryParse(parameters[1], out int n);
                    if (isNumeric == true && n > 0 && n < 5)
                    {
                        nrpInfo = ERC.DisplayOutput.GenerateFindNRPTable(info, n);
                    }
                    else if (parameters[1] == "true")
                    {
                        nrpInfo = ERC.DisplayOutput.GenerateFindNRPTable(info, 0, true);
                    }
                    else
                    {
                        nrpInfo = ERC.DisplayOutput.GenerateFindNRPTable(info);
                    }
                }
            }
            else
            {
                nrpInfo = ERC.DisplayOutput.GenerateFindNRPTable(info);
            }
            foreach (string s in nrpInfo)
            {
                PLog.WriteLine(s);
            }
            //return nrpInfo;
            return;
        }

        private static void rop(ERC.ProcessInfo info)
        {
            ERC.Utilities.RopChainGenerator64 RCG = new ERC.Utilities.RopChainGenerator64(info);
            try
            {
                PLog.WriteLine("Generating ROP chain files, this could take some time...");
                RCG.GenerateRopChain64();             //Uncomment if 64 bit
                //RCG.GenerateRopChain32();             //Uncomment if 32 bit
                PLog.WriteLine("ROP chain generation completed. Files can be found in {0}", info.WorkingDirectory);
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
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}
