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
    public static partial class RegisteredCommands
    {
        /// <summary>
        /// Global switches, which persist until x64dbg restarts.
        /// </summary>
        /// <remarks>
        /// One object rather than the static mutable class this replaces. It is still
        /// process-wide, because the settings genuinely are per debugging session, but
        /// it can now be copied, reset and asserted on.
        /// </remarks>
        private static SessionState Session = new SessionState();

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
                    Reset(Session);
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
                                        Update(args, Session);
                                    }
                                    break;
                                case "--config":
                                    exitWithError = false;
                                    if (config == false)
                                    {
                                        config = true;
                                        List<string> args = argv[0].Split(' ').ToList<string>();
                                        args.RemoveAt(0);
                                        Config(args, coreTemp, Session);
                                    }
                                    break;
                                case "--debug":
                                    exitWithError = false;
                                    if (debug == false)
                                    {
                                        debug = true;
                                        List<string> args = argv[0].Split(' ').ToList<string>();
                                        args.RemoveAt(0);
                                        Debug(args, Session);
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

                // One core, shared. This used to construct two: one for "core" and a
                // second passed to ProcessInfo, so the two halves of a command read
                // and wrote separate configuration and logged to separate loggers.
                ERC.ErcCore core = new ERC.ErcCore();

                // "using" so the thread handles opened while inspecting the target are
                // closed when the command finishes. This runs on every ERC command, and
                // a ProcessInfo opens one handle per thread in the debuggee, so without
                // it handles accumulated for the whole debugging session.
                using (ERC.ProcessInfo info = new ERC.ProcessInfo(core, hProcess))
                {
                    ParseCommand(argv[0], core, info);
                }
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

        private static void PrintHelp(string? errorMessage = null)
        {
            foreach (string line in ERC.Cli.CommandHelp.Banner.Split('\n'))
            {
                PLog.WriteLine(line);
            }

            if (errorMessage != null)
            {
                PLog.WriteLine("Error: {0}", errorMessage);
            }

            PLog.WriteLine(ERC.Cli.CommandHelp.Text);
        }

        /// <summary>
        /// Runs a parsed command.
        /// </summary>
        /// <remarks>
        /// Parsing now happens in ERC.Cli.CommandParser, which reads and writes
        /// nothing and can therefore be tested. This method only dispatches.
        ///
        /// It replaces a routine that split the line, mutated a static settings class
        /// as a side effect of scanning it, counted options, and dispatched - all in
        /// one place, none of it reachable from a test.
        /// </remarks>
        private static void ParseCommand(string command, ERC.ErcCore core, ERC.ProcessInfo info)
        {
            ErcCommand parsed = CommandParser.Parse(command, Session);

            if (!parsed.IsValid)
            {
                PrintHelp(parsed.Error);
                return;
            }

            // Global switches persist for the session, which is what the
            // documentation promises.
            Session = parsed.Session;

            SessionState session = Session;
            var parameters = new List<string>(parsed.Arguments);
            string option = parsed.Option;

            bool writeToFile = true;

            switch (option)
            {
                case "--help":
                    PrintHelp();
                    return;
                case "--update":
                    Update(parameters, session);
                    return;
                case "--config":
                    Config(parameters, core, session);
                    return;
                case "--pattern":
                    Pattern(core, parameters, session);
                    return;
                case "--bytearray":
                    ByteArray(parameters, core, session);
                    return;
                case "--compare":
                    Compare(info, parameters, session);
                    return;
                case "--convert":
                    Convert(info, parameters, session);
                    return;
                case "--assemble":
                    Assemble(info, parameters, session);
                    return;
                case "--disassemble":
                    Disassemble(info, parameters, session);
                    return;
                case "--searchmemory":
                    SearchMemory(info, parameters, session);
                    return;
                case "--searchmodules":
                    SearchModules(info, parameters, session);
                    return;
                case "--dump":
                    DumpMemory(info, parameters, session);
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
                    SEH(parameters, info, session);
                    break;
                case "--jmp":
                    Jmp(info, parameters, session);
                    return;
                case "--sehchain":
                    SehChain(info, parameters, session);
                    return;
                case "--ropfunc":
                    RopFunc(info, parameters, session);
                    return;
                case "--gadget":
                    Gadget(info, parameters, session);
                    return;
                case "--egghunters":
                    if(parameters.Count <= 2)
                    {
                        if(parameters.Count == 1)
                        {
                            EggHunters(session, core);
                        }
                        else
                        {
                            EggHunters(session, core, parameters[1]);
                        }
                    }
                    return;
                case "--findnrp":
                    FindNRP(info, parameters, session);
                    return;
                case "--heapinfo":
                    HeapInfo(info, parameters, session);
                    return;
                case "--ropgadgets":
                    rop(info, session, true);
                    return;
                case "--rop":
                    rop(info, session);
                    return;
                case "--debug":
                    Debug(info, parameters, session);
                    return;
                case "--reset":
                    Reset(session);
                    return;
                default:
                    PrintHelp("The command was not structured correctly: Option is not supported. ERC <option> <parameters>");
                    return;
            }

            return;
        }

    }
}
