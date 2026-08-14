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
    /// The commands for configuration.
    /// </summary>
    /// <remarks>
    /// Reading and writing the stored configuration, and resetting the session.
    ///
    /// One part of RegisteredCommands, which was a single 2,100 line file holding
    /// every command. Splitting it by command group leaves the dispatcher in
    /// RegisteredCommands.cs and each group beside the others it shares helpers with.
    /// </remarks>
    public static partial class RegisteredCommands
    {
        private static void Config(List<string> parameters, ERC.ErcCore core, SessionState session)
        {
            PLog.WriteLine("ERC --Config");
            PLog.WriteLine("--------------------------------------------");
            // Strip the switches, keeping the positional arguments.
            //
            // This was a forward loop calling parameters.Remove(parameters[i]),
            // which shifted the next element into the current index and skipped it,
            // so a switch immediately following another switch survived and was then
            // treated as a positional argument. The same loop was copy-pasted into
            // nearly every command handler.
            parameters.RemoveAll(p => p.Contains("--"));

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
                    // Same forward-loop removal defect as the switch stripping above.
                    parameters.RemoveAll(p => p.ToLower().Contains("setauthor"));
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

        /// <summary>
        /// Clears the session settings and deletes the stored configuration.
        /// </summary>
        /// <remarks>
        /// One method where there were two identical ones, differing only in the
        /// arguments they ignored.
        ///
        /// The file it deletes now comes from the library rather than being rebuilt
        /// here. The path assembled here was wrong twice over: it joined a directory
        /// to a file name with no separator, and spelled the extension in lower case
        /// where the library writes it in upper. File.Delete does nothing when the
        /// file is absent, so --reset reported success while leaving the configuration
        /// in place.
        /// </remarks>
        private static void Reset(SessionState session)
        {
            session.Reset();

            string path = ERC.Config.XmlConfigStore.DefaultPath();

            try
            {
                File.Delete(path);
            }
            catch (Exception e)
            {
                // Worth saying which file could not be removed: silently continuing is
                // what hid the bug above.
                PLog.WriteLine("ERC Reset: session settings cleared, but {0} could not be deleted: {1}",
                    path, e.Message);
                PLog.WriteLine("--------------------------------------------");
                return;
            }

            PLog.WriteLine("ERC Reset: All configuration settings have been reset to the default values.");
            PLog.WriteLine("--------------------------------------------");
        }
    }
}
