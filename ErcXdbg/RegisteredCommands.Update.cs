using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using Managed.x64dbg.SDK;
using ERC.Cli;
using ERC.Update;

namespace ErcXdbg
{
    /// <summary>
    /// The commands for updating the plugin.
    /// </summary>
    /// <remarks>
    /// Downloading, verifying and installing a new release.
    ///
    /// One part of RegisteredCommands, which was a single 2,100 line file holding
    /// every command. Splitting it by command group leaves the dispatcher in
    /// RegisteredCommands.cs and each group beside the others it shares helpers with.
    /// </remarks>
    public static partial class RegisteredCommands
    {
        /// <summary>
        /// Downloads and installs the latest release.
        /// </summary>
        /// <remarks>
        /// The work is in ERC.Update.PluginUpdater. What is left here is reading the
        /// proxy argument, working out which directories to update, and printing.
        ///
        /// It replaces a 170-line method that held two nearly identical copies of the
        /// whole flow, one per architecture. Three defects lived in the difference
        /// between them and in the parts no test could reach; they are described where
        /// they are fixed, in PluginUpdater.
        /// </remarks>
        private static void Update(List<string> parameters, SessionState session)
        {
            PLog.WriteLine("ERC --Update");
            PLog.WriteLine("----------------------------------------------------------------------");

            // Strip the switches, keeping the positional arguments.
            //
            // This was a forward loop calling parameters.Remove(parameters[i]),
            // which shifted the next element into the current index and skipped it,
            // so a switch immediately following another switch survived and was then
            // treated as a positional argument.
            parameters.RemoveAll(p => p.Contains("--"));

            IWebProxy? proxy;
            if (!TryReadProxy(parameters, out proxy))
            {
                return;
            }

            try
            {
                using (var transport = new HttpTransport(proxy))
                {
                    foreach (var target in UpdateTargets())
                    {
                        PLog.WriteLine("Updating the {0}-bit plugin in {1}", target.Tag, target.Directory);
                        PluginUpdater.Update(transport, target.Tag, target.Directory, line => PLog.WriteLine(line));
                    }
                }

                PLog.WriteLine("\nUpdate was downloaded successfully.");
                PLog.WriteLine("In order to use the updated binary you will need to restart X64dbg.");
                PLog.WriteLine("----------------------------------------------------------------------");
            }
            catch (Exception e)
            {
                PrintHelp(e.Message + (e.InnerException == null ? "" : "\n" + e.InnerException.Message));
            }
        }

        /// <summary>
        /// A release tag and the directory its build is installed into.
        /// </summary>
        private struct UpdateTarget
        {
            public UpdateTarget(string tag, string directory)
            {
                Tag = tag;
                Directory = directory;
            }

            public string Tag { get; }

            public string Directory { get; }
        }

        /// <summary>
        /// Which builds this machine should update.
        /// </summary>
        /// <remarks>
        /// x64dbg installs the two architectures side by side in "x32" and "x64"
        /// directories, and both are updated on a 64-bit machine because either
        /// debugger may be started next.
        ///
        /// The directory is only rewritten when the sibling exists. The original
        /// rewrote the path unconditionally and then failed on a machine where only
        /// one architecture was installed.
        /// </remarks>
        private static IEnumerable<UpdateTarget> UpdateTargets()
        {
            string here = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? string.Empty;

            if (Environment.Is64BitOperatingSystem)
            {
                string x64 = Sibling(here, "\\x32\\", "\\x64\\");
                if (Directory.Exists(x64))
                {
                    yield return new UpdateTarget(PluginUpdater.Tag64, x64);
                }
            }

            string x32 = Sibling(here, "\\x64\\", "\\x32\\");
            if (Directory.Exists(x32))
            {
                yield return new UpdateTarget(PluginUpdater.Tag32, x32);
            }
        }

        private static string Sibling(string path, string from, string to)
        {
            return path.IndexOf(to, StringComparison.OrdinalIgnoreCase) >= 0
                ? path
                : path.Replace(from, to);
        }

        /// <summary>
        /// Reads the optional "ip:port" proxy argument.
        /// </summary>
        /// <returns>False when the argument was present but unusable.</returns>
        private static bool TryReadProxy(List<string> parameters, out IWebProxy? proxy)
        {
            proxy = null;

            if (parameters.Count == 0)
            {
                return true;
            }

            if (parameters.Count > 1)
            {
                PrintHelp("Too many parameters provided. Update must be called as \"ERC --update <proxyIP:port>\"");
                return false;
            }

            string[] parts = parameters[0].Split(':');
            IPAddress? address;

            if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out address) || parts[1].Length == 0)
            {
                PrintHelp("Proxy IP address:Port not formatted correctly. Update must be called as \"ERC --update <proxyIP:port>\"");
                return false;
            }

            // Validated as a number here rather than left to WebProxy, which accepts
            // "1.2.3.4:notaport" and then fails much later with a parse error that
            // does not mention the proxy.
            int port;
            if (!int.TryParse(parts[1], out port) || port < 1 || port > 65535)
            {
                PrintHelp("Proxy port must be a number between 1 and 65535. Update must be called as \"ERC --update <proxyIP:port>\"");
                return false;
            }

            proxy = new WebProxy(parts[0] + ":" + port.ToString());
            return true;
        }

        /// <summary>
        /// Removes the backups and archives left by previous updates.
        /// </summary>
        private static void DeleteOldPlugins()
        {
            try
            {
                foreach (var target in UpdateTargets())
                {
                    PluginUpdater.DeleteOldPlugins(target.Directory);
                }
            }
            catch (Exception e)
            {
                PLog.WriteLine("ERROR: " + e.Message);
            }
        }
    }
}
