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
    /// The commands for ROP.
    /// </summary>
    /// <remarks>
    /// Collecting gadgets and building ROP chains.
    ///
    /// One part of RegisteredCommands, which was a single 2,100 line file holding
    /// every command. Splitting it by command group leaves the dispatcher in
    /// RegisteredCommands.cs and each group beside the others it shares helpers with.
    /// </remarks>
    public static partial class RegisteredCommands
    {
        private static void rop(ERC.ProcessInfo info, SessionState session, bool gadgetsOnly = false)
        {
            PLog.WriteLine("Starting to build ROP Chains.");

            // The generator is chosen from the architecture of the process actually
            // under debug, rather than from a hand-edited build. Picking the wrong
            // one produces a plausible-looking chain that cannot work on the target.
            bool target64Bit = info.ProcessMachineType == ERC.MachineType.x64;

            List<string> excludes = new List<string>();
            foreach(ERC.ModuleInfo mi in info.ModulesInfo)
            {
                if(!mi.ModuleASLR == session.Aslr || !mi.ModuleNXCompat == session.NxCompat || !mi.ModuleOsDll == session.OsDll || !mi.ModuleSafeSEH == session.SafeSeh
                    || !mi.ModuleRebase == session.Rebase)
                {
                    excludes.Add(mi.ModulePath);
                }
            }

            bool filtered = session.Bytes.Length > 0 || excludes.Count > 0;

            try
            {
                PLog.WriteLine("Generating ROP chain files...");

                if (target64Bit)
                {
                    var generator = new ERC.Utilities.RopChainGenerator64(info);
                    if (gadgetsOnly)
                    {
                        if (filtered)
                        {
                            generator.GenerateRopGadgets64(session.Bytes, excludes);
                        }
                        else
                        {
                            generator.GenerateRopGadgets64();
                        }
                    }
                    else
                    {
                        // Named arguments. Positionally, session.Bytes used to bind to
                        // startAddress rather than ptrsToExclude, so the user's
                        // bad-character list was handed over as the address to make
                        // executable and no bad characters were excluded at all.
                        var ropHolder = filtered
                            ? generator.GenerateRopChain64(excludes: excludes, ptrsToExclude: session.Bytes)
                            : generator.GenerateRopChain64();
                        PLog.WriteLine(ropHolder.ReturnValue);
                    }
                }
                else
                {
                    var generator = new ERC.Utilities.RopChainGenerator32(info);
                    if (gadgetsOnly)
                    {
                        if (filtered)
                        {
                            generator.GenerateRopGadgets32(session.Bytes, excludes);
                        }
                        else
                        {
                            generator.GenerateRopGadgets32();
                        }
                    }
                    else
                    {
                        var ropHolder = filtered
                            ? generator.GenerateRopChain32(excludes: excludes, ptrsToExclude: session.Bytes)
                            : generator.GenerateRopChain32();
                        PLog.WriteLine(ropHolder.ReturnValue);
                    }
                }

                PLog.WriteLine("ROP chain generation completed. Files can be found in {0}", info.WorkingDirectory);
            }
            catch(Exception e)
            {
                PrintHelp(e.Message);
            }

            return;
        }
    }
}
