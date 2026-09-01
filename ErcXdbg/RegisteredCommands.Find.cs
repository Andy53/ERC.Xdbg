using System;
using System.Collections.Generic;
using System.Linq;
using Managed.x64dbg.SDK;
using ERC;
using ERC.Cli;
using ERC.Utilities;

namespace ErcXdbg
{
    /// <summary>
    /// The commands for locating the things an exploit is built out of.
    /// </summary>
    /// <remarks>
    /// Jumps to a register, the SEH chain, the API functions a ROP chain calls, and
    /// a single kind of gadget. Every one of these was already computable by the
    /// library and none of them had a command, so they could only be reached by
    /// generating something larger and reading the part you wanted out of it.
    /// </remarks>
    public static partial class RegisteredCommands
    {
        /// <summary>
        /// The modules the global switches say to leave out.
        /// </summary>
        /// <remarks>
        /// The help text is explicit about what these mean: "-Aslr" excludes ASLR
        /// enabled modules. So a module is excluded when the switch is set and the
        /// module has the property.
        ///
        /// The ROP commands used to express this as
        ///
        ///     if (!mi.ModuleASLR == session.Aslr || ...)
        ///
        /// which is the opposite, and worse than the opposite. With no switches set
        /// at all - the default - that reduces to "exclude this module if it has
        /// ASLR, or NXCompat, or is an OS DLL, or has SafeSEH, or can be rebased".
        /// Almost every module in a modern process has NXCompat, so almost every
        /// module was excluded from the gadget scan before it began, and setting
        /// "-Aslr" kept ASLR modules in rather than dropping them.
        /// </remarks>
        private static List<string> ModuleExcludes(ERC.ProcessInfo info, SessionState session)
        {
            var excludes = new List<string>();

            if (session.Modules.Length > 0)
            {
                // -m names the modules to search and, as in mona, ignores the other
                // module switches. -m * means every module.
                if (ModuleFilter.IsAll(session.Modules))
                {
                    return excludes;
                }

                foreach (ERC.ModuleInfo module in info.ModulesInfo)
                {
                    if (!ModuleFilter.Matches(module.ModuleName, module.ModulePath, session.Modules))
                    {
                        excludes.Add(module.ModulePath);
                    }
                }

                return excludes;
            }

            foreach (ERC.ModuleInfo module in info.ModulesInfo)
            {
                bool excluded =
                    (session.Aslr && module.ModuleASLR) ||
                    (session.SafeSeh && module.ModuleSafeSEH) ||
                    (session.Rebase && module.ModuleRebase) ||
                    (session.NxCompat && module.ModuleNXCompat) ||
                    (session.OsDll && module.ModuleOsDll) ||
                    (session.Cfg && module.ModuleCFG);

                if (excluded)
                {
                    excludes.Add(module.ModulePath);
                }
            }

            return excludes;
        }

        /// <summary>
        /// Finds every way of jumping to a register.
        /// </summary>
        private static void Jmp(ERC.ProcessInfo info, List<string> parameters, SessionState session)
        {
            parameters.RemoveAll(p => p.Contains("--"));

            // "-r esp" is how mona spells it and what people's fingers already know.
            parameters.RemoveAll(p => p.Equals("-r", StringComparison.OrdinalIgnoreCase));

            if (parameters.Count != 1)
            {
                PrintHelp("--Jmp takes one register. Example: ERC --jmp -r esp");
                return;
            }

            ErcResult<Dictionary<IntPtr, string>> found = JumpToRegister.Search(
                info, parameters[0], ModuleExcludes(info, session), session.Bytes);

            if (found.Error != null)
            {
                PrintHelp(found.Error.Message);
                return;
            }

            found.ReturnValue = ApplyShape(info, found.ReturnValue, session);

            PLog.WriteLine("\nJumps to {0}: {1} found", parameters[0].ToLowerInvariant(), found.ReturnValue.Count);
            PLog.WriteLine("----------------------------------------------------------------------");

            if (found.ReturnValue.Count == 0)
            {
                PLog.WriteLine("Nothing found. Every module may be excluded by the global switches, or " +
                               "every address may contain one of the bytes given to -Bytes.");
                return;
            }

            string format = info.ProcessMachineType == ERC.MachineType.x64 ? "X16" : "X8";

            foreach (KeyValuePair<IntPtr, string> match in found.ReturnValue.OrderBy(m => (long)m.Key))
            {
                PLog.WriteLine("0x{0} | {1}", match.Key.ToString(format), match.Value);
            }
        }

        /// <summary>
        /// Finds instructions that move the stack pointer.
        /// </summary>
        private static void StackPivotCommand(ERC.ProcessInfo info, List<string> parameters, SessionState session)
        {
            parameters.RemoveAll(p => p.Contains("--"));

            int minimum = 0;
            if (parameters.Count > 0 && !int.TryParse(parameters[0], out minimum))
            {
                PrintHelp("--StackPivot takes an optional minimum distance in bytes. Example: ERC --stackpivot 200");
                return;
            }

            ErcResult<Dictionary<IntPtr, string>> found = StackPivot.Search(
                info, minimum, 256, ModuleExcludes(info, session), session.Bytes);

            if (found.Error != null)
            {
                PrintHelp(found.Error.Message);
                return;
            }

            found.ReturnValue = ApplyShape(info, found.ReturnValue, session);

            PLog.WriteLine("");
            PLog.WriteLine("Stack pivots{0}: {1} found",
                minimum > 0 ? " moving at least " + minimum + " bytes" : "", found.ReturnValue.Count);
            PLog.WriteLine("----------------------------------------------------------------------");

            if (found.ReturnValue.Count == 0)
            {
                PLog.WriteLine("Nothing found. Every module may be excluded by the global switches, or " +
                               "every address may contain one of the bytes given to -Bytes.");
                return;
            }

            string format = info.ProcessMachineType == ERC.MachineType.x64 ? "X16" : "X8";

            foreach (KeyValuePair<IntPtr, string> match in found.ReturnValue.OrderBy(m => (long)m.Key))
            {
                PLog.WriteLine("0x{0} | {1}", match.Key.ToString(format), match.Value);
            }
        }

        /// <summary>
        /// Displays the structured exception handler chain of each thread.
        /// </summary>
        private static void SehChain(ERC.ProcessInfo info, List<string> parameters, SessionState session)
        {
            parameters.RemoveAll(p => p.Contains("--"));

            string format = info.ProcessMachineType == ERC.MachineType.x64 ? "X16" : "X8";
            bool any = false;

            PLog.WriteLine("\nSEH chains");
            PLog.WriteLine("----------------------------------------------------------------------");

            foreach (ERC.ThreadInfo thread in info.ThreadsInfo)
            {
                List<Tuple<IntPtr, IntPtr>> chain;

                try
                {
                    chain = thread.GetSehChain();
                }
                catch (Exception e)
                {
                    // A thread with no chain is the ordinary case on a healthy
                    // process, so it is reported per thread rather than aborting.
                    PLog.WriteLine("Thread {0}: {1}", thread.ThreadID, e.Message);
                    continue;
                }

                if (chain.Count == 0)
                {
                    continue;
                }

                any = true;
                PLog.WriteLine("\nThread {0}: {1} frame(s)", thread.ThreadID, chain.Count);

                for (int i = 0; i < chain.Count; i++)
                {
                    PLog.WriteLine("  [{0}] nSEH 0x{1}   SEH 0x{2}",
                        i, chain[i].Item1.ToString(format), chain[i].Item2.ToString(format));
                }
            }

            if (!any)
            {
                PLog.WriteLine("No SEH chain has been built. One is only created once an exception has occurred.");
            }
        }

        /// <summary>
        /// Lists the API functions a ROP chain is usually built around.
        /// </summary>
        private static void RopFunc(ERC.ProcessInfo info, List<string> parameters, SessionState session)
        {
            parameters.RemoveAll(p => p.Contains("--"));

            ErcResult<List<RopFunction>> found = RopFunctions.Find(
                info, ModuleExcludes(info, session), session.Bytes);

            if (found.Error != null)
            {
                PrintHelp(found.Error.Message);
                return;
            }

            if (session.Shape != PointerCriteria.None)
            {
                found.ReturnValue.RemoveAll(f =>
                    !PointerShape.Matches(f.Address, info.ProcessMachineType, session.Shape));
            }

            PLog.WriteLine("\nROP functions: {0} found", found.ReturnValue.Count);
            PLog.WriteLine("----------------------------------------------------------------------");

            if (found.ReturnValue.Count == 0)
            {
                PLog.WriteLine("Nothing found. The modules exporting these may be excluded by the " +
                               "global switches, or every address may contain a byte given to -Bytes.");
                return;
            }

            string format = info.ProcessMachineType == ERC.MachineType.x64 ? "X16" : "X8";

            foreach (RopFunction function in found.ReturnValue)
            {
                PLog.WriteLine("0x{0} | {1,-24} {2,-16} {3}{4}",
                    function.Address.ToString(format), function.Name, function.Module, function.Purpose,
                    function.Iat ? "  [IAT]" : "");
            }
        }

        /// <summary>
        /// Collects one kind of ROP gadget.
        /// </summary>
        private static void Gadget(ERC.ProcessInfo info, List<string> parameters, SessionState session)
        {
            parameters.RemoveAll(p => p.Contains("--"));

            if (parameters.Count == 0)
            {
                PLog.WriteLine("Available gadget kinds for this process:");
                PLog.WriteLine("  {0}", string.Join(", ", GadgetLookup.Available(info.ProcessMachineType)));
                PLog.WriteLine("\nExample: ERC --gadget pop ecx");
                return;
            }

            // Taken as the whole remainder so "--gadget pop ecx" works without quotes.
            string instruction = string.Join(" ", parameters.ToArray());

            List<string> excludes = ModuleExcludes(info, session);
            byte[] bad = session.Bytes;

            PLog.WriteLine("Scanning for \"{0}\". This reads every executable page and may take a while.", instruction);

            ErcResult<Dictionary<IntPtr, string>> found;

            if (info.ProcessMachineType == ERC.MachineType.x64)
            {
                found = new ERC.Utilities.RopChainGenerator64(info).FindGadgets(instruction, bad, excludes);
            }
            else
            {
                found = new ERC.Utilities.RopChainGenerator32(info).FindGadgets(instruction, bad, excludes);
            }

            if (found.Error != null)
            {
                PrintHelp(found.Error.Message);
                return;
            }

            found.ReturnValue = ApplyShape(info, found.ReturnValue, session);

            PLog.WriteLine("\n{0}: {1} found", instruction, found.ReturnValue.Count);
            PLog.WriteLine("----------------------------------------------------------------------");

            string format = info.ProcessMachineType == ERC.MachineType.x64 ? "X16" : "X8";

            foreach (KeyValuePair<IntPtr, string> gadget in found.ReturnValue.OrderBy(g => (long)g.Key))
            {
                PLog.WriteLine("0x{0} | {1}", gadget.Key.ToString(format), gadget.Value);
            }
        }

        /// <summary>
        /// Finds an instruction sequence, with wildcards.
        /// </summary>
        private static void FindWildCommand(ERC.ProcessInfo info, List<string> parameters, SessionState session)
        {
            parameters.RemoveAll(p => p.Contains("--"));

            if (parameters.Count == 0)
            {
                PrintHelp("--FindWild takes an instruction sequence. Separate instructions with # or ;. " +
                          "* matches any instruction, jmp * matches any jump. " +
                          "Example: ERC --findwild pop eax # pop ebx # ret");
                return;
            }

            string text = string.Join(" ", parameters.ToArray());
            InstructionPattern pattern;
            try
            {
                pattern = FindWild.Parse(text);
            }
            catch (Exception e)
            {
                PrintHelp(e.Message);
                return;
            }

            PLog.WriteLine("Searching for \"{0}\". This disassembles every readable page and may take a while.", text);

            ErcResult<Dictionary<IntPtr, string>> found = FindWild.Search(
                info, pattern, ModuleExcludes(info, session), session.Bytes, session.Shape);

            if (found.Error != null)
            {
                PrintHelp(found.Error.Message);
                return;
            }

            PLog.WriteLine("\n{0}: {1} found", text, found.ReturnValue.Count);
            PLog.WriteLine("----------------------------------------------------------------------");

            if (found.ReturnValue.Count == 0)
            {
                PLog.WriteLine("Nothing found. Every module may be excluded by the global switches, " +
                               "every address may contain a byte given to -Bytes, or -cp may have filtered them all out.");
                return;
            }

            string format = info.ProcessMachineType == ERC.MachineType.x64 ? "X16" : "X8";

            foreach (KeyValuePair<IntPtr, string> match in found.ReturnValue.OrderBy(m => (long)m.Key))
            {
                PLog.WriteLine("0x{0} | {1}", match.Key.ToString(format), match.Value);
            }
        }

        private static Dictionary<IntPtr, string> ApplyShape(
            ERC.ProcessInfo info, Dictionary<IntPtr, string> found, SessionState session)
        {
            return PointerShape.Filter(info.ProcessMachineType, found, session.Shape);
        }

        /// <summary>
        /// Finds jump-oriented-programming gadgets: jmp/call through a memory operand.
        /// </summary>
        private static void JopCommand(ERC.ProcessInfo info, List<string> parameters, SessionState session)
        {
            parameters.RemoveAll(p => p.Contains("--"));
            parameters.RemoveAll(p => p.Equals("-r", StringComparison.OrdinalIgnoreCase));

            string? register = null;
            if (parameters.Count > 1)
            {
                PrintHelp("--Jop takes an optional register. Example: ERC --jop eax");
                return;
            }

            if (parameters.Count == 1)
            {
                register = parameters[0];
            }

            PLog.WriteLine("Searching for JOP gadgets{0}. This reads every loaded module and may take a while.",
                register == null ? "" : " using " + register);

            ErcResult<Dictionary<IntPtr, string>> found = Jop.Search(
                info, register, ModuleExcludes(info, session), session.Bytes, session.Shape);

            if (found.Error != null)
            {
                PrintHelp(found.Error.Message);
                return;
            }

            PLog.WriteLine("\nJOP gadgets: {0} found", found.ReturnValue.Count);
            PLog.WriteLine("----------------------------------------------------------------------");

            if (found.ReturnValue.Count == 0)
            {
                PLog.WriteLine("Nothing found. Every module may be excluded by the global switches, " +
                               "every address may contain a byte given to -Bytes, or -cp may have filtered them all out.");
                return;
            }

            string format = info.ProcessMachineType == ERC.MachineType.x64 ? "X16" : "X8";

            foreach (KeyValuePair<IntPtr, string> match in found.ReturnValue.OrderBy(m => (long)m.Key))
            {
                PLog.WriteLine("0x{0} | {1}", match.Key.ToString(format), match.Value);
            }
        }

        /// <summary>
        /// Finds calls and jumps through a pointer in writable memory.
        /// </summary>
        private static void FwptrCommand(ERC.ProcessInfo info, List<string> parameters, SessionState session)
        {
            parameters.RemoveAll(p => p.Contains("--"));

            PLog.WriteLine("Searching for calls/jumps through writable pointers. This reads executable pages and may take a while.");

            ErcResult<List<FwptrHit>> found = Fwptr.Search(
                info, ModuleExcludes(info, session), session.Bytes, session.Shape);

            if (found.Error != null)
            {
                PrintHelp(found.Error.Message);
                return;
            }

            PLog.WriteLine("\nWritable call/jump pointers: {0} found", found.ReturnValue.Count);
            PLog.WriteLine("----------------------------------------------------------------------");

            if (found.ReturnValue.Count == 0)
            {
                PLog.WriteLine("Nothing found. The call target may not be writable, every module may be excluded, or -cp/-Bytes may have filtered them all out.");
                return;
            }

            string format = info.ProcessMachineType == ERC.MachineType.x64 ? "X16" : "X8";

            foreach (FwptrHit hit in found.ReturnValue)
            {
                PLog.WriteLine("0x{0} | {1}  ptr=0x{2}  ({3})",
                    hit.Call.ToString(format), hit.Instruction, hit.Pointer.ToString(format), hit.Module);
            }
        }

        /// <summary>
        /// Lists IAT slots: pointers to pointers a ROP chain can reuse.
        /// </summary>
        private static void IatCommand(ERC.ProcessInfo info, List<string> parameters, SessionState session)
        {
            parameters.RemoveAll(p => p.Contains("--"));

            string? moduleFilter = parameters.Count > 0 ? parameters[0] : null;
            string? nameFilter = parameters.Count > 1 ? parameters[1] : null;
            List<string> excludes = ModuleExcludes(info, session);
            string format = info.ProcessMachineType == ERC.MachineType.x64 ? "X16" : "X8";
            int count = 0;

            PLog.WriteLine("\nIAT slots");
            PLog.WriteLine("----------------------------------------------------------------------");

            foreach (ERC.ModuleInfo module in info.ModulesInfo)
            {
                if (module.ModuleFailed)
                {
                    continue;
                }

                if (IsModuleExcluded(module, excludes, moduleFilter))
                {
                    continue;
                }

                foreach (ImportEntry entry in ImportTable.Read(module.ModulePath, info.ProcessMachineType == ERC.MachineType.x64))
                {
                    if (!string.IsNullOrEmpty(nameFilter) &&
                        entry.DisplayName.IndexOf(nameFilter, StringComparison.OrdinalIgnoreCase) < 0)
                    {
                        continue;
                    }

                    IntPtr slot = ImportTable.SlotAddress(module.ModuleBase, entry.IatRva);
                    if (!PointerShape.Matches(slot, info.ProcessMachineType, session.Shape))
                    {
                        continue;
                    }

                    if (session.Bytes.Length > 0)
                    {
                        var one = new Dictionary<IntPtr, string> { { slot, entry.DisplayName } };
                        if (PtrRemover.RemovePointers(info.ProcessMachineType, one, session.Bytes).Count == 0)
                        {
                            continue;
                        }
                    }

                    PLog.WriteLine("0x{0} | {1,-24} {2}",
                        slot.ToString(format), entry.DisplayName, entry.Dll);
                    count++;
                }
            }

            PLog.WriteLine("----------------------------------------------------------------------");
            PLog.WriteLine("{0} slot(s).", count);
        }

        /// <summary>
        /// Lists exported functions. --RopFunc lists IAT slots for the same APIs.
        /// </summary>
        private static void EatCommand(ERC.ProcessInfo info, List<string> parameters, SessionState session)
        {
            parameters.RemoveAll(p => p.Contains("--"));

            string? moduleFilter = parameters.Count > 0 ? parameters[0] : null;
            string? nameFilter = parameters.Count > 1 ? parameters[1] : null;
            List<string> excludes = ModuleExcludes(info, session);
            string format = info.ProcessMachineType == ERC.MachineType.x64 ? "X16" : "X8";
            int count = 0;

            PLog.WriteLine("\nExports");
            PLog.WriteLine("----------------------------------------------------------------------");

            foreach (ERC.ModuleInfo module in info.ModulesInfo)
            {
                if (module.ModuleFailed)
                {
                    continue;
                }

                if (IsModuleExcluded(module, excludes, moduleFilter))
                {
                    continue;
                }

                foreach (KeyValuePair<string, uint> export in ExportTable.Read(module.ModulePath))
                {
                    if (!string.IsNullOrEmpty(nameFilter) &&
                        export.Key.IndexOf(nameFilter, StringComparison.OrdinalIgnoreCase) < 0)
                    {
                        continue;
                    }

                    IntPtr address = new IntPtr(module.ModuleBase.ToInt64() + export.Value);
                    if (!PointerShape.Matches(address, info.ProcessMachineType, session.Shape))
                    {
                        continue;
                    }

                    if (session.Bytes.Length > 0)
                    {
                        var one = new Dictionary<IntPtr, string> { { address, export.Key } };
                        if (PtrRemover.RemovePointers(info.ProcessMachineType, one, session.Bytes).Count == 0)
                        {
                            continue;
                        }
                    }

                    PLog.WriteLine("0x{0} | {1,-32} {2}",
                        address.ToString(format), export.Key, module.ModuleName);
                    count++;
                }
            }

            PLog.WriteLine("----------------------------------------------------------------------");
            PLog.WriteLine("{0} export(s).", count);
        }

        private static bool IsModuleExcluded(ERC.ModuleInfo module, List<string> excludes, string? moduleFilter)
        {
            if (!string.IsNullOrEmpty(moduleFilter))
            {
                bool matches =
                    module.ModuleName.IndexOf(moduleFilter, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    module.ModulePath.IndexOf(moduleFilter, StringComparison.OrdinalIgnoreCase) >= 0;
                if (!matches)
                {
                    return true;
                }
            }

            foreach (string exclude in excludes)
            {
                if (module.ModulePath.Equals(exclude, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
