using System;
using System.Collections.Generic;
using System.IO;

namespace ERC.Utilities
{
    /// <summary>
    /// Where a ROP-relevant API lives in the target process.
    /// </summary>
    public sealed class RopFunction
    {
        internal RopFunction(string name, string module, IntPtr address, string purpose)
        {
            Name = name;
            Module = module;
            Address = address;
            Purpose = purpose;
        }

        /// <summary>The exported function name, for example "VirtualProtect".</summary>
        public string Name { get; }

        /// <summary>The module exporting it.</summary>
        public string Module { get; }

        /// <summary>Its address in the target process.</summary>
        public IntPtr Address { get; }

        /// <summary>Why a chain would want it.</summary>
        public string Purpose { get; }
    }

    /// <summary>
    /// Finds the API functions a ROP chain is usually built around.
    /// </summary>
    /// <remarks>
    /// A chain that defeats DEP has to call something that makes memory executable,
    /// or allocate memory that already is, so the first thing wanted after a gadget
    /// list is the address of those functions in this process.
    ///
    /// The addresses come from each module's export directory rather than from
    /// GetProcAddress, which resolves in the calling process and cannot answer for
    /// somebody else's - see ExportTable.
    /// </remarks>
    public static class RopFunctions
    {
        /// <summary>
        /// The functions worth reporting, and why each is useful.
        /// </summary>
        /// <remarks>
        /// Deliberately short. A list of everything a chain could conceivably call is
        /// a worse answer than the handful that a chain is actually built around.
        /// </remarks>
        private static readonly (string Name, string Purpose)[] Wanted =
        {
            ("VirtualProtect",      "Make an existing region executable."),
            ("VirtualAlloc",        "Allocate a region that is already executable."),
            ("VirtualProtectEx",    "As VirtualProtect, against another process."),
            ("VirtualAllocEx",      "As VirtualAlloc, against another process."),
            ("HeapCreate",          "Create a heap with execute permission."),
            ("HeapAlloc",           "Allocate from a heap created executable."),
            ("WriteProcessMemory",  "Copy a payload over memory that is already executable."),
            ("SetProcessDEPPolicy", "Turn DEP off for the process, where the OS still allows it."),
            ("NtSetInformationProcess", "Change the process DEP policy directly."),
            ("LoadLibraryA",        "Load a module and get executable pages for free."),
            ("WinExec",             "Skip the payload and run a command."),
            ("system",              "As WinExec, through the C runtime."),
        };

        /// <summary>
        /// Resolves the ROP-relevant exports of every module loaded in a process.
        /// </summary>
        /// <param name="info">The process to inspect.</param>
        /// <param name="excludes">Modules to leave out.</param>
        /// <param name="ptrsToExclude">
        /// Bytes that disqualify an address, as elsewhere: a pointer holding a byte
        /// the target mangles cannot be written into a chain.
        /// </param>
        /// <returns>One entry per function found, in the order listed above.</returns>
        public static ErcResult<List<RopFunction>> Find(
            ProcessInfo info,
            List<string>? excludes = null,
            byte[]? ptrsToExclude = null)
        {
            if (info == null)
            {
                throw new ArgumentNullException(nameof(info));
            }

            var result = new ErcResult<List<RopFunction>>(info.ProcessCore);
            result.ReturnValue = new List<RopFunction>();

            foreach ((string name, string purpose) in Wanted)
            {
                foreach (ModuleInfo module in info.ModulesInfo)
                {
                    if (module.ModuleFailed || !File.Exists(module.ModulePath))
                    {
                        continue;
                    }

                    if (excludes != null && excludes.Contains(module.ModulePath))
                    {
                        continue;
                    }

                    IntPtr address;
                    if (!ExportTable.TryResolve(module.ModulePath, module.ModuleBase, name, out address))
                    {
                        continue;
                    }

                    if (ptrsToExclude != null && ContainsExcludedByte(address, info.ProcessMachineType, ptrsToExclude))
                    {
                        continue;
                    }

                    result.ReturnValue.Add(new RopFunction(
                        name, Path.GetFileName(module.ModulePath), address, purpose));
                }
            }

            return result;
        }

        /// <summary>
        /// The four functions the ROP chain builders construct chains around.
        /// </summary>
        public static readonly string[] ChainApiNames =
        {
            "VirtualAlloc", "HeapCreate", "VirtualProtect", "WriteProcessMemory"
        };

        /// <summary>
        /// Resolves the functions the chain builders call, in the target process.
        /// </summary>
        /// <param name="info">The process the chain is being built for.</param>
        /// <returns>
        /// Name to address for each function found. The error is set when any could
        /// not be resolved, but whatever was found is still returned - a chain for one
        /// method is still useful when another cannot be built.
        /// </returns>
        /// <remarks>
        /// What this replaces asked the wrong process. It took kernel32's base address
        /// in the target and passed it to GetProcAddress, which resolves exports in the
        /// *calling* process - so the handle meant nothing to it.
        ///
        /// On x64 that went unnoticed, because a module is loaded at the same address
        /// in every process for the life of a boot, so ERC's own kernel32 base happened
        /// to match the target's. On a 32-bit target inspected from a 64-bit ERC the
        /// bases differ, and rather than the call failing it was worked around with a
        /// table of hard-coded offsets:
        ///
        ///     ApiAddresses.Add("VirtualAlloc", hModule + 0x166B0);
        ///
        /// Those offsets describe one build of kernel32. On any other Windows version,
        /// or after any update to it, they point somewhere else in the module - and
        /// nothing detects that, so the chain is produced, looks entirely plausible,
        /// and calls into the middle of an unrelated function.
        ///
        /// Reading the target module's own export directory answers the question that
        /// was actually being asked, on every Windows version, for both architectures.
        /// </remarks>
        public static ErcResult<Dictionary<string, IntPtr>> ChainApis(ProcessInfo info)
        {
            if (info == null)
            {
                throw new ArgumentNullException(nameof(info));
            }

            var result = new ErcResult<Dictionary<string, IntPtr>>(info.ProcessCore);
            result.ReturnValue = new Dictionary<string, IntPtr>();

            var missing = new List<string>();

            foreach (string name in ChainApiNames)
            {
                IntPtr address;

                if (TryResolveInProcess(info, name, out address))
                {
                    result.ReturnValue.Add(name, address);
                }
                else
                {
                    missing.Add(name);
                }
            }

            if (missing.Count > 0)
            {
                result.Error = new ERCException(
                    "Could not resolve " + string.Join(", ", missing.ToArray()) +
                    " in any module loaded by this process. Chains needing them cannot be built.");
            }

            return result;
        }

        /// <summary>
        /// Finds a function in whichever loaded module exports it.
        /// </summary>
        /// <remarks>
        /// kernel32 is tried first because that is where all four live on every
        /// supported Windows version, and preferring it keeps the resolved address
        /// stable rather than depending on module enumeration order.
        /// </remarks>
        private static bool TryResolveInProcess(ProcessInfo info, string name, out IntPtr address)
        {
            address = IntPtr.Zero;

            foreach (bool kernel32Only in new[] { true, false })
            {
                foreach (ModuleInfo module in info.ModulesInfo)
                {
                    if (module.ModuleFailed || !File.Exists(module.ModulePath))
                    {
                        continue;
                    }

                    bool isKernel32 = Path.GetFileName(module.ModulePath)
                        .Equals("kernel32.dll", StringComparison.OrdinalIgnoreCase);

                    if (kernel32Only != isKernel32)
                    {
                        continue;
                    }

                    if (ExportTable.TryResolve(module.ModulePath, module.ModuleBase, name, out address))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Whether an address contains a byte the target would mangle.
        /// </summary>
        /// <remarks>
        /// Reuses the same filter the searches use, so "excluded" means the same
        /// thing everywhere rather than being reimplemented per command.
        /// </remarks>
        private static bool ContainsExcludedByte(IntPtr address, MachineType machineType, byte[] excluded)
        {
            var single = new Dictionary<IntPtr, string> { { address, string.Empty } };
            return PtrRemover.RemovePointers(machineType, single, excluded).Count == 0;
        }
    }
}
