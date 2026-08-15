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
