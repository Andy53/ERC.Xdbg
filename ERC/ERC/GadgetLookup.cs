using System;
using System.Collections.Generic;
using System.Linq;

namespace ERC.Utilities
{
    /// <summary>
    /// Finds a single kind of ROP gadget by name.
    /// </summary>
    /// <remarks>
    /// The gadget scan collects 45 kinds of gadget on x86 and 85 on x64, and the only
    /// way to see any of them was to generate the whole listing and read the section
    /// you wanted out of a file. When what you want is "the pop ecx gadgets", that is
    /// a lot of output to produce and discard.
    ///
    /// The catalogue already names every list and the instruction it holds, so
    /// selecting one is a lookup rather than new machinery.
    /// </remarks>
    public static class GadgetLookup
    {
        /// <summary>
        /// The gadget kinds available for an architecture.
        /// </summary>
        /// <param name="machineType">Architecture of the process.</param>
        /// <returns>The instruction each kind holds, for example "pop eax".</returns>
        public static IReadOnlyList<string> Available(MachineType machineType)
        {
            return machineType == MachineType.x64
                ? GadgetCatalog.X64Lists.Select(l => l.Mnemonic).ToList()
                : GadgetCatalog.X86Lists.Select(l => l.Mnemonic).ToList();
        }

        /// <summary>
        /// Selects the gadgets matching an instruction from an already-scanned set.
        /// </summary>
        /// <param name="lists">The collected 32-bit gadgets.</param>
        /// <param name="instruction">
        /// The instruction wanted, for example "pop ecx". Matched against the
        /// catalogue's own names, so it is the same spelling the listing uses.
        /// </param>
        /// <param name="matched">The name of the list that matched.</param>
        /// <returns>The gadgets, or null when nothing matched the instruction.</returns>
        public static Dictionary<IntPtr, string>? Select32(
            RopChainGenerator32.X86Lists lists, string? instruction, out string? matched)
        {
            return Select(GadgetCatalog.X86Lists, lists, instruction, out matched);
        }

        /// <summary>
        /// Selects the gadgets matching an instruction from an already-scanned set.
        /// </summary>
        /// <param name="lists">The collected 64-bit gadgets.</param>
        /// <param name="instruction">The instruction wanted, for example "pop rcx".</param>
        /// <param name="matched">The name of the list that matched.</param>
        /// <returns>The gadgets, or null when nothing matched the instruction.</returns>
        public static Dictionary<IntPtr, string>? Select64(
            RopChainGenerator64.X64Lists lists, string? instruction, out string? matched)
        {
            return Select(GadgetCatalog.X64Lists, lists, instruction, out matched);
        }

        private static Dictionary<IntPtr, string>? Select<TLists>(
            IReadOnlyList<GadgetList<TLists>> catalog,
            TLists lists,
            string? instruction,
            out string? matched)
        {
            matched = null;

            if (string.IsNullOrWhiteSpace(instruction))
            {
                return null;
            }

            // Whitespace is normalised so that "pop  eax" and "pop eax" are the same
            // request, and the list's own field name is accepted too, because that is
            // what the headings in the full listing say.
            string wanted = Normalise(instruction!);

            foreach (GadgetList<TLists> list in catalog)
            {
                if (Normalise(list.Mnemonic) == wanted ||
                    list.Name.Equals(instruction!.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    matched = list.Name;
                    return list.Get(lists) ?? new Dictionary<IntPtr, string>();
                }
            }

            return null;
        }

        private static string Normalise(string text)
        {
            return string.Join(" ", text.ToLowerInvariant()
                                        .Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries));
        }
    }
}
