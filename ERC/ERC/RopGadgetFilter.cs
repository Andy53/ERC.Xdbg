using System;
using System.Collections.Generic;
using System.Linq;

namespace ERC.Utilities
{
    /// <summary>
    /// Selects the gadgets that are usable for chain building.
    /// </summary>
    /// <remarks>
    /// Extracted from the ~130 near-identical blocks in the two ROP generators, one
    /// per register and instruction. Having it in one place makes the rule testable
    /// and stops the blocks drifting apart, which they already had.
    /// </remarks>
    public static class RopGadgetFilter
    {
        /// <summary>
        /// Returns the gadgets that perform the wanted instruction and end in a
        /// return, shortest first.
        /// </summary>
        /// <param name="source">Candidate gadgets, keyed by address.</param>
        /// <param name="mnemonic">The instruction the gadget must contain, e.g. "push eax".</param>
        /// <param name="excludeNumericOperands">
        /// When true, gadgets whose disassembly contains a digit are rejected, which
        /// is how the generators avoid instructions with immediate operands such as
        /// "ret 0x8". It cannot be used for the r8-r15 registers, whose names contain
        /// digits, which is why it is a parameter rather than a fixed rule.
        /// </param>
        /// <returns>A new dictionary; the source is not modified.</returns>
        public static Dictionary<IntPtr, string> SelectUsable(
            Dictionary<IntPtr, string> source,
            string mnemonic,
            bool excludeNumericOperands)
        {
            var usable = new Dictionary<IntPtr, string>();

            if (source == null)
            {
                return usable;
            }

            // Shortest disassembly first, so chain building prefers gadgets with the
            // fewest side effects. Insertion order is preserved by the dictionary and
            // the generators rely on it.
            List<KeyValuePair<IntPtr, string>> candidates = source.ToList();
            candidates.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));

            foreach (KeyValuePair<IntPtr, string> candidate in candidates)
            {
                if (IsUsable(candidate.Value, mnemonic, excludeNumericOperands))
                {
                    usable[candidate.Key] = candidate.Value;
                }
            }

            return usable;
        }

        /// <summary>
        /// Whether a single disassembled gadget is usable.
        /// </summary>
        public static bool IsUsable(string disassembly, string mnemonic, bool excludeNumericOperands)
        {
            if (string.IsNullOrEmpty(disassembly))
            {
                return false;
            }

            if (!disassembly.Contains(mnemonic))
            {
                return false;
            }

            if (!disassembly.Contains("ret"))
            {
                return false;
            }

            if (excludeNumericOperands && disassembly.Any(char.IsDigit))
            {
                return false;
            }

            return true;
        }
    }
}
