using System;
using System.Collections.Generic;
using System.Linq;
using ERC.Utilities;

namespace ERC.Output
{
    /// <summary>
    /// Formats collected ROP gadgets into the two listings ERC writes out.
    /// </summary>
    /// <remarks>
    /// One loop over <see cref="GadgetCatalog"/> in place of 130 copy-pasted blocks -
    /// one per gadget list, per architecture - each of which restated the list name,
    /// the instruction to look for and the address width by hand.
    ///
    /// Ten of them were wrong, and each failure was silent: the section simply came
    /// out empty, which is indistinguishable from a process that has no such gadget.
    ///
    ///   popEdi  looked for "pop edo", which is not an instruction. The 32-bit
    ///           listing therefore never showed a single "pop edi" gadget, one of
    ///           the most useful gadgets there is.
    ///   decRax through decRdi (seven lists) looked for "dec eax" through "dec edi"
    ///           in the 64-bit listing, but the lists are collected as "dec rax" and
    ///           so on, so none of those sections ever matched anything.
    ///   xorRax  was printed under the heading "xorEax" and looked for "xor eax".
    ///
    /// Taking the instruction from the same table the collector uses means the two
    /// can no longer disagree.
    /// </remarks>
    public static class RopGadgetReport
    {
        /// <summary>
        /// Appends a section per gadget list to the total and curated listings.
        /// </summary>
        /// <typeparam name="TLists">The catalogue type holding the gadget lists.</typeparam>
        /// <param name="catalog">The lists to report, in order.</param>
        /// <param name="lists">The collected gadgets.</param>
        /// <param name="addressDigits">Hex digits per address: 8 for 32-bit, 16 for 64-bit.</param>
        /// <param name="total">Receives every gadget found.</param>
        /// <param name="curated">Receives the subset worth using.</param>
        public static void Append<TLists>(
            IReadOnlyList<GadgetList<TLists>> catalog,
            TLists lists,
            int addressDigits,
            List<string> total,
            List<string> curated)
        {
            if (catalog == null)
            {
                throw new ArgumentNullException(nameof(catalog));
            }

            if (total == null || curated == null)
            {
                throw new ArgumentNullException(total == null ? nameof(total) : nameof(curated));
            }

            string format = "X" + addressDigits.ToString();

            foreach (GadgetList<TLists> list in catalog)
            {
                total.Add(list.Name + ": ");
                curated.Add(list.Name + ": ");

                Dictionary<IntPtr, string> gadgets = list.Get(lists);
                if (gadgets == null)
                {
                    continue;
                }

                foreach (KeyValuePair<IntPtr, string> gadget in gadgets)
                {
                    if (!Matches(gadget.Value, list.Mnemonic))
                    {
                        continue;
                    }

                    string line = "0x" + gadget.Key.ToString(format) + " | " + gadget.Value;
                    total.Add(line);

                    if (IsCurated(gadget.Value))
                    {
                        curated.Add(line);
                    }
                }
            }
        }

        /// <summary>
        /// Whether a gadget's disassembly is one this list wants.
        /// </summary>
        /// <remarks>
        /// A gadget has to both perform the instruction and end in a return, or
        /// execution does not continue to the next entry in the chain.
        /// </remarks>
        private static bool Matches(string? disassembly, string mnemonic)
        {
            return disassembly != null
                && disassembly.IndexOf(mnemonic, StringComparison.OrdinalIgnoreCase) >= 0
                && disassembly.IndexOf("ret", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        /// <summary>
        /// Whether a gadget belongs in the shorter, hand-usable listing.
        /// </summary>
        /// <remarks>
        /// Anything the disassembler could not read is dropped, as is anything with a
        /// literal number in it: those consume or displace stack slots, which shifts
        /// every entry after them in the chain.
        /// </remarks>
        private static bool IsCurated(string disassembly)
        {
            return !disassembly.Any(char.IsDigit)
                && disassembly.IndexOf("invalid", StringComparison.OrdinalIgnoreCase) < 0;
        }
    }
}
