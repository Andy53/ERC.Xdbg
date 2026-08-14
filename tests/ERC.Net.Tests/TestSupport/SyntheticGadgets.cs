using System;
using System.Collections.Generic;
using System.Linq;
using ERC.Utilities;

namespace ERC.Net.Tests.TestSupport
{
    /// <summary>
    /// A fixed gadget table, so a generated ROP chain is reproducible.
    /// </summary>
    /// <remarks>
    /// The chain builders read only three things: the usable gadget lists, the API
    /// addresses and the ROP nops. Supplying all three by hand removes the live
    /// process from the result, which is what makes a recorded chain a meaningful
    /// thing to compare against - real gadget addresses move with every load.
    ///
    /// Addresses are chosen to be recognisable in a recorded chain and to contain no
    /// byte that a bad-character test would reject.
    /// </remarks>
    public static class SyntheticGadgets
    {
        /// <summary>Base address the synthetic gadgets are laid out from.</summary>
        public const long Base32 = 0x11110000;

        /// <summary>Base address the synthetic 64-bit gadgets are laid out from.</summary>
        public const long Base64 = 0x0000111122220000;

        /// <summary>A ROP nop, as the builders expect at least one.</summary>
        public const long RopNop32 = 0x11119999;

        /// <summary>A 64-bit ROP nop.</summary>
        public const long RopNop64 = 0x0000111122229999;

        /// <summary>
        /// Every 32-bit list populated with one gadget, at a predictable address.
        /// </summary>
        /// <remarks>
        /// One entry per list rather than several: the builders take the first usable
        /// gadget, so extra entries would not change the chain but would make a
        /// recorded one harder to read.
        /// </remarks>
        public static RopChainGenerator32.X86Lists Lists32()
        {
            var lists = new RopChainGenerator32.X86Lists();

            for (int i = 0; i < GadgetCatalog.X86Lists.Count; i++)
            {
                GadgetList<RopChainGenerator32.X86Lists> list = GadgetCatalog.X86Lists[i];

                GadgetCatalog.X86Lists[i].Set(lists, new Dictionary<IntPtr, string>
                {
                    { new IntPtr(Base32 + ((i + 1) * 0x10)), list.Mnemonic + ", ret" }
                });
            }

            return lists;
        }

        /// <summary>
        /// Every 64-bit list populated with one gadget, at a predictable address.
        /// </summary>
        public static RopChainGenerator64.X64Lists Lists64()
        {
            var lists = new RopChainGenerator64.X64Lists();

            for (int i = 0; i < GadgetCatalog.X64Lists.Count; i++)
            {
                GadgetList<RopChainGenerator64.X64Lists> list = GadgetCatalog.X64Lists[i];

                GadgetCatalog.X64Lists[i].Set(lists, new Dictionary<IntPtr, string>
                {
                    { new IntPtr(Base64 + ((i + 1) * 0x10)), list.Mnemonic + ", ret" }
                });
            }

            return lists;
        }

        /// <summary>The four API addresses a chain can be built around.</summary>
        public static Dictionary<string, IntPtr> ApiAddresses(bool is64Bit)
        {
            long apiBase = is64Bit ? 0x0000111133330000 : 0x11113330;

            return new Dictionary<string, IntPtr>
            {
                { "VirtualAlloc", new IntPtr(apiBase + 0x1) },
                { "HeapCreate", new IntPtr(apiBase + 0x2) },
                { "VirtualProtect", new IntPtr(apiBase + 0x3) },
                { "WriteProcessMemory", new IntPtr(apiBase + 0x4) }
            };
        }

        /// <summary>
        /// Renders a chain as text, so it can be compared line by line.
        /// </summary>
        /// <remarks>
        /// A mismatch then names the entry that changed rather than reporting that two
        /// long byte arrays differ.
        /// </remarks>
        public static IReadOnlyList<string> Render(IEnumerable<Tuple<byte[], string>> chain)
        {
            return chain
                .Select(entry => BitConverter.ToString(entry.Item1).Replace("-", "") + " | " + entry.Item2)
                .ToList();
        }
    }
}
