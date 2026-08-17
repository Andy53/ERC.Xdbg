using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using ERC.Config;
using ERC.Net.Tests.TestSupport;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Records the chains the builders produce from a fixed gadget table.
    /// </summary>
    /// <remarks>
    /// The chain builders are about three thousand lines of near-identical blocks -
    /// seven per chain, three chains, two architectures - and nothing could be said
    /// about their output because it depended on whichever gadgets happened to be in
    /// a live process at the time.
    ///
    /// Supplying the gadget table, the API addresses and the ROP nops makes the result
    /// a function of its input. These tests record that result so the blocks can be
    /// collapsed into one parameterised routine and the output shown to be unchanged.
    ///
    /// They are not assertions that the chains are correct - they record what the
    /// builders do today. Where the recorded behaviour is visibly wrong it is called
    /// out rather than quietly enshrined.
    ///
    /// Tagged Integration: a ProcessInfo needs a real process to attach to.
    /// </remarks>
    [Trait("Category", "Integration")]
    [Collection("LiveProcess")]
    public class RopChainGoldenTests
    {
        private static void SkipIfNoFixture()
        {
            if (TargetProcess.Locate() == null)
            {
                Assert.Skip("ErcTestTarget.exe was not built beside the test assembly.");
            }
        }

        /// <summary>
        /// A generator wired to a real process but a synthetic gadget table.
        /// </summary>
        private static void Run32(Action<RopChainGenerator32, ERC.ProcessInfo> body)
        {
            SkipIfNoFixture();

            if (IntPtr.Size != 4)
            {
                Assert.Skip("The 32-bit builders need a 32-bit target.");
            }

            using (var target = TargetProcess.Start())
            using (var info = new ERC.ProcessInfo(
                new ERC.ErcCore(new InMemoryConfigStore(), new InMemoryErcLogger()), target.Process))
            {
                var generator = new RopChainGenerator32(info);
                generator.usableX86Opcodes = SyntheticGadgets.Lists32();
                generator.ApiAddresses = SyntheticGadgets.ApiAddresses(false);
                generator.RopNops = new List<IntPtr> { new IntPtr(SyntheticGadgets.RopNop32) };

                body(generator, info);
            }
        }

        private static void Run64(Action<RopChainGenerator64, ERC.ProcessInfo> body)
        {
            SkipIfNoFixture();

            if (IntPtr.Size != 8)
            {
                Assert.Skip("The 64-bit builders need a 64-bit target.");
            }

            using (var target = TargetProcess.Start())
            using (var info = new ERC.ProcessInfo(
                new ERC.ErcCore(new InMemoryConfigStore(), new InMemoryErcLogger()), target.Process))
            {
                var generator = new RopChainGenerator64(info);
                generator.usableX64Opcodes = SyntheticGadgets.Lists64();
                generator.ApiAddresses = SyntheticGadgets.ApiAddresses(true);
                generator.RopNops = new List<IntPtr> { new IntPtr(SyntheticGadgets.RopNop64) };

                body(generator, info);
            }
        }

        // ------------------------------------------------------------ recorded chains

        /// <summary>Where the recorded chains live, beside this file.</summary>
        private static string GoldenPath(string name)
        {
            string? directory = AppContext.BaseDirectory;

            while (directory != null && !File.Exists(Path.Combine(directory, "ErcXdbgPlugin.sln")))
            {
                directory = Path.GetDirectoryName(directory.TrimEnd(Path.DirectorySeparatorChar));
            }

            return Path.Combine(directory ?? ".", "tests", "ERC.Net.Tests", "Golden", name + ".txt");
        }

        /// <summary>
        /// Compares a chain against its recorded form, writing the file if absent.
        /// </summary>
        /// <remarks>
        /// Writing on first run means a new chain is recorded rather than failing, and
        /// the file is then reviewed and committed like any other source.
        /// </remarks>
        private static void ShouldMatchGolden(IReadOnlyList<string> actual, string name)
        {
            string path = GoldenPath(name);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);

            if (!File.Exists(path))
            {
                File.WriteAllLines(path, actual);
                return;
            }

            string[] expected = File.ReadAllLines(path);

            // Compared line by line so a failure names the entry that moved.
            for (int i = 0; i < Math.Min(expected.Length, actual.Count); i++)
            {
                actual[i].ShouldBe(expected[i], name + " entry " + i);
            }

            actual.Count.ShouldBe(expected.Length, name + " chain length");
        }

        [Fact]
        public void The_VirtualAlloc_chain_is_unchanged()
        {
            Run32((generator, info) =>
            {
                var chain = generator.GenerateVirtualAllocChain32(info);

                chain.Error.ShouldBeNull();
                ShouldMatchGolden(SyntheticGadgets.Render(chain.ReturnValue), "virtualalloc32");
            });
        }

        [Fact]
        public void The_HeapCreate_chain_is_unchanged()
        {
            Run32((generator, info) =>
            {
                var chain = generator.GenerateHeapCreateChain32(info);

                chain.Error.ShouldBeNull();
                ShouldMatchGolden(SyntheticGadgets.Render(chain.ReturnValue), "heapcreate32");
            });
        }

        [Fact]
        public void The_VirtualProtect_chain_is_unchanged()
        {
            Run32((generator, info) =>
            {
                var chain = generator.GenerateVirtualProtectChain32(info);

                chain.Error.ShouldBeNull();
                ShouldMatchGolden(SyntheticGadgets.Render(chain.ReturnValue), "virtualprotect32");
            });
        }

        [Fact]
        public void The_64_bit_VirtualAlloc_chain_is_unchanged()
        {
            Run64((generator, info) =>
            {
                var chain = generator.GenerateVirtualAllocChain64(info);

                chain.Error.ShouldBeNull();
                ShouldMatchGolden(SyntheticGadgets.Render(chain.ReturnValue), "virtualalloc64");
            });
        }

        [Fact]
        public void The_64_bit_HeapCreate_chain_is_unchanged()
        {
            Run64((generator, info) =>
            {
                var chain = generator.GenerateHeapCreateChain64(info);

                chain.Error.ShouldBeNull();
                ShouldMatchGolden(SyntheticGadgets.Render(chain.ReturnValue), "heapcreate64");
            });
        }

        [Fact]
        public void The_64_bit_VirtualProtect_chain_is_unchanged()
        {
            Run64((generator, info) =>
            {
                var chain = generator.GenerateVirtualProtectChain64(info);

                chain.Error.ShouldBeNull();
                ShouldMatchGolden(SyntheticGadgets.Render(chain.ReturnValue), "virtualprotect64");
            });
        }

        // ------------------------------------------------- properties of any chain

        [Fact]
        public void Every_chain_entry_is_a_pointer_width_value_with_a_label()
        {
            Run32((generator, info) =>
            {
                var chain = generator.GenerateVirtualAllocChain32(info);

                chain.ReturnValue.ShouldNotBeEmpty();

                foreach (Tuple<byte[], string> entry in chain.ReturnValue)
                {
                    // A chain is written onto the stack a slot at a time; an entry of
                    // any other width would shift everything after it.
                    entry.Item1.Length.ShouldBe(4, entry.Item2);
                    entry.Item2.ShouldNotBeNullOrWhiteSpace();
                }
            });
        }

        [Fact]
        public void A_chain_built_with_no_gadgets_at_all_reports_rather_than_throwing()
        {
            // The realistic failure: a target where the bad-character filter removed
            // everything. Each register then falls through to the "must be allocated
            // manually" placeholder.
            Run32((generator, info) =>
            {
                generator.usableX86Opcodes = new RopChainGenerator32.X86Lists();

                var chain = generator.GenerateVirtualAllocChain32(info);

                chain.ReturnValue.ShouldNotBeNull();
                chain.ReturnValue.ShouldContain(e => e.Item2.Contains("must be allocated manually"));
            });
        }

        [Fact]
        public void The_chain_uses_the_supplied_api_address()
        {
            Run32((generator, info) =>
            {
                var chain = generator.GenerateVirtualAllocChain32(info);

                byte[] expected = BitConverter.GetBytes((int)SyntheticGadgets.ApiAddresses(false)["VirtualAlloc"]);

                chain.ReturnValue.ShouldContain(e => e.Item1.SequenceEqual(expected),
                    "the VirtualAlloc chain should place the address of VirtualAlloc on the stack");
            });
        }

        [Theory]
        [InlineData("VirtualAlloc")]
        [InlineData("HeapCreate")]
        [InlineData("VirtualProtect")]
        public void A_pop_gadget_is_immediately_followed_by_the_value_it_pops(string method)
        {
            // A chain is executed by returning into each address in turn, so a
            // "pop esi" runs and then consumes the slot after itself. The value has to
            // sit immediately below the gadget, or the register is loaded with
            // whatever followed instead.
            //
            // The three chains did not agree on this. HeapCreate and VirtualProtect
            // put the gadget first; VirtualAlloc put the value first, so EDI and ESI
            // in every VirtualAlloc chain were loaded with the wrong values.
            //
            // Checked for ESI and EDI specifically. A blanket rule does not hold:
            // EBP is deliberately loaded with the address of a "jmp esp" gadget, so
            // there the value legitimately looks like one.
            Run32((generator, info) =>
            {
                var chain = method == "VirtualAlloc" ? generator.GenerateVirtualAllocChain32(info)
                          : method == "HeapCreate" ? generator.GenerateHeapCreateChain32(info)
                          : generator.GenerateVirtualProtectChain32(info);

                List<Tuple<byte[], string>> entries = chain.ReturnValue;

                ShouldFollow(entries, "pop esi", "Pointer to " + method + ".", method);
                ShouldFollow(entries, "pop edi", "ROP NOP", method);
            });
        }

        /// <summary>
        /// Asserts that <paramref name="value"/> sits immediately after the gadget.
        /// </summary>
        private static void ShouldFollow(
            List<Tuple<byte[], string>> entries, string gadget, string value, string method)
        {
            int at = entries.FindIndex(e => e.Item2.StartsWith(gadget, StringComparison.OrdinalIgnoreCase));

            if (at < 0)
            {
                return;
            }

            (at + 1).ShouldBeLessThan(entries.Count,
                method + ": \"" + gadget + "\" is the last entry, so it pops nothing");

            entries[at + 1].Item2.ShouldBe(value,
                method + ": \"" + gadget + "\" should be followed by the value it pops");
        }

        [Theory]
        [InlineData("VirtualAlloc")]
        [InlineData("HeapCreate")]
        [InlineData("VirtualProtect")]
        public void Every_register_the_template_needs_is_set(string method)
        {
            // A register block that fails is supposed to leave a marked gap. What it
            // must not do is leave nothing at all, which is what happened when the ECX
            // block wrote its failure into edxList: ECX was marked satisfied, its own
            // fragment stayed empty, and the chain silently omitted the setup for
            // flProtect - the permission bits the chain exists to obtain.
            //
            // Against a gadget table where every list is populated, nothing should be
            // missing and nothing should be a gap.
            Run32((generator, info) =>
            {
                var chain = method == "VirtualAlloc" ? generator.GenerateVirtualAllocChain32(info)
                          : method == "HeapCreate" ? generator.GenerateHeapCreateChain32(info)
                          : generator.GenerateVirtualProtectChain32(info);

                List<Tuple<byte[], string>> entries = chain.ReturnValue;

                entries.ShouldNotContain(e => e.Item2.Contains("must be allocated manually"),
                    method + " left a register unset despite every gadget kind being available");

                // Each of the six registers the templates load should appear, either as
                // a pop into it or as a mov/xor touching it.
                foreach (string register in new[] { "eax", "ebx", "ecx", "edx", "ebp", "esi", "edi" })
                {
                    entries.ShouldContain(e => e.Item2.IndexOf(register, StringComparison.OrdinalIgnoreCase) >= 0,
                        method + " never touches " + register);
                }
            });
        }

        [Theory]
        [InlineData("VirtualAlloc")]
        [InlineData("HeapCreate")]
        [InlineData("VirtualProtect")]
        public void A_64_bit_pop_gadget_is_followed_by_the_value_it_pops(string method)
        {
            // The 64-bit builders emitted the value before the gadget, so every
            // register was loaded with whatever followed its gadget rather than the
            // value written for it. The 32-bit builders had the same defect in the
            // VirtualAlloc chain only.
            Run64((generator, info) =>
            {
                var chain = method == "VirtualAlloc" ? generator.GenerateVirtualAllocChain64(info)
                          : method == "HeapCreate" ? generator.GenerateHeapCreateChain64(info)
                          : generator.GenerateVirtualProtectChain64(info);

                List<Tuple<byte[], string>> entries = chain.ReturnValue;

                for (int i = 0; i < entries.Count; i++)
                {
                    if (!entries[i].Item2.StartsWith("pop ", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    // A pop preceded by a push is a register copy - it takes what the
                    // push put there, so no literal follows it. RCX and R9 are loaded
                    // that way, because they hold pointers rather than constants.
                    if (i > 0 && entries[i - 1].Item2.StartsWith("push ", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    (i + 1).ShouldBeLessThan(entries.Count,
                        method + ": \"" + entries[i].Item2 + "\" is the last entry, so it pops nothing");

                    // A gadget label ends in ", ret"; a value label names an argument.
                    entries[i + 1].Item2.ShouldNotEndWith(", ret",
                        method + ": \"" + entries[i].Item2 + "\" at " + i +
                        " is followed by another gadget rather than the value it pops");
                }
            });
        }

        [Fact]
        public void The_chain_uses_the_supplied_rop_nop()
        {
            Run32((generator, info) =>
            {
                var chain = generator.GenerateVirtualAllocChain32(info);

                byte[] expected = BitConverter.GetBytes((int)SyntheticGadgets.RopNop32);

                chain.ReturnValue.ShouldContain(e => e.Item1.SequenceEqual(expected));
            });
        }
    }
}
