using System;
using System.Collections.Generic;
using System.Linq;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers selecting one kind of gadget out of a collected set.
    /// </summary>
    /// <remarks>
    /// Backed by the same catalogue the full listing uses, so the names accepted here
    /// and the headings printed there cannot disagree.
    /// </remarks>
    public class GadgetLookupTests
    {
        private static RopChainGenerator32.X86Lists With(string name, params long[] addresses)
        {
            var lists = new RopChainGenerator32.X86Lists();
            var gadgets = addresses.ToDictionary(a => new IntPtr(a), a => "gadget at " + a);
            GadgetCatalog.X86Lists.Single(l => l.Name == name).Set(lists, gadgets);
            return lists;
        }

        [Fact]
        public void A_gadget_kind_is_selected_by_its_instruction()
        {
            string? matched;
            Dictionary<IntPtr, string>? found =
                GadgetLookup.Select32(With("popEcx", 0x401000), "pop ecx", out matched);

            found.ShouldNotBeNull();
            found!.Keys.Single().ShouldBe(new IntPtr(0x401000));
            matched.ShouldBe("popEcx");
        }

        [Fact]
        public void The_catalogue_list_name_is_accepted_too()
        {
            // That is the spelling the full listing prints as its heading, so it is
            // the spelling someone will copy back in.
            string? matched;

            GadgetLookup.Select32(With("popEcx", 0x401000), "popEcx", out matched).ShouldNotBeNull();
            matched.ShouldBe("popEcx");
        }

        [Theory]
        [InlineData("POP ECX")]
        [InlineData("pop  ecx")]
        [InlineData("  pop ecx  ")]
        public void Spelling_is_forgiving_about_case_and_spacing(string instruction)
        {
            string? matched;

            GadgetLookup.Select32(With("popEcx", 0x401000), instruction, out matched).ShouldNotBeNull();
            matched.ShouldBe("popEcx");
        }

        [Fact]
        public void An_instruction_that_is_not_collected_returns_nothing()
        {
            // Distinct from "collected but none found", which returns an empty set.
            // The command turns this into a message listing what does exist.
            string? matched;

            GadgetLookup.Select32(With("popEcx", 0x401000), "pop rcx", out matched).ShouldBeNull();
            matched.ShouldBeNull();
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData(null)]
        public void An_empty_request_returns_nothing(string? instruction)
        {
            string? matched;
            GadgetLookup.Select32(new RopChainGenerator32.X86Lists(), instruction, out matched).ShouldBeNull();
        }

        [Fact]
        public void A_collected_kind_with_no_gadgets_returns_an_empty_set_rather_than_nothing()
        {
            string? matched;
            Dictionary<IntPtr, string>? found =
                GadgetLookup.Select32(new RopChainGenerator32.X86Lists(), "pop ecx", out matched);

            found.ShouldNotBeNull();
            found!.ShouldBeEmpty();
            matched.ShouldBe("popEcx");
        }

        [Fact]
        public void Every_kind_in_the_catalogue_can_be_selected_by_its_own_mnemonic()
        {
            // The catalogue is the source of both the available list and the lookup,
            // so this checks they cannot drift apart.
            var lists = new RopChainGenerator32.X86Lists();

            foreach (string mnemonic in GadgetLookup.Available(MachineType.I386))
            {
                string? matched;
                GadgetLookup.Select32(lists, mnemonic, out matched)
                    .ShouldNotBeNull("\"" + mnemonic + "\" is offered but cannot be selected");
            }
        }

        [Fact]
        public void Every_64_bit_kind_can_be_selected_by_its_own_mnemonic()
        {
            var lists = new RopChainGenerator64.X64Lists();

            foreach (string mnemonic in GadgetLookup.Available(MachineType.x64))
            {
                string? matched;
                GadgetLookup.Select64(lists, mnemonic, out matched)
                    .ShouldNotBeNull("\"" + mnemonic + "\" is offered but cannot be selected");
            }
        }

        [Fact]
        public void The_available_kinds_differ_by_architecture()
        {
            IReadOnlyList<string> x86 = GadgetLookup.Available(MachineType.I386);
            IReadOnlyList<string> x64 = GadgetLookup.Available(MachineType.x64);

            x86.ShouldContain("pop ecx");
            x86.ShouldNotContain("pop rcx");

            x64.ShouldContain("pop rcx");
            x64.ShouldNotContain("pop ecx");

            x86.Count.ShouldBe(GadgetCatalog.X86Lists.Count);
            x64.Count.ShouldBe(GadgetCatalog.X64Lists.Count);
        }
    }
}
