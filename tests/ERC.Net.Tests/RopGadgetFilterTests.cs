using System;
using System.Collections.Generic;
using System.Linq;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Tests for the gadget selection rule shared by both ROP generators.
    /// </summary>
    /// <remarks>
    /// This rule used to be copy-pasted into ~130 blocks, one per register and
    /// instruction, every one of which carried the same defect.
    /// </remarks>
    public class RopGadgetFilterTests
    {
        private static Dictionary<IntPtr, string> Gadgets(params string[] disassembly)
        {
            var d = new Dictionary<IntPtr, string>();
            for (int i = 0; i < disassembly.Length; i++)
            {
                d.Add((IntPtr)(0x1000 + i), disassembly[i]);
            }
            return d;
        }

        // ------------------------------------------------- the defect

        [Fact]
        public void Every_matching_gadget_is_kept_even_after_a_rejection()
        {
            // The defect. Each block iterated a list forwards while calling
            // RemoveAt(i) on rejection, so the element after every rejected gadget
            // shifted into the current index and was skipped without ever being
            // considered. Usable gadgets were silently dropped, and the more
            // unusable ones a module contained the more were lost.
            //
            // Interleaving rejects and matches is what exposes it.
            var source = Gadgets(
                "nop, ret",            // rejected: no "push eax"
                "push eax, ret",       // would have been skipped
                "xor ebx, ebx, ret",   // rejected
                "push eax, pop ebx, ret",   // would have been skipped
                "int3",                // rejected
                "push eax, nop, ret");      // would have been skipped

            var usable = RopGadgetFilter.SelectUsable(source, "push eax", false);

            usable.Count.ShouldBe(3);
            usable.Values.ShouldContain("push eax, ret");
            usable.Values.ShouldContain("push eax, pop ebx, ret");
            usable.Values.ShouldContain("push eax, nop, ret");
        }

        [Fact]
        public void Consecutive_rejections_do_not_hide_a_later_match()
        {
            var source = Gadgets("nop, ret", "int3", "hlt", "push eax, ret");

            RopGadgetFilter.SelectUsable(source, "push eax", false)
                           .Values.ShouldBe(new[] { "push eax, ret" });
        }

        // ------------------------------------------------- the rule itself

        [Fact]
        public void A_gadget_must_contain_the_wanted_instruction()
        {
            var source = Gadgets("push ebx, ret");

            RopGadgetFilter.SelectUsable(source, "push eax", false).ShouldBeEmpty();
        }

        [Fact]
        public void A_gadget_must_end_in_a_return()
        {
            var source = Gadgets("push eax, nop");

            RopGadgetFilter.SelectUsable(source, "push eax", false).ShouldBeEmpty();
        }

        [Fact]
        public void Numeric_operands_are_rejected_when_asked_for()
        {
            // How the generators avoid gadgets like "ret 0x8", whose stack
            // adjustment would have to be accounted for in the chain.
            var source = Gadgets("push eax, ret 0x8", "push eax, ret");

            RopGadgetFilter.SelectUsable(source, "push eax", true)
                           .Values.ShouldBe(new[] { "push eax, ret" });
        }

        [Fact]
        public void Numeric_operands_are_kept_when_not_asked_for()
        {
            var source = Gadgets("push eax, ret 0x8", "push eax, ret");

            RopGadgetFilter.SelectUsable(source, "push eax", false).Count.ShouldBe(2);
        }

        [Fact]
        public void The_digit_filter_cannot_be_used_for_the_numbered_registers()
        {
            // r8 through r15 contain digits in their own names, so the digit filter
            // would reject every one of their gadgets. This is why the generators
            // pass false for those registers, and why it is a parameter rather than
            // a fixed rule.
            var source = Gadgets("push r8, ret");

            RopGadgetFilter.SelectUsable(source, "push r8", true).ShouldBeEmpty();
            RopGadgetFilter.SelectUsable(source, "push r8", false).Count.ShouldBe(1);
        }

        // ------------------------------------------------- ordering and safety

        [Fact]
        public void Shortest_gadgets_come_first()
        {
            // Chain building takes the first match, so the ordering is what makes it
            // prefer gadgets with the fewest side effects.
            var source = Gadgets(
                "push eax, pop ebx, pop ecx, nop, ret",
                "push eax, ret",
                "push eax, nop, ret");

            RopGadgetFilter.SelectUsable(source, "push eax", false)
                           .Values.ToList()
                           .ShouldBe(new List<string>
                           {
                               "push eax, ret",
                               "push eax, nop, ret",
                               "push eax, pop ebx, pop ecx, nop, ret"
                           });
        }

        [Fact]
        public void The_source_collection_is_not_modified()
        {
            var source = Gadgets("nop, ret", "push eax, ret");

            RopGadgetFilter.SelectUsable(source, "push eax", false);

            source.Count.ShouldBe(2);
        }

        [Fact]
        public void Addresses_are_preserved()
        {
            var source = new Dictionary<IntPtr, string>
            {
                { (IntPtr)0x41414141, "push eax, ret" }
            };

            RopGadgetFilter.SelectUsable(source, "push eax", false)
                           .ShouldContainKey((IntPtr)0x41414141);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void Empty_input_yields_no_gadgets(string _)
        {
            RopGadgetFilter.SelectUsable(null, "push eax", false).ShouldBeEmpty();
            RopGadgetFilter.SelectUsable(new Dictionary<IntPtr, string>(), "push eax", false).ShouldBeEmpty();
        }

        [Fact]
        public void IsUsable_matches_the_selection_rule()
        {
            RopGadgetFilter.IsUsable("push eax, ret", "push eax", false).ShouldBeTrue();
            RopGadgetFilter.IsUsable("push eax", "push eax", false).ShouldBeFalse();
            RopGadgetFilter.IsUsable("pop eax, ret", "push eax", false).ShouldBeFalse();
            RopGadgetFilter.IsUsable("push eax, ret 0x4", "push eax", true).ShouldBeFalse();
            RopGadgetFilter.IsUsable(null, "push eax", false).ShouldBeFalse();
            RopGadgetFilter.IsUsable("", "push eax", false).ShouldBeFalse();
        }
    }
}
