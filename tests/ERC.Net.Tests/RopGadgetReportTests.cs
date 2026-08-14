using System;
using System.Collections.Generic;
using System.Linq;
using ERC.Output;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers the ROP gadget listings.
    /// </summary>
    /// <remarks>
    /// The formatter was 130 copy-pasted blocks - one per gadget list, per
    /// architecture - each restating the list name, the instruction to look for and
    /// the address width by hand. Ten of them named an instruction the list can never
    /// contain, and the only symptom was an empty section, which looks exactly like a
    /// process that has no such gadget.
    /// </remarks>
    public class RopGadgetReportTests
    {
        private static RopChainGenerator32.X86Lists X86(string name, params (long Address, string Disassembly)[] gadgets)
        {
            var lists = new RopChainGenerator32.X86Lists();
            var dictionary = gadgets.ToDictionary(g => new IntPtr(g.Address), g => g.Disassembly);
            GadgetCatalog.X86Lists.Single(l => l.Name == name).Set(lists, dictionary);
            return lists;
        }

        private static RopChainGenerator64.X64Lists X64(string name, params (long Address, string Disassembly)[] gadgets)
        {
            var lists = new RopChainGenerator64.X64Lists();
            var dictionary = gadgets.ToDictionary(g => new IntPtr(g.Address), g => g.Disassembly);
            GadgetCatalog.X64Lists.Single(l => l.Name == name).Set(lists, dictionary);
            return lists;
        }

        private static (List<string> Total, List<string> Curated) Report32(RopChainGenerator32.X86Lists lists)
        {
            var total = new List<string>();
            var curated = new List<string>();
            RopGadgetReport.Append(GadgetCatalog.X86Lists, lists, 8, total, curated);
            return (total, curated);
        }

        private static (List<string> Total, List<string> Curated) Report64(RopChainGenerator64.X64Lists lists)
        {
            var total = new List<string>();
            var curated = new List<string>();
            RopGadgetReport.Append(GadgetCatalog.X64Lists, lists, 16, total, curated);
            return (total, curated);
        }

        /// <summary>The lines under a section heading, up to the next heading.</summary>
        private static IReadOnlyList<string> Section(IReadOnlyList<string> lines, string name)
        {
            int start = lines.ToList().IndexOf(name + ": ");
            start.ShouldBeGreaterThanOrEqualTo(0, "no section headed " + name);

            var section = new List<string>();
            for (int i = start + 1; i < lines.Count && !lines[i].EndsWith(": "); i++)
            {
                section.Add(lines[i]);
            }

            return section;
        }

        // ------------------------------------------------------- the ten broken lists

        [Fact]
        public void A_pop_edi_gadget_appears_in_the_popEdi_section()
        {
            // The block this replaces looked for "pop edo", which is not an
            // instruction, so the 32-bit listing never showed a single "pop edi"
            // gadget - one of the most useful gadgets there is.
            var lists = X86("popEdi", (0x00401000, "pop edi, ret"));

            Section(Report32(lists).Total, "popEdi")
                .ShouldBe(new[] { "0x00401000 | pop edi, ret" });
        }

        [Theory]
        [InlineData("decRax", "dec rax")]
        [InlineData("decRbx", "dec rbx")]
        [InlineData("decRcx", "dec rcx")]
        [InlineData("decRdx", "dec rdx")]
        [InlineData("decRbp", "dec rbp")]
        [InlineData("decRsp", "dec rsp")]
        [InlineData("decRdi", "dec rdi")]
        public void A_64_bit_dec_gadget_appears_in_its_own_section(string name, string instruction)
        {
            // These seven looked for the 32-bit register names - "dec eax" and so on -
            // while the lists are collected as "dec rax". Nothing ever matched.
            var lists = X64(name, (0x40001000, instruction + ", ret"));

            Section(Report64(lists).Total, name)
                .ShouldBe(new[] { "0x0000000040001000 | " + instruction + ", ret" });
        }

        [Fact]
        public void A_xor_rax_gadget_appears_under_its_own_heading()
        {
            // Printed under the heading "xorEax" and filtered on "xor eax".
            var lists = X64("xorRax", (0x40002000, "xor rax, rax, ret"));

            Report64(lists).Total.ShouldContain("xorRax: ");
            Report64(lists).Total.ShouldNotContain("xorEax: ");

            Section(Report64(lists).Total, "xorRax")
                .ShouldBe(new[] { "0x0000000040002000 | xor rax, rax, ret" });
        }

        // ------------------------------------------------------------- what it selects

        [Fact]
        public void A_gadget_that_does_not_return_is_not_listed()
        {
            // Without a return, execution never reaches the next entry in the chain.
            var lists = X86("popEdi", (0x00401000, "pop edi, jmp eax"));

            Section(Report32(lists).Total, "popEdi").ShouldBeEmpty();
        }

        [Fact]
        public void A_gadget_that_does_not_perform_the_instruction_is_not_listed()
        {
            var lists = X86("popEdi", (0x00401000, "pop esi, ret"));

            Section(Report32(lists).Total, "popEdi").ShouldBeEmpty();
        }

        [Fact]
        public void Every_matching_gadget_reaches_the_total_listing()
        {
            var lists = X86("popEdi",
                (0x00401000, "pop edi, ret"),
                (0x00402000, "pop edi, add esp, 8, ret"),
                (0x00403000, "pop edi, invalid, ret"));

            Section(Report32(lists).Total, "popEdi").Count.ShouldBe(3);
        }

        [Fact]
        public void The_curated_listing_leaves_out_gadgets_with_a_literal_number()
        {
            // A literal consumes or displaces stack slots, which shifts every entry
            // after it in the chain.
            var lists = X86("popEdi",
                (0x00401000, "pop edi, ret"),
                (0x00402000, "pop edi, add esp, 8, ret"));

            Section(Report32(lists).Curated, "popEdi")
                .ShouldBe(new[] { "0x00401000 | pop edi, ret" });
        }

        [Fact]
        public void The_curated_listing_leaves_out_gadgets_the_disassembler_could_not_read()
        {
            var lists = X86("popEdi",
                (0x00401000, "pop edi, ret"),
                (0x00402000, "pop edi, (bad), invalid, ret"));

            Section(Report32(lists).Curated, "popEdi")
                .ShouldBe(new[] { "0x00401000 | pop edi, ret" });
        }

        // --------------------------------------------------------------- presentation

        [Fact]
        public void A_32_bit_address_is_printed_in_eight_hex_digits()
        {
            var lists = X86("popEdi", (0x00401000, "pop edi, ret"));

            Section(Report32(lists).Total, "popEdi").Single().ShouldStartWith("0x00401000 | ");
        }

        [Fact]
        public void A_64_bit_address_is_printed_in_sixteen_hex_digits()
        {
            // IntPtr is the width of the process, so an address this size cannot even
            // be constructed when the tests run as 32-bit.
            if (IntPtr.Size != 8)
            {
                return;
            }

            // Truncating to eight digits would print an address that does not exist.
            var lists = X64("pushRax", (0x00007FF612340000, "push rax, ret"));

            Section(Report64(lists).Total, "pushRax").Single()
                .ShouldStartWith("0x00007FF612340000 | ");
        }

        [Fact]
        public void Every_list_gets_a_heading_even_when_it_found_nothing()
        {
            // An absent heading and an empty section mean different things: the first
            // says ERC did not look, the second that it looked and found none.
            var report = Report32(new RopChainGenerator32.X86Lists());

            foreach (var list in GadgetCatalog.X86Lists)
            {
                report.Total.ShouldContain(list.Name + ": ");
                report.Curated.ShouldContain(list.Name + ": ");
            }
        }

        [Fact]
        public void The_sections_appear_in_catalogue_order()
        {
            var report = Report32(new RopChainGenerator32.X86Lists());

            report.Total.Where(l => l.EndsWith(": "))
                .ShouldBe(GadgetCatalog.X86Lists.Select(l => l.Name + ": "));
        }

        [Fact]
        public void Both_architectures_report_every_list_they_have()
        {
            Report32(new RopChainGenerator32.X86Lists()).Total
                .Count(l => l.EndsWith(": ")).ShouldBe(GadgetCatalog.X86Lists.Count);

            Report64(new RopChainGenerator64.X64Lists()).Total
                .Count(l => l.EndsWith(": ")).ShouldBe(GadgetCatalog.X64Lists.Count);
        }

        [Fact]
        public void A_list_that_was_never_populated_is_reported_as_empty_rather_than_throwing()
        {
            // Nothing guarantees every list has been assigned by the time output runs.
            var lists = new RopChainGenerator32.X86Lists();
            GadgetCatalog.X86Lists.Single(l => l.Name == "popEdi").Set(lists, null!);

            Should.NotThrow(() => Report32(lists));
        }

        [Fact]
        public void Matching_ignores_case_so_a_disassembler_change_does_not_empty_a_section()
        {
            var lists = X86("popEdi", (0x00401000, "POP EDI, RET"));

            Section(Report32(lists).Total, "popEdi").Count.ShouldBe(1);
        }
    }
}
