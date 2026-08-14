using ERC;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Pins the exact text the disassembler produces.
    /// </summary>
    /// <remarks>
    /// This is a contract, not a formatting preference. The ROP generators identify
    /// gadgets by searching the disassembly *string* - "push eax", "ret", and a digit
    /// test for immediate operands - so any change to spacing, casing or operand
    /// syntax silently changes which gadgets are found.
    ///
    /// These tests exist so that swapping the disassembler engine is a visible,
    /// reviewed change rather than a silent one.
    /// </remarks>
    public class DisassemblyContractTests
    {
        private static string Disassemble(byte[] opcodes, MachineType machine)
        {
            ErcResult<string> result = OpcodeDisassembler.Disassemble(opcodes, machine);
            result.Error.ShouldBeNull();
            return result.ReturnValue.Trim();
        }

        [Theory]
        [InlineData(new byte[] { 0xFF, 0xE4 }, "jmp esp")]
        [InlineData(new byte[] { 0x90 }, "nop")]
        [InlineData(new byte[] { 0xC3 }, "ret")]
        [InlineData(new byte[] { 0x58 }, "pop eax")]
        [InlineData(new byte[] { 0x5B }, "pop ebx")]
        [InlineData(new byte[] { 0x50 }, "push eax")]
        [InlineData(new byte[] { 0x53 }, "push ebx")]
        [InlineData(new byte[] { 0x31, 0xC0 }, "xor eax, eax")]
        [InlineData(new byte[] { 0x60 }, "pusha")]
        public void X86_instructions_render_as_expected(byte[] opcodes, string expected)
        {
            Disassemble(opcodes, MachineType.I386).ShouldBe(expected);
        }

        [Theory]
        [InlineData(new byte[] { 0xFF, 0xE4 }, "jmp rsp")]
        [InlineData(new byte[] { 0x50 }, "push rax")]
        [InlineData(new byte[] { 0x41, 0x50 }, "push r8")]
        [InlineData(new byte[] { 0x41, 0x57 }, "push r15")]
        [InlineData(new byte[] { 0x48, 0x31, 0xC9 }, "xor rcx, rcx")]
        public void X64_instructions_render_as_expected(byte[] opcodes, string expected)
        {
            Disassemble(opcodes, MachineType.x64).ShouldBe(expected);
        }

        [Fact]
        public void Mnemonics_are_lower_case()
        {
            // The gadget search compares against lower-case literals such as
            // "push eax", so upper-case output would match nothing at all.
            string text = Disassemble(new byte[] { 0x50, 0xC3 }, MachineType.I386);

            text.ShouldBe(text.ToLowerInvariant());
        }

        [Fact]
        public void Operands_are_separated_by_a_comma_and_a_space()
        {
            Disassemble(new byte[] { 0x31, 0xC0 }, MachineType.I386).ShouldBe("xor eax, eax");
        }

        [Fact]
        public void Multiple_instructions_appear_one_per_line()
        {
            // The ROP generators join these with ", " and then search the result, so
            // the line-per-instruction shape matters.
            ErcResult<string> result = OpcodeDisassembler.Disassemble(
                new byte[] { 0x58, 0x5B, 0xC3 }, MachineType.I386);

            string[] lines = result.ReturnValue
                .Split(new[] { "\r\n", "\n" }, System.StringSplitOptions.RemoveEmptyEntries);

            lines.Length.ShouldBe(3);
            lines[0].Trim().ShouldBe("pop eax");
            lines[1].Trim().ShouldBe("pop ebx");
            lines[2].Trim().ShouldBe("ret");
        }

        [Fact]
        public void A_return_with_an_immediate_contains_a_digit()
        {
            // The gadget filter rejects immediates by testing for any digit in the
            // disassembly, so this rendering has to keep one.
            string text = Disassemble(new byte[] { 0xC2, 0x08, 0x00 }, MachineType.I386);

            text.ShouldStartWith("ret");
            text.ShouldContain("8");
        }

        [Fact]
        public void Register_names_that_contain_digits_still_render_with_them()
        {
            // The mirror of the above: r8-r15 legitimately contain digits, which is
            // why the digit filter is off for those registers.
            Disassemble(new byte[] { 0x41, 0x50 }, MachineType.x64).ShouldContain("8");
        }

        [Theory]
        // The mnemonic on the right is the literal a ROP generator searches for.
        [InlineData(new byte[] { 0x50, 0xC3 }, "push eax", MachineType.I386)]
        [InlineData(new byte[] { 0x58, 0xC3 }, "pop eax",  MachineType.I386)]
        [InlineData(new byte[] { 0x31, 0xC0, 0xC3 }, "xor eax", MachineType.I386)]
        [InlineData(new byte[] { 0xFF, 0xE4, 0xC3 }, "jmp esp", MachineType.I386)]
        [InlineData(new byte[] { 0x60, 0xC3 }, "pusha",   MachineType.I386)]
        [InlineData(new byte[] { 0x41, 0x50, 0xC3 }, "push r8", MachineType.x64)]
        [InlineData(new byte[] { 0x41, 0x5F, 0xC3 }, "pop r15", MachineType.x64)]
        [InlineData(new byte[] { 0x48, 0x31, 0xC9, 0xC3 }, "xor rcx", MachineType.x64)]
        public void The_gadget_search_terms_match_what_the_disassembler_produces(
            byte[] opcodes, string searchTerm, MachineType machine)
        {
            // Ties the two halves together. The generators find gadgets by searching
            // the disassembly text, so a formatter that renders an instruction
            // differently silently empties a gadget list rather than failing.
            //
            // That is not hypothetical: swapping SharpDisasm for Iced changed 0x60
            // from "pushad" to "pusha", which would have left the pushad list empty
            // for every target, with no error anywhere.
            //
            // Each sample ends in a return because the generators require one - they
            // disassemble from the match to the end of the scanned region, so a real
            // gadget string reaches a ret. Whether that requirement makes sense for
            // jmp/call gadgets is a separate question for the ROP rework.
            string text = Disassemble(opcodes, machine).Replace(System.Environment.NewLine, ", ");

            RopGadgetFilter.IsUsable(text, searchTerm, false)
                .ShouldBeTrue("gadget search for \"" + searchTerm + "\" should match \"" + text + "\"");
        }

        [Fact]
        public void An_unsupported_machine_type_is_refused()
        {
            OpcodeDisassembler.Disassemble(new byte[] { 0x90 }, MachineType.Itanium)
                              .Error.ShouldNotBeNull();
        }

        [Fact]
        public void Empty_input_produces_no_instructions()
        {
            ErcResult<string> result = OpcodeDisassembler.Disassemble(new byte[0], MachineType.I386);

            result.Error.ShouldBeNull();
            (result.ReturnValue ?? string.Empty).Trim().ShouldBeEmpty();
        }
    }
}
