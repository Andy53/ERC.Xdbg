using System.Linq;
using ERC;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers instruction-sequence search behind "ERC --findwild".
    /// </summary>
    public class FindWildTests
    {
        [Fact]
        public void Parse_splits_on_hash_and_semicolon()
        {
            InstructionPattern pattern = FindWild.Parse("pop eax # pop ebx ; ret");

            pattern.Length.ShouldBe(3);
            pattern.Elements[0].Exact.ShouldBe("pop eax");
            pattern.Elements[1].Exact.ShouldBe("pop ebx");
            pattern.Elements[2].Exact.ShouldBe("ret");
        }

        [Fact]
        public void Parse_treats_a_star_as_any_instruction()
        {
            InstructionPattern pattern = FindWild.Parse("pop eax # * # ret");

            pattern.Elements[1].AnyInstruction.ShouldBeTrue();
        }

        [Fact]
        public void Parse_treats_jmp_star_as_any_jump()
        {
            InstructionPattern pattern = FindWild.Parse("jmp *");

            pattern.Length.ShouldBe(1);
            pattern.Elements[0].AnyOperand.ShouldBeTrue();
            pattern.Elements[0].Mnemonic.ShouldBe("jmp");
        }

        [Fact]
        public void Parse_normalises_commas_inside_an_instruction()
        {
            InstructionPattern pattern = FindWild.Parse("mov ebx,eax");

            pattern.Elements[0].Exact.ShouldBe("mov ebx, eax");
        }

        [Fact]
        public void Parse_rejects_an_empty_line()
        {
            Should.Throw<ERCException>(() => FindWild.Parse("")).Message.ShouldContain("instructions");
            Should.Throw<ERCException>(() => FindWild.Parse(" # ; ")).Message.ShouldContain("instructions");
        }

        [Fact]
        public void Match_finds_pop_pop_ret()
        {
            byte[] bytes = { 0x90, 0x58, 0x5B, 0xC3, 0x90 };
            InstructionPattern pattern = FindWild.Parse("pop eax # pop ebx # ret");

            System.Collections.Generic.IReadOnlyList<InstructionMatch> matches =
                FindWild.Match(bytes, pattern, MachineType.I386);

            matches.Count.ShouldBe(1);
            matches[0].Offset.ShouldBe(1);
            matches[0].Disassembly.ShouldBe("pop eax # pop ebx # ret");
        }

        [Fact]
        public void Match_finds_jmp_esp_through_an_operand_wildcard()
        {
            byte[] bytes = { 0xFF, 0xE4 };
            InstructionPattern pattern = FindWild.Parse("jmp *");

            FindWild.Match(bytes, pattern, MachineType.I386)
                    .Single().Disassembly.ShouldBe("jmp esp");
        }

        [Fact]
        public void A_wildcard_instruction_fills_one_slot()
        {
            byte[] bytes = { 0x58, 0x5B, 0xC3 };
            InstructionPattern pattern = FindWild.Parse("pop eax # * # ret");

            FindWild.Match(bytes, pattern, MachineType.I386)
                    .Single().Disassembly.ShouldBe("pop eax # pop ebx # ret");
        }

        [Fact]
        public void Match_returns_empty_when_the_sequence_is_absent()
        {
            byte[] bytes = { 0x90, 0x90, 0xC3 };
            InstructionPattern pattern = FindWild.Parse("pop eax # pop ebx # ret");

            FindWild.Match(bytes, pattern, MachineType.I386).ShouldBeEmpty();
        }

        [Fact]
        public void Match_finds_every_occurrence()
        {
            byte[] bytes = { 0xC3, 0x90, 0xC3 };
            InstructionPattern pattern = FindWild.Parse("ret");

            FindWild.Match(bytes, pattern, MachineType.I386)
                    .Select(m => m.Offset)
                    .ShouldBe(new[] { 0, 2 });
        }

        [Fact]
        public void Decode_offsets_and_lengths_cover_the_buffer()
        {
            byte[] bytes = { 0x58, 0x5B, 0xC3 };
            System.Collections.Generic.IReadOnlyList<DecodedInstruction> decoded =
                OpcodeDisassembler.Decode(bytes, MachineType.I386).ReturnValue;

            decoded.Count.ShouldBe(3);
            decoded[0].Offset.ShouldBe(0);
            decoded[0].Length.ShouldBe(1);
            decoded[1].Offset.ShouldBe(1);
            decoded[2].Offset.ShouldBe(2);
            decoded.Sum(d => d.Length).ShouldBe(bytes.Length);
        }
    }
}
