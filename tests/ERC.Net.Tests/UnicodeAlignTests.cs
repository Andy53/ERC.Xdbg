using System.Linq;
using ERC;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers the Venetian alignment stub behind "ERC --unicodealign".
    /// </summary>
    public class UnicodeAlignTests
    {
        [Fact]
        public void A_one_byte_increment_is_inc_then_add_ebp_ch()
        {
            UnicodeAlignment stub = UnicodeAlign.Generate(1);

            stub.BufferRegister.ShouldBe("eax");
            stub.Delta.ShouldBe(1);
            stub.AsciiBytes.ShouldBe(new byte[] { 0x40, 0x6D });
            stub.ExpandedBytes.ShouldBe(new byte[] { 0x40, 0x00, 0x6D, 0x00 });
            stub.Instructions.ShouldBe(new[] { "inc eax", "add byte ptr [ebp], ch" });
        }

        [Fact]
        public void A_negative_offset_uses_dec()
        {
            UnicodeAlignment stub = UnicodeAlign.Generate(-2, "ecx");

            stub.AsciiBytes.ShouldBe(new byte[] { 0x49, 0x6D, 0x49, 0x6D });
            stub.Instructions[0].ShouldBe("dec ecx");
        }

        [Fact]
        public void Leak_starts_the_ascii_form_with_6D_so_a_leaked_null_becomes_add_ebp_ch()
        {
            UnicodeAlignment stub = UnicodeAlign.Generate(1, prependNullNop: true);

            stub.AsciiBytes[0].ShouldBe((byte)0x6D);
            stub.ExpandedBytes.Take(4).ShouldBe(new byte[] { 0x00, 0x6D, 0x00, 0x40 });
            stub.Instructions[0].ShouldBe("add byte ptr [ebp], ch");
        }

        [Fact]
        public void Jmp_appends_push_and_ret_as_venetian_pairs()
        {
            UnicodeAlignment stub = UnicodeAlign.Generate(0, jumpToBuffer: true);

            stub.AsciiBytes.ShouldBe(new byte[] { 0x50, 0x6D, 0xC3, 0x6D });
            stub.Instructions.ShouldBe(new[]
            {
                "push eax",
                "add byte ptr [ebp], ch",
                "ret",
                "add byte ptr [ebp], ch"
            });
        }

        [Fact]
        public void A_source_register_is_copied_with_push_pop()
        {
            UnicodeAlignment stub = UnicodeAlign.Generate(0, "eax", sourceRegister: "ebp");

            stub.AsciiBytes.Take(4).ShouldBe(new byte[] { 0x55, 0x6D, 0x58, 0x6D });
            stub.Instructions[0].ShouldBe("push ebp");
            stub.Instructions[2].ShouldBe("pop eax");
        }

        [Fact]
        public void Copying_a_register_to_itself_is_skipped()
        {
            UnicodeAlignment stub = UnicodeAlign.Generate(1, "eax", sourceRegister: "eax");

            stub.AsciiBytes.ShouldBe(new byte[] { 0x40, 0x6D });
        }

        [Fact]
        public void Zero_delta_with_nothing_else_emits_a_nop_pair()
        {
            UnicodeAlignment stub = UnicodeAlign.Generate(0);

            stub.AsciiBytes.ShouldBe(new byte[] { 0x90, 0x6D });
        }

        [Fact]
        public void GenerateToTarget_chooses_the_shorter_direction()
        {
            UnicodeAlignment forward = UnicodeAlign.GenerateToTarget(0x1000, 0x1003);
            forward.Delta.ShouldBe(3);

            UnicodeAlignment backward = UnicodeAlign.GenerateToTarget(0x1003, 0x1000);
            backward.Delta.ShouldBe(-3);
        }

        [Fact]
        public void GenerateToTarget_wraps_and_still_picks_the_short_path()
        {
            UnicodeAlignment stub = UnicodeAlign.GenerateToTarget(0x00000002, 0x00000000);
            stub.Delta.ShouldBe(-2);
        }

        [Fact]
        public void An_unknown_register_is_rejected()
        {
            Should.Throw<ERCException>(() => UnicodeAlign.Generate(1, "rax"))
                  .Message.ShouldContain("32-bit");
        }

        [Fact]
        public void A_gap_larger_than_the_limit_is_rejected()
        {
            Should.Throw<ERCException>(() => UnicodeAlign.Generate(UnicodeAlign.MaximumDelta + 1))
                  .Message.ShouldContain("limit");
        }

        [Fact]
        public void Expanded_bytes_are_each_ascii_byte_followed_by_zero()
        {
            UnicodeAlignment stub = UnicodeAlign.Generate(3, "ebx");

            stub.ExpandedBytes.Length.ShouldBe(stub.AsciiBytes.Length * 2);
            for (int i = 0; i < stub.AsciiBytes.Length; i++)
            {
                stub.ExpandedBytes[i * 2].ShouldBe(stub.AsciiBytes[i]);
                stub.ExpandedBytes[i * 2 + 1].ShouldBe((byte)0x00);
            }
        }
    }
}
