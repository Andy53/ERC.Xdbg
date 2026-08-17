using System;
using System.Collections.Generic;
using System.Linq;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers the instructions that move the stack pointer.
    /// </summary>
    /// <remarks>
    /// ERC could build a chain but had no way to find a pivot to reach one, which is
    /// the harder half of the problem when the crash gives too few bytes to hold a
    /// chain at the point of the overwrite.
    /// </remarks>
    public class StackPivotTests
    {
        private static PivotEncoding Find(MachineType machineType, string instruction, int max = 256)
        {
            return StackPivot.Encodings(machineType, max)
                .Single(e => e.Instruction.Equals(instruction, StringComparison.Ordinal));
        }

        // --------------------------------------------------------- the encodings

        [Theory]
        [InlineData("eax", 0xE0)]
        [InlineData("ecx", 0xE1)]
        [InlineData("ebx", 0xE3)]
        [InlineData("ebp", 0xE5)]
        [InlineData("edi", 0xE7)]
        public void Xchg_with_the_stack_pointer_is_87_plus_the_modrm_byte(string register, byte modrm)
        {
            Find(MachineType.I386, "xchg " + register + ", esp").Opcodes
                .ShouldBe(new byte[] { 0x87, modrm });
        }

        [Fact]
        public void Swapping_the_stack_pointer_with_itself_is_not_offered()
        {
            // 0x87 0xE4 is "xchg esp, esp", which moves nothing.
            StackPivot.Encodings(MachineType.I386)
                .ShouldNotContain(e => e.Opcodes.SequenceEqual(new byte[] { 0x87, 0xE4 }));
        }

        [Fact]
        public void Leave_is_offered_because_it_is_a_pivot_in_disguise()
        {
            // It sets esp from ebp, which is a pivot whenever ebp is controlled.
            Find(MachineType.I386, "leave").Opcodes.ShouldBe(new byte[] { 0xC9 });
        }

        [Theory]
        [InlineData("eax", 0xE0)]
        [InlineData("ebp", 0xE5)]
        public void Mov_into_the_stack_pointer_is_8B_plus_the_modrm_byte(string register, byte modrm)
        {
            Find(MachineType.I386, "mov esp, " + register).Opcodes
                .ShouldBe(new byte[] { 0x8B, modrm });
        }

        [Fact]
        public void A_small_adjustment_uses_the_short_immediate_form()
        {
            // 83 C4 nn is "add esp, nn" with a one-byte operand, which is both the
            // most common form and the shortest to find.
            Find(MachineType.I386, "add esp, 0x20").Opcodes
                .ShouldBe(new byte[] { 0x83, 0xC4, 0x20 });
        }

        [Fact]
        public void A_large_adjustment_uses_the_wide_immediate_form()
        {
            // Above 0x7F the one-byte operand would be read as negative, so the
            // four-byte form is needed.
            PivotEncoding encoding = Find(MachineType.I386, "add esp, 0x100", 0x100);

            encoding.Opcodes.Take(2).ShouldBe(new byte[] { 0x81, 0xC4 });
            BitConverter.ToInt32(encoding.Opcodes, 2).ShouldBe(0x100);
        }

        [Fact]
        public void Ret_with_an_operand_is_offered_because_it_pivots_and_transfers_at_once()
        {
            PivotEncoding encoding = Find(MachineType.I386, "ret 0x20");

            encoding.Opcodes[0].ShouldBe((byte)0xC2);
            BitConverter.ToUInt16(encoding.Opcodes, 1).ShouldBe((ushort)0x20);
        }

        // ------------------------------------------------------------ distances

        [Fact]
        public void Adjustments_step_by_the_word_size()
        {
            // A stack pointer that is not word aligned makes everything after it
            // unusable, so half-word steps are not worth offering.
            foreach (PivotEncoding encoding in StackPivot.Encodings(MachineType.I386))
            {
                if (encoding.Distance != 0)
                {
                    (encoding.Distance % 4).ShouldBe(0, encoding.Instruction);
                }
            }

            foreach (PivotEncoding encoding in StackPivot.Encodings(MachineType.x64))
            {
                if (encoding.Distance != 0)
                {
                    (encoding.Distance % 8).ShouldBe(0, encoding.Instruction);
                }
            }
        }

        [Fact]
        public void A_register_swap_has_no_fixed_distance()
        {
            // How far it moves depends on the register's contents, so it cannot be
            // filtered out by a minimum distance.
            Find(MachineType.I386, "xchg eax, esp").Distance.ShouldBe(0);
            Find(MachineType.I386, "leave").Distance.ShouldBe(0);
        }

        [Fact]
        public void The_stated_distance_matches_the_encoded_operand()
        {
            foreach (PivotEncoding encoding in StackPivot.Encodings(MachineType.I386, 512))
            {
                if (encoding.Opcodes[0] == 0x83)
                {
                    ((int)encoding.Opcodes[2]).ShouldBe(encoding.Distance, encoding.Instruction);
                }
                else if (encoding.Opcodes[0] == 0x81)
                {
                    BitConverter.ToInt32(encoding.Opcodes, 2).ShouldBe(encoding.Distance, encoding.Instruction);
                }
                else if (encoding.Opcodes[0] == 0xC2)
                {
                    ((int)BitConverter.ToUInt16(encoding.Opcodes, 1)).ShouldBe(encoding.Distance, encoding.Instruction);
                }
            }
        }

        [Fact]
        public void A_larger_ceiling_offers_more_without_dropping_anything()
        {
            var small = StackPivot.Encodings(MachineType.I386, 64).Select(e => e.Instruction).ToList();
            var large = StackPivot.Encodings(MachineType.I386, 512).Select(e => e.Instruction).ToList();

            large.Count.ShouldBeGreaterThan(small.Count);

            foreach (string instruction in small)
            {
                large.ShouldContain(instruction);
            }
        }

        // ------------------------------------------------------------ x64

        [Fact]
        public void The_64_bit_encodings_name_the_64_bit_registers()
        {
            Find(MachineType.x64, "xchg rax, rsp").Opcodes.ShouldBe(new byte[] { 0x87, 0xE0 });
            Find(MachineType.x64, "mov rsp, rbp").Opcodes.ShouldBe(new byte[] { 0x8B, 0xE5 });
        }

        [Fact]
        public void No_two_pivots_share_an_encoding()
        {
            // A duplicate would report the same address under two descriptions.
            foreach (MachineType machineType in new[] { MachineType.I386, MachineType.x64 })
            {
                StackPivot.Encodings(machineType, 512)
                    .Select(e => BitConverter.ToString(e.Opcodes))
                    .ShouldBeUnique();
            }
        }

        [Fact]
        public void Every_encoding_describes_itself()
        {
            foreach (PivotEncoding encoding in StackPivot.Encodings(MachineType.I386, 512))
            {
                encoding.Opcodes.Length.ShouldBeGreaterThan(0);
                encoding.Instruction.ShouldNotBeNullOrWhiteSpace();
            }
        }
    }
}
