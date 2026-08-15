using System;
using System.Collections.Generic;
using System.Linq;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers the opcodes that transfer execution to a register.
    /// </summary>
    /// <remarks>
    /// Finding a "jmp esp" is the most common single lookup in a stack overflow
    /// workflow and the plugin had no command for it. Getting the encoding wrong
    /// would be worse than not having it: the addresses returned would look right
    /// and point at some other instruction.
    /// </remarks>
    public class JumpToRegisterTests
    {
        private static byte[] Bytes(string register, MachineType machineType, string instruction)
        {
            return JumpToRegister.Encodings(register, machineType)
                .Single(e => e.Instruction.StartsWith(instruction, StringComparison.Ordinal))
                .Opcodes;
        }

        // ------------------------------------------------------- the encodings

        [Theory]
        [InlineData("eax", 0xE0)]
        [InlineData("ecx", 0xE1)]
        [InlineData("edx", 0xE2)]
        [InlineData("ebx", 0xE3)]
        [InlineData("esp", 0xE4)]
        [InlineData("ebp", 0xE5)]
        [InlineData("esi", 0xE6)]
        [InlineData("edi", 0xE7)]
        public void Jmp_is_FF_followed_by_the_registers_modrm_byte(string register, byte modrm)
        {
            Bytes(register, MachineType.I386, "jmp").ShouldBe(new byte[] { 0xFF, modrm });
        }

        [Theory]
        [InlineData("eax", 0xD0)]
        [InlineData("esp", 0xD4)]
        [InlineData("edi", 0xD7)]
        public void Call_is_FF_followed_by_the_registers_modrm_byte(string register, byte modrm)
        {
            Bytes(register, MachineType.I386, "call").ShouldBe(new byte[] { 0xFF, modrm });
        }

        [Theory]
        [InlineData("eax", 0x50)]
        [InlineData("esp", 0x54)]
        [InlineData("edi", 0x57)]
        public void Push_then_ret_is_the_push_opcode_followed_by_C3(string register, byte push)
        {
            // A push followed by a return puts the register on the stack and then
            // takes it straight back off into the instruction pointer, which reaches
            // the same place as a jump.
            Bytes(register, MachineType.I386, "push").ShouldBe(new byte[] { push, 0xC3 });
        }

        [Fact]
        public void The_canonical_jmp_esp_is_FF_E4()
        {
            // The single most looked-up value in this whole library. Written out
            // literally so a change to the encoding logic cannot quietly redefine it.
            // The same two bytes mean "jmp esp" in a 32-bit process and "jmp rsp" in
            // a 64-bit one: the operand size comes from the mode, not the encoding.
            Bytes("esp", MachineType.I386, "jmp").ShouldBe(new byte[] { 0xFF, 0xE4 });
            Bytes("rsp", MachineType.x64, "jmp").ShouldBe(new byte[] { 0xFF, 0xE4 });
        }

        [Fact]
        public void Three_ways_of_reaching_a_register_are_offered()
        {
            JumpToRegister.Encodings("esp", MachineType.I386)
                .Select(e => e.Instruction)
                .ShouldBe(new[] { "jmp esp", "call esp", "push esp # ret" });
        }

        // ------------------------------------------------------------ x64

        [Fact]
        public void The_64_bit_registers_use_the_same_bytes_as_their_32_bit_names()
        {
            // In 64-bit mode FF E4 means "jmp rsp"; the operand size is implied by the
            // mode rather than by a different encoding.
            Bytes("rsp", MachineType.x64, "jmp").ShouldBe(new byte[] { 0xFF, 0xE4 });
        }

        [Theory]
        [InlineData("r8", 0xE0)]
        [InlineData("r12", 0xE4)]
        [InlineData("r15", 0xE7)]
        public void The_extended_registers_take_a_REX_prefix(string register, byte modrm)
        {
            // r8 to r15 are only reachable with REX.B set, which is 0x41.
            Bytes(register, MachineType.x64, "jmp").ShouldBe(new byte[] { 0x41, 0xFF, modrm });
        }

        [Fact]
        public void Push_of_an_extended_register_also_takes_the_prefix()
        {
            Bytes("r8", MachineType.x64, "push").ShouldBe(new byte[] { 0x41, 0x50, 0xC3 });
        }

        // -------------------------------------------------------- what it accepts

        [Fact]
        public void Register_names_are_case_insensitive()
        {
            Bytes("ESP", MachineType.I386, "jmp").ShouldBe(new byte[] { 0xFF, 0xE4 });
            Bytes(" esp ", MachineType.I386, "jmp").ShouldBe(new byte[] { 0xFF, 0xE4 });
        }

        [Fact]
        public void A_32_bit_process_does_not_accept_64_bit_register_names()
        {
            // Accepting "rsp" against a 32-bit target and quietly encoding FF E4 would
            // give the right bytes for the wrong reason, and would accept "r15" - which
            // does not exist there at all.
            var error = Should.Throw<ERCException>(() => JumpToRegister.Encodings("rsp", MachineType.I386));

            error.Message.ShouldContain("32-bit");
            error.Message.ShouldContain("esp");
        }

        [Fact]
        public void A_64_bit_process_does_not_accept_32_bit_register_names()
        {
            Should.Throw<ERCException>(() => JumpToRegister.Encodings("esp", MachineType.x64));
        }

        [Fact]
        public void The_extended_registers_do_not_exist_on_a_32_bit_process()
        {
            Should.Throw<ERCException>(() => JumpToRegister.Encodings("r8", MachineType.I386));
        }

        [Theory]
        [InlineData("r16")]
        [InlineData("r7")]
        [InlineData("rip")]
        [InlineData("xmm0")]
        [InlineData("")]
        [InlineData(null)]
        public void Anything_that_is_not_a_general_purpose_register_is_refused(string? register)
        {
            var error = Should.Throw<ERCException>(() => JumpToRegister.Encodings(register, MachineType.x64));

            // The message lists what would have worked, because the answer to "which
            // register did you mean" should not require reading the source.
            error.Message.ShouldContain("rsp");
        }

        [Fact]
        public void The_supported_registers_are_the_ones_the_architecture_has()
        {
            JumpToRegister.SupportedRegisters(MachineType.I386)
                .ShouldBe(new[] { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" });

            IReadOnlyList<string> x64 = JumpToRegister.SupportedRegisters(MachineType.x64);
            x64.Count.ShouldBe(16);
            x64.ShouldContain("rsp");
            x64.ShouldContain("r15");
        }

        [Fact]
        public void Every_supported_register_encodes_without_throwing()
        {
            foreach (MachineType machineType in new[] { MachineType.I386, MachineType.x64 })
            {
                foreach (string register in JumpToRegister.SupportedRegisters(machineType))
                {
                    JumpToRegister.Encodings(register, machineType).Count.ShouldBe(3, register);
                }
            }
        }

        [Fact]
        public void No_two_registers_share_an_encoding()
        {
            // A copy-paste slip in the register table would show up as two registers
            // producing the same bytes, and the addresses found would be attributed to
            // the wrong one.
            var seen = new List<string>();

            foreach (string register in JumpToRegister.SupportedRegisters(MachineType.x64))
            {
                seen.Add(BitConverter.ToString(Bytes(register, MachineType.x64, "jmp")));
            }

            seen.ShouldBeUnique();
        }
    }
}
