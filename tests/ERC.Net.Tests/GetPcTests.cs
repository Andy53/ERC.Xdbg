using System.Collections.Generic;
using System.Linq;
using ERC;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers the GetPC stubs behind "ERC --getpc".
    /// </summary>
    public class GetPcTests
    {
        [Fact]
        public void Fstenv_for_eax_is_the_mona_sequence()
        {
            // D9 EB 9B D9 74 24 F4 58 - fldpi; wait; fnstenv [esp-0xc]; pop eax
            Named("eax", MachineType.I386, "fstenv")
                .Opcodes.ShouldBe(new byte[] { 0xD9, 0xEB, 0x9B, 0xD9, 0x74, 0x24, 0xF4, 0x58 });
        }

        [Fact]
        public void Jmp_short_back_for_eax_is_the_mona_sequence()
        {
            Named("eax", MachineType.I386, "jmp-short-back")
                .Opcodes.ShouldBe(new byte[] { 0xEB, 0x03, 0x58, 0xFF, 0xD0, 0xE8, 0xF8, 0xFF, 0xFF, 0xFF });
        }

        [Fact]
        public void Call_plus_four_for_eax_is_the_mona_sequence()
        {
            Named("eax", MachineType.I386, "call-plus-4")
                .Opcodes.ShouldBe(new byte[] { 0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3, 0x58 });
        }

        [Theory]
        [InlineData("ecx", 0x59, 0xD1)]
        [InlineData("edx", 0x5A, 0xD2)]
        [InlineData("ebx", 0x5B, 0xD3)]
        [InlineData("esp", 0x5C, 0xD4)]
        [InlineData("ebp", 0x5D, 0xD5)]
        [InlineData("esi", 0x5E, 0xD6)]
        [InlineData("edi", 0x5F, 0xD7)]
        public void Pop_and_call_follow_the_register_number(string register, byte pop, byte call)
        {
            byte[] jmp = Named(register, MachineType.I386, "jmp-short-back").Opcodes;
            jmp[2].ShouldBe(pop);
            jmp[4].ShouldBe(call);

            Named(register, MachineType.I386, "call-plus-4").Opcodes.Last().ShouldBe(pop);
            Named(register, MachineType.I386, "fstenv").Opcodes.Last().ShouldBe(pop);
        }

        [Fact]
        public void X64_includes_a_rip_relative_lea()
        {
            // 48 8D 05 00 00 00 00 - lea rax, [rip+0]
            Named("rax", MachineType.x64, "lea-rip")
                .Opcodes.ShouldBe(new byte[] { 0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00 });
        }

        [Fact]
        public void Lea_for_rcx_uses_the_rcx_modrm()
        {
            Named("rcx", MachineType.x64, "lea-rip")
                .Opcodes.ShouldBe(new byte[] { 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00 });
        }

        [Fact]
        public void Lea_for_r8_sets_rex_r()
        {
            Named("r8", MachineType.x64, "lea-rip")
                .Opcodes.ShouldBe(new byte[] { 0x4C, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00 });
        }

        [Fact]
        public void R8_does_not_get_the_mona_sequences_whose_displacements_assume_a_one_byte_pop()
        {
            IReadOnlyList<GetPcRoutine> routines = GetPc.For("r8", MachineType.x64);

            routines.Select(r => r.Name).ShouldBe(new[] { "lea-rip", "fstenv" });
        }

        [Fact]
        public void Fstenv_for_r8_prefixes_the_pop()
        {
            Named("r8", MachineType.x64, "fstenv")
                .Opcodes.ShouldBe(new byte[] { 0xD9, 0xEB, 0x9B, 0xD9, 0x74, 0x24, 0xF4, 0x41, 0x58 });
        }

        [Fact]
        public void X86_eax_offers_the_three_mona_variants()
        {
            GetPc.For("eax", MachineType.I386)
                 .Select(r => r.Name)
                 .ShouldBe(new[] { "jmp-short-back", "call-plus-4", "fstenv" });
        }

        [Fact]
        public void Register_names_are_case_insensitive()
        {
            GetPc.For("EAX", MachineType.I386).Count.ShouldBe(GetPc.For("eax", MachineType.I386).Count);
        }

        [Fact]
        public void A_missing_register_is_rejected()
        {
            Should.Throw<ERCException>(() => GetPc.For(null, MachineType.I386))
                  .Message.ShouldContain("register");
        }

        [Fact]
        public void A_64_bit_register_is_rejected_on_x86()
        {
            Should.Throw<ERCException>(() => GetPc.For("rax", MachineType.I386))
                  .Message.ShouldContain("32");
        }

        [Fact]
        public void Fstenv_disassembles_to_fldpi_then_fnstenv_then_pop()
        {
            ErcResult<string> disassembly = OpcodeDisassembler.Disassemble(
                Named("eax", MachineType.I386, "fstenv").Opcodes, MachineType.I386);

            disassembly.Error.ShouldBeNull();
            string text = disassembly.ReturnValue.ToLowerInvariant();
            text.ShouldContain("fldpi");
            text.ShouldContain("fnstenv");
            text.ShouldContain("pop eax");
        }

        private static GetPcRoutine Named(string register, MachineType machineType, string name)
        {
            return GetPc.For(register, machineType).Single(r => r.Name == name);
        }
    }
}
