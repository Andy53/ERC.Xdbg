using System;
using ERC;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers jump-oriented-programming gadget recognition behind "ERC --jop".
    /// </summary>
    public class JopTests
    {
        [Theory]
        [InlineData(new byte[] { 0xFF, 0x20 }, MachineType.I386)] // jmp [eax]
        [InlineData(new byte[] { 0xFF, 0x10 }, MachineType.I386)] // call [eax]
        [InlineData(new byte[] { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 }, MachineType.x64)] // jmp [rip+0]
        public void Memory_indirect_jmp_and_call_are_gadgets(byte[] opcodes, MachineType machine)
        {
            string text = OpcodeDisassembler.Disassemble(opcodes, machine).ReturnValue.Trim();
            Jop.IsGadget(text).ShouldBeTrue(text);
        }

        [Theory]
        [InlineData(new byte[] { 0xFF, 0xE0 }, MachineType.I386)] // jmp eax
        [InlineData(new byte[] { 0xFF, 0xD0 }, MachineType.I386)] // call eax
        [InlineData(new byte[] { 0xC3 }, MachineType.I386)]
        [InlineData(new byte[] { 0x90 }, MachineType.I386)]
        public void Register_indirect_jmp_call_and_unrelated_instructions_are_not(byte[] opcodes, MachineType machine)
        {
            string text = OpcodeDisassembler.Disassemble(opcodes, machine).ReturnValue.Trim();
            Jop.IsGadget(text).ShouldBeFalse(text);
        }

        [Fact]
        public void RefersToRegister_matches_the_operand_not_a_substring()
        {
            Jop.RefersToRegister("jmp dword ptr [eax]", "eax").ShouldBeTrue();
            Jop.RefersToRegister("jmp dword ptr [eax+4]", "eax").ShouldBeTrue();
            Jop.RefersToRegister("jmp dword ptr [eax-4]", "eax").ShouldBeTrue();
            Jop.RefersToRegister("call qword ptr [rax]", "rax").ShouldBeTrue();
            Jop.RefersToRegister("jmp dword ptr [ebx]", "eax").ShouldBeFalse();
            // 32-bit names are valid JOP operands on x64; do not require jmp-reg encodings.
            Jop.RefersToRegister("jmp dword ptr [eax]", "EAX").ShouldBeTrue();
        }

        [Fact]
        public void Cfg_alignment_is_sixteen_bytes()
        {
            Jop.IsCfgAligned((IntPtr)0x1000).ShouldBeTrue();
            Jop.IsCfgAligned((IntPtr)0x1008).ShouldBeFalse();
            Jop.IsCfgAligned((IntPtr)0x100F).ShouldBeFalse();
        }
    }
}
