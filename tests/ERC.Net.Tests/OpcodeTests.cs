using System.Collections.Generic;
using ERC;
using ERC.Net.Tests.TestSupport;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Characterization tests for the assembler and disassembler behind
    /// "ERC --assemble" and "ERC --disassemble".
    /// </summary>
    /// <remarks>
    /// The static overloads used here construct an ErcCore internally, so despite
    /// looking pure they touch disk. Phase 02 removes that.
    /// </remarks>
    public class OpcodeTests
    {
        [Fact]
        public void Disassemble_decodes_jmp_esp_on_x86()
        {
            ErcResult<string> result = OpcodeDisassembler.Disassemble(
                new byte[] { 0xFF, 0xE4 }, MachineType.I386);

            result.Error.ShouldBeNull();
            result.ReturnValue.Trim().ShouldBe("jmp esp");
        }

        [Fact]
        public void Disassemble_decodes_the_same_bytes_as_jmp_rsp_on_x64()
        {
            ErcResult<string> result = OpcodeDisassembler.Disassemble(
                new byte[] { 0xFF, 0xE4 }, MachineType.x64);

            result.Error.ShouldBeNull();
            result.ReturnValue.Trim().ShouldBe("jmp rsp");
        }

        [Fact]
        public void Disassemble_rejects_an_unsupported_machine_type()
        {
            ErcResult<string> result = OpcodeDisassembler.Disassemble(
                new byte[] { 0xFF, 0xE4 }, MachineType.Itanium);

            result.Error.ShouldNotBeNull();
        }

        [Fact]
        public void Assemble_encodes_jmp_esp_on_x86()
        {
            ErcResult<byte[]> result = OpcodeAssembler.AssembleOpcodes(
                new List<string> { "jmp esp" }, MachineType.I386);

            result.Error.ShouldBeNull();
            result.ReturnValue.ShouldBe(new byte[] { 0xFF, 0xE4 });
        }

        [Fact]
        public void Assemble_encodes_multiple_instructions_in_order()
        {
            ErcResult<byte[]> result = OpcodeAssembler.AssembleOpcodes(
                new List<string> { "nop", "nop", "ret" }, MachineType.I386);

            result.Error.ShouldBeNull();
            result.ReturnValue.ShouldBe(new byte[] { 0x90, 0x90, 0xC3 });
        }

        [Fact]
        public void Assemble_reports_an_invalid_instruction()
        {
            ErcResult<byte[]> result = OpcodeAssembler.AssembleOpcodes(
                new List<string> { "not_an_instruction" }, MachineType.I386);

            result.Error.ShouldNotBeNull();
            result.Error.Message.ShouldContain("IllegalInstruction");
        }

        [Theory]
        [InlineData("jmp esp")]
        [InlineData("nop")]
        [InlineData("ret")]
        [InlineData("pop eax")]
        public void Assemble_then_Disassemble_round_trips_on_x86(string instruction)
        {
            byte[] encoded = OpcodeAssembler
                .AssembleOpcodes(new List<string> { instruction }, MachineType.I386)
                .ReturnValue;

            OpcodeDisassembler.Disassemble(encoded, MachineType.I386)
                              .ReturnValue.Trim().ShouldBe(instruction);
        }

        [Theory]
        [InlineData("jmp rsp")]
        [InlineData("nop")]
        [InlineData("ret")]
        public void Assemble_then_Disassemble_round_trips_on_x64(string instruction)
        {
            byte[] encoded = OpcodeAssembler
                .AssembleOpcodes(new List<string> { instruction }, MachineType.x64)
                .ReturnValue;

            OpcodeDisassembler.Disassemble(encoded, MachineType.x64)
                              .ReturnValue.Trim().ShouldBe(instruction);
        }

        [Fact]
        public void Disassemble_decodes_a_pop_pop_ret_sequence()
        {
            // The sequence "ERC --seh" hunts for; worth pinning because the ROP and
            // SEH features both depend on this decoding exactly.
            ErcResult<string> result = OpcodeDisassembler.Disassemble(
                new byte[] { 0x58, 0x5B, 0xC3 }, MachineType.I386);

            result.Error.ShouldBeNull();
            result.ReturnValue.ShouldContain("pop eax");
            result.ReturnValue.ShouldContain("pop ebx");
            result.ReturnValue.ShouldContain("ret");
        }
    }
}
