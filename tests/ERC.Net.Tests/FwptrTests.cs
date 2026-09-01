using ERC;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers recognition of call/jmp through a fixed pointer, behind "ERC --fwptr".
    /// </summary>
    public class FwptrTests
    {
        [Fact]
        public void An_absolute_call_on_x86_is_the_immediate()
        {
            // call dword ptr [0x00401000]
            byte[] code = { 0xFF, 0x15, 0x00, 0x10, 0x40, 0x00 };
            ulong pointer;
            string text;

            Fwptr.TryPointer(code, 0x00400000, MachineType.I386, out pointer, out text).ShouldBeTrue();
            pointer.ShouldBe(0x00401000UL);
            text.ShouldContain("call");
            text.ShouldContain("[");
        }

        [Fact]
        public void A_rip_relative_call_on_x64_is_next_ip_plus_displacement()
        {
            // call qword ptr [rip+0]
            byte[] code = { 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00 };
            ulong pointer;
            string text;

            Fwptr.TryPointer(code, 0x140001000UL, MachineType.x64, out pointer, out text).ShouldBeTrue();
            pointer.ShouldBe(0x140001000UL + 6);
            text.ShouldContain("call");
        }

        [Fact]
        public void A_register_indirect_call_is_not_a_fixed_pointer()
        {
            byte[] code = { 0xFF, 0x10 }; // call [eax]
            ulong pointer;
            string text;

            Fwptr.TryPointer(code, 0x401000, MachineType.I386, out pointer, out text).ShouldBeFalse();
        }

        [Fact]
        public void A_near_call_is_not_indirect()
        {
            byte[] code = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
            ulong pointer;
            string text;

            Fwptr.TryPointer(code, 0x401000, MachineType.I386, out pointer, out text).ShouldBeFalse();
        }
    }
}
