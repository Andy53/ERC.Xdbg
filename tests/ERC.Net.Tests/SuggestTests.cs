using System;
using System.Collections.Generic;
using ERC;
using ERC.Structures;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers buffer layouts behind "ERC --suggest".
    /// </summary>
    public class SuggestTests
    {
        [Fact]
        public void A_saved_return_overwrite_with_esp_in_the_pattern_is_junk_jmp_payload()
        {
            var nrp = new List<RegisterInfo>
            {
                Ip(260, 1001),
                Esp(264, 0, 1200, 1001)
            };

            BufferSuggestion suggestion = Only(Suggest.From(nrp));

            suggestion.Kind.ShouldBe("eip");
            suggestion.Offset.ShouldBe(260);
            suggestion.LandingRegister.ShouldBe("esp");
            suggestion.PayloadBytes.ShouldBe(1200);
            suggestion.Text.ShouldContain("EIP overwritten with pattern at offset 260");
            suggestion.Text.ShouldContain("ESP points into pattern at offset 264");
            suggestion.Text.ShouldContain("buf  = b\"A\" * 260");
            suggestion.Text.ShouldContain("jmp esp");
            suggestion.Text.ShouldContain("buf += payload");
        }

        [Fact]
        public void A_known_jmp_is_packed_into_the_layout()
        {
            var nrp = new List<RegisterInfo>
            {
                Ip(260, 1),
                Esp(264, 0, 100, 1)
            };
            var jumps = new Dictionary<IntPtr, string>
            {
                { (IntPtr)0x625011AF, "jmp esp" }
            };

            string text = Only(Suggest.From(nrp, MachineType.I386, jumps)).Text;

            text.ShouldContain("0x625011AF");
            text.ShouldContain("struct.pack(\"<I\", 0x625011AF)");
            text.ShouldNotContain("????????");
        }

        [Fact]
        public void Esp_plus_n_inserts_padding_before_the_payload()
        {
            var nrp = new List<RegisterInfo>
            {
                Ip(200, 1),
                Esp(208, 8, 50, 1)
            };

            BufferSuggestion suggestion = Only(Suggest.From(nrp));

            suggestion.StackDelta.ShouldBe(8);
            suggestion.Text.ShouldContain("ESP+8");
            suggestion.Text.ShouldContain("buf += b\"A\" * 8");
        }

        [Fact]
        public void Without_esp_the_largest_pointing_register_is_the_landing()
        {
            var nrp = new List<RegisterInfo>
            {
                Ip(100, 1),
                Reg("EAX", 104, 40, 1),
                Reg("ECX", 200, 400, 1)
            };

            Only(Suggest.From(nrp)).LandingRegister.ShouldBe("ecx");
        }

        [Fact]
        public void An_seh_overwrite_is_junk_nseh_ppr_payload()
        {
            var nrp = new List<RegisterInfo>
            {
                new RegisterInfo
                {
                    Register = "SEH0",
                    StringOffset = 780,
                    ThreadID = 7
                }
            };
            var ppr = new Dictionary<IntPtr, string>
            {
                { (IntPtr)0x625011B3, "pop ebx # pop ebp # ret" }
            };

            BufferSuggestion suggestion = Only(Suggest.From(nrp, MachineType.I386, null, ppr));

            suggestion.Kind.ShouldBe("seh");
            suggestion.Offset.ShouldBe(780);
            suggestion.Text.ShouldContain("b\"\\xeb\\x06\\x90\\x90\"");
            suggestion.Text.ShouldContain("0x625011B3");
            suggestion.Text.ShouldContain("pop ebx # pop ebp # ret");
        }

        [Fact]
        public void Eip_and_seh_in_the_same_thread_produce_both_layouts()
        {
            var nrp = new List<RegisterInfo>
            {
                Ip(260, 1),
                Esp(264, 0, 10, 1),
                new RegisterInfo { Register = "SEH0", StringOffset = 780, ThreadID = 1 }
            };

            IReadOnlyList<BufferSuggestion> suggestions = Suggest.From(nrp);

            suggestions.Count.ShouldBe(2);
            suggestions[0].Kind.ShouldBe("eip");
            suggestions[1].Kind.ShouldBe("seh");
        }

        [Fact]
        public void Nothing_is_suggested_when_the_pattern_did_not_land()
        {
            var nrp = new List<RegisterInfo>
            {
                new RegisterInfo { Register = "EAX", StringOffset = -1, ThreadID = 1 }
            };

            Suggest.From(nrp).ShouldBeEmpty();
        }

        [Fact]
        public void X64_packs_an_eight_byte_return_address()
        {
            var nrp = new List<RegisterInfo>
            {
                new RegisterInfo
                {
                    Register = "RIP",
                    StringOffset = 40,
                    ThreadID = 1,
                    overwritten = true
                },
                new RegisterInfo
                {
                    Register = "RSP",
                    StringOffset = 48,
                    RegisterOffset = 0,
                    BufferSize = 80,
                    ThreadID = 1
                }
            };

            string text = Only(Suggest.From(nrp, MachineType.x64)).Text;

            text.ShouldContain("struct.pack(\"<Q\"");
            text.ShouldContain("jmp rsp");
        }

        private static BufferSuggestion Only(IReadOnlyList<BufferSuggestion> suggestions)
        {
            suggestions.Count.ShouldBe(1);
            return suggestions[0];
        }

        private static RegisterInfo Ip(int offset, int thread)
        {
            return new RegisterInfo
            {
                Register = "EIP",
                StringOffset = offset,
                ThreadID = thread,
                overwritten = true
            };
        }

        private static RegisterInfo Esp(int offset, int delta, int size, int thread)
        {
            return new RegisterInfo
            {
                Register = "ESP",
                StringOffset = offset,
                RegisterOffset = delta,
                BufferSize = size,
                ThreadID = thread
            };
        }

        private static RegisterInfo Reg(string name, int offset, int size, int thread)
        {
            return new RegisterInfo
            {
                Register = name,
                StringOffset = offset,
                BufferSize = size,
                ThreadID = thread
            };
        }
    }
}
