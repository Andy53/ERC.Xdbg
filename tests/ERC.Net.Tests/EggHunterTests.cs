using System;
using System.Collections.Generic;
using System.Linq;
using ERC;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers the egg hunters behind "ERC --egghunters": tag, startreg, checksum,
    /// WOW64 per OS, DEP-on-egg and the SEH stub.
    /// </summary>
    public class EggHunterTests
    {
        private static readonly byte[] NtAccessCheckMona =
        {
            0x66, 0x81, 0xCA, 0xFF, 0x0F, 0x42, 0x52, 0x6A, 0x02, 0x58,
            0xCD, 0x2E, 0x3C, 0x05, 0x5A, 0x74, 0xEF, 0xB8, 0x77, 0x30,
            0x30, 0x74, 0x8B, 0xFA, 0xAF, 0x75, 0xEA, 0xAF, 0x75, 0xE7,
            0xFF, 0xE7
        };

        [Fact]
        public void NtAccessCheck_with_w00t_is_the_mona_sequence()
        {
            Named("NtAccessCheck", new EggHunterRequest { Tag = "w00t" })
                .Opcodes.ShouldBe(NtAccessCheckMona);
        }

        [Fact]
        public void Default_tag_matches_the_existing_32_bit_template()
        {
            Named("NtAccessCheck").Opcodes.ShouldBe(Payloads.EggHunter32);
        }

        [Fact]
        public void Tag_is_substituted_in_every_hunter()
        {
            foreach (EggHunterStub hunter in EggHunter.Generate(new EggHunterRequest { Tag = "ABCD" }))
            {
                IndexOf(hunter.Opcodes, new byte[] { 0x41, 0x42, 0x43, 0x44 })
                    .ShouldBeGreaterThanOrEqualTo(0, hunter.Name);
                IndexOf(hunter.Opcodes, new byte[] { 0x45, 0x52, 0x43, 0x44 })
                    .ShouldBe(-1, hunter.Name);
            }
        }

        [Fact]
        public void Startreg_eax_moves_edx_and_skips_the_page_align()
        {
            byte[] opcodes = Named("NtAccessCheck", new EggHunterRequest { StartRegister = "eax" }).Opcodes;

            opcodes.Take(4).ShouldBe(new byte[] { 0x8B, 0xD0, 0xEB, 0x05 });
            opcodes.Skip(4).Take(5).ShouldBe(new byte[] { 0x66, 0x81, 0xCA, 0xFF, 0x0F });
        }

        [Fact]
        public void Startreg_edx_only_skips_the_page_align()
        {
            byte[] opcodes = Named("NtAccessCheck", new EggHunterRequest { StartRegister = "edx" }).Opcodes;

            opcodes.Take(2).ShouldBe(new byte[] { 0xEB, 0x05 });
            opcodes[2].ShouldBe((byte)0x66);
        }

        [Fact]
        public void Checksum_of_two_nops_and_int3_is_0xEC()
        {
            EggHunter.ChecksumOf(new byte[] { 0x90, 0x90, 0xCC }).ShouldBe((byte)0xEC);
        }

        [Fact]
        public void Checksum_appends_the_mona_loop_and_stores_the_byte_to_append()
        {
            byte[] payload = { 0x90, 0x90, 0xCC };
            EggHunterStub hunter = Named("NtAccessCheck", new EggHunterRequest
            {
                Tag = "w00t",
                ChecksumPayload = payload
            });

            hunter.ChecksumByte.ShouldBe((byte)0xEC);
            hunter.Opcodes.Take(NtAccessCheckMona.Length - 2).ShouldBe(NtAccessCheckMona.Take(30));
            hunter.Opcodes.Skip(30).Take(9).ShouldBe(new byte[]
            {
                0x51, 0x31, 0xC9, 0x31, 0xC0, 0x02, 0x04, 0x0F, 0x41
            });
            hunter.Opcodes.Skip(39).Take(3).ShouldBe(new byte[] { 0x80, 0xF9, 0x03 });
            hunter.Opcodes[hunter.Opcodes.Length - 2].ShouldBe((byte)0xFF);
            hunter.Opcodes[hunter.Opcodes.Length - 1].ShouldBe((byte)0xE7);
        }

        [Fact]
        public void Wow64_win7_uses_syscall_0x26()
        {
            EggHunterStub hunter = Named("WOW64 Windows 7", new EggHunterRequest
            {
                Tag = "w00t",
                Wow64 = Wow64WindowsVersion.Win7
            });

            hunter.Opcodes.ShouldContain((byte)0x26);
            hunter.Opcodes.ShouldNotContain((byte)0x29);
            EggHunter.Generate(new EggHunterRequest { Wow64 = Wow64WindowsVersion.Win7 })
                     .Any(h => h.Name == "WOW64 Windows 10").ShouldBeFalse();
        }

        [Fact]
        public void Wow64_win10_uses_syscall_0x29()
        {
            Named("WOW64 Windows 10", new EggHunterRequest { Wow64 = Wow64WindowsVersion.Win10 })
                .Opcodes.ShouldContain((byte)0x29);
        }

        [Fact]
        public void Seh_hunter_has_no_int_2e_and_a_pop_pop_ret_placeholder()
        {
            EggHunterStub hunter = Named("SEH");

            IndexOf(hunter.Opcodes, new byte[] { 0xCD, 0x2E }).ShouldBe(-1);
            IndexOf(hunter.Opcodes, new byte[] { 0xCC, 0xCC, 0xCC, 0xCC })
                .ShouldBeGreaterThanOrEqualTo(0);
            hunter.Opcodes[hunter.Opcodes.Length - 2].ShouldBe((byte)0xFF);
            hunter.Opcodes[hunter.Opcodes.Length - 1].ShouldBe((byte)0xE7);
        }

        [Fact]
        public void VirtualProtect_pushes_esp_page_execute_readwrite_and_returns_into_the_api()
        {
            byte[] opcodes = Named("NtAccessCheck", new EggHunterRequest
            {
                DepMethod = EggHunterDepMethod.VirtualProtect,
                DepSize = 64
            }).Opcodes;

            // push esp; push 0x40; push 64; push edi; push edi; push esi; ret
            opcodes.Skip(opcodes.Length - 9).ShouldBe(new byte[]
            {
                0x54, 0x6A, 0x40, 0x6A, 0x40, 0x57, 0x57, 0x56, 0xC3
            });
        }

        [Fact]
        public void Copy_size_emits_a_getpc_when_depdest_is_omitted()
        {
            byte[] opcodes = Named("NtAccessCheck", new EggHunterRequest
            {
                DepMethod = EggHunterDepMethod.CopySize,
                DepSize = 32
            }).Opcodes;

            IndexOf(opcodes, new byte[] { 0xD9, 0xEE, 0xD9, 0x74, 0xE4, 0xF4 })
                .ShouldBeGreaterThanOrEqualTo(0);
            opcodes.Last().ShouldBe((byte)0xC3);
        }

        [Theory]
        [InlineData("AB")]
        [InlineData("ABCDE")]
        [InlineData("")]
        public void A_wrong_length_tag_is_rejected(string tag)
        {
            Should.Throw<ArgumentException>(() =>
                EggHunter.Generate(new EggHunterRequest { Tag = tag }));
        }

        [Fact]
        public void TryParse_reads_the_documented_examples()
        {
            string? error;
            EggHunterRequest? parsed = EggHunter.TryParse(
                new[] { "ABCD", "startreg", "eax" }, out error);

            error.ShouldBeNull();
            parsed.ShouldNotBeNull();
            parsed!.Tag.ShouldBe("ABCD");
            parsed.StartRegister.ShouldBe("eax");
        }

        [Fact]
        public void TryParse_reads_checksum_hex_and_wow64_version()
        {
            string? error;
            EggHunterRequest? parsed = EggHunter.TryParse(
                new[] { "checksum", "9090CC", "wow64", "7" }, out error);

            error.ShouldBeNull();
            parsed.ShouldNotBeNull();
            parsed!.ChecksumPayload.ShouldBe(new byte[] { 0x90, 0x90, 0xCC });
            parsed.Wow64.ShouldBe(Wow64WindowsVersion.Win7);
        }

        [Fact]
        public void TryParse_rejects_an_unknown_option()
        {
            string? error;
            EggHunter.TryParse(new[] { "bogus" }, out error).ShouldBeNull();
            error.ShouldNotBeNull();
            error.ShouldContain("bogus");
        }

        private static EggHunterStub Named(string name, EggHunterRequest? request = null)
        {
            return EggHunter.Generate(request).Single(h => h.Name == name);
        }

        private static int IndexOf(byte[] haystack, byte[] needle)
        {
            for (int i = 0; i + needle.Length <= haystack.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j])
                    {
                        match = false;
                        break;
                    }
                }

                if (match)
                {
                    return i;
                }
            }

            return -1;
        }
    }
}
