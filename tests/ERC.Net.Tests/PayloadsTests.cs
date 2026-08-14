using System;
using System.Collections.Generic;
using System.Linq;
using ERC.Net.Tests.TestSupport;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Characterization tests for ERC.Utilities.Payloads.
    /// </summary>
    public class PayloadsTests
    {
        // ------------------------------------------------- ByteArrayConstructor

        [Fact]
        public void ByteArrayConstructor_returns_all_256_bytes_when_nothing_excluded()
        {
            Payloads.ByteArrayConstructor(null).Length.ShouldBe(256);
            Payloads.ByteArrayConstructor(new byte[0]).Length.ShouldBe(256);
        }

        [Fact]
        public void ByteArrayConstructor_covers_every_value_in_order()
        {
            byte[] all = Payloads.ByteArrayConstructor(null);

            for (int i = 0; i < 256; i++)
            {
                all[i].ShouldBe((byte)i);
            }
        }

        [Fact]
        public void ByteArrayConstructor_omits_excluded_bytes()
        {
            byte[] result = Payloads.ByteArrayConstructor(new byte[] { 0x00 });

            result.Length.ShouldBe(255);
            result.ShouldNotContain((byte)0x00);
            result.Take(4).ShouldBe(new byte[] { 0x01, 0x02, 0x03, 0x04 });
        }

        [Fact]
        public void ByteArrayConstructor_omits_the_classic_bad_char_set()
        {
            byte[] result = Payloads.ByteArrayConstructor(new byte[] { 0x0A, 0x0D });

            result.Length.ShouldBe(254);
            result.ShouldNotContain((byte)0x0A);
            result.ShouldNotContain((byte)0x0D);
        }

        [Fact]
        public void ByteArrayConstructor_handles_a_byte_excluded_twice()
        {
            // Was a pinned defect: the output was sized as 256 minus the *count* of
            // excluded bytes rather than the number of distinct ones, so a repeat -
            // "ERC --bytearray -bytes 0x0A0x0A" - left the buffer short and the copy
            // ran off the end.
            byte[] result = Payloads.ByteArrayConstructor(new byte[] { 0x41, 0x41 });

            result.Length.ShouldBe(255);
            result.ShouldNotContain((byte)0x41);
        }

        [Fact]
        public void ByteArrayConstructor_ignores_duplicates_across_a_larger_set()
        {
            byte[] result = Payloads.ByteArrayConstructor(new byte[] { 0x00, 0x0A, 0x0A, 0x0D, 0x00 });

            result.Length.ShouldBe(253);
            result.ShouldNotContain((byte)0x00);
            result.ShouldNotContain((byte)0x0A);
            result.ShouldNotContain((byte)0x0D);
        }

        // ------------------------------------------------- EggHunterConstructor

        [Fact]
        public void EggHunterConstructor_returns_four_hunters()
        {
            Payloads.EggHunterConstructor().Count.ShouldBe(4);
        }

        [Fact]
        public void EggHunterConstructor_uses_the_default_tag_when_none_given()
        {
            byte[] hunter = ThirtyTwoBitHunter(Payloads.EggHunterConstructor());

            // "ERCD" == 45 52 43 44
            IndexOfSequence(hunter, new byte[] { 0x45, 0x52, 0x43, 0x44 }).ShouldBeGreaterThanOrEqualTo(0);
        }

        [Fact]
        public void EggHunterConstructor_substitutes_a_four_character_tag()
        {
            byte[] hunter = ThirtyTwoBitHunter(Payloads.EggHunterConstructor("ABCD"));

            IndexOfSequence(hunter, new byte[] { 0x41, 0x42, 0x43, 0x44 }).ShouldBeGreaterThanOrEqualTo(0);
            IndexOfSequence(hunter, new byte[] { 0x45, 0x52, 0x43, 0x44 }).ShouldBe(-1);
        }

        [Theory]
        [InlineData("AB")]
        [InlineData("ABCDE")]
        [InlineData("")]
        public void EggHunterConstructor_rejects_a_wrong_length_tag(string tag)
        {
            // Was a pinned defect: a tag that is not exactly four characters was
            // discarded without a word, so "ERC --egghunters AB" handed back default
            // ERCD hunters that would never match the egg the user actually placed -
            // a failure that only shows up as an exploit that does not work.
            var ex = Should.Throw<ArgumentException>(() => Payloads.EggHunterConstructor(tag));

            ex.Message.ShouldContain("4 characters");
        }

        [Fact]
        public void EggHunterConstructor_returns_copies_not_the_shared_statics()
        {
            // Was a pinned defect: the untagged path handed out the static field
            // itself, so a caller editing the returned array corrupted the template
            // for every later call in the session.
            byte[] untagged = ThirtyTwoBitHunter(Payloads.EggHunterConstructor());
            untagged.ShouldNotBeSameAs(Payloads.EggHunter32);
            untagged.ShouldBe(Payloads.EggHunter32);

            byte[] tagged = ThirtyTwoBitHunter(Payloads.EggHunterConstructor("ABCD"));
            tagged.ShouldNotBeSameAs(Payloads.EggHunter32);
        }

        [Fact]
        public void EggHunterConstructor_result_can_be_edited_without_affecting_later_calls()
        {
            byte[] first = ThirtyTwoBitHunter(Payloads.EggHunterConstructor());
            first[0] = 0xFF;

            byte[] second = ThirtyTwoBitHunter(Payloads.EggHunterConstructor());
            second[0].ShouldNotBe((byte)0xFF);
        }

        // ------------------------------------------------- PopPopRet

        [Theory]
        // pop eax; pop ebx; ret
        [InlineData(new byte[] { 0x90, 0x58, 0x5B, 0xC3 }, 1)]
        [InlineData(new byte[] { 0x90, 0x90, 0x58, 0x5B, 0xC3 }, 2)]
        [InlineData(new byte[] { 0x90, 0x90, 0x90, 0x90, 0x58, 0x5B, 0xC3 }, 4)]
        // pop ebp; pop ebp; ret
        [InlineData(new byte[] { 0x90, 0x90, 0x90, 0x90, 0x5D, 0x5D, 0xC3 }, 4)]
        public void PopPopRet_finds_the_sequence(byte[] data, int expectedOffset)
        {
            Payloads.PopPopRet(data).ShouldBe(new List<int> { expectedOffset });
        }

        [Fact]
        public void PopPopRet_finds_every_occurrence()
        {
            byte[] data =
            {
                0x90, 0x90, 0x90, 0x90,
                0x58, 0x5B, 0xC3,       // offset 4
                0x90,
                0x59, 0x5A, 0xC3        // offset 8
            };

            Payloads.PopPopRet(data).ShouldBe(new List<int> { 4, 8 });
        }

        [Theory]
        [InlineData(new byte[] { 0x90, 0x90, 0x90 })]
        [InlineData(new byte[0])]
        [InlineData(new byte[] { 0xC3 })]
        public void PopPopRet_returns_empty_when_no_sequence_present(byte[] data)
        {
            Payloads.PopPopRet(data).ShouldBeEmpty();
        }

        [Fact]
        public void PopPopRet_finds_a_sequence_starting_at_offset_zero()
        {
            // Was a pinned defect: the scan starts at index 2 but reached back to
            // data[i - 3] and data[i - 4] unguarded, so a pop/pop/ret in the first
            // few bytes of a region indexed before the start of the array. "ERC
            // --seh" scans every module region, so one such region killed the whole
            // command.
            Payloads.PopPopRet(new byte[] { 0x58, 0x5B, 0xC3 })
                    .ShouldBe(new List<int> { 0 });
        }

        [Fact]
        public void PopPopRet_handles_a_ret_in_the_first_bytes_without_a_sequence()
        {
            Should.NotThrow(() => Payloads.PopPopRet(new byte[] { 0x5D, 0xC3, 0x90 }));
            Should.NotThrow(() => Payloads.PopPopRet(new byte[] { 0xC3, 0xC3, 0xC3 }));
        }

        // ------------------------------------------------- helpers

        private static byte[] ThirtyTwoBitHunter(Dictionary<string, byte[]> hunters)
        {
            return hunters.First(kv => kv.Key.StartsWith("32 Bit Egg")).Value;
        }

        private static int IndexOfSequence(byte[] haystack, byte[] needle)
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
