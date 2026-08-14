using System;
using ERC.Net.Tests.TestSupport;
using Shouldly;
using Xunit;
using ErcConvert = ERC.Utilities.Convert;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Characterization tests for ERC.Utilities.Convert.
    /// </summary>
    public class ConvertTests
    {
        // ---------------------------------------------------------------- HexToAscii

        [Theory]
        [InlineData("41", "A")]
        [InlineData("414243", "ABC")]
        [InlineData("4a", "J")]
        [InlineData("4A", "J")]
        [InlineData("", "")]
        public void HexToAscii_converts_valid_hex(string hex, string expected)
        {
            ErcConvert.HexToAscii(hex).ShouldBe(expected);
        }

        [Fact]
        public void HexToAscii_left_pads_odd_length_input()
        {
            // "4" is treated as "04" (a control character), not "40" ("@").
            ErcConvert.HexToAscii("4").ShouldBe("\u0004");
        }

        [Fact]
        public void HexToAscii_maps_high_bytes_to_the_same_code_point()
        {
            // Bytes above 0x7F become the code point of the same value; nothing is
            // decoded through an ASCII code page despite the method name.
            ErcConvert.HexToAscii("FF").ShouldBe("\u00FF");
        }

        [Theory]
        [InlineData("zz")]
        [InlineData("41ZZ")]
        [InlineData(" 41")]
        public void HexToAscii_returns_empty_for_non_hex_input(string hex)
        {
            ErcConvert.HexToAscii(hex).ShouldBe(string.Empty);
        }

        [Fact]
        public void HexToAscii_returns_empty_for_null()
        {
            // Was a pinned defect: null was the one invalid input that threw, so a
            // caller guarding by checking for an empty result still crashed.
            ErcConvert.HexToAscii(null).ShouldBe(string.Empty);
        }

        // ---------------------------------------------------------------- HexToBytes

        [Fact]
        public void HexToBytes_converts_valid_hex()
        {
            ErcConvert.HexToBytes("4142").ShouldBe(new byte[] { 0x41, 0x42 });
        }

        [Fact]
        public void HexToBytes_left_pads_odd_length_input()
        {
            ErcConvert.HexToBytes("F").ShouldBe(new byte[] { 0x0F });
        }

        [Fact]
        public void HexToBytes_returns_empty_array_for_empty_input()
        {
            ErcConvert.HexToBytes("").ShouldBeEmpty();
        }

        [Fact]
        [Trait(Defect.Category, Defect.Pinned)]
        public void HexToBytes_throws_on_non_hex_while_HexToAscii_returns_empty()
        {
            // The two hex parsers disagree on how to reject bad input: this one
            // throws, HexToAscii returns "". Callers cannot handle both uniformly.
            Should.Throw<FormatException>(() => ErcConvert.HexToBytes("zz"));
            ErcConvert.HexToAscii("zz").ShouldBe(string.Empty);
        }

        // ---------------------------------------------------------------- Encodings

        [Fact]
        public void AsciiToBytes_encodes_as_ascii()
        {
            ErcConvert.AsciiToBytes("AB").ShouldBe(new byte[] { 0x41, 0x42 });
        }

        [Theory]
        [InlineData("AB", "41 42")]
        [InlineData("A", "41")]
        [InlineData("", "")]
        public void AsciiToHex_returns_space_separated_pairs(string input, string expected)
        {
            ErcConvert.AsciiToHex(input).ShouldBe(expected);
        }

        [Fact]
        public void UnicodeToHex_is_utf16_little_endian()
        {
            ErcConvert.UnicodeToHex("A").ShouldBe("41 00");
            ErcConvert.UnicodeToBytes("A").ShouldBe(new byte[] { 0x41, 0x00 });
        }

        [Fact]
        public void UTF8ToHex_matches_ascii_for_ascii_input()
        {
            ErcConvert.UTF8ToHex("A").ShouldBe("41");
            ErcConvert.UTF8ToBytes("A").ShouldBe(new byte[] { 0x41 });
        }

        [Fact]
        public void UTF7ToHex_matches_ascii_for_ascii_input()
        {
            ErcConvert.UTF7ToHex("A").ShouldBe("41");
        }

        [Fact]
        public void UTF32ToHex_is_four_bytes_little_endian()
        {
            ErcConvert.UTF32ToHex("A").ShouldBe("41 00 00 00");
            ErcConvert.UTF32ToBytes("A").ShouldBe(new byte[] { 0x41, 0x00, 0x00, 0x00 });
        }

        [Fact]
        public void UTF8_and_Unicode_differ_for_non_ascii()
        {
            // U+00A3 POUND SIGN: two bytes in UTF-8, two in UTF-16 one of them null.
            ErcConvert.UTF8ToHex("\u00A3").ShouldBe("C2 A3");
            ErcConvert.UnicodeToHex("\u00A3").ShouldBe("A3 00");
        }

        // ---------------------------------------------------------------- Round trips

        [Theory]
        [InlineData("A")]
        [InlineData("HelloWorld")]
        [InlineData("0123456789")]
        public void AsciiToHex_then_HexToAscii_round_trips(string original)
        {
            string hex = ErcConvert.AsciiToHex(original).Replace(" ", string.Empty);
            ErcConvert.HexToAscii(hex).ShouldBe(original);
        }

        [Theory]
        [InlineData("A")]
        [InlineData("HelloWorld")]
        public void AsciiToBytes_then_HexToBytes_agree(string original)
        {
            string hex = ErcConvert.AsciiToHex(original).Replace(" ", string.Empty);
            ErcConvert.HexToBytes(hex).ShouldBe(ErcConvert.AsciiToBytes(original));
        }

        // ---------------------------------------------------------------- HTML

        [Fact]
        public void htmlWhitespaceFix_replaces_every_space()
        {
            ErcConvert.htmlWhitespaceFix("a b c").ShouldBe("a&nbsp;b&nbsp;c");
        }

        [Fact]
        public void htmlWhitespaceFix_leaves_input_without_spaces_alone()
        {
            ErcConvert.htmlWhitespaceFix("abc").ShouldBe("abc");
        }
    }
}
