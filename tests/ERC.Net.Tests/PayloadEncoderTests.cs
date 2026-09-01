using System;
using System.Linq;
using ERC;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers the encoders behind "ERC --encode".
    /// </summary>
    public class PayloadEncoderTests
    {
        // --------------------------------------------------------------- XOR

        [Fact]
        public void Xor_round_trips()
        {
            byte[] original = { 0x90, 0x90, 0x90, 0xCC };
            EncodedPayload encoded = PayloadEncoder.Encode(original, PayloadEncoding.Xor);

            encoded.XorKey.ShouldNotBe((byte)0);
            int decoderLength = encoded.Bytes.Length - original.Length;
            decoderLength.ShouldBeGreaterThan(0);

            byte[] body = encoded.Bytes.Skip(decoderLength).ToArray();
            PayloadEncoder.XorDecode(body, encoded.XorKey).ShouldBe(original);
        }

        [Fact]
        public void Xor_avoids_the_excluded_bytes_in_the_whole_buffer()
        {
            byte[] original = { 0x41, 0x42, 0x43, 0x44 };
            byte[] bad = { 0x00, 0x0A, 0x0D };
            EncodedPayload encoded = PayloadEncoder.Encode(
                original, PayloadEncoding.Xor, MachineType.I386, bad);

            encoded.Bytes.ShouldNotContain((byte)0x00);
            encoded.Bytes.ShouldNotContain((byte)0x0A);
            encoded.Bytes.ShouldNotContain((byte)0x0D);
            encoded.XorKey.ShouldNotBe((byte)0x00);
            encoded.XorKey.ShouldNotBe((byte)0x0A);
            encoded.XorKey.ShouldNotBe((byte)0x0D);
        }

        [Fact]
        public void Xor_decoder_starts_with_a_short_jump()
        {
            EncodedPayload encoded = PayloadEncoder.Encode(new byte[] { 0xCC }, PayloadEncoding.Xor);

            encoded.Bytes[0].ShouldBe((byte)0xEB);
        }

        [Fact]
        public void Xor_on_x64_uses_a_64_bit_inc()
        {
            EncodedPayload encoded = PayloadEncoder.Encode(
                new byte[] { 0xCC }, PayloadEncoding.Xor, MachineType.x64);

            // 48 FF C6 = inc rsi. The 8-bit 0x46 is a REX prefix on x64, so a 32-bit
            // decoder copied verbatim would not increment rsi.
            IndexOf(encoded.Bytes, new byte[] { 0x48, 0xFF, 0xC6 }).ShouldBeGreaterThanOrEqualTo(0);
        }

        [Fact]
        public void Xor_rejects_an_empty_payload()
        {
            Should.Throw<ERCException>(() => PayloadEncoder.Encode(new byte[0], PayloadEncoding.Xor))
                  .Message.ShouldContain("Nothing to encode");
        }

        [Fact]
        public void Xor_fails_clearly_when_every_key_is_excluded()
        {
            var bad = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();

            Should.Throw<ERCException>(() =>
                    PayloadEncoder.Encode(new byte[] { 0x41 }, PayloadEncoding.Xor, MachineType.I386, bad))
                  .Message.ShouldContain("No XOR key");
        }

        [Fact]
        public void TryParseEncoding_accepts_the_documented_names()
        {
            PayloadEncoding encoding;
            PayloadEncoder.TryParseEncoding("xor", out encoding).ShouldBeTrue();
            encoding.ShouldBe(PayloadEncoding.Xor);
            PayloadEncoder.TryParseEncoding("alphanum", out encoding).ShouldBeTrue();
            encoding.ShouldBe(PayloadEncoding.Alphanumeric);
            PayloadEncoder.TryParseEncoding("printable", out encoding).ShouldBeTrue();
            encoding.ShouldBe(PayloadEncoding.Alphanumeric);
            PayloadEncoder.TryParseEncoding("nope", out encoding).ShouldBeFalse();
        }

        // -------------------------------------------------------- alphanumeric

        [Fact]
        public void Alphanumeric_round_trips_a_four_byte_payload()
        {
            byte[] original = { 0x41, 0x42, 0x43, 0x44 };
            EncodedPayload encoded = PayloadEncoder.Encode(original, PayloadEncoding.Alphanumeric);

            encoded.Bytes[0].ShouldBe((byte)0x25);
            encoded.Bytes.ShouldContain((byte)0x2D);
            encoded.Bytes.ShouldContain((byte)0x50);

            PayloadEncoder.SimulateAlphanumeric(encoded.Bytes).ShouldBe(original);
        }

        [Fact]
        public void Alphanumeric_pads_to_a_multiple_of_four_and_the_padding_survives()
        {
            byte[] original = { 0xCC };
            EncodedPayload encoded = PayloadEncoder.Encode(original, PayloadEncoding.Alphanumeric);

            byte[] recovered = PayloadEncoder.SimulateAlphanumeric(encoded.Bytes);
            recovered.Length.ShouldBe(4);
            recovered[0].ShouldBe((byte)0xCC);
            recovered[1].ShouldBe((byte)0x90);
            recovered[2].ShouldBe((byte)0x90);
            recovered[3].ShouldBe((byte)0x90);
        }

        [Fact]
        public void Alphanumeric_avoids_excluded_bytes()
        {
            byte[] original = { 0x90, 0x90, 0x90, 0x90 };
            byte[] bad = { 0x00, 0x0A, 0x0D };
            EncodedPayload encoded = PayloadEncoder.Encode(
                original, PayloadEncoding.Alphanumeric, MachineType.I386, bad);

            encoded.Bytes.ShouldNotContain((byte)0x00);
            encoded.Bytes.ShouldNotContain((byte)0x0A);
            encoded.Bytes.ShouldNotContain((byte)0x0D);
            PayloadEncoder.SimulateAlphanumeric(encoded.Bytes).ShouldBe(original);
        }

        [Fact]
        public void Alphanumeric_refuses_to_exclude_a_byte_it_uses_as_an_opcode()
        {
            Should.Throw<ERCException>(() =>
                    PayloadEncoder.Encode(
                        new byte[] { 0x90, 0x90, 0x90, 0x90 },
                        PayloadEncoding.Alphanumeric,
                        MachineType.I386,
                        new byte[] { 0x25 }))
                  .Message.ShouldContain("0x25");
        }

        [Fact]
        public void Alphanumeric_is_32_bit_only()
        {
            Should.Throw<ERCException>(() =>
                    PayloadEncoder.Encode(
                        new byte[] { 0x90, 0x90, 0x90, 0x90 },
                        PayloadEncoding.Alphanumeric,
                        MachineType.x64))
                  .Message.ShouldContain("32-bit");
        }

        [Fact]
        public void FormatPayloadBytes_includes_the_three_paste_forms()
        {
            string text = ERC.DisplayOutput.FormatPayloadBytes(new byte[] { 0xEB, 0x03 });

            text.ShouldContain("\\xEB\\x03");
            text.ShouldContain("0xEB, 0x03");
            text.ShouldContain("b\"");
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
