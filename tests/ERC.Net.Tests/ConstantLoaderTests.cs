using System;
using System.Linq;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers getting a constant into a register without writing forbidden bytes.
    /// </summary>
    /// <remarks>
    /// The generators used a hard-coded pair of values for this, labelled
    /// "combined = 0x00001000". 0xFFFFFFFF + 0x01011101 is 0x01011100. Arithmetic is
    /// exactly the sort of thing to compute and check rather than write down once.
    /// </remarks>
    public class ConstantLoaderTests
    {
        private static readonly byte[] NoNulls = { 0x00 };
        private static readonly byte[] Typical = { 0x00, 0x0A, 0x0D };

        // ------------------------------------------------- writing directly

        [Fact]
        public void A_value_with_no_forbidden_bytes_can_be_written_directly()
        {
            ConstantLoader.CanWriteDirectly(0x11223344, Typical).ShouldBeTrue();
        }

        [Fact]
        public void A_value_containing_a_forbidden_byte_cannot()
        {
            // 0x00001000 is VirtualAlloc's flAllocationType and is half nulls, which
            // is the whole reason the arithmetic route exists.
            ConstantLoader.CanWriteDirectly(0x00001000, NoNulls).ShouldBeFalse();
        }

        [Fact]
        public void Every_value_can_be_written_when_nothing_is_forbidden()
        {
            // The case the generators never checked for. With no bad characters there
            // is no reason to construct a value at all.
            ConstantLoader.CanWriteDirectly(0x00001000, null).ShouldBeTrue();
            ConstantLoader.CanWriteDirectly(0x00001000, new byte[0]).ShouldBeTrue();
        }

        [Fact]
        public void A_forbidden_byte_is_detected_in_any_position()
        {
            foreach (int shift in new[] { 0, 8, 16, 24 })
            {
                uint value = 0x11111111u & ~(0xFFu << shift);
                ConstantLoader.CanWriteDirectly(value, NoNulls).ShouldBeFalse("shift " + shift);
            }
        }

        // ------------------------------------------------- the additive pair

        [Theory]
        [InlineData(0x00001000u)]   // VirtualAlloc flAllocationType
        [InlineData(0x00000040u)]   // VirtualAlloc flProtect
        [InlineData(0x00040000u)]   // HeapCreate flOptions
        [InlineData(0x00010000u)]   // HeapCreate dwMaximumSize
        [InlineData(0x00000500u)]
        [InlineData(0x00000001u)]
        [InlineData(0xFFFFFFFFu)]
        [InlineData(0x00000000u)]
        public void A_pair_is_found_for_the_constants_a_chain_needs(uint target)
        {
            uint first, second;
            ConstantLoader.TryFindAdditivePair(target, NoNulls, out first, out second).ShouldBeTrue();

            // The processor adds modulo 2^32, so the sum wraps. That is what makes a
            // null-free route to a null-heavy constant possible at all.
            unchecked((uint)(first + second)).ShouldBe(target);
        }

        [Theory]
        [InlineData(0x00001000u)]
        [InlineData(0x00000040u)]
        [InlineData(0x00040000u)]
        public void Neither_half_of_the_pair_contains_a_forbidden_byte(uint target)
        {
            uint first, second;
            ConstantLoader.TryFindAdditivePair(target, Typical, out first, out second).ShouldBeTrue();

            foreach (uint value in new[] { first, second })
            {
                foreach (byte b in BitConverter.GetBytes(value))
                {
                    Typical.ShouldNotContain(b, "0x" + value.ToString("X8") + " contains a forbidden byte");
                }
            }
        }

        [Fact]
        public void The_pair_the_generators_hard_coded_did_not_add_up()
        {
            // Recorded because it is the reason this class exists. The two values were
            // 0xFFFFFFFF and 0x01011101 - little-endian { 01, 11, 01, 01 } - and the
            // chain claimed their sum was 0x1000.
            unchecked((uint)(0xFFFFFFFF + 0x01011101)).ShouldNotBe(0x00001000u);

            // What it should have been, computed rather than written down.
            uint first, second;
            ConstantLoader.TryFindAdditivePair(0x00001000, NoNulls, out first, out second).ShouldBeTrue();
            unchecked((uint)(first + second)).ShouldBe(0x00001000u);
        }

        [Fact]
        public void Every_constant_is_reachable_when_only_nulls_are_forbidden()
        {
            // Exhaustive over a spread of values rather than a couple of examples:
            // the byte-at-a-time solver either handles the carries or it does not.
            var random = new Random(20260817);

            for (int i = 0; i < 500; i++)
            {
                uint target = unchecked((uint)random.Next(int.MinValue, int.MaxValue));

                uint first, second;
                ConstantLoader.TryFindAdditivePair(target, NoNulls, out first, out second)
                    .ShouldBeTrue("0x" + target.ToString("X8"));

                unchecked((uint)(first + second)).ShouldBe(target, "0x" + target.ToString("X8"));
            }
        }

        [Fact]
        public void An_impossible_restriction_is_reported_rather_than_guessed_at()
        {
            // Forbidding every byte leaves nothing to write, and saying so is more use
            // than returning a pair that cannot be placed.
            byte[] everything = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();

            uint first, second;
            ConstantLoader.TryFindAdditivePair(0x1000, everything, out first, out second).ShouldBeFalse();
        }

        [Fact]
        public void A_severe_restriction_still_finds_a_pair_where_one_exists()
        {
            // Only 0x01 and 0x02 permitted. Reaching 0x02020202 needs 0x01010101
            // twice, which exists; the solver has to find it without help.
            byte[] excluded = Enumerable.Range(0, 256)
                .Where(i => i != 0x01 && i != 0x02)
                .Select(i => (byte)i).ToArray();

            uint first, second;
            ConstantLoader.TryFindAdditivePair(0x02020202, excluded, out first, out second).ShouldBeTrue();

            first.ShouldBe(0x01010101u);
            second.ShouldBe(0x01010101u);
        }

        [Fact]
        public void Nulls_are_used_only_when_they_are_permitted()
        {
            // With nulls allowed the answer may legitimately contain them, but the
            // search prefers non-null bytes so the output stays readable.
            uint first, second;
            ConstantLoader.TryFindAdditivePair(0x00001000, null, out first, out second).ShouldBeTrue();

            unchecked((uint)(first + second)).ShouldBe(0x00001000u);
        }
    }
}
