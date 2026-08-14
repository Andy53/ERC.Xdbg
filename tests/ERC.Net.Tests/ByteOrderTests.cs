using System;
using System.Linq;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers the byte reversal used when laying an address onto the stack.
    /// </summary>
    /// <remarks>
    /// This replaced <c>bytes.Reverse().ToArray()</c>, which looked unambiguous and
    /// was not: an array has two candidate <c>Reverse</c> extensions in scope, and
    /// the one from System.Memory reverses in place and returns <c>void</c>. The
    /// same source compiled here and failed on CI with CS0023 for exactly that
    /// reason, which is why the operation now has a name of its own.
    /// </remarks>
    public class ByteOrderTests
    {
        [Fact]
        public void The_order_of_the_bytes_is_flipped()
        {
            new byte[] { 0x01, 0x02, 0x03, 0x04 }.Reversed()
                .ShouldBe(new byte[] { 0x04, 0x03, 0x02, 0x01 });
        }

        [Fact]
        public void The_input_is_left_alone()
        {
            // The System.Memory overload reverses in place. Anything relying on the
            // old LINQ behaviour would break silently if this copied rather than
            // returned a new array, because a chain entry is built from a buffer that
            // is read again afterwards.
            var original = new byte[] { 0x01, 0x02, 0x03, 0x04 };

            original.Reversed();

            original.ShouldBe(new byte[] { 0x01, 0x02, 0x03, 0x04 });
        }

        [Fact]
        public void The_result_is_a_new_array()
        {
            var original = new byte[] { 0x01, 0x02 };

            original.Reversed().ShouldNotBeSameAs(original);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(4)]
        [InlineData(8)]
        public void Any_length_round_trips(int length)
        {
            var bytes = new byte[length];
            for (int i = 0; i < length; i++)
            {
                bytes[i] = (byte)(i + 1);
            }

            bytes.Reversed().Reversed().ShouldBe(bytes);
        }

        [Fact]
        public void A_null_array_gives_an_empty_one_rather_than_throwing()
        {
            ((byte[]?)null).Reversed().ShouldBeEmpty();
        }

        [Fact]
        public void It_agrees_with_what_the_LINQ_form_produced()
        {
            // The behaviour being preserved: every call site previously went through
            // Enumerable.Reverse, and the recorded ROP chains were produced by it.
            var bytes = BitConverter.GetBytes(0x1122334455667788L);

            bytes.Reversed().ShouldBe(Enumerable.Reverse(bytes).ToArray());
        }
    }
}
