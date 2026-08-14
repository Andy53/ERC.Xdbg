using System;
using System.Collections.Generic;
using ERC;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Tests for ERC.Utilities.PtrRemover, which backs the "-Bytes" global used to
    /// keep pointers containing bad characters out of search results.
    /// </summary>
    public class PtrRemoverTests
    {
        [Fact]
        public void RemovePointers_drops_pointers_containing_an_excluded_byte()
        {
            var pointers = new List<IntPtr> { (IntPtr)0x11223344, (IntPtr)0x11220A44 };

            PtrRemover.RemovePointers(MachineType.I386, pointers, new byte[] { 0x0A })
                      .ShouldBe(new List<IntPtr> { (IntPtr)0x11223344 });
        }

        [Fact]
        public void RemovePointers_keeps_pointers_with_no_excluded_byte()
        {
            var pointers = new List<IntPtr> { (IntPtr)0x11223344 };

            PtrRemover.RemovePointers(MachineType.I386, pointers, new byte[] { 0x99 })
                      .ShouldBe(new List<IntPtr> { (IntPtr)0x11223344 });
        }

        [Fact]
        public void RemovePointers_is_a_no_op_when_no_bytes_are_excluded()
        {
            var pointers = new List<IntPtr> { (IntPtr)0x11223344 };

            PtrRemover.RemovePointers(MachineType.I386, pointers, new byte[0])
                      .ShouldBe(new List<IntPtr> { (IntPtr)0x11223344 });
            PtrRemover.RemovePointers(MachineType.I386, pointers, null)
                      .ShouldBe(new List<IntPtr> { (IntPtr)0x11223344 });
        }

        [Fact]
        public void RemovePointers_drops_pointers_that_really_do_contain_a_null_byte()
        {
            // 0x00001234 occupies bytes 34 12 00 00 on a 32-bit target.
            var pointers = new List<IntPtr> { (IntPtr)0x00001234 };

            PtrRemover.RemovePointers(MachineType.I386, pointers, new byte[] { 0x00 })
                      .ShouldBeEmpty();
        }

        [Fact]
        public void RemovePointers_does_not_mutate_the_callers_list()
        {
            // Was a pinned defect: the caller's list was edited and handed straight
            // back, so anything still holding it silently lost entries.
            var pointers = new List<IntPtr> { (IntPtr)0x11223344, (IntPtr)0x11220A44 };

            List<IntPtr> result = PtrRemover.RemovePointers(MachineType.I386, pointers, new byte[] { 0x0A });

            result.ShouldNotBeSameAs(pointers);
            pointers.Count.ShouldBe(2);
            result.Count.ShouldBe(1);
        }

        [Fact]
        public void RemovePointers_filters_addresses_above_two_gigabytes_on_x64()
        {
            // Was a pinned defect: pointers were narrowed with "(int)", a checked
            // conversion, so any address that did not fit in a signed 32-bit value
            // threw an OverflowException. Module bases on a real 64-bit target sit
            // well above that, which made "-Bytes" unusable there.
            if (IntPtr.Size != 8)
            {
                // A 32-bit IntPtr cannot represent these addresses at all, so the
                // scenario only exists in a 64-bit process.
                Assert.Skip("Requires a 64-bit test host.");
            }

            var pointers = new List<IntPtr>
            {
                (IntPtr)0x00007FFA12345678L,   // clean
                (IntPtr)0x00007FFA12340A78L    // contains 0x0A
            };

            PtrRemover.RemovePointers(MachineType.x64, pointers, new byte[] { 0x0A })
                      .ShouldBe(new List<IntPtr> { (IntPtr)0x00007FFA12345678L });
        }

        [Fact]
        public void RemovePointers_sees_bad_bytes_in_the_high_half_of_a_64_bit_pointer()
        {
            if (IntPtr.Size != 8)
            {
                Assert.Skip("Requires a 64-bit test host.");
            }

            // The whole pointer is inspected, not just its low 32 bits.
            var pointers = new List<IntPtr> { (IntPtr)0x0A007FFA12345678L };

            PtrRemover.RemovePointers(MachineType.x64, pointers, new byte[] { 0x0A })
                      .ShouldBeEmpty();
        }

        [Fact]
        public void RemovePointers_keeps_clean_32_bit_pointers_when_nulls_are_excluded()
        {
            // Was a pinned defect in the dictionary overload: every pointer was
            // widened to eight bytes, so the four bytes of padding on a 32-bit
            // target read as nulls and excluding 0x00 - the most common bad
            // character - discarded everything. The failure was silent: the user
            // simply saw no results.
            var pointers = new Dictionary<IntPtr, string>
            {
                { (IntPtr)0x11223344, "no null bytes" }
            };

            PtrRemover.RemovePointers(MachineType.I386, pointers, new byte[] { 0x00 })
                      .ShouldContainKey((IntPtr)0x11223344);
        }

        [Fact]
        public void RemovePointers_dictionary_overload_drops_matching_entries()
        {
            var pointers = new Dictionary<IntPtr, string>
            {
                { (IntPtr)0x11223344, "good" },
                { (IntPtr)0x11220A44, "bad" }
            };

            Dictionary<IntPtr, string> result =
                PtrRemover.RemovePointers(MachineType.I386, pointers, new byte[] { 0x0A });

            result.ShouldContainKey((IntPtr)0x11223344);
            result.ShouldNotContainKey((IntPtr)0x11220A44);
            result[(IntPtr)0x11223344].ShouldBe("good");
        }

        [Fact]
        public void RemovePointers_dictionary_overload_does_not_mutate_the_caller()
        {
            var pointers = new Dictionary<IntPtr, string>
            {
                { (IntPtr)0x11223344, "good" },
                { (IntPtr)0x11220A44, "bad" }
            };

            PtrRemover.RemovePointers(MachineType.I386, pointers, new byte[] { 0x0A });

            pointers.Count.ShouldBe(2);
        }

        [Theory]
        [InlineData(0x11223344, new byte[] { 0x11 }, true)]
        [InlineData(0x11223344, new byte[] { 0x22 }, true)]
        [InlineData(0x11223344, new byte[] { 0x33 }, true)]
        [InlineData(0x11223344, new byte[] { 0x44 }, true)]
        [InlineData(0x11223344, new byte[] { 0x55 }, false)]
        [InlineData(0x11223344, new byte[] { 0x0A, 0x0D, 0x22 }, true)]
        public void RemovePointers_inspects_every_byte_of_a_32_bit_pointer(
            int address, byte[] excluded, bool shouldBeRemoved)
        {
            var pointers = new List<IntPtr> { (IntPtr)address };

            List<IntPtr> result = PtrRemover.RemovePointers(MachineType.I386, pointers, excluded);

            result.Count.ShouldBe(shouldBeRemoved ? 0 : 1);
        }
    }
}
