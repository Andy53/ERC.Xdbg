using System;
using System.Collections.Generic;
using ERC;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers the pointer-shape filter behind "-Cp".
    /// </summary>
    public class PointerShapeTests
    {
        [Fact]
        public void TryParse_accepts_every_documented_name()
        {
            foreach (string name in PointerShape.Names)
            {
                PointerCriteria criteria;
                string? error;
                PointerShape.TryParse(name, out criteria, out error).ShouldBeTrue(name);
                error.ShouldBeNull();
                criteria.ShouldNotBe(PointerCriteria.None);
            }
        }

        [Fact]
        public void TryParse_combines_names_with_and()
        {
            PointerCriteria criteria;
            string? error;
            PointerShape.TryParse("unicode,ascii", out criteria, out error).ShouldBeTrue();
            criteria.ShouldBe(PointerCriteria.Unicode | PointerCriteria.Ascii);
        }

        [Fact]
        public void TryParse_rejects_an_unknown_name_and_names_it()
        {
            PointerCriteria criteria;
            string? error;
            PointerShape.TryParse("rwx", out criteria, out error).ShouldBeFalse();
            error.ShouldNotBeNull();
            error.ShouldContain("rwx");
            error.ShouldContain("alphanum");
        }

        [Fact]
        public void Format_round_trips_a_combination()
        {
            PointerCriteria original = PointerCriteria.NoNull | PointerCriteria.AlphaNum;
            string text = PointerShape.Format(original);

            PointerCriteria parsed;
            string? error;
            PointerShape.TryParse(text, out parsed, out error).ShouldBeTrue();
            parsed.ShouldBe(original);
        }

        [Fact]
        public void None_matches_everything()
        {
            PointerShape.Matches((IntPtr)0x00000000, MachineType.I386, PointerCriteria.None).ShouldBeTrue();
            PointerShape.Matches((IntPtr)0x41414141, MachineType.I386, PointerCriteria.None).ShouldBeTrue();
        }

        [Fact]
        public void NoNull_rejects_a_pointer_containing_zero()
        {
            // 0x00414141 occupies 41 41 41 00 in memory.
            PointerShape.Matches((IntPtr)0x00414141, MachineType.I386, PointerCriteria.NoNull)
                        .ShouldBeFalse();
            PointerShape.Matches((IntPtr)0x41414141, MachineType.I386, PointerCriteria.NoNull)
                        .ShouldBeTrue();
        }

        [Fact]
        public void StartsWithNull_is_the_most_significant_byte()
        {
            PointerShape.Matches((IntPtr)0x00414141, MachineType.I386, PointerCriteria.StartsWithNull)
                        .ShouldBeTrue();
            PointerShape.Matches((IntPtr)0x41414141, MachineType.I386, PointerCriteria.StartsWithNull)
                        .ShouldBeFalse();
        }

        [Fact]
        public void AlphaNum_accepts_only_letters_and_digits()
        {
            PointerShape.Matches((IntPtr)0x41424344, MachineType.I386, PointerCriteria.AlphaNum)
                        .ShouldBeTrue();
            PointerShape.Matches((IntPtr)0x41414120, MachineType.I386, PointerCriteria.AlphaNum)
                        .ShouldBeFalse();
        }

        [Fact]
        public void Upper_accepts_only_A_to_Z()
        {
            PointerShape.Matches((IntPtr)0x41414141, MachineType.I386, PointerCriteria.Upper)
                        .ShouldBeTrue();
            PointerShape.Matches((IntPtr)0x41424141, MachineType.I386, PointerCriteria.Upper)
                        .ShouldBeTrue();
            PointerShape.Matches((IntPtr)0x61614141, MachineType.I386, PointerCriteria.Upper)
                        .ShouldBeFalse();
        }

        [Fact]
        public void Unicode_is_XX_00_XX_00_in_memory()
        {
            // 0x00410041 -> 41 00 41 00
            PointerShape.Matches((IntPtr)0x00410041, MachineType.I386, PointerCriteria.Unicode)
                        .ShouldBeTrue();
            PointerShape.Matches((IntPtr)0x41004100, MachineType.I386, PointerCriteria.Unicode)
                        .ShouldBeFalse();
        }

        [Fact]
        public void UnicodeRev_is_00_XX_00_XX_in_memory()
        {
            PointerShape.Matches((IntPtr)0x41004100, MachineType.I386, PointerCriteria.UnicodeRev)
                        .ShouldBeTrue();
            PointerShape.Matches((IntPtr)0x00410041, MachineType.I386, PointerCriteria.UnicodeRev)
                        .ShouldBeFalse();
        }

        [Fact]
        public void Unicode_plus_ascii_tests_the_non_null_bytes()
        {
            // 0x00410041 -> 41 00 41 00, non-null bytes 41 41, both ASCII.
            PointerShape.Matches(
                (IntPtr)0x00410041, MachineType.I386,
                PointerCriteria.Unicode | PointerCriteria.Ascii)
                        .ShouldBeTrue();

            // 0x00FF0041 -> 41 00 FF 00, non-null 41 FF; FF is not ASCII.
            PointerShape.Matches(
                (IntPtr)0x00FF0041, MachineType.I386,
                PointerCriteria.Unicode | PointerCriteria.Ascii)
                        .ShouldBeFalse();
        }

        [Fact]
        public void Filter_drops_pointers_that_fail_and_keeps_the_rest()
        {
            var source = new Dictionary<IntPtr, string>
            {
                { (IntPtr)0x41414141, "ok" },
                { (IntPtr)0x00414141, "null" }
            };

            Dictionary<IntPtr, string> kept =
                PointerShape.Filter(MachineType.I386, source, PointerCriteria.NoNull);

            kept.Keys.ShouldBe(new[] { (IntPtr)0x41414141 });
            source.Count.ShouldBe(2);
        }

        [Fact]
        public void AsciiPrint_rejects_a_newline()
        {
            PointerShape.Matches((IntPtr)0x4141410A, MachineType.I386, PointerCriteria.AsciiPrint)
                        .ShouldBeFalse();
            PointerShape.Matches((IntPtr)0x4141410A, MachineType.I386, PointerCriteria.Ascii)
                        .ShouldBeTrue();
        }
    }
}
