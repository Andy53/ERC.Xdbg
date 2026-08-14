using System.Collections.Generic;
using ERC;
using ERC.Net.Tests.TestSupport;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Characterization tests for ERC.Utilities.PatternTools, which backs
    /// "ERC --pattern create" and "ERC --pattern offset".
    /// </summary>
    [Collection(ErcCoreCollection.Name)]
    public class PatternToolsTests
    {
        private readonly ErcCore _core;

        public PatternToolsTests(ErcCoreFixture fixture)
        {
            _core = fixture.Core;
        }

        // ------------------------------------------------------------ PatternCreate

        [Theory]
        [InlineData(1, "A")]
        [InlineData(2, "Aa")]
        [InlineData(3, "Aa0")]
        [InlineData(4, "Aa0A")]
        [InlineData(5, "Aa0Aa")]
        [InlineData(6, "Aa0Aa1")]
        [InlineData(10, "Aa0Aa1Aa2A")]
        public void PatternCreate_produces_the_expected_prefix(int length, string expected)
        {
            PatternTools.PatternCreate(length, _core).ReturnValue.ShouldBe(expected);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(50)]
        [InlineData(1000)]
        [InlineData(20277)]
        public void PatternCreate_returns_exactly_the_requested_length(int length)
        {
            PatternTools.PatternCreate(length, _core).ReturnValue.Length.ShouldBe(length);
        }

        [Fact]
        public void PatternCreate_produces_no_repeating_three_character_window()
        {
            // The whole point of the pattern: every 3-character window is unique, so
            // a crash offset can be identified from the register contents.
            string pattern = PatternTools.PatternCreate(20277, _core).ReturnValue;

            var seen = new HashSet<string>();
            for (int i = 0; i + 3 <= pattern.Length; i++)
            {
                seen.Add(pattern.Substring(i, 3)).ShouldBeTrue(
                    "window at " + i + " repeats: " + pattern.Substring(i, 3));
            }
        }

        [Fact]
        public void PatternCreate_accepts_its_documented_maximum()
        {
            ErcResult<string> result = PatternTools.PatternCreate(20277, _core);

            result.Error.ShouldBeNull();
            result.ReturnValue.Length.ShouldBe(20277);
        }

        [Fact]
        public void PatternCreate_rejects_one_past_the_standard_maximum()
        {
            ErcResult<string> result = PatternTools.PatternCreate(20278, _core);

            result.Error.ShouldNotBeNull();
            result.Error.Message.ShouldContain("20277");
        }

        [Fact]
        public void PatternCreate_extended_accepts_its_documented_maximum()
        {
            ErcResult<string> result = PatternTools.PatternCreate(66923, _core, extended: true);

            result.Error.ShouldBeNull();
            result.ReturnValue.Length.ShouldBe(66923);
        }

        [Fact]
        public void PatternCreate_extended_rejects_one_past_its_maximum()
        {
            ErcResult<string> result = PatternTools.PatternCreate(66924, _core, extended: true);

            result.Error.ShouldNotBeNull();
            result.Error.Message.ShouldContain("66923");
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-5)]
        public void PatternCreate_rejects_non_positive_lengths(int length)
        {
            ErcResult<string> result = PatternTools.PatternCreate(length, _core);

            result.Error.ShouldNotBeNull();
            result.ReturnValue.ShouldBe(string.Empty);
        }

        // ------------------------------------------------------------ PatternOffset

        [Fact]
        public void PatternOffset_finds_a_pattern_at_the_start()
        {
            PatternTools.PatternOffset("Aa0", _core).ReturnValue
                        .ShouldBe("Value found at position 0 in pattern.");
        }

        [Fact]
        public void PatternOffset_finds_a_pattern_further_in()
        {
            PatternTools.PatternOffset("Ab1", _core).ReturnValue
                        .ShouldBe("Value found at position 33 in pattern.");
        }

        [Fact]
        public void PatternOffset_reports_the_offset_agreeing_with_PatternCreate()
        {
            // Cross-check the two halves of the feature against each other: take a
            // slice of a generated pattern and confirm the reported offset matches.
            string pattern = PatternTools.PatternCreate(200, _core).ReturnValue;
            string slice = pattern.Substring(60, 4);

            PatternTools.PatternOffset(slice, _core).ReturnValue
                        .ShouldBe("Value found at position 60 in pattern.");
        }

        [Fact]
        public void PatternOffset_detects_a_reversed_pattern()
        {
            // Little-endian register contents show up reversed, so this is the
            // common case when reading EIP off a crash.
            PatternTools.PatternOffset("0aA", _core).ReturnValue
                        .ShouldBe("Value found reversed at position 0 in pattern.");
        }

        [Fact]
        public void PatternOffset_reports_when_the_value_is_absent()
        {
            ErcResult<string> result = PatternTools.PatternOffset("ZZZ9", _core);

            result.ReturnValue.ShouldBe("Value not found in pattern.");
            result.Error.ShouldNotBeNull();
        }

        [Theory]
        [InlineData("Aa")]
        [InlineData("A")]
        [InlineData("")]
        [InlineData(null)]
        public void PatternOffset_explains_itself_for_too_short_input(string? search)
        {
            // Was a pinned defect: input under three characters set Error but left
            // ReturnValue null, while every other failure path sets an explanatory
            // string. The plugin prints ReturnValue, so "ERC --pattern o Aa" printed
            // nothing at all.
            ErcResult<string> result = PatternTools.PatternOffset(search, _core);

            result.Error.ShouldNotBeNull();
            result.Error.Message.ShouldContain("3 characters or longer");
            result.ReturnValue.ShouldNotBeNullOrEmpty();
        }
    }
}
