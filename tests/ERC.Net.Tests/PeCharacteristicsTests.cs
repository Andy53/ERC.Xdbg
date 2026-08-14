using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Tests for reading mitigation flags out of a PE header.
    /// </summary>
    /// <remarks>
    /// These flags decide which modules the "-ASLR", "-NXCompat" and "-SafeSEH"
    /// globals exclude from search results. Reading them wrongly does not fail
    /// loudly - it just offers the user pointers they asked to be filtered out.
    /// </remarks>
    public class PeCharacteristicsTests
    {
        // Values from winnt.h, so the constants are pinned to the real ones rather
        // than to whatever the library happens to say.
        private const ushort IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040;
        private const ushort IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100;
        private const ushort IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400;
        private const ushort IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020;
        private const ushort IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080;
        private const ushort IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000;

        [Fact]
        public void The_constants_match_the_documented_values()
        {
            PeCharacteristics.DynamicBase.ShouldBe(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
            PeCharacteristics.NxCompat.ShouldBe(IMAGE_DLLCHARACTERISTICS_NX_COMPAT);
            PeCharacteristics.NoSeh.ShouldBe(IMAGE_DLLCHARACTERISTICS_NO_SEH);
        }

        // ------------------------------------------------- the defect

        [Fact]
        public void Aslr_is_detected_when_only_that_bit_is_set()
        {
            // The defect this replaced. The old 32-bit derivation walked all sixteen
            // bits and assigned in a plain "else", so every iteration after bit 6
            // reset the flag: ASLR always came back false on a 32-bit target, and the
            // "-ASLR" exclusion silently stopped excluding anything.
            PeCharacteristics.HasAslr(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE).ShouldBeTrue();
        }

        [Fact]
        public void Nx_is_detected_when_only_that_bit_is_set()
        {
            PeCharacteristics.HasNxCompat(IMAGE_DLLCHARACTERISTICS_NX_COMPAT).ShouldBeTrue();
        }

        [Fact]
        public void A_flag_set_alongside_higher_bits_is_still_detected()
        {
            // The specific shape that broke the old loop: a bit of interest set, plus
            // another bit above it. TERMINAL_SERVER_AWARE is bit 15 and is set on
            // essentially every real Windows binary, so this was the normal case.
            ushort characteristics = (ushort)(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                                              IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE);

            PeCharacteristics.HasAslr(characteristics).ShouldBeTrue();
        }

        [Fact]
        public void A_realistic_modern_binary_reports_both_mitigations()
        {
            // What a current compiler emits: ASLR, DEP, high entropy, TS aware.
            ushort characteristics = (ushort)(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                                              IMAGE_DLLCHARACTERISTICS_NX_COMPAT |
                                              IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA |
                                              IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE);

            PeCharacteristics.HasAslr(characteristics).ShouldBeTrue();
            PeCharacteristics.HasNxCompat(characteristics).ShouldBeTrue();
        }

        // ------------------------------------------------- absence

        [Fact]
        public void Nothing_is_reported_for_a_header_with_no_flags()
        {
            PeCharacteristics.HasAslr(0).ShouldBeFalse();
            PeCharacteristics.HasNxCompat(0).ShouldBeFalse();
            PeCharacteristics.HasNoSeh(0).ShouldBeFalse();
        }

        [Fact]
        public void A_module_built_without_a_mitigation_does_not_report_it()
        {
            // The target an exploit-development tool actually cares about: built
            // /DYNAMICBASE:NO /NXCOMPAT:NO, so neither should be reported even though
            // other bits are set.
            ushort characteristics = IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;

            PeCharacteristics.HasAslr(characteristics).ShouldBeFalse();
            PeCharacteristics.HasNxCompat(characteristics).ShouldBeFalse();
        }

        [Fact]
        public void The_flags_are_read_independently()
        {
            // ASLR without DEP, and DEP without ASLR, are both real configurations.
            PeCharacteristics.HasAslr(IMAGE_DLLCHARACTERISTICS_NX_COMPAT).ShouldBeFalse();
            PeCharacteristics.HasNxCompat(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE).ShouldBeFalse();
        }

        [Fact]
        public void A_neighbouring_bit_is_not_mistaken_for_a_flag()
        {
            // FORCE_INTEGRITY (0x0080) sits directly above DYNAMIC_BASE (0x0040), and
            // HIGH_ENTROPY_VA (0x0020) directly below.
            PeCharacteristics.HasAslr(IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY).ShouldBeFalse();
            PeCharacteristics.HasAslr(IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA).ShouldBeFalse();
        }

        [Fact]
        public void Every_flag_is_detected_when_all_bits_are_set()
        {
            PeCharacteristics.HasAslr(0xFFFF).ShouldBeTrue();
            PeCharacteristics.HasNxCompat(0xFFFF).ShouldBeTrue();
            PeCharacteristics.HasNoSeh(0xFFFF).ShouldBeTrue();
        }

        [Fact]
        public void NoSeh_is_detected_on_its_own()
        {
            PeCharacteristics.HasNoSeh(IMAGE_DLLCHARACTERISTICS_NO_SEH).ShouldBeTrue();
            PeCharacteristics.HasNoSeh(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE).ShouldBeFalse();
        }
    }
}
