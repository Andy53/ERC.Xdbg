using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers the <c>-m</c> module-name patterns behind searches.
    /// </summary>
    public class ModuleFilterTests
    {
        [Fact]
        public void An_empty_list_matches_everything()
        {
            ModuleFilter.IsUnrestricted(null).ShouldBeTrue();
            ModuleFilter.IsUnrestricted(new string[0]).ShouldBeTrue();
            ModuleFilter.Matches("kernel32.dll", @"C:\Windows\System32\kernel32.dll", null).ShouldBeTrue();
        }

        [Fact]
        public void A_star_matches_every_module()
        {
            ModuleFilter.IsAll(new[] { "*" }).ShouldBeTrue();
            ModuleFilter.Matches("ntdll.dll", @"C:\Windows\System32\ntdll.dll", new[] { "*" }).ShouldBeTrue();
        }

        [Fact]
        public void A_plain_token_is_a_substring()
        {
            string[] patterns = ModuleFilter.Parse("kernel32");

            ModuleFilter.Matches("KERNEL32.DLL", @"C:\Windows\System32\kernel32.dll", patterns).ShouldBeTrue();
            ModuleFilter.Matches("ntdll.dll", @"C:\Windows\System32\ntdll.dll", patterns).ShouldBeFalse();
        }

        [Fact]
        public void A_star_prefix_is_a_suffix()
        {
            string[] patterns = ModuleFilter.Parse("*32.dll");

            ModuleFilter.Matches("kernel32.dll", @"C:\Windows\System32\kernel32.dll", patterns).ShouldBeTrue();
            ModuleFilter.Matches("ntdll.dll", @"C:\Windows\System32\ntdll.dll", patterns).ShouldBeFalse();
        }

        [Fact]
        public void A_star_suffix_is_a_prefix()
        {
            string[] patterns = ModuleFilter.Parse("kernel*");

            ModuleFilter.Matches("kernel32.dll", @"C:\Windows\System32\kernel32.dll", patterns).ShouldBeTrue();
            ModuleFilter.Matches("ntdll.dll", @"C:\Windows\System32\ntdll.dll", patterns).ShouldBeFalse();
        }

        [Fact]
        public void Comma_separated_patterns_are_or()
        {
            string[] patterns = ModuleFilter.Parse("kernel32,ntdll");

            ModuleFilter.Matches("kernel32.dll", @"C:\k\kernel32.dll", patterns).ShouldBeTrue();
            ModuleFilter.Matches("ntdll.dll", @"C:\n\ntdll.dll", patterns).ShouldBeTrue();
            ModuleFilter.Matches("user32.dll", @"C:\u\user32.dll", patterns).ShouldBeFalse();
        }

        [Fact]
        public void Keep_drops_an_excluded_path()
        {
            ModuleFilter.Keep("kernel32.dll", @"C:\k\kernel32.dll", null, new[] { @"C:\k\kernel32.dll" })
                        .ShouldBeFalse();
            ModuleFilter.Keep("ntdll.dll", @"C:\n\ntdll.dll", null, new[] { @"C:\k\kernel32.dll" })
                        .ShouldBeTrue();
        }

        [Fact]
        public void Keep_applies_includes_before_excludes()
        {
            ModuleFilter.Keep("kernel32.dll", @"C:\k\kernel32.dll", new[] { "kernel32" }, new string[0])
                        .ShouldBeTrue();
            ModuleFilter.Keep("ntdll.dll", @"C:\n\ntdll.dll", new[] { "kernel32" }, new string[0])
                        .ShouldBeFalse();
        }
    }
}
