using System;
using System.IO;
using System.Text;
using ERC;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Tests for verifying a downloaded update against its published hash.
    /// </summary>
    /// <remarks>
    /// Security relevant: whatever survives this check is extracted into the x64dbg
    /// plugin directory and loaded by the debugger.
    /// </remarks>
    public class ReleaseVerifierTests : IDisposable
    {
        private readonly string _directory;
        private readonly string _file;

        // "hello" hashed with SHA-256.
        private const string HelloHash =
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

        public ReleaseVerifierTests()
        {
            _directory = Path.Combine(Path.GetTempPath(), "erc-verify-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_directory);
            _file = Path.Combine(_directory, "plugin.zip");
            File.WriteAllText(_file, "hello");
        }

        public void Dispose()
        {
            Directory.Delete(_directory, recursive: true);
        }

        [Fact]
        public void The_hash_matches_a_known_value()
        {
            ReleaseVerifier.ComputeSha256(_file).ShouldBe(HelloHash);
            ReleaseVerifier.ComputeSha256(Encoding.UTF8.GetBytes("hello")).ShouldBe(HelloHash);
        }

        [Fact]
        public void A_matching_download_is_accepted()
        {
            Should.NotThrow(() => ReleaseVerifier.Verify(_file, HelloHash));
        }

        [Fact]
        public void A_tampered_download_is_refused()
        {
            // The case that matters: the file is not what was published.
            File.WriteAllText(_file, "hello, plus something extra");

            var ex = Should.Throw<ERCException>(() => ReleaseVerifier.Verify(_file, HelloHash));
            ex.Message.ShouldContain("does not match");
            ex.Message.ShouldContain("nothing was installed");
        }

        [Fact]
        public void Verification_ignores_case_in_the_published_hash()
        {
            Should.NotThrow(() => ReleaseVerifier.Verify(_file, HelloHash.ToUpperInvariant()));
        }

        [Theory]
        // Bare hash
        [InlineData("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")]
        // sha256sum style
        [InlineData("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  plugin.zip")]
        // sha256sum binary style
        [InlineData("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 *plugin.zip")]
        // trailing newline, as a published file would have
        [InlineData("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\r\n")]
        public void The_common_published_hash_formats_are_understood(string published)
        {
            ReleaseVerifier.ParsePublishedHash(published).ShouldBe(HelloHash);
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData(null)]
        public void A_missing_hash_is_refused_rather_than_ignored(string? published)
        {
            // Refusing beats installing something unverified.
            Should.Throw<ERCException>(() => ReleaseVerifier.ParsePublishedHash(published))
                  .Message.ShouldContain("cannot be verified");
        }

        [Theory]
        [InlineData("not a hash at all")]
        [InlineData("deadbeef")]                       // too short
        [InlineData("<html>404 not found</html>")]     // an error page, not a hash
        public void Something_that_is_not_a_hash_is_refused(string published)
        {
            Should.Throw<ERCException>(() => ReleaseVerifier.ParsePublishedHash(published));
        }

        [Fact]
        public void A_hash_for_a_different_file_is_refused()
        {
            string otherHash = ReleaseVerifier.ComputeSha256(Encoding.UTF8.GetBytes("a different release"));

            Should.Throw<ERCException>(() => ReleaseVerifier.Verify(_file, otherHash));
        }
    }
}
