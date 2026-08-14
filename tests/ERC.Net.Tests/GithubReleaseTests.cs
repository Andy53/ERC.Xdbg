using ERC;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Tests for parsing the GitHub release response the updater downloads from.
    /// </summary>
    /// <remarks>
    /// Security relevant: the URL taken from this response is downloaded and
    /// installed where x64dbg will load it, so picking the wrong one matters.
    /// </remarks>
    public class GithubReleaseTests
    {
        private const string Realistic = @"{
            ""tag_name"": ""64"",
            ""name"": ""Release 2.0.3"",
            ""assets"": [
                { ""name"": ""ERC.Xdbg-x64.zip"",
                  ""browser_download_url"": ""https://github.com/Andy53/ERC.Xdbg/releases/download/64/ERC.Xdbg-x64.zip"" }
            ]
        }";

        [Fact]
        public void The_download_url_is_read_from_the_matching_asset()
        {
            GithubRelease release = GithubRelease.Parse(Realistic);

            release.TagName.ShouldBe("64");
            release.DownloadUrlFor(".zip")
                   .ShouldBe("https://github.com/Andy53/ERC.Xdbg/releases/download/64/ERC.Xdbg-x64.zip");
        }

        [Fact]
        public void A_comma_in_the_release_name_does_not_shift_the_result()
        {
            // The defect this replaced: the response was split on commas and the URL
            // taken from a fixed offset within whichever fragment mentioned
            // "browser_download_url". Any comma in the free-text name or body moved
            // the fragments and produced the wrong URL - or an empty one, after which
            // the plugin downloaded and installed whatever that pointed at.
            const string withCommas = @"{
                ""tag_name"": ""64"",
                ""name"": ""Release 2.0.3, with fixes, and more"",
                ""body"": ""Fixes: one, two, three. See https://example.com/not-the-download"",
                ""assets"": [
                    { ""name"": ""ERC.Xdbg-x64.zip"",
                      ""browser_download_url"": ""https://github.com/real/download.zip"" }
                ]
            }";

            GithubRelease.Parse(withCommas).DownloadUrlFor(".zip")
                         .ShouldBe("https://github.com/real/download.zip");
        }

        [Fact]
        public void The_wanted_extension_selects_between_several_assets()
        {
            const string many = @"{
                ""assets"": [
                    { ""name"": ""notes.txt"",   ""browser_download_url"": ""https://example.com/notes.txt"" },
                    { ""name"": ""plugin.zip"",  ""browser_download_url"": ""https://example.com/plugin.zip"" },
                    { ""name"": ""source.tar.gz"", ""browser_download_url"": ""https://example.com/source.tar.gz"" }
                ]
            }";

            GithubRelease.Parse(many).DownloadUrlFor(".zip").ShouldBe("https://example.com/plugin.zip");
        }

        [Fact]
        public void A_release_with_no_matching_asset_is_refused()
        {
            const string noZip = @"{ ""assets"": [ { ""name"": ""notes.txt"",
                                    ""browser_download_url"": ""https://example.com/notes.txt"" } ] }";

            // Refusing beats returning an empty URL and downloading from nowhere.
            Should.Throw<ERCException>(() => GithubRelease.Parse(noZip).DownloadUrlFor(".zip"))
                  .Message.ShouldContain("no .zip asset");
        }

        [Fact]
        public void A_release_with_no_assets_at_all_is_refused()
        {
            Should.Throw<ERCException>(() => GithubRelease.Parse(@"{ ""tag_name"": ""64"" }").DownloadUrlFor(".zip"));
            Should.Throw<ERCException>(() => GithubRelease.Parse(@"{ ""assets"": [] }").DownloadUrlFor(".zip"));
        }

        [Fact]
        public void An_asset_without_a_url_is_not_offered()
        {
            const string urlless = @"{ ""assets"": [ { ""name"": ""plugin.zip"" } ] }";

            Should.Throw<ERCException>(() => GithubRelease.Parse(urlless).DownloadUrlFor(".zip"));
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData(null)]
        public void An_empty_response_is_refused(string json)
        {
            Should.Throw<ERCException>(() => GithubRelease.Parse(json))
                  .Message.ShouldContain("empty response");
        }

        [Theory]
        [InlineData("not json at all")]
        [InlineData("{ unterminated")]
        [InlineData("<html>error page</html>")]
        public void A_response_that_is_not_json_is_refused(string json)
        {
            // A proxy or captive portal returning an HTML error page must not be
            // mistaken for a release.
            Should.Throw<ERCException>(() => GithubRelease.Parse(json));
        }

        [Fact]
        public void Extension_matching_ignores_case()
        {
            const string upper = @"{ ""assets"": [ { ""name"": ""PLUGIN.ZIP"",
                                    ""browser_download_url"": ""https://example.com/PLUGIN.ZIP"" } ] }";

            GithubRelease.Parse(upper).DownloadUrlFor(".zip").ShouldBe("https://example.com/PLUGIN.ZIP");
        }
    }
}
