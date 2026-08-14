using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using ERC.Net.Tests.TestSupport;
using ERC.Update;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers downloading, verifying and installing an update.
    /// </summary>
    /// <remarks>
    /// This was a 170-line method inside the plugin holding two nearly identical
    /// copies of the flow, one per architecture, reachable only by running the real
    /// command against GitHub. Three defects were living in it; each has a test here.
    /// </remarks>
    public sealed class PluginUpdaterTests : IDisposable
    {
        private readonly string _directory;

        public PluginUpdaterTests()
        {
            _directory = Path.Combine(Path.GetTempPath(), "erc-update-" + Path.GetRandomFileName());
            Directory.CreateDirectory(_directory);
        }

        public void Dispose()
        {
            try
            {
                Directory.Delete(_directory, true);
            }
            catch (Exception)
            {
            }
        }

        // --------------------------------------------------------------- helpers

        private const string AssetUrl = "https://github.com/andy53/erc.xdbg/releases/download/64/Erc.Xdbg.zip";

        private static string ReleaseJson(string assetUrl)
        {
            return "{\"tag_name\":\"64\",\"assets\":[{\"name\":\"Erc.Xdbg.zip\"," +
                   "\"browser_download_url\":\"" + assetUrl + "\"}]}";
        }

        /// <summary>Builds a zip in memory from a name/content map.</summary>
        private static byte[] Zip(params (string Name, string Content)[] entries)
        {
            using (var buffer = new MemoryStream())
            {
                using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, true))
                {
                    foreach (var entry in entries)
                    {
                        ZipArchiveEntry created = archive.CreateEntry(entry.Name);
                        using (var writer = new StreamWriter(created.Open()))
                        {
                            writer.Write(entry.Content);
                        }
                    }
                }

                return buffer.ToArray();
            }
        }

        /// <summary>A transport serving a release whose asset is <paramref name="zip"/>.</summary>
        private static FakeHttpTransport TransportFor(byte[] zip, string? publishedHash = null)
        {
            return new FakeHttpTransport()
                .WithString(PluginUpdater.ReleasesUrl(PluginUpdater.Tag64), ReleaseJson(AssetUrl))
                .WithFile(AssetUrl, zip)
                .WithString(AssetUrl + ".sha256", publishedHash ?? ReleaseVerifier.ComputeSha256(zip));
        }

        // ------------------------------------------------------------ the happy path

        [Fact]
        public void An_update_is_downloaded_verified_and_installed()
        {
            byte[] zip = Zip(("Erc.Xdbg.dp64", "new plugin"));

            IReadOnlyList<string> written = PluginUpdater.Update(
                TransportFor(zip), PluginUpdater.Tag64, _directory);

            written.Count.ShouldBe(1);
            File.ReadAllText(Path.Combine(_directory, "Erc.Xdbg.dp64")).ShouldBe("new plugin");
        }

        [Fact]
        public void The_downloaded_archive_is_not_left_behind()
        {
            PluginUpdater.Update(TransportFor(Zip(("Erc.Xdbg.dp64", "x"))), PluginUpdater.Tag64, _directory);

            Directory.GetFiles(_directory, "*.zip").ShouldBeEmpty();
        }

        [Fact]
        public void The_published_hash_is_fetched_from_beside_the_asset()
        {
            var transport = TransportFor(Zip(("Erc.Xdbg.dp64", "x")));

            PluginUpdater.Update(transport, PluginUpdater.Tag64, _directory);

            transport.Requested.ShouldContain(AssetUrl + ".sha256");
        }

        // ------------------------------------------------------------ verification

        [Fact]
        public void An_asset_that_does_not_match_the_published_hash_is_not_installed()
        {
            // The extracted file is loaded by x64dbg, so installing an unverified
            // download is arbitrary code execution.
            byte[] zip = Zip(("Erc.Xdbg.dp64", "tampered"));
            var transport = TransportFor(zip, ReleaseVerifier.ComputeSha256(Encoding.ASCII.GetBytes("something else")));

            Should.Throw<ERCException>(() =>
                PluginUpdater.Update(transport, PluginUpdater.Tag64, _directory));

            File.Exists(Path.Combine(_directory, "Erc.Xdbg.dp64")).ShouldBeFalse();
            Directory.GetFiles(_directory).ShouldBeEmpty();
        }

        [Fact]
        public void A_release_with_no_published_hash_is_refused_rather_than_installed_unchecked()
        {
            byte[] zip = Zip(("Erc.Xdbg.dp64", "x"));

            var transport = new FakeHttpTransport()
                .WithString(PluginUpdater.ReleasesUrl(PluginUpdater.Tag64), ReleaseJson(AssetUrl))
                .WithFile(AssetUrl, zip);
            // no .sha256

            var error = Should.Throw<ERCException>(() =>
                PluginUpdater.Update(transport, PluginUpdater.Tag64, _directory));

            error.Message.ShouldContain("could not be verified");
            Directory.GetFiles(_directory).ShouldBeEmpty();
        }

        // ------------------------------------------------------- backup numbering

        [Fact]
        public void The_installed_plugin_is_backed_up_before_being_replaced()
        {
            File.WriteAllText(Path.Combine(_directory, "Erc.Xdbg.dp64"), "old plugin");

            PluginUpdater.Update(TransportFor(Zip(("Erc.Xdbg.dp64", "new plugin"))), PluginUpdater.Tag64, _directory);

            File.ReadAllText(Path.Combine(_directory, "Erc.Xdbg.dp64")).ShouldBe("new plugin");
            File.ReadAllText(Path.Combine(_directory, "Erc.Xdbg.dp64-OLD_0.txt")).ShouldBe("old plugin");
        }

        [Fact]
        public void Updating_twice_does_not_fail_on_the_existing_backup()
        {
            // The original read the number out of an existing backup's name and then
            // renamed the current plugin to that same name, so File.Move threw and the
            // second update aborted. Anyone who updated twice hit this.
            File.WriteAllText(Path.Combine(_directory, "Erc.Xdbg.dp64"), "first");

            PluginUpdater.Update(TransportFor(Zip(("Erc.Xdbg.dp64", "second"))), PluginUpdater.Tag64, _directory);
            PluginUpdater.Update(TransportFor(Zip(("Erc.Xdbg.dp64", "third"))), PluginUpdater.Tag64, _directory);

            File.ReadAllText(Path.Combine(_directory, "Erc.Xdbg.dp64")).ShouldBe("third");
            File.ReadAllText(Path.Combine(_directory, "Erc.Xdbg.dp64-OLD_0.txt")).ShouldBe("first");
            File.ReadAllText(Path.Combine(_directory, "Erc.Xdbg.dp64-OLD_1.txt")).ShouldBe("second");
        }

        [Fact]
        public void Backup_numbering_reads_the_whole_number_not_the_first_digit()
        {
            // The original called int.TryParse on holder[0].ToString() - a single
            // character - so "-OLD_10.txt" was read as 1 and the next backup collided
            // with an existing one.
            File.WriteAllText(Path.Combine(_directory, "Erc.Xdbg.dp64-OLD_10.txt"), "ten");

            PluginUpdater.NextBackupPath(_directory, "Erc.Xdbg.dp64")
                .ShouldBe(Path.Combine(_directory, "Erc.Xdbg.dp64-OLD_11.txt"));
        }

        [Fact]
        public void Backup_numbering_is_not_confused_by_underscores_in_the_directory_name()
        {
            // The original split the full path on "_" and took segment 1, so a parent
            // directory containing an underscore shifted which segment it read.
            string awkward = Path.Combine(_directory, "my_plugins");
            Directory.CreateDirectory(awkward);
            File.WriteAllText(Path.Combine(awkward, "Erc.Xdbg.dp64-OLD_3.txt"), "three");

            PluginUpdater.NextBackupPath(awkward, "Erc.Xdbg.dp64")
                .ShouldBe(Path.Combine(awkward, "Erc.Xdbg.dp64-OLD_4.txt"));
        }

        [Fact]
        public void Backup_numbering_starts_at_zero_in_an_empty_directory()
        {
            PluginUpdater.NextBackupPath(_directory, "Erc.Xdbg.dp32")
                .ShouldBe(Path.Combine(_directory, "Erc.Xdbg.dp32-OLD_0.txt"));
        }

        [Fact]
        public void Backup_numbering_ignores_the_other_architectures_backups()
        {
            File.WriteAllText(Path.Combine(_directory, "Erc.Xdbg.dp32-OLD_7.txt"), "x");

            PluginUpdater.NextBackupPath(_directory, "Erc.Xdbg.dp64")
                .ShouldBe(Path.Combine(_directory, "Erc.Xdbg.dp64-OLD_0.txt"));
        }

        // ------------------------------------------------------------- extraction

        [Fact]
        public void An_archive_entry_pointing_outside_the_directory_is_refused()
        {
            // The original computed the full destination path and carried a comment
            // explaining that an archive could otherwise escape the directory - but
            // never compared the result against the directory, so the check the
            // comment described never happened.
            byte[] zip = Zip((@"..\escaped.txt", "owned"));
            string archive = Path.Combine(_directory, "evil.zip");
            File.WriteAllBytes(archive, zip);

            string target = Path.Combine(_directory, "plugins");
            Directory.CreateDirectory(target);

            var error = Should.Throw<ERCException>(() => PluginUpdater.ExtractSafely(archive, target));

            error.Message.ShouldContain("outside");
            File.Exists(Path.Combine(_directory, "escaped.txt")).ShouldBeFalse();
        }

        [Fact]
        public void An_update_containing_a_traversing_entry_is_not_installed()
        {
            byte[] zip = Zip((@"..\escaped.txt", "owned"));
            string target = Path.Combine(_directory, "plugins");
            Directory.CreateDirectory(target);

            Should.Throw<ERCException>(() =>
                PluginUpdater.Update(TransportFor(zip), PluginUpdater.Tag64, target));

            File.Exists(Path.Combine(_directory, "escaped.txt")).ShouldBeFalse();
        }

        [Fact]
        public void A_sibling_directory_sharing_a_prefix_is_still_outside()
        {
            // "C:\plugins" is a prefix of "C:\plugins-evil", so a StartsWith test
            // without the trailing separator would let this through.
            string target = Path.Combine(_directory, "plugins");
            Directory.CreateDirectory(target);
            Directory.CreateDirectory(Path.Combine(_directory, "plugins-evil"));

            byte[] zip = Zip((@"..\plugins-evil\payload.txt", "owned"));
            string archive = Path.Combine(_directory, "evil.zip");
            File.WriteAllBytes(archive, zip);

            Should.Throw<ERCException>(() => PluginUpdater.ExtractSafely(archive, target));

            File.Exists(Path.Combine(_directory, "plugins-evil", "payload.txt")).ShouldBeFalse();
        }

        [Fact]
        public void Nested_entries_are_extracted_into_their_subdirectories()
        {
            byte[] zip = Zip(("Erc.Xdbg.dp64", "plugin"), ("docs/readme.txt", "hello"));
            string archive = Path.Combine(_directory, "update.zip");
            File.WriteAllBytes(archive, zip);

            PluginUpdater.ExtractSafely(archive, _directory).Count.ShouldBe(2);

            File.ReadAllText(Path.Combine(_directory, "docs", "readme.txt")).ShouldBe("hello");
        }

        // ------------------------------------------------------------------ tidying

        [Fact]
        public void Old_backups_and_archives_are_deleted()
        {
            File.WriteAllText(Path.Combine(_directory, "Erc.Xdbg.dp64-OLD_0.txt"), "x");
            File.WriteAllText(Path.Combine(_directory, "Erc.Xdbg.dp32-OLD_2.txt"), "x");
            File.WriteAllText(Path.Combine(_directory, "leftover.zip"), "x");
            File.WriteAllText(Path.Combine(_directory, "Erc.Xdbg.dp64"), "keep");

            PluginUpdater.DeleteOldPlugins(_directory).Count.ShouldBe(3);

            Directory.GetFiles(_directory).Select(Path.GetFileName)
                .ShouldBe(new[] { "Erc.Xdbg.dp64" });
        }

        [Fact]
        public void Tidying_matches_the_zip_extension_not_the_substring()
        {
            // The original tested s.Contains(".zip"), which also matched a file whose
            // name merely mentioned one.
            File.WriteAllText(Path.Combine(_directory, "notes.zip.txt"), "keep");

            PluginUpdater.DeleteOldPlugins(_directory).ShouldBeEmpty();

            File.Exists(Path.Combine(_directory, "notes.zip.txt")).ShouldBeTrue();
        }

        [Fact]
        public void Tidying_a_directory_that_does_not_exist_is_not_an_error()
        {
            PluginUpdater.DeleteOldPlugins(Path.Combine(_directory, "nope")).ShouldBeEmpty();
        }

        // -------------------------------------------------------------------- misc

        [Fact]
        public void Updating_into_a_directory_that_does_not_exist_reports_which_one()
        {
            string missing = Path.Combine(_directory, "nope");

            var error = Should.Throw<ERCException>(() =>
                PluginUpdater.Update(TransportFor(Zip(("x", "y"))), PluginUpdater.Tag64, missing));

            error.Message.ShouldContain(missing);
        }

        [Fact]
        public void The_release_urls_and_file_names_pair_up_by_tag()
        {
            PluginUpdater.ReleasesUrl(PluginUpdater.Tag32).ShouldEndWith("/32");
            PluginUpdater.ReleasesUrl(PluginUpdater.Tag64).ShouldEndWith("/64");

            PluginUpdater.PluginFileName(PluginUpdater.Tag32).ShouldBe("Erc.Xdbg.dp32");
            PluginUpdater.PluginFileName(PluginUpdater.Tag64).ShouldBe("Erc.Xdbg.dp64");
        }

        [Fact]
        public void Progress_is_reported_for_each_step()
        {
            var lines = new List<string>();

            PluginUpdater.Update(TransportFor(Zip(("Erc.Xdbg.dp64", "x"))),
                PluginUpdater.Tag64, _directory, lines.Add);

            lines.ShouldContain(l => l.Contains("verified"));
        }
    }
}
