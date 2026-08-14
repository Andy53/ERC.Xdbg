using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using ERC.Net.Tests.TestSupport;
using ERC.Update;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Holds the release archives to what the in-plugin updater needs from them.
    /// </summary>
    /// <remarks>
    /// "ERC --update" extracts a release archive straight into x64dbg's plugins
    /// directory, so the archive's contents are exactly what ends up installed. The
    /// two sides of that contract were written years apart and nothing checked them
    /// against each other.
    ///
    /// These tests take the archive package.ps1 actually produced and run it through
    /// the real updater, so a dependency dropped from the package, an archive layout
    /// the extractor rejects, or a hash file the parser cannot read all fail here
    /// rather than on a user's machine after they have replaced their working plugin.
    ///
    /// They skip when nothing has been packaged, so an ordinary test run does not
    /// require one; CI packages before testing.
    /// </remarks>
    public class ReleasePackageTests
    {
        /// <summary>Files a release archive must contain, and why.</summary>
        /// <remarks>Stated independently of package.ps1 so the two must agree.</remarks>
        private static readonly string[] Required =
        {
            "FASM.DLL",          // native assembler behind --assemble
            "FASMX64.DLL",       // its 64-bit half
            "FASM-LICENSE.TXT"   // the licence those two ship under
        };

        /// <summary>Build by-products that must not reach a plugins directory.</summary>
        private static readonly string[] Excluded =
        {
            "Erc.Xdbg.dll",              // the same assembly as the .dp file
            "ERC.Net.xml",               // API docs
            "Erc.Xdbg.dll.config",       // read from x64dbg.exe.config, never from here
            "Managed.x64dbg.dll.config",
            "Reloaded.Assembler.targets" // build-time MSBuild import
        };

        private static string? RepositoryRoot()
        {
            string? directory = AppContext.BaseDirectory;

            while (directory != null && !File.Exists(Path.Combine(directory, "ErcXdbgPlugin.sln")))
            {
                directory = Path.GetDirectoryName(directory.TrimEnd(Path.DirectorySeparatorChar));
            }

            return directory;
        }

        /// <summary>The packaged archive for a platform, or null when not packaged.</summary>
        private static string? Archive(string platform)
        {
            string? root = RepositoryRoot();
            if (root == null)
            {
                return null;
            }

            string path = Path.Combine(root, "artifacts", "Erc.Xdbg-" + platform + ".zip");
            return File.Exists(path) ? path : null;
        }

        private static string SkipUnlessPackaged(string platform)
        {
            string? archive = Archive(platform);

            if (archive == null)
            {
                Assert.Skip("No release archive for " + platform + ". Run package.ps1 first.");
            }

            return archive!;
        }

        private static IReadOnlyList<string> EntryNames(string archive)
        {
            using (ZipArchive zip = ZipFile.OpenRead(archive))
            {
                return zip.Entries.Select(e => e.FullName).ToList();
            }
        }

        // ------------------------------------------------------------- contents

        [Theory]
        [InlineData("x86", "Erc.Xdbg.dp32")]
        [InlineData("x64", "Erc.Xdbg.dp64")]
        public void The_archive_contains_the_plugin_for_its_architecture(string platform, string plugin)
        {
            // x64dbg selects a plugin by file extension, so shipping the wrong one
            // produces an archive that installs cleanly and then does nothing.
            EntryNames(SkipUnlessPackaged(platform)).ShouldContain(plugin);
        }

        [Theory]
        [InlineData("x86")]
        [InlineData("x64")]
        public void The_archive_contains_every_runtime_dependency(string platform)
        {
            // Costura embeds the managed dependencies into the plugin, but FASM is
            // native and has to travel beside it. Without it --assemble throws a
            // DllNotFoundException at the point of use, long after installation.
            IReadOnlyList<string> entries = EntryNames(SkipUnlessPackaged(platform));

            foreach (string required in Required)
            {
                entries.ShouldContain(required, platform + " is missing " + required);
            }
        }

        [Theory]
        [InlineData("x86")]
        [InlineData("x64")]
        public void The_archive_carries_no_build_by_products(string platform)
        {
            IReadOnlyList<string> entries = EntryNames(SkipUnlessPackaged(platform));

            foreach (string excluded in Excluded)
            {
                entries.ShouldNotContain(excluded,
                    platform + " ships " + excluded + ", which lands in the user's plugins directory");
            }
        }

        [Theory]
        [InlineData("x86")]
        [InlineData("x64")]
        public void The_archive_is_flat_and_stays_inside_the_plugins_directory(string platform)
        {
            // The updater refuses an entry that resolves outside the target directory,
            // so a nested or traversing layout would be rejected at install time.
            foreach (string entry in EntryNames(SkipUnlessPackaged(platform)))
            {
                entry.Contains("..").ShouldBeFalse(entry + " traverses out of the directory");
                entry.Contains("/").ShouldBeFalse(entry + " is nested; the archive should be flat");
                entry.Contains("\\").ShouldBeFalse(entry + " is nested; the archive should be flat");
            }
        }

        [Theory]
        [InlineData("x86", "Erc.Xdbg.dp64")]
        [InlineData("x64", "Erc.Xdbg.dp32")]
        public void The_archive_does_not_carry_the_other_architecture(string platform, string other)
        {
            // Both would install, and x64dbg would load whichever matched its own
            // build - masking a packaging mistake rather than surfacing it.
            EntryNames(SkipUnlessPackaged(platform)).ShouldNotContain(other);
        }

        // ------------------------------------------------------------ the hash

        [Theory]
        [InlineData("x86")]
        [InlineData("x64")]
        public void The_published_hash_is_readable_and_correct(string platform)
        {
            string archive = SkipUnlessPackaged(platform);
            string hashFile = archive + ".sha256";

            File.Exists(hashFile).ShouldBeTrue(
                "the updater refuses any download whose hash is not published beside it");

            // Parsed by the same code the plugin uses, so a format it cannot read
            // fails here rather than at update time.
            string published = ReleaseVerifier.ParsePublishedHash(File.ReadAllText(hashFile));

            published.ShouldBe(ReleaseVerifier.ComputeSha256(archive));
        }

        [Theory]
        [InlineData("x86")]
        [InlineData("x64")]
        public void Verification_accepts_the_packaged_archive(string platform)
        {
            string archive = SkipUnlessPackaged(platform);

            Should.NotThrow(() => ReleaseVerifier.Verify(archive, File.ReadAllText(archive + ".sha256")));
        }

        // -------------------------------------------------- the whole update flow

        [Theory]
        [InlineData("x86", "32")]
        [InlineData("x64", "64")]
        public void The_packaged_release_installs_through_the_updater(string platform, string tag)
        {
            // The end of the contract: the archive that package.ps1 produced, served
            // exactly as GitHub would serve it, installed by the code that runs inside
            // x64dbg. Nothing here is a stand-in except the network.
            string archive = SkipUnlessPackaged(platform);
            string assetUrl = "https://github.com/andy53/erc.xdbg/releases/download/" +
                              tag + "/Erc.Xdbg-" + platform + ".zip";

            var transport = new FakeHttpTransport()
                .WithString(PluginUpdater.ReleasesUrl(tag),
                    "{\"tag_name\":\"" + tag + "\",\"assets\":[{\"name\":\"Erc.Xdbg-" + platform + ".zip\"," +
                    "\"browser_download_url\":\"" + assetUrl + "\"}]}")
                .WithFile(assetUrl, File.ReadAllBytes(archive))
                .WithString(assetUrl + ".sha256", File.ReadAllText(archive + ".sha256"));

            string plugins = Path.Combine(Path.GetTempPath(), "erc-plugins-" + Path.GetRandomFileName());
            Directory.CreateDirectory(plugins);

            try
            {
                // An existing installation, so the backup path is exercised too.
                string installed = Path.Combine(plugins, PluginUpdater.PluginFileName(tag));
                File.WriteAllText(installed, "the previous plugin");

                PluginUpdater.Update(transport, tag, plugins);

                File.Exists(installed).ShouldBeTrue("the plugin should be installed");
                new FileInfo(installed).Length.ShouldBeGreaterThan(1000,
                    "the installed plugin should be the real binary, not the placeholder");

                foreach (string required in Required)
                {
                    File.Exists(Path.Combine(plugins, required))
                        .ShouldBeTrue(required + " should have been installed beside the plugin");
                }

                File.ReadAllText(Path.Combine(plugins, PluginUpdater.PluginFileName(tag) + "-OLD_0.txt"))
                    .ShouldBe("the previous plugin");

                Directory.GetFiles(plugins, "*.zip").ShouldBeEmpty("the download should be cleaned up");
            }
            finally
            {
                try { Directory.Delete(plugins, true); } catch (Exception) { }
            }
        }

        [Theory]
        [InlineData("x86", "32")]
        [InlineData("x64", "64")]
        public void The_installed_plugin_is_byte_for_byte_what_was_packaged(string platform, string tag)
        {
            string archive = SkipUnlessPackaged(platform);
            string plugins = Path.Combine(Path.GetTempPath(), "erc-plugins-" + Path.GetRandomFileName());
            Directory.CreateDirectory(plugins);

            try
            {
                PluginUpdater.ExtractSafely(archive, plugins);

                string name = PluginUpdater.PluginFileName(tag);
                string installedHash = ReleaseVerifier.ComputeSha256(Path.Combine(plugins, name));

                using (ZipArchive zip = ZipFile.OpenRead(archive))
                using (Stream entry = zip.GetEntry(name)!.Open())
                using (var buffer = new MemoryStream())
                {
                    entry.CopyTo(buffer);
                    ReleaseVerifier.ComputeSha256(buffer.ToArray()).ShouldBe(installedHash);
                }
            }
            finally
            {
                try { Directory.Delete(plugins, true); } catch (Exception) { }
            }
        }
    }
}
