using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.RegularExpressions;
using ERC.Utilities;

namespace ERC.Update
{
    /// <summary>
    /// Downloads, verifies and installs a new build of the plugin.
    /// </summary>
    /// <remarks>
    /// Moved out of the plugin, where it was one 170-line method holding two nearly
    /// identical copies of this logic - one for the 64-bit build and one for the
    /// 32-bit - so that a fix applied to one copy did not reach the other.
    ///
    /// Everything here is driven through <see cref="IHttpTransport"/> and a directory
    /// path, so the whole flow runs in a test against a temporary directory.
    /// </remarks>
    public static class PluginUpdater
    {
        /// <summary>
        /// GitHub release tag holding the 32-bit build.
        /// </summary>
        public const string Tag32 = "32";

        /// <summary>
        /// GitHub release tag holding the 64-bit build.
        /// </summary>
        public const string Tag64 = "64";

        /// <summary>
        /// The releases endpoint for a tag.
        /// </summary>
        /// <param name="tag">Release tag, <see cref="Tag32"/> or <see cref="Tag64"/>.</param>
        /// <returns>The API URL listing that release's assets.</returns>
        public static string ReleasesUrl(string tag)
        {
            return "https://api.github.com/repos/andy53/erc.xdbg/releases/tags/" + tag;
        }

        /// <summary>
        /// The plugin file name for a tag, as x64dbg loads it.
        /// </summary>
        /// <param name="tag">Release tag, <see cref="Tag32"/> or <see cref="Tag64"/>.</param>
        /// <returns>"Erc.Xdbg.dp32" or "Erc.Xdbg.dp64".</returns>
        public static string PluginFileName(string tag)
        {
            return tag == Tag64 ? "Erc.Xdbg.dp64" : "Erc.Xdbg.dp32";
        }

        /// <summary>
        /// Picks a backup name for the plugin currently installed, one that is not
        /// already taken.
        /// </summary>
        /// <param name="directory">The plugins directory.</param>
        /// <param name="pluginFileName">Name of the plugin being replaced.</param>
        /// <returns>The full path to move the current plugin to.</returns>
        /// <remarks>
        /// This is the second defect the duplicated code hid. The original scanned the
        /// directory for an existing backup, read a single character out of the name
        /// to recover its number, and then renamed the current plugin to that same
        /// number - so the second update always tried to move a file onto an existing
        /// one and threw, aborting the update. Reading one character also meant
        /// "-OLD_10.txt" was read as 1.
        ///
        /// Numbering upwards from the highest in use is what the original was reaching
        /// for.
        /// </remarks>
        public static string NextBackupPath(string directory, string pluginFileName)
        {
            var pattern = new Regex(
                "^" + Regex.Escape(pluginFileName) + @"-OLD_(\d+)\.txt$",
                RegexOptions.IgnoreCase);

            int highest = -1;

            foreach (string path in Directory.GetFiles(directory))
            {
                // Matched against the file name only. The original split the whole
                // path on "_", so any underscore in a parent directory name shifted
                // which segment it read.
                Match match = pattern.Match(Path.GetFileName(path));

                int number;
                if (match.Success &&
                    int.TryParse(match.Groups[1].Value, NumberStyles.Integer,
                                 CultureInfo.InvariantCulture, out number) &&
                    number > highest)
                {
                    highest = number;
                }
            }

            return Path.Combine(directory, pluginFileName + "-OLD_" + (highest + 1).ToString(CultureInfo.InvariantCulture) + ".txt");
        }

        /// <summary>
        /// Extracts an archive into a directory, refusing entries that would be
        /// written outside it.
        /// </summary>
        /// <param name="archivePath">The archive to extract.</param>
        /// <param name="destinationDirectory">Where its entries should land.</param>
        /// <returns>The full paths written.</returns>
        /// <exception cref="ERCException">An entry pointed outside the directory.</exception>
        /// <remarks>
        /// The code this replaces computed the full destination path and left a comment
        /// explaining that a malicious archive could otherwise escape the directory -
        /// but never compared the result against the directory, so the check the
        /// comment described was not actually performed. An entry named
        /// "..\..\evil.dll" was written wherever it pointed.
        ///
        /// The trailing separator matters: without it "C:\plugins" is a prefix of
        /// "C:\plugins-evil", so a StartsWith test would pass for a path outside the
        /// directory.
        /// </remarks>
        public static IReadOnlyList<string> ExtractSafely(string archivePath, string destinationDirectory)
        {
            string root = Path.GetFullPath(destinationDirectory);

            if (!root.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal))
            {
                root += Path.DirectorySeparatorChar;
            }

            var written = new List<string>();

            using (ZipArchive archive = ZipFile.OpenRead(archivePath))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    // Directory entries have an empty name and no content.
                    if (string.IsNullOrEmpty(entry.Name))
                    {
                        continue;
                    }

                    string destination = Path.GetFullPath(Path.Combine(root, entry.FullName));

                    if (!destination.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new ERCException(
                            "The update archive contains an entry that would be written outside the " +
                            "plugins directory (" + entry.FullName + "). It has not been installed.");
                    }

                    string? parent = Path.GetDirectoryName(destination);
                    if (!string.IsNullOrEmpty(parent) && !Directory.Exists(parent))
                    {
                        Directory.CreateDirectory(parent!);
                    }

                    entry.ExtractToFile(destination, true);
                    written.Add(destination);
                }
            }

            return written;
        }

        /// <summary>
        /// Confirms a downloaded file matches the hash published beside it.
        /// </summary>
        /// <param name="transport">Used to fetch the published hash.</param>
        /// <param name="assetUrl">URL the file was downloaded from.</param>
        /// <param name="downloadedPath">The downloaded file.</param>
        /// <exception cref="ERCException">
        /// No hash was published, or the file does not match it. The download is
        /// deleted in both cases.
        /// </exception>
        /// <remarks>
        /// The extracted DLL is loaded by x64dbg, so an unverified download is code
        /// execution. TLS stops the file being swapped in transit; this stops a file
        /// that was never the published one being installed at all.
        /// </remarks>
        public static void VerifyDownload(IHttpTransport transport, string assetUrl, string downloadedPath)
        {
            string publishedHash;

            try
            {
                publishedHash = transport.GetString(assetUrl + ".sha256");
            }
            catch (Exception e)
            {
                Delete(downloadedPath);
                throw new ERCException(
                    "No published hash was found for this release (" + assetUrl + ".sha256), so the " +
                    "download could not be verified and has been discarded.", e);
            }

            try
            {
                ReleaseVerifier.Verify(downloadedPath, publishedHash);
            }
            catch
            {
                Delete(downloadedPath);
                throw;
            }
        }

        /// <summary>
        /// Downloads, verifies and installs the build published under a tag.
        /// </summary>
        /// <param name="transport">How to reach GitHub.</param>
        /// <param name="tag">Release tag, <see cref="Tag32"/> or <see cref="Tag64"/>.</param>
        /// <param name="pluginsDirectory">Directory x64dbg loads plugins from.</param>
        /// <param name="progress">Called with a line of progress, or null for none.</param>
        /// <returns>The full paths written into the plugins directory.</returns>
        /// <exception cref="ERCException">The update could not be completed.</exception>
        public static IReadOnlyList<string> Update(
            IHttpTransport transport,
            string tag,
            string pluginsDirectory,
            Action<string>? progress = null)
        {
            if (transport == null)
            {
                throw new ArgumentNullException(nameof(transport));
            }

            if (!Directory.Exists(pluginsDirectory))
            {
                throw new ERCException("The plugins directory does not exist: " + pluginsDirectory);
            }

            Action<string> report = progress ?? (_ => { });

            string releases = transport.GetString(ReleasesUrl(tag));

            // Parsed properly rather than by splitting the raw JSON on commas, which
            // picked up the wrong URL whenever a release name or body contained one.
            string assetUrl = GithubRelease.Parse(releases).DownloadUrlFor(".zip");

            string assetName = assetUrl.Split('/').Last();
            string archivePath = Path.Combine(pluginsDirectory, assetName);

            report("Downloading " + assetName + ".");
            transport.DownloadFile(assetUrl, archivePath);

            VerifyDownload(transport, assetUrl, archivePath);
            report("Update verified against the published SHA-256.");

            try
            {
                string pluginFileName = PluginFileName(tag);
                string installed = Path.Combine(pluginsDirectory, pluginFileName);

                if (File.Exists(installed))
                {
                    // Renamed rather than deleted, because x64dbg has the current
                    // plugin loaded and cannot replace it in place.
                    string backup = NextBackupPath(pluginsDirectory, pluginFileName);
                    File.Move(installed, backup);
                    report("Existing plugin moved to " + Path.GetFileName(backup) + ".");
                }

                IReadOnlyList<string> written = ExtractSafely(archivePath, pluginsDirectory);
                report("Installed " + written.Count + " file(s).");
                return written;
            }
            finally
            {
                Delete(archivePath);
            }
        }

        /// <summary>
        /// Removes the backups and archives left by previous updates.
        /// </summary>
        /// <param name="pluginsDirectory">Directory x64dbg loads plugins from.</param>
        /// <returns>The paths that were deleted.</returns>
        public static IReadOnlyList<string> DeleteOldPlugins(string pluginsDirectory)
        {
            var deleted = new List<string>();

            if (!Directory.Exists(pluginsDirectory))
            {
                return deleted;
            }

            foreach (string path in Directory.GetFiles(pluginsDirectory))
            {
                string name = Path.GetFileName(path);

                bool isBackup = name.IndexOf("Erc.Xdbg.dp64-OLD", StringComparison.OrdinalIgnoreCase) >= 0
                             || name.IndexOf("Erc.Xdbg.dp32-OLD", StringComparison.OrdinalIgnoreCase) >= 0;

                // Matched on the extension rather than "contains .zip", which also
                // matched a file called "notes.zip.txt".
                bool isArchive = name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase);

                if ((isBackup || isArchive) && Delete(path))
                {
                    deleted.Add(path);
                }
            }

            return deleted;
        }

        /// <summary>
        /// Deletes a file, reporting whether it went, and never throwing.
        /// </summary>
        private static bool Delete(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                    return true;
                }
            }
            catch (Exception)
            {
                // A locked leftover is not worth failing an update over.
            }

            return false;
        }
    }
}
