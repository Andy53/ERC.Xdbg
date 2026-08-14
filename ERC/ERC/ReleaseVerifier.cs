using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ERC.Utilities
{
    /// <summary>
    /// Checks a downloaded release against the hash published alongside it.
    /// </summary>
    /// <remarks>
    /// The updater downloads a ZIP and extracts a DLL into the directory x64dbg
    /// loads plugins from, so whatever arrives is executed with the debugger's
    /// privileges. Restoring TLS validation stopped a network attacker substituting
    /// the download, but nothing confirmed the file was the one that was published.
    ///
    /// The release workflow publishes a "&lt;asset&gt;.sha256" next to each asset; the
    /// updater fetches it and calls <see cref="Verify"/> before extracting anything.
    /// </remarks>
    public static class ReleaseVerifier
    {
        /// <summary>
        /// Computes the SHA-256 of a file as a lower-case hex string.
        /// </summary>
        /// <param name="path">File to hash.</param>
        public static string ComputeSha256(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentNullException("path");
            }

            using (var sha = SHA256.Create())
            using (var stream = File.OpenRead(path))
            {
                return ToHex(sha.ComputeHash(stream));
            }
        }

        /// <summary>
        /// Computes the SHA-256 of a byte array as a lower-case hex string.
        /// </summary>
        /// <param name="content">Bytes to hash.</param>
        public static string ComputeSha256(byte[] content)
        {
            if (content == null)
            {
                throw new ArgumentNullException("content");
            }

            using (var sha = SHA256.Create())
            {
                return ToHex(sha.ComputeHash(content));
            }
        }

        /// <summary>
        /// Extracts the hash from the contents of a published .sha256 file.
        /// </summary>
        /// <param name="published">
        /// Either a bare hash, or the "&lt;hash&gt;  &lt;filename&gt;" form that
        /// sha256sum and CertUtil produce.
        /// </param>
        /// <returns>The hash in lower case.</returns>
        /// <exception cref="ERCException">No 64 character hex hash was found.</exception>
        public static string ParsePublishedHash(string? published)
        {
            if (published == null || published.Trim().Length == 0)
            {
                throw new ERCException("No hash was published for this release, so it cannot be verified.");
            }

            foreach (string token in published.Split(new[] { ' ', '\t', '\r', '\n', '*' },
                                                     StringSplitOptions.RemoveEmptyEntries))
            {
                if (IsSha256Hex(token))
                {
                    return token.ToLowerInvariant();
                }
            }

            throw new ERCException(
                "The published hash could not be read; expected a 64 character SHA-256 value.");
        }

        /// <summary>
        /// Confirms a file matches its published hash.
        /// </summary>
        /// <param name="path">The downloaded file.</param>
        /// <param name="publishedHash">Contents of the published .sha256 file.</param>
        /// <exception cref="ERCException">
        /// The file does not match, so it must not be installed.
        /// </exception>
        public static void Verify(string path, string? publishedHash)
        {
            string expected = ParsePublishedHash(publishedHash);
            string actual = ComputeSha256(path);

            if (!FixedTimeEquals(expected, actual))
            {
                throw new ERCException(
                    "The downloaded update does not match the hash published for this release. " +
                    "Expected " + expected + " but the file hashed to " + actual + ". " +
                    "The download has been discarded and nothing was installed.");
            }
        }

        private static bool IsSha256Hex(string token)
        {
            if (token == null || token.Length != 64)
            {
                return false;
            }

            foreach (char c in token)
            {
                bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!hex)
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Compares two hashes without leaking where they first differ.
        /// </summary>
        /// <remarks>
        /// Overkill for a public release hash, but comparing digests in constant time
        /// costs nothing and keeps the habit.
        /// </remarks>
        private static bool FixedTimeEquals(string a, string b)
        {
            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }

            int difference = 0;
            for (int i = 0; i < a.Length; i++)
            {
                difference |= a[i] ^ b[i];
            }

            return difference == 0;
        }

        private static string ToHex(byte[] hash)
        {
            var text = new StringBuilder(hash.Length * 2);
            foreach (byte b in hash)
            {
                text.Append(b.ToString("x2", CultureInfo.InvariantCulture));
            }

            return text.ToString();
        }
    }
}
