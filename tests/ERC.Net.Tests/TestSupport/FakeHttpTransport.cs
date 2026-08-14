using System;
using System.Collections.Generic;
using System.IO;
using ERC.Update;

namespace ERC.Net.Tests.TestSupport
{
    /// <summary>
    /// An <see cref="IHttpTransport"/> serving content held in memory.
    /// </summary>
    /// <remarks>
    /// Lets the update flow - fetch the release list, download the asset, fetch the
    /// published hash, install - run end to end in a temporary directory with no
    /// network. None of that was reachable from a test before.
    /// </remarks>
    public sealed class FakeHttpTransport : IHttpTransport
    {
        private readonly Dictionary<string, string> _strings =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        private readonly Dictionary<string, byte[]> _files =
            new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);

        /// <summary>Every URL requested, in order.</summary>
        public List<string> Requested { get; } = new List<string>();

        /// <summary>Whether Dispose has been called.</summary>
        public bool Disposed { get; private set; }

        /// <summary>Serves <paramref name="body"/> as text at <paramref name="url"/>.</summary>
        public FakeHttpTransport WithString(string url, string body)
        {
            _strings[url] = body;
            return this;
        }

        /// <summary>Serves <paramref name="content"/> as a download at <paramref name="url"/>.</summary>
        public FakeHttpTransport WithFile(string url, byte[] content)
        {
            _files[url] = content;
            return this;
        }

        public string GetString(string url)
        {
            Requested.Add(url);

            string? body;
            if (!_strings.TryGetValue(url, out body))
            {
                throw new ERCException("404 for " + url);
            }

            return body;
        }

        public void DownloadFile(string url, string destinationPath)
        {
            Requested.Add(url);

            byte[]? content;
            if (!_files.TryGetValue(url, out content))
            {
                throw new ERCException("404 for " + url);
            }

            File.WriteAllBytes(destinationPath, content);
        }

        public void Dispose()
        {
            Disposed = true;
        }
    }
}
