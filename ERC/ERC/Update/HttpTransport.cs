using System;
using System.IO;
using System.Net;
using System.Net.Http;

namespace ERC.Update
{
    /// <summary>
    /// An <see cref="IHttpTransport"/> backed by <see cref="HttpClient"/>.
    /// </summary>
    /// <remarks>
    /// Replaces WebClient, which has been obsolete since .NET 6 and which the update
    /// command used in a way that leaked its state between requests: the same client
    /// had its Accept and User-Agent headers added twice on a 64-bit machine, once per
    /// architecture, and WebHeaderCollection.Add appends rather than replaces, so the
    /// second pass sent each header value twice.
    ///
    /// One HttpClient is created per updater and disposed with it. That is the
    /// documented usage; creating one per request exhausts sockets.
    /// </remarks>
    public sealed class HttpTransport : IHttpTransport
    {
        private readonly HttpClient _client;
        private bool _disposed;

        /// <summary>
        /// Creates a transport, optionally routed through a proxy.
        /// </summary>
        /// <param name="proxy">Proxy to route through, or null for a direct connection.</param>
        public HttpTransport(IWebProxy? proxy = null)
        {
            // Certificate validation is deliberately left alone.
            //
            // The update command used to add a callback returning true for every
            // certificate, which disabled TLS validation for the whole x64dbg process
            // - and because it used "+=" on a global static, permanently, for every
            // other component too. On a path that downloads a DLL and installs it
            // where the debugger will load it, that turned anyone on the network into
            // code execution. If a proxy needs to be trusted, install its CA
            // certificate.
            ServicePointManager.SecurityProtocol =
                SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11;

            var handler = new HttpClientHandler();

            if (proxy != null)
            {
                handler.Proxy = proxy;
                handler.UseProxy = true;
            }

            _client = new HttpClient(handler);

            // GitHub rejects requests with no User-Agent.
            _client.DefaultRequestHeaders.Add("User-Agent", "ERC-Plugin");
            _client.DefaultRequestHeaders.Add("Accept", "application/vnd.github+json");
            _client.Timeout = TimeSpan.FromMinutes(5);
        }

        /// <inheritdoc/>
        public string GetString(string url)
        {
            try
            {
                // .Result rather than await: the command runs on x64dbg's command
                // thread, which has no synchronisation context, and the surrounding
                // plugin API is synchronous. GetAwaiter().GetResult() rethrows the
                // original exception instead of an AggregateException.
                HttpResponseMessage response = _client.GetAsync(url).GetAwaiter().GetResult();
                response.EnsureSuccessStatusCode();
                return response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            }
            catch (Exception e)
            {
                throw new ERCException("Could not fetch " + url + ": " + e.Message, e);
            }
        }

        /// <inheritdoc/>
        public void DownloadFile(string url, string destinationPath)
        {
            try
            {
                HttpResponseMessage response = _client.GetAsync(url).GetAwaiter().GetResult();
                response.EnsureSuccessStatusCode();

                using (Stream source = response.Content.ReadAsStreamAsync().GetAwaiter().GetResult())
                using (var target = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    source.CopyTo(target);
                }
            }
            catch (Exception e)
            {
                // A partial file is worse than none: the caller would hash it and
                // report a mismatch rather than a failed download.
                try
                {
                    if (File.Exists(destinationPath))
                    {
                        File.Delete(destinationPath);
                    }
                }
                catch (Exception)
                {
                }

                throw new ERCException("Could not download " + url + ": " + e.Message, e);
            }
        }

        /// <summary>
        /// Disposes the underlying client.
        /// </summary>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _client.Dispose();
        }
    }
}
