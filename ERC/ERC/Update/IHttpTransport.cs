using System;

namespace ERC.Update
{
    /// <summary>
    /// The HTTP requests the updater makes.
    /// </summary>
    /// <remarks>
    /// A seam, so the update logic can be tested without a network. It is deliberately
    /// small: the updater fetches two strings and one file, and nothing else.
    /// </remarks>
    public interface IHttpTransport : IDisposable
    {
        /// <summary>
        /// Fetches a URL as text.
        /// </summary>
        /// <param name="url">The URL to fetch.</param>
        /// <returns>The response body.</returns>
        /// <exception cref="ERCException">The request failed.</exception>
        string GetString(string url);

        /// <summary>
        /// Downloads a URL to a file.
        /// </summary>
        /// <param name="url">The URL to fetch.</param>
        /// <param name="destinationPath">Where to write the response body.</param>
        /// <exception cref="ERCException">The request failed.</exception>
        void DownloadFile(string url, string destinationPath);
    }
}
