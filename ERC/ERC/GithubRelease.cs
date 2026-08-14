using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace ERC.Utilities
{
    /// <summary>
    /// The part of a GitHub release response the updater needs.
    /// </summary>
    /// <remarks>
    /// Parsed with DataContractJsonSerializer, which ships in the box, so this adds
    /// no dependency to the plugin.
    ///
    /// It lives in the library rather than in the plugin so it can be tested: the
    /// plugin assembly is a native-export DLL that the test project cannot reference.
    ///
    /// The previous code split the raw response on commas and took
    /// <c>s.Split('"')[3]</c> from whichever fragment contained
    /// "browser_download_url". A comma anywhere earlier in the JSON - in a release
    /// name or body, which are free text - shifted the fragments and produced either
    /// a wrong URL or an empty one, and the plugin would then download and install
    /// whatever that pointed at.
    /// </remarks>
    [DataContract]
    public class GithubRelease
    {
        [DataMember(Name = "tag_name")]
        public string TagName { get; set; }

        [DataMember(Name = "assets")]
        public List<GithubReleaseAsset> Assets { get; set; }

        /// <summary>
        /// Reads a release from a GitHub API response.
        /// </summary>
        /// <exception cref="ERCException">The response could not be parsed.</exception>
        public static GithubRelease Parse(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                throw new ERCException("The update server returned an empty response.");
            }

            try
            {
                var serialiser = new DataContractJsonSerializer(typeof(GithubRelease));
                using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(json)))
                {
                    return (GithubRelease)serialiser.ReadObject(stream);
                }
            }
            catch (SerializationException e)
            {
                throw new ERCException(
                    "The update server response could not be understood: " + e.Message);
            }
        }

        /// <summary>
        /// The download URL of the single asset whose name ends with the extension.
        /// </summary>
        /// <param name="extension">For example ".zip".</param>
        /// <exception cref="ERCException">
        /// No asset matched, so there is nothing safe to download.
        /// </exception>
        public string DownloadUrlFor(string extension)
        {
            if (Assets != null)
            {
                foreach (GithubReleaseAsset asset in Assets)
                {
                    if (!string.IsNullOrEmpty(asset.Name) &&
                        asset.Name.EndsWith(extension, StringComparison.OrdinalIgnoreCase) &&
                        !string.IsNullOrEmpty(asset.BrowserDownloadUrl))
                    {
                        return asset.BrowserDownloadUrl;
                    }
                }
            }

            throw new ERCException(
                "The latest release contains no " + extension + " asset to download.");
        }
    }

    /// <summary>
    /// A downloadable file attached to a GitHub release.
    /// </summary>
    [DataContract]
    public class GithubReleaseAsset
    {
        [DataMember(Name = "name")]
        public string Name { get; set; }

        [DataMember(Name = "browser_download_url")]
        public string BrowserDownloadUrl { get; set; }
    }
}
