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
        /// <summary>The release tag, for example "64".</summary>
        [DataMember(Name = "tag_name")]
        public string? TagName { get; set; }

        /// <summary>The files published with the release.</summary>
        [DataMember(Name = "assets")]
        public List<GithubReleaseAsset>? Assets { get; set; }

        /// <summary>
        /// Reads a release from a GitHub API response.
        /// </summary>
        /// <exception cref="ERCException">The response could not be parsed.</exception>
        public static GithubRelease Parse(string? json)
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
                    // ReadObject can hand back null for input that is valid JSON but
                    // not an object, such as the literal "null".
                    var release = serialiser.ReadObject(stream) as GithubRelease;
                    if (release == null)
                    {
                        throw new ERCException(
                            "The update server response did not contain a release.");
                    }

                    return release;
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
            var matches = new List<GithubReleaseAsset>();

            if (Assets != null)
            {
                foreach (GithubReleaseAsset asset in Assets)
                {
                    string? name = asset.Name;
                    string? url = asset.BrowserDownloadUrl;

                    if (name != null && url != null && url.Length > 0 &&
                        name.EndsWith(extension, StringComparison.OrdinalIgnoreCase))
                    {
                        matches.Add(asset);
                    }
                }
            }

            if (matches.Count == 0)
            {
                throw new ERCException(
                    "The latest release contains no " + extension + " asset to download.");
            }

            // More than one candidate is refused rather than resolved by taking the
            // first. The order assets come back in is GitHub's, not ours, so picking
            // one would mean installing whichever it happened to list first.
            //
            // This is a real state to be in: a release updated in place keeps its old
            // assets unless they are explicitly removed, and the asset naming has
            // changed across releases of this plugin. Downloading the wrong one would
            // install an older build over a newer one, and it would verify correctly
            // against its own published hash while doing so.
            if (matches.Count > 1)
            {
                var names = new List<string>();
                foreach (GithubReleaseAsset asset in matches)
                {
                    names.Add(asset.Name!);
                }

                throw new ERCException(
                    "The latest release contains more than one " + extension + " asset (" +
                    string.Join(", ", names.ToArray()) + "), so it is not clear which should be " +
                    "installed. Nothing has been downloaded.");
            }

            return matches[0].BrowserDownloadUrl!;
        }
    }

    /// <summary>
    /// A downloadable file attached to a GitHub release.
    /// </summary>
    [DataContract]
    public class GithubReleaseAsset
    {
        /// <summary>The asset's file name.</summary>
        [DataMember(Name = "name")]
        public string? Name { get; set; }

        /// <summary>Where the asset can be downloaded from.</summary>
        [DataMember(Name = "browser_download_url")]
        public string? BrowserDownloadUrl { get; set; }
    }
}
