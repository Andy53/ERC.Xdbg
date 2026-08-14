using System.ComponentModel;

namespace ERC.Cli
{
    /// <summary>
    /// Character encoding a text search uses.
    /// </summary>
    /// <remarks>
    /// Named SearchEncoding rather than Encoding: the plugin previously declared an
    /// "Encoding" enum in its own namespace, which shadowed System.Text.Encoding and
    /// forced every use of the real one to be fully qualified.
    ///
    /// The numbering matches the searchType values the commands accept, so a value
    /// can be passed straight through.
    /// </remarks>
    public enum SearchEncoding
    {
        /// <summary>UTF-16.</summary>
        [Description("Unicode")]
        Unicode = 1,

        /// <summary>ASCII.</summary>
        [Description("ASCII")]
        ASCII = 2,

        /// <summary>UTF-8.</summary>
        [Description("UTF8")]
        UTF8 = 3,

        /// <summary>UTF-7.</summary>
        [Description("UTF7")]
        UTF7 = 4,

        /// <summary>UTF-32.</summary>
        [Description("UTF32")]
        UTF32 = 5
    }
}
