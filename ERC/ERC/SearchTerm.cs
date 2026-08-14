using System;
using System.Text;

namespace ERC.Utilities
{
    /// <summary>
    /// Turns a search request into the bytes to look for in memory.
    /// </summary>
    /// <remarks>
    /// The search methods accept a byte array or a string, and a type saying how to
    /// encode the string. Which of the two is required depends on the type, and
    /// getting that wrong used to fail in ways the caller never saw coming:
    ///
    /// The only guard was "both are null", so supplying bytes together with a text
    /// search type reached Encoding.Unicode.GetBytes(null) and raised an
    /// ArgumentNullException from inside the encoder. Supplying only a string with
    /// search type 0 left the byte array null and passed it straight to the memory
    /// scan.
    ///
    /// Resolving it in one place makes the requirement explicit, reportable, and
    /// testable, and removes three copies of the same switch.
    /// </remarks>
    public static class SearchTerm
    {
        /// <summary>Search for raw bytes.</summary>
        public const int Bytes = 0;
        /// <summary>Search for UTF-16 text.</summary>
        public const int Unicode = 1;
        /// <summary>Search for ASCII text.</summary>
        public const int Ascii = 2;
        /// <summary>Search for UTF-8 text.</summary>
        public const int Utf8 = 3;
        /// <summary>Search for UTF-7 text.</summary>
        public const int Utf7 = 4;
        /// <summary>Search for UTF-32 text.</summary>
        public const int Utf32 = 5;

        /// <summary>
        /// Resolves a search request to the bytes to search for.
        /// </summary>
        /// <param name="core">Used for error reporting.</param>
        /// <param name="searchType">0 for raw bytes, 1-5 for a text encoding.</param>
        /// <param name="searchBytes">The bytes to search for, required when searchType is 0.</param>
        /// <param name="searchString">The text to search for, required when searchType is 1-5.</param>
        /// <returns>
        /// A result holding the bytes to search for, or carrying an error explaining
        /// which argument was missing.
        /// </returns>
        public static ErcResult<byte[]> Resolve(ErcCore core, int searchType, byte[]? searchBytes, string? searchString)
        {
            var result = new ErcResult<byte[]>(core);

            if (searchType == Bytes)
            {
                if (searchBytes == null)
                {
                    result.Error = new ERCException(
                        "Search type 0 searches for raw bytes, so a byte array must be supplied.");
                    result.LogEvent();
                    return result;
                }

                result.ReturnValue = searchBytes;
                return result;
            }

            if (searchType < Bytes || searchType > Utf32)
            {
                // The old message said 0-4 while the switch handled 0-5.
                result.Error = new ERCException(
                    "Incorrect searchType value provided, value must be 0-5.");
                result.LogEvent();
                return result;
            }

            if (searchString == null)
            {
                result.Error = new ERCException(
                    "Search type " + searchType + " searches for text, so a search string must be supplied.");
                result.LogEvent();
                return result;
            }

            switch (searchType)
            {
                case Unicode:
                    result.ReturnValue = Encoding.Unicode.GetBytes(searchString);
                    break;
                case Ascii:
                    result.ReturnValue = Encoding.ASCII.GetBytes(searchString);
                    break;
                case Utf8:
                    result.ReturnValue = Encoding.UTF8.GetBytes(searchString);
                    break;
                case Utf7:
                    result.ReturnValue = Encoding.UTF7.GetBytes(searchString);
                    break;
                case Utf32:
                    result.ReturnValue = Encoding.UTF32.GetBytes(searchString);
                    break;
            }

            return result;
        }
    }
}
