using System;
using System.Globalization;
using System.Linq;
using System.Text;

namespace ERC.Utilities
{
    /// <summary>
    /// Static class containing methods for common conversions.
    /// </summary>
    public static class Convert
    {
        const string HEX_CHARS = "abcdefABCDEF1234567890";

        #region Hex
        /// <summary>
        /// Converts a hex string to ASCII."
        /// </summary>
        /// <param name="hex">A string containing hex characters.</param>
        /// <returns>A string containing the equivalent ASCII values</returns>
        public static string HexToAscii(string? hex)
        {
            // Null is treated like any other unusable input. It used to be the one
            // case that threw, so a caller guarding on an empty result still crashed.
            if (hex == null)
            {
                return string.Empty;
            }

            if (hex.Length % 2 != 0)
            {
                hex = "0" + hex;
            }

            foreach (char c in hex)
            {
                if (!HEX_CHARS.Contains(c))
                {
                    return string.Empty;
                }
            }

            // No try/catch here any more. It caught every exception and reported it
            // with Console.WriteLine, which goes nowhere at all inside x64dbg, then
            // returned "" - indistinguishable from a valid conversion of empty input.
            //
            // Nothing in this loop can throw: the input has already been checked to
            // contain only hex characters and to have an even length, so Substring is
            // in range and two hex digits always convert to a value of 0 to 255.
            var ascii = new StringBuilder(hex.Length / 2);

            for (int i = 0; i < hex.Length; i += 2)
            {
                uint value = System.Convert.ToUInt32(hex.Substring(i, 2), 16);
                ascii.Append((char)value);
            }

            return ascii.ToString();
        }

        /// <summary>
        /// Converts a hex string to the equivalent bytes.
        /// </summary>
        /// <param name="hex">A string containing hex characters.</param>
        /// <returns>A byte array containing the associated values.</returns>
        public static byte[] HexToBytes(string? hex)
        {
            // Rejects the same input HexToAscii rejects, and in the same way.
            //
            // These two used to disagree: this one threw a FormatException from
            // deep inside byte.Parse, while HexToAscii returned "" for exactly the
            // same input. A caller could not handle both uniformly, and the plugin
            // surfaced a raw parse error for what is ordinary user input.
            if (hex == null)
            {
                return new byte[0];
            }

            if (hex.Length % 2 != 0)
            {
                hex = "0" + hex;
            }

            foreach (char c in hex)
            {
                if (!HEX_CHARS.Contains(c))
                {
                    return new byte[0];
                }
            }

            byte[] bytes = new byte[hex.Length / 2];
            for (int index = 0; index < bytes.Length; index++)
            {
                string byteValue = hex.Substring(index * 2, 2);
                bytes[index] = byte.Parse(byteValue, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }

            return bytes;
        }

        /// <summary>
        /// Converts a hex string to bytes, reporting whether the input was valid.
        /// </summary>
        /// <param name="hex">A string containing hex characters.</param>
        /// <param name="bytes">The converted bytes, or an empty array on failure.</param>
        /// <returns>True when the input was a valid hex string.</returns>
        /// <remarks>
        /// Use this where the difference between "empty input" and "invalid input"
        /// matters; <see cref="HexToBytes(string)"/> cannot express it.
        /// </remarks>
        public static bool TryHexToBytes(string? hex, out byte[] bytes)
        {
            bytes = new byte[0];

            if (hex == null)
            {
                return false;
            }

            if (hex.Length == 0)
            {
                return true;
            }

            string padded = hex.Length % 2 != 0 ? "0" + hex : hex;

            foreach (char c in padded)
            {
                if (!HEX_CHARS.Contains(c))
                {
                    return false;
                }
            }

            bytes = HexToBytes(padded);
            return true;
        }
        #endregion

        #region Ascii
        /// <summary>
        /// Converts an ASCII string to a byte array.
        /// </summary>
        /// <param name="ascii">An ASCII string.</param>
        /// <returns>A byte array containing the associated values.</returns>
        public static byte[] AsciiToBytes(string ascii)
        {
            return Encoding.ASCII.GetBytes(ascii);
        }

        /// <summary>
        /// Converts an ASCII string to a hex string
        /// </summary>
        /// <param name="ascii">An ASCII string.</param>
        /// <returns>A hex string.</returns>
        public static string AsciiToHex(string ascii)
        {
            return BitConverter.ToString(Encoding.ASCII.GetBytes(ascii)).Replace("-", " ");
        }
        #endregion

        #region Unicode
        /// <summary>
        /// Converts a Unicode string to a byte array.
        /// </summary>
        /// <param name="unicode">A Unicode string.</param>
        /// <returns>A byte array.</returns>
        public static byte[] UnicodeToBytes(string unicode)
        {
            return Encoding.Unicode.GetBytes(unicode);
        }

        /// <summary>
        /// Converts a Unicode string to a hex string.
        /// </summary>
        /// <param name="unicode">A Unicode string.</param>
        /// <returns>A hex string.</returns>
        public static string UnicodeToHex(string unicode)
        {
            return BitConverter.ToString(Encoding.Unicode.GetBytes(unicode)).Replace("-", " ");
        }
        #endregion

        #region UTF7
        /// <summary>
        /// Converts a UTF-7 string to a byte array.
        /// </summary>
        /// <param name="utf7">A UTF-7 string.</param>
        /// <returns>A byte array.</returns>
        public static byte[] UTF7ToBytes(string utf7)
        {
            return Encoding.UTF7.GetBytes(utf7);
        }

        /// <summary>
        /// Converts a UTF-7 string to a hex string.
        /// </summary>
        /// <param name="utf7">A UTF-7 string.</param>
        /// <returns>A hex string.</returns>
        public static string UTF7ToHex(string utf7)
        {
            return BitConverter.ToString(Encoding.UTF7.GetBytes(utf7)).Replace("-", " ");
        }
        #endregion

        #region UTF8
        /// <summary>
        /// Converts a UTF-8 string to a byte array.
        /// </summary>
        /// <param name="utf8">A UTF-8 string.</param>
        /// <returns>A byte array.</returns>
        public static byte[] UTF8ToBytes(string utf8)
        {
            return Encoding.UTF8.GetBytes(utf8);
        }

        /// <summary>
        /// Converts a UTF-8 string to a hex string.
        /// </summary>
        /// <param name="utf8">A UTF-8 string.</param>
        /// <returns>A hex string.</returns>
        public static string UTF8ToHex(string utf8)
        {
            return BitConverter.ToString(Encoding.UTF8.GetBytes(utf8)).Replace("-", " ");
        }
        #endregion

        #region UTF32
        /// <summary>
        /// Converts a UTF-32 string to a byte array.
        /// </summary>
        /// <param name="utf32">A UTF-32 string.</param>
        /// <returns>A byte array.</returns>
        public static byte[] UTF32ToBytes(string utf32)
        {
            return Encoding.UTF32.GetBytes(utf32);
        }

        /// <summary>
        /// Converts a UTF-32 string to a hex string.
        /// </summary>
        /// <param name="utf32">A UTF-32 string.</param>
        /// <returns>A hex string.</returns>
        public static string UTF32ToHex(string utf32)
        {
            return BitConverter.ToString(Encoding.UTF32.GetBytes(utf32)).Replace("-", " ");
        }
        #endregion

        #region HTML
        /// <summary>
        /// Converts the spaces in a string to Html fixed width character.
        /// </summary>
        /// <param name="str">A UTF-8 string.</param>
        /// <returns>A string with spaces converted to HTML entities.</returns>
        public static string htmlWhitespaceFix(string str)
        {
            return str.Replace(" ", "&nbsp;");
        }
        #endregion
    }
}
