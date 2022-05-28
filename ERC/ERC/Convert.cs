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
        public static string HexToAscii(string hex)
        {
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

            try
            {
                string ascii = string.Empty;

                for (int i = 0; i < hex.Length; i += 2)
                {
                    String hs = string.Empty;

                    hs = hex.Substring(i, 2);
                    uint decval = System.Convert.ToUInt32(hs, 16);
                    char character = System.Convert.ToChar(decval);
                    ascii += character;

                }

                return ascii;
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }

            return string.Empty;
        }

        /// <summary>
        /// Converts a hex string to the equivalent bytes.
        /// </summary>
        /// <param name="hex">A string containing hex characters.</param>
        /// <returns>A byte array containing the associated values.</returns>
        public static byte[] HexToBytes(string hex)
        {
            if (hex.Length % 2 != 0)
            {
                hex = "0" + hex;
            }

            byte[] bytes = new byte[hex.Length / 2];
            for (int index = 0; index < bytes.Length; index++)
            {
                string byteValue = hex.Substring(index * 2, 2);
                bytes[index] = byte.Parse(byteValue, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }

            return bytes;
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
