using System;
using System.Collections.Generic;

namespace ERC.Utilities
{
    /// <summary>
    /// The shape a pointer's bytes must have to appear in search results.
    /// </summary>
    /// <remarks>
    /// These are mona's <c>-cp</c> criteria. They describe the pointer as it would
    /// be written into the exploit, little-endian, which is what a restricted
    /// character set actually sees. Several can be combined; they are ANDed, except
    /// that unicode (or unicoderev) with another criterion applies the other only
    /// to the non-null bytes.
    /// </remarks>
    [Flags]
    public enum PointerCriteria
    {
        /// <summary>No extra restriction.</summary>
        None = 0,
        /// <summary>No byte of the pointer is 0x00.</summary>
        NoNull = 1 << 0,
        /// <summary>
        /// The most significant byte is 0x00, so the address is in the low 24 bits
        /// (32-bit) or has a leading 00 when printed. Written little-endian the
        /// null lands last, which is the string-terminator-after-the-pointer case.
        /// </summary>
        StartsWithNull = 1 << 1,
        /// <summary>Every byte is a tab, CR, LF, or 0x20-0x7E.</summary>
        Ascii = 1 << 2,
        /// <summary>Every byte is 0x20-0x7E.</summary>
        AsciiPrint = 1 << 3,
        /// <summary>Every byte is A-Z.</summary>
        Upper = 1 << 4,
        /// <summary>Every byte is a-z.</summary>
        Lower = 1 << 5,
        /// <summary>Every byte is A-Z or 0-9.</summary>
        UpperNum = 1 << 6,
        /// <summary>Every byte is a-z or 0-9.</summary>
        LowerNum = 1 << 7,
        /// <summary>Every byte is 0-9.</summary>
        Numeric = 1 << 8,
        /// <summary>Every byte is A-Z, a-z or 0-9.</summary>
        AlphaNum = 1 << 9,
        /// <summary>
        /// Alternate bytes are 0x00 starting at the second byte in memory
        /// (XX 00 XX 00). A UTF-16-expanded ASCII overflow produces this.
        /// </summary>
        Unicode = 1 << 10,
        /// <summary>Alternate bytes are 0x00 starting at the first byte (00 XX 00 XX).</summary>
        UnicodeRev = 1 << 11
    }

    /// <summary>
    /// Parses and applies <see cref="PointerCriteria"/> to addresses.
    /// </summary>
    public static class PointerShape
    {
        /// <summary>The names <see cref="TryParse"/> accepts, in help-text order.</summary>
        public static readonly string[] Names =
        {
            "nonull", "startswithnull", "ascii", "asciiprint",
            "upper", "lower", "uppernum", "lowernum", "numeric", "alphanum",
            "unicode", "unicoderev"
        };

        /// <summary>
        /// Parses a comma-separated list of criterion names.
        /// </summary>
        /// <param name="text">The value supplied to -cp. Empty or null means none.</param>
        /// <param name="criteria">The parsed flags, or None on failure.</param>
        /// <param name="error">Why parsing failed, or null.</param>
        /// <returns>True when every name was recognised.</returns>
        public static bool TryParse(string? text, out PointerCriteria criteria, out string? error)
        {
            criteria = PointerCriteria.None;
            error = null;

            if (string.IsNullOrWhiteSpace(text))
            {
                return true;
            }

            foreach (string part in text!.Split(new[] { ',' }, StringSplitOptions.None))
            {
                string name = part.Trim().ToLowerInvariant();
                if (name.Length == 0)
                {
                    error = "A -cp value cannot contain an empty name. Use comma-separated names without spaces: " +
                            string.Join(", ", Names) + ".";
                    criteria = PointerCriteria.None;
                    return false;
                }

                PointerCriteria flag;
                if (!TryOne(name, out flag))
                {
                    error = "\"" + part.Trim() + "\" is not a pointer-shape criterion. Use: " +
                            string.Join(", ", Names) + ".";
                    criteria = PointerCriteria.None;
                    return false;
                }

                criteria |= flag;
            }

            return true;
        }

        /// <summary>
        /// The names of the set flags, comma-separated, or empty when none.
        /// </summary>
        public static string Format(PointerCriteria criteria)
        {
            if (criteria == PointerCriteria.None)
            {
                return string.Empty;
            }

            var parts = new List<string>();
            foreach (string name in Names)
            {
                PointerCriteria flag;
                TryOne(name, out flag);
                if ((criteria & flag) != 0)
                {
                    parts.Add(name);
                }
            }

            return string.Join(",", parts.ToArray());
        }

        /// <summary>
        /// Whether the pointer's bytes, as they would appear in the target, satisfy
        /// every flag in <paramref name="criteria"/>.
        /// </summary>
        public static bool Matches(IntPtr pointer, MachineType machineType, PointerCriteria criteria)
        {
            if (criteria == PointerCriteria.None)
            {
                return true;
            }

            byte[] bytes = ToBytes(pointer, Width(machineType));
            byte[] tested = bytes;

            bool unicode = (criteria & PointerCriteria.Unicode) != 0;
            bool unicodeRev = (criteria & PointerCriteria.UnicodeRev) != 0;

            if (unicode && !IsAlternatingNull(bytes, startAt: 1))
            {
                return false;
            }

            if (unicodeRev && !IsAlternatingNull(bytes, startAt: 0))
            {
                return false;
            }

            // Unicode plus another criterion: the 0x00s are an artefact of UTF-16
            // expansion, so the other test runs against the non-null bytes only.
            PointerCriteria rest = criteria & ~(PointerCriteria.Unicode | PointerCriteria.UnicodeRev);
            if ((unicode || unicodeRev) && rest != PointerCriteria.None)
            {
                tested = NonNull(bytes);
                if (tested.Length == 0)
                {
                    return false;
                }
            }

            if ((criteria & PointerCriteria.NoNull) != 0 && Contains(bytes, 0x00))
            {
                return false;
            }

            if ((criteria & PointerCriteria.StartsWithNull) != 0 && bytes[bytes.Length - 1] != 0x00)
            {
                return false;
            }

            if ((rest & PointerCriteria.Ascii) != 0 && !All(tested, IsAscii))
            {
                return false;
            }

            if ((rest & PointerCriteria.AsciiPrint) != 0 && !All(tested, IsAsciiPrint))
            {
                return false;
            }

            if ((rest & PointerCriteria.Upper) != 0 && !All(tested, IsUpper))
            {
                return false;
            }

            if ((rest & PointerCriteria.Lower) != 0 && !All(tested, IsLower))
            {
                return false;
            }

            if ((rest & PointerCriteria.UpperNum) != 0 && !All(tested, b => IsUpper(b) || IsDigit(b)))
            {
                return false;
            }

            if ((rest & PointerCriteria.LowerNum) != 0 && !All(tested, b => IsLower(b) || IsDigit(b)))
            {
                return false;
            }

            if ((rest & PointerCriteria.Numeric) != 0 && !All(tested, IsDigit))
            {
                return false;
            }

            if ((rest & PointerCriteria.AlphaNum) != 0 && !All(tested, b => IsUpper(b) || IsLower(b) || IsDigit(b)))
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Keeps the pointers whose bytes satisfy <paramref name="criteria"/>.
        /// </summary>
        public static Dictionary<IntPtr, string> Filter(
            MachineType machineType, Dictionary<IntPtr, string>? source, PointerCriteria criteria)
        {
            if (source == null)
            {
                return new Dictionary<IntPtr, string>();
            }

            if (criteria == PointerCriteria.None)
            {
                return source;
            }

            var kept = new Dictionary<IntPtr, string>(source.Count);
            foreach (KeyValuePair<IntPtr, string> entry in source)
            {
                if (Matches(entry.Key, machineType, criteria))
                {
                    kept.Add(entry.Key, entry.Value);
                }
            }

            return kept;
        }

        /// <summary>
        /// Keeps the pointers whose bytes satisfy <paramref name="criteria"/>.
        /// </summary>
        public static List<IntPtr> Filter(
            MachineType machineType, List<IntPtr>? source, PointerCriteria criteria)
        {
            if (source == null)
            {
                return new List<IntPtr>();
            }

            if (criteria == PointerCriteria.None)
            {
                return source;
            }

            var kept = new List<IntPtr>(source.Count);
            foreach (IntPtr pointer in source)
            {
                if (Matches(pointer, machineType, criteria))
                {
                    kept.Add(pointer);
                }
            }

            return kept;
        }

        private static bool TryOne(string name, out PointerCriteria flag)
        {
            switch (name)
            {
                case "nonull": flag = PointerCriteria.NoNull; return true;
                case "startswithnull": flag = PointerCriteria.StartsWithNull; return true;
                case "ascii": flag = PointerCriteria.Ascii; return true;
                case "asciiprint": flag = PointerCriteria.AsciiPrint; return true;
                case "upper": flag = PointerCriteria.Upper; return true;
                case "lower": flag = PointerCriteria.Lower; return true;
                case "uppernum": flag = PointerCriteria.UpperNum; return true;
                case "lowernum": flag = PointerCriteria.LowerNum; return true;
                case "numeric": flag = PointerCriteria.Numeric; return true;
                case "alphanum": flag = PointerCriteria.AlphaNum; return true;
                case "unicode": flag = PointerCriteria.Unicode; return true;
                case "unicoderev": flag = PointerCriteria.UnicodeRev; return true;
                default: flag = PointerCriteria.None; return false;
            }
        }

        private static int Width(MachineType machineType)
        {
            return machineType == MachineType.x64 ? 8 : 4;
        }

        private static byte[] ToBytes(IntPtr pointer, int width)
        {
            long value = pointer.ToInt64();
            var bytes = new byte[width];
            for (int i = 0; i < width; i++)
            {
                bytes[i] = (byte)(value >> (i * 8));
            }

            return bytes;
        }

        private static bool IsAlternatingNull(byte[] bytes, int startAt)
        {
            if (bytes.Length < 2)
            {
                return false;
            }

            for (int i = startAt; i < bytes.Length; i += 2)
            {
                if (bytes[i] != 0x00)
                {
                    return false;
                }
            }

            return true;
        }

        private static byte[] NonNull(byte[] bytes)
        {
            var kept = new List<byte>(bytes.Length);
            for (int i = 0; i < bytes.Length; i++)
            {
                if (bytes[i] != 0x00)
                {
                    kept.Add(bytes[i]);
                }
            }

            return kept.ToArray();
        }

        private static bool Contains(byte[] bytes, byte value)
        {
            for (int i = 0; i < bytes.Length; i++)
            {
                if (bytes[i] == value)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool All(byte[] bytes, Func<byte, bool> test)
        {
            for (int i = 0; i < bytes.Length; i++)
            {
                if (!test(bytes[i]))
                {
                    return false;
                }
            }

            return true;
        }

        private static bool IsAscii(byte b)
        {
            return b == 0x09 || b == 0x0A || b == 0x0D || (b >= 0x20 && b <= 0x7E);
        }

        private static bool IsAsciiPrint(byte b)
        {
            return b >= 0x20 && b <= 0x7E;
        }

        private static bool IsUpper(byte b)
        {
            return b >= 0x41 && b <= 0x5A;
        }

        private static bool IsLower(byte b)
        {
            return b >= 0x61 && b <= 0x7A;
        }

        private static bool IsDigit(byte b)
        {
            return b >= 0x30 && b <= 0x39;
        }
    }
}
