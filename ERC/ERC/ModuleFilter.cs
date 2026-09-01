using System;
using System.Collections.Generic;
using System.IO;

namespace ERC.Utilities
{
    /// <summary>
    /// Whether a module is in the set the user asked to search, mona's <c>-m</c>.
    /// </summary>
    /// <remarks>
    /// The global ASLR/SafeSEH/CFG switches drop modules that have a property. They
    /// cannot say "only kernel32". <c>-m</c> can, and when it is set those switches
    /// are ignored for the same reason they are in mona: the user has already named
    /// the modules they want.
    ///
    /// Patterns are comma-separated. <c>*</c> means every module. <c>*blah.dll</c>
    /// matches a suffix, <c>blah*</c> a prefix, anything else a substring of the
    /// module name or file name. Comparison is case-insensitive.
    /// </remarks>
    public static class ModuleFilter
    {
        /// <summary>True when the list is empty, meaning "no include filter".</summary>
        public static bool IsUnrestricted(IReadOnlyList<string>? patterns)
        {
            return patterns == null || patterns.Count == 0;
        }

        /// <summary>True when the list is exactly <c>*</c>, meaning every module.</summary>
        public static bool IsAll(IReadOnlyList<string>? patterns)
        {
            if (patterns == null || patterns.Count != 1)
            {
                return false;
            }

            return patterns[0] == "*";
        }

        /// <summary>
        /// Splits a <c>-m</c> value into patterns. Empty or whitespace is no filter.
        /// </summary>
        public static string[] Parse(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return new string[0];
            }

            string[] parts = value!.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < parts.Length; i++)
            {
                parts[i] = parts[i].Trim();
            }

            return parts;
        }

        /// <summary>
        /// Whether this module is one of the named patterns.
        /// </summary>
        public static bool Matches(string name, string path, IReadOnlyList<string>? patterns)
        {
            if (IsUnrestricted(patterns) || IsAll(patterns))
            {
                return true;
            }

            string file = string.IsNullOrEmpty(path) ? string.Empty : Path.GetFileName(path);

            foreach (string pattern in patterns!)
            {
                if (string.IsNullOrEmpty(pattern))
                {
                    continue;
                }

                if (MatchesOne(name, pattern) || MatchesOne(file, pattern) || MatchesOne(path, pattern))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Whether the module should be searched, combining <c>-m</c> with the
        /// exclude list built from the other globals.
        /// </summary>
        public static bool Keep(
            string name, string path,
            IReadOnlyList<string>? includes,
            IReadOnlyList<string>? excludes)
        {
            if (!IsUnrestricted(includes) && !IsAll(includes) && !Matches(name, path, includes))
            {
                return false;
            }

            if (excludes == null || excludes.Count == 0)
            {
                return true;
            }

            foreach (string exclude in excludes)
            {
                if (path.Equals(exclude, StringComparison.OrdinalIgnoreCase) ||
                    name.Equals(exclude, StringComparison.OrdinalIgnoreCase) ||
                    fileNameEquals(path, exclude))
                {
                    return false;
                }
            }

            return true;
        }

        private static bool fileNameEquals(string path, string exclude)
        {
            if (string.IsNullOrEmpty(path))
            {
                return false;
            }

            return Path.GetFileName(path).Equals(exclude, StringComparison.OrdinalIgnoreCase);
        }

        private static bool MatchesOne(string value, string pattern)
        {
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            if (pattern == "*")
            {
                return true;
            }

            bool starStart = pattern[0] == '*';
            bool starEnd = pattern[pattern.Length - 1] == '*';
            string body = pattern.Trim('*');

            if (starStart && starEnd)
            {
                return value.IndexOf(body, StringComparison.OrdinalIgnoreCase) >= 0;
            }

            if (starStart)
            {
                return value.EndsWith(body, StringComparison.OrdinalIgnoreCase);
            }

            if (starEnd)
            {
                return value.StartsWith(body, StringComparison.OrdinalIgnoreCase);
            }

            return value.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0;
        }
    }
}
