using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace ERC.Cli
{
    /// <summary>
    /// A parsed ERC command line.
    /// </summary>
    public sealed class ErcCommand
    {
        internal ErcCommand(string option, IReadOnlyList<string> arguments, SessionState session, string? error)
        {
            Option = option;
            Arguments = arguments;
            Session = session;
            Error = error;
        }

        /// <summary>
        /// The option that was requested, lower-cased and including the leading
        /// dashes, for example "--pattern". Empty when parsing failed.
        /// </summary>
        public string Option { get; }

        /// <summary>
        /// What followed the option, with the global switches removed.
        /// </summary>
        public IReadOnlyList<string> Arguments { get; }

        /// <summary>
        /// Session settings after applying any global switches on this line.
        /// </summary>
        public SessionState Session { get; }

        /// <summary>
        /// Why the line could not be understood, or null when it was.
        /// </summary>
        public string? Error { get; }

        /// <summary>Whether the line parsed.</summary>
        public bool IsValid { get { return Error == null; } }
    }

    /// <summary>
    /// Turns the text a user types into a command and a set of session settings.
    /// </summary>
    /// <remarks>
    /// Split out from the command handler so that argument handling can be tested
    /// without a debugger, a target process or the filesystem. It reads nothing and
    /// writes nothing; every result is returned.
    ///
    /// The behaviour it reproduces was previously spread through a 300-line routine
    /// that mutated static fields as a side effect of scanning the argument list.
    /// </remarks>
    public static class CommandParser
    {
        /// <summary>
        /// Global switches that stand alone or take an optional true/false.
        /// </summary>
        private static readonly string[] BooleanSwitches =
        {
            "-aslr", "-safeseh", "-rebase", "-nxcompat", "-osdll", "-extended"
        };

        /// <summary>
        /// Global switches that select a character encoding.
        /// </summary>
        private static readonly Dictionary<string, SearchEncoding> EncodingSwitches =
            new Dictionary<string, SearchEncoding>(StringComparer.OrdinalIgnoreCase)
            {
                { "-ascii", SearchEncoding.ASCII },
                { "-unicode", SearchEncoding.Unicode },
                { "-utf7", SearchEncoding.UTF7 },
                { "-utf8", SearchEncoding.UTF8 },
                { "-utf32", SearchEncoding.UTF32 }
            };

        /// <summary>
        /// Parses a command line, applying any global switches to a copy of the
        /// session state.
        /// </summary>
        /// <param name="commandLine">The whole line, including the leading "ERC".</param>
        /// <param name="session">Current session settings; not modified.</param>
        /// <returns>The command, or one carrying an explanation of what was wrong.</returns>
        public static ErcCommand Parse(string? commandLine, SessionState? session)
        {
            SessionState state = session == null ? new SessionState() : session.Clone();

            var tokens = new List<string>(
                (commandLine ?? string.Empty).Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries));

            // The first token is the command name x64dbg matched ("ERC").
            if (tokens.Count > 0 && !tokens[0].StartsWith("-", StringComparison.Ordinal))
            {
                tokens.RemoveAt(0);
            }

            string? error = ApplyGlobals(tokens, state);
            if (error != null)
            {
                return new ErcCommand(string.Empty, new string[0], state, error);
            }

            List<string> options = tokens
                .Where(t => t.StartsWith("--", StringComparison.Ordinal))
                .ToList();

            if (options.Count == 0)
            {
                return new ErcCommand(string.Empty, new string[0], state,
                    "No option was provided. Options start with -- , for example \"ERC --help\".");
            }

            if (options.Count > 1)
            {
                return new ErcCommand(string.Empty, new string[0], state,
                    "One option and its parameters must be executed at a time (options start with --). " +
                    "Found: " + string.Join(", ", options.ToArray()));
            }

            string option = options[0].ToLowerInvariant();
            int index = tokens.FindIndex(t => t.StartsWith("--", StringComparison.Ordinal));

            // Everything after the option is its arguments. Anything before it is not
            // a global - those have already been removed - so it is not usable input.
            List<string> arguments = tokens.Skip(index + 1).ToList();

            return new ErcCommand(option, arguments, state, null);
        }

        /// <summary>
        /// Removes the global switches from the token list and applies them.
        /// </summary>
        /// <returns>An explanation when a switch was malformed, otherwise null.</returns>
        private static string? ApplyGlobals(List<string> tokens, SessionState state)
        {
            for (int i = 0; i < tokens.Count; i++)
            {
                string token = tokens[i].ToLowerInvariant();

                if (BooleanSwitches.Contains(token))
                {
                    // "-aslr" turns it on; "-aslr false" turns it off. Anything else
                    // following the switch belongs to the command.
                    bool value = true;
                    int consumed = 1;

                    if (i + 1 < tokens.Count)
                    {
                        string next = tokens[i + 1].ToLowerInvariant();
                        if (next == "true" || next == "false")
                        {
                            value = next == "true";
                            consumed = 2;
                        }
                    }

                    Set(state, token, value);
                    tokens.RemoveRange(i, consumed);
                    i--;
                    continue;
                }

                if (EncodingSwitches.ContainsKey(token))
                {
                    state.Encode = EncodingSwitches[token];
                    tokens.RemoveAt(i);
                    i--;
                    continue;
                }

                if (token == "-bytes")
                {
                    // "-bytes" on its own clears the restriction; otherwise the next
                    // token is a run of hex, optionally with 0x or \x separators.
                    if (i + 1 < tokens.Count && !tokens[i + 1].StartsWith("-", StringComparison.Ordinal))
                    {
                        byte[]? bytes = ParseByteList(tokens[i + 1]);
                        if (bytes == null)
                        {
                            return "The value supplied to -bytes is not a valid list of hex bytes: " + tokens[i + 1];
                        }

                        state.Bytes = bytes;
                        tokens.RemoveRange(i, 2);
                    }
                    else
                    {
                        state.Bytes = new byte[0];
                        tokens.RemoveAt(i);
                    }

                    i--;
                    continue;
                }

                if (token == "-protection")
                {
                    if (i + 1 >= tokens.Count)
                    {
                        return "-protection requires a value: read, write, exec or all, comma separated.";
                    }

                    string protection = tokens[i + 1].ToLowerInvariant();
                    if (!IsValidProtection(protection))
                    {
                        return "The value supplied to -protection is not valid: " + tokens[i + 1] +
                               ". Use read, write, exec or all, comma separated and without spaces.";
                    }

                    state.Protection = protection;
                    tokens.RemoveRange(i, 2);
                    i--;
                    continue;
                }
            }

            return null;
        }

        private static void Set(SessionState state, string token, bool value)
        {
            switch (token)
            {
                case "-aslr": state.Aslr = value; break;
                case "-safeseh": state.SafeSeh = value; break;
                case "-rebase": state.Rebase = value; break;
                case "-nxcompat": state.NxCompat = value; break;
                case "-osdll": state.OsDll = value; break;
                case "-extended": state.Extended = value; break;
            }
        }

        private static bool IsValidProtection(string protection)
        {
            foreach (string part in protection.Split(','))
            {
                if (part != "read" && part != "write" && part != "exec" && part != "all")
                {
                    return false;
                }
            }

            return protection.Length > 0;
        }

        /// <summary>
        /// Reads a run of hex bytes, accepting the forms the documentation shows:
        /// "0x0A0x0D", "740D" and "\x0b".
        /// </summary>
        /// <returns>The bytes, or null when the text is not a valid list.</returns>
        public static byte[]? ParseByteList(string? text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return null;
            }

            string cleaned = text!
                .Replace("0x", string.Empty)
                .Replace("0X", string.Empty)
                .Replace("\\x", string.Empty)
                .Replace("\\X", string.Empty);

            if (cleaned.Length == 0 || cleaned.Length % 2 != 0)
            {
                return null;
            }

            var bytes = new byte[cleaned.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                if (!byte.TryParse(cleaned.Substring(i * 2, 2), NumberStyles.HexNumber,
                                   CultureInfo.InvariantCulture, out bytes[i]))
                {
                    return null;
                }
            }

            return bytes;
        }
    }
}
