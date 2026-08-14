using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using ERC.Cli;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Holds the help text and the command surface to each other.
    /// </summary>
    /// <remarks>
    /// The help text was previously built by string concatenation inside the plugin,
    /// unreachable from a test, so nothing stopped it drifting from what the plugin
    /// accepted. It now lives in the library and these tests compare the two.
    /// </remarks>
    public class CommandHelpTests
    {
        /// <summary>Options as the help text lists them, for example "--SearchMemory".</summary>
        private static IReadOnlyList<string> DocumentedInHelp()
        {
            // Options are introduced by an indented entry ending in a column bar:
            //     "   --SearchMemory  |"
            return Regex.Matches(CommandHelp.Text, @"^   (--[A-Za-z0-9]+)\s*\|", RegexOptions.Multiline)
                .Cast<Match>()
                .Select(m => m.Groups[1].Value.ToLowerInvariant())
                .ToList();
        }

        /// <summary>Global switches as the help text lists them.</summary>
        private static IReadOnlyList<string> SwitchesDocumentedInHelp()
        {
            return Regex.Matches(CommandHelp.Text, @"^   (-[A-Za-z0-9]+)\s*\|", RegexOptions.Multiline)
                .Cast<Match>()
                .Select(m => m.Groups[1].Value.ToLowerInvariant())
                .Where(s => !s.StartsWith("--", StringComparison.Ordinal))
                .ToList();
        }

        [Fact]
        public void The_help_text_documents_every_option_the_tests_cover()
        {
            DocumentedInHelp().ShouldBe(CommandParserTests.DocumentedOptions, ignoreOrder: true);
        }

        [Fact]
        public void Every_option_the_help_text_lists_parses()
        {
            foreach (string option in DocumentedInHelp())
            {
                ErcCommand parsed = CommandParser.Parse("ERC " + option, new SessionState());

                parsed.IsValid.ShouldBeTrue(option + ": " + parsed.Error);
                parsed.Option.ShouldBe(option);
            }
        }

        [Fact]
        public void Every_global_switch_the_help_text_lists_is_consumed_by_the_parser()
        {
            // A switch the parser does not recognise is not merely ignored: it stays in
            // the token list and is handed to the command as a positional argument, so
            // "ERC --searchmemory -nosuchswitch FF E4" would search for "-nosuchswitch".
            foreach (string @switch in SwitchesDocumentedInHelp())
            {
                string line = "ERC --searchmemory " + @switch +
                              (@switch == "-protection" ? " read" : @switch == "-bytes" ? " 00" : string.Empty);

                ErcCommand parsed = CommandParser.Parse(line, new SessionState());

                parsed.IsValid.ShouldBeTrue(@switch + ": " + parsed.Error);
                parsed.Arguments.ShouldNotContain(@switch, @switch + " was left in the arguments");
            }
        }

        [Fact]
        public void The_help_text_lists_the_switches_the_parser_implements()
        {
            SwitchesDocumentedInHelp().ShouldBe(
                new[]
                {
                    "-aslr", "-safeseh", "-rebase", "-nxcompat", "-osdll",
                    "-bytes", "-protection", "-unicode", "-ascii", "-utf7", "-utf8", "-utf32",
                    "-extended"
                },
                ignoreOrder: true);
        }

        [Fact]
        public void Every_example_in_the_help_text_parses()
        {
            // The examples are written as prose - "Example: ERC --HeapInfo stats. Display
            // statistics..." - so the command is the text up to the sentence that explains
            // it. Taking everything up to the first ". " recovers it.
            var examples = Regex.Matches(CommandHelp.Text, @"Example: (ERC .+)$", RegexOptions.Multiline)
                .Cast<Match>()
                .Select(m => m.Groups[1].Value.Trim())
                .Select(line => line.Split(new[] { ". " }, StringSplitOptions.None)[0].TrimEnd('.', ' '))
                .ToList();

            examples.ShouldNotBeEmpty();

            foreach (string example in examples)
            {
                ErcCommand parsed = CommandParser.Parse(example, new SessionState());

                parsed.IsValid.ShouldBeTrue(example + ": " + parsed.Error);
                CommandParserTests.DocumentedOptions.ShouldContain(parsed.Option, example);
            }
        }

        [Fact]
        public void The_help_text_survived_being_moved_out_of_the_plugin()
        {
            // It was assembled by concatenating 130 string literals with embedded
            // escapes. These are spot checks that the escapes came through as text
            // rather than as their two-character source form.
            CommandHelp.Text.ShouldContain("Globals:");
            CommandHelp.Text.ShouldContain("Clears all global variables and user defined configurations.");
            CommandHelp.Text.ShouldContain("passing \"false\"");
            CommandHelp.Text.ShouldNotContain("\\n");
            CommandHelp.Text.ShouldNotContain("\\\"");

            CommandHelp.Banner.Split('\n').Length.ShouldBe(6);
        }

        [Fact]
        public void The_help_text_has_no_trailing_whitespace_on_the_option_lines()
        {
            // Cosmetic, but it is the kind of thing that is invisible in source and
            // obvious in a terminal.
            string[] lines = CommandHelp.Text.Split('\n');

            lines.Where(l => l.TrimStart().StartsWith("-", StringComparison.Ordinal))
                 .Where(l => l != l.TrimEnd())
                 .ShouldBeEmpty();
        }
    }
}
