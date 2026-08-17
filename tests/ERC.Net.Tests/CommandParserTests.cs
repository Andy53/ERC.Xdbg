using System;
using System.Collections.Generic;
using System.Linq;
using ERC.Cli;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers the command line the plugin documents.
    /// </summary>
    /// <remarks>
    /// Argument handling used to live inside the x64dbg command handler, mixed with
    /// static field mutation, disk access and calls into a live process, so none of
    /// it could be tested. Once it was a function of its input these became possible.
    ///
    /// The cases below are the examples printed by --help. They are the plugin's own
    /// statement of what it accepts, so a change that breaks one is a change to the
    /// documented interface.
    /// </remarks>
    public class CommandParserTests
    {
        /// <summary>
        /// Every option --help lists. If an option appears here it must parse; if it
        /// parses it must be dispatchable, which the test below this one checks.
        /// </summary>
        public static readonly string[] DocumentedOptions =
        {
            "--help", "--update", "--config", "--pattern", "--bytearray", "--compare",
            "--convert", "--assemble", "--disassemble", "--searchmemory", "--searchmodules",
            "--dump", "--listprocesses", "--processinfo", "--moduleinfo", "--threadinfo",
            "--seh", "--egghunters", "--findnrp", "--heapinfo", "--rop", "--ropgadgets",
            "--reset", "--jmp", "--sehchain", "--ropfunc", "--gadget", "--stackpivot"
        };

        public static TheoryData<string> AllDocumentedOptions()
        {
            var data = new TheoryData<string>();
            foreach (string option in DocumentedOptions)
            {
                data.Add(option);
            }

            return data;
        }

        [Theory]
        [MemberData(nameof(AllDocumentedOptions))]
        public void Every_documented_option_parses(string option)
        {
            ErcCommand parsed = CommandParser.Parse("ERC " + option, new SessionState());

            parsed.IsValid.ShouldBeTrue(parsed.Error);
            parsed.Option.ShouldBe(option);
        }

        [Theory]
        [MemberData(nameof(AllDocumentedOptions))]
        public void Options_are_case_insensitive(string option)
        {
            // --help prints them capitalised ("--SearchMemory") but the dispatcher
            // switches on lower case, so the parser has to normalise.
            string typed = "--" + option.Substring(2, 1).ToUpperInvariant() + option.Substring(3);

            ErcCommand parsed = CommandParser.Parse("ERC " + typed, new SessionState());

            parsed.Option.ShouldBe(option);
        }

        // ------------------------------------------------------------- the examples

        [Fact]
        public void Example_search_memory_for_bytes()
        {
            // ERC --SearchMemory FF E4
            ErcCommand parsed = CommandParser.Parse("ERC --SearchMemory FF E4", new SessionState());

            parsed.IsValid.ShouldBeTrue(parsed.Error);
            parsed.Option.ShouldBe("--searchmemory");
            parsed.Arguments.ShouldBe(new[] { "FF", "E4" });
        }

        [Fact]
        public void Example_search_memory_for_a_string()
        {
            // ERC --SearchMemory HelloWorld 1
            ErcCommand parsed = CommandParser.Parse("ERC --SearchMemory HelloWorld 1", new SessionState());

            parsed.Arguments.ShouldBe(new[] { "HelloWorld", "1" });
        }

        [Fact]
        public void Example_search_modules_scoped_to_named_modules()
        {
            // ERC --SearchModules FF E4 module1.dll module2.dll
            ErcCommand parsed = CommandParser.Parse(
                "ERC --SearchModules FF E4 module1.dll module2.dll", new SessionState());

            parsed.Arguments.ShouldBe(new[] { "FF", "E4", "module1.dll", "module2.dll" });
        }

        [Fact]
        public void Example_heap_info_statistics()
        {
            // ERC --HeapInfo stats
            ErcCommand parsed = CommandParser.Parse("ERC --HeapInfo stats", new SessionState());

            parsed.Option.ShouldBe("--heapinfo");
            parsed.Arguments.ShouldBe(new[] { "stats" });
        }

        [Fact]
        public void Example_heap_info_search_within_an_entry()
        {
            // ERC --HeapInfo 0x00453563 search FFE4
            ErcCommand parsed = CommandParser.Parse("ERC --HeapInfo 0x00453563 search FFE4", new SessionState());

            parsed.Arguments.ShouldBe(new[] { "0x00453563", "search", "FFE4" });
        }

        [Fact]
        public void Example_heap_info_dump_an_entry()
        {
            // ERC --HeapInfo 0x00453563 dump
            ErcCommand parsed = CommandParser.Parse("ERC --HeapInfo 0x00453563 dump", new SessionState());

            parsed.Arguments.ShouldBe(new[] { "0x00453563", "dump" });
        }

        [Fact]
        public void Example_pattern_create()
        {
            ErcCommand parsed = CommandParser.Parse("ERC --pattern c 1000", new SessionState());

            parsed.Option.ShouldBe("--pattern");
            parsed.Arguments.ShouldBe(new[] { "c", "1000" });
        }

        [Fact]
        public void Example_convert()
        {
            ErcCommand parsed = CommandParser.Parse("ERC --convert 7 A%$3", new SessionState());

            parsed.Arguments.ShouldBe(new[] { "7", "A%$3" });
        }

        // -------------------------------------------------------------- the line itself

        [Fact]
        public void The_leading_command_name_is_dropped()
        {
            // x64dbg passes the whole line, including the word that selected the plugin.
            CommandParser.Parse("ERC --help", new SessionState()).Option.ShouldBe("--help");
            CommandParser.Parse("erc --help", new SessionState()).Option.ShouldBe("--help");
        }

        [Fact]
        public void A_line_without_the_command_name_still_parses()
        {
            CommandParser.Parse("--help", new SessionState()).Option.ShouldBe("--help");
        }

        [Fact]
        public void Runs_of_whitespace_do_not_produce_empty_arguments()
        {
            // The routine this replaces used Split(' '), so "ERC  --pattern  c  1000"
            // produced empty strings that the handlers then indexed into.
            ErcCommand parsed = CommandParser.Parse("ERC   --pattern    c   1000", new SessionState());

            parsed.Arguments.ShouldBe(new[] { "c", "1000" });
        }

        [Fact]
        public void Tabs_separate_arguments_too()
        {
            ErcCommand parsed = CommandParser.Parse("ERC\t--pattern\tc\t1000", new SessionState());

            parsed.Arguments.ShouldBe(new[] { "c", "1000" });
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("ERC")]
        public void An_empty_line_is_rejected_rather_than_throwing(string? line)
        {
            ErcCommand parsed = CommandParser.Parse(line, new SessionState());

            parsed.IsValid.ShouldBeFalse();
            parsed.Error.ShouldNotBeNull();
        }

        [Fact]
        public void Two_options_are_rejected_and_both_are_named()
        {
            ErcCommand parsed = CommandParser.Parse("ERC --pattern --compare", new SessionState());

            parsed.IsValid.ShouldBeFalse();
            parsed.Error!.ShouldContain("--pattern");
            parsed.Error!.ShouldContain("--compare");
        }

        [Fact]
        public void An_unknown_option_parses_and_is_rejected_by_the_dispatcher()
        {
            // The parser's job is the shape of the line, not the set of valid options;
            // the dispatcher's default case reports those. Keeping the split here means
            // an option can be added in one place.
            ErcCommand parsed = CommandParser.Parse("ERC --nosuchoption", new SessionState());

            parsed.IsValid.ShouldBeTrue();
            parsed.Option.ShouldBe("--nosuchoption");
        }

        // ------------------------------------------------------------ global switches

        [Fact]
        public void A_bare_global_switch_turns_the_setting_on()
        {
            ErcCommand parsed = CommandParser.Parse("ERC --moduleinfo -aslr", new SessionState());

            parsed.Session.Aslr.ShouldBeTrue();
            parsed.Arguments.ShouldBeEmpty();
        }

        [Theory]
        [InlineData("-aslr")]
        [InlineData("-safeseh")]
        [InlineData("-rebase")]
        [InlineData("-nxcompat")]
        [InlineData("-osdll")]
        [InlineData("-extended")]
        public void Every_boolean_switch_accepts_an_explicit_value(string @switch)
        {
            ErcCommand on = CommandParser.Parse("ERC --moduleinfo " + @switch + " true", new SessionState());
            ErcCommand off = CommandParser.Parse("ERC --moduleinfo " + @switch + " false", new SessionState());

            Read(on.Session, @switch).ShouldBeTrue();
            Read(off.Session, @switch).ShouldBeFalse();

            // Consumed, so they never reach the handler as arguments.
            on.Arguments.ShouldBeEmpty();
            off.Arguments.ShouldBeEmpty();
        }

        private static bool Read(SessionState state, string @switch)
        {
            switch (@switch)
            {
                case "-aslr": return state.Aslr;
                case "-safeseh": return state.SafeSeh;
                case "-rebase": return state.Rebase;
                case "-nxcompat": return state.NxCompat;
                case "-osdll": return state.OsDll;
                case "-extended": return state.Extended;
                default: throw new ArgumentOutOfRangeException(nameof(@switch), @switch, null);
            }
        }

        [Fact]
        public void Global_switches_are_removed_from_the_arguments()
        {
            // This is the point of parsing them first: --searchmemory reads its
            // arguments positionally, so a switch left in the list would be taken
            // as a search term.
            ErcCommand parsed = CommandParser.Parse(
                "ERC --searchmemory -aslr FF E4 -osdll", new SessionState());

            parsed.Arguments.ShouldBe(new[] { "FF", "E4" });
            parsed.Session.Aslr.ShouldBeTrue();
            parsed.Session.OsDll.ShouldBeTrue();
        }

        [Fact]
        public void A_switch_before_the_option_is_still_applied()
        {
            ErcCommand parsed = CommandParser.Parse("ERC -aslr --moduleinfo", new SessionState());

            parsed.Option.ShouldBe("--moduleinfo");
            parsed.Session.Aslr.ShouldBeTrue();
        }

        [Fact]
        public void Adjacent_switches_are_all_applied()
        {
            // The scan removes tokens as it goes, so it has to step back correctly -
            // the same forward-loop-with-removal mistake that was fixed in the ROP
            // gadget filter would silently skip every second switch here.
            ErcCommand parsed = CommandParser.Parse(
                "ERC --moduleinfo -aslr -safeseh -rebase -nxcompat -osdll -extended",
                new SessionState());

            parsed.Session.Aslr.ShouldBeTrue();
            parsed.Session.SafeSeh.ShouldBeTrue();
            parsed.Session.Rebase.ShouldBeTrue();
            parsed.Session.NxCompat.ShouldBeTrue();
            parsed.Session.OsDll.ShouldBeTrue();
            parsed.Session.Extended.ShouldBeTrue();
        }

        [Fact]
        public void The_supplied_session_is_not_modified()
        {
            // Parsing must be free of side effects, so that a rejected line cannot
            // leave half its switches applied.
            var session = new SessionState();

            CommandParser.Parse("ERC --moduleinfo -aslr -osdll", session);

            session.Aslr.ShouldBeFalse();
            session.OsDll.ShouldBeFalse();
        }

        [Fact]
        public void Settings_carry_forward_from_the_supplied_session()
        {
            var session = new SessionState { Aslr = true };

            ErcCommand parsed = CommandParser.Parse("ERC --moduleinfo -osdll", session);

            parsed.Session.Aslr.ShouldBeTrue();
            parsed.Session.OsDll.ShouldBeTrue();
        }

        [Fact]
        public void A_rejected_line_carries_no_applied_switches_to_the_caller()
        {
            var session = new SessionState();

            ErcCommand parsed = CommandParser.Parse("ERC --pattern --compare -aslr", session);

            parsed.IsValid.ShouldBeFalse();
            session.Aslr.ShouldBeFalse();
        }

        // ------------------------------------------------------------------ encodings

        [Theory]
        [InlineData("-ascii", SearchEncoding.ASCII)]
        [InlineData("-unicode", SearchEncoding.Unicode)]
        [InlineData("-utf7", SearchEncoding.UTF7)]
        [InlineData("-utf8", SearchEncoding.UTF8)]
        [InlineData("-utf32", SearchEncoding.UTF32)]
        public void An_encoding_switch_selects_that_encoding(string @switch, SearchEncoding expected)
        {
            ErcCommand parsed = CommandParser.Parse("ERC --searchmemory " + @switch + " hello", new SessionState());

            parsed.Session.Encode.ShouldBe(expected);
            parsed.Arguments.ShouldBe(new[] { "hello" });
        }

        [Fact]
        public void The_last_encoding_switch_wins()
        {
            ErcCommand parsed = CommandParser.Parse("ERC --searchmemory -ascii -utf8 hello", new SessionState());

            parsed.Session.Encode.ShouldBe(SearchEncoding.UTF8);
        }

        [Fact]
        public void Encoding_values_match_the_search_type_numbers_the_library_uses()
        {
            // The enum is passed straight to ProcessInfo.SearchMemory as searchType,
            // so the two numberings have to agree. SearchTerm.Bytes is 0 and has no
            // switch, since bytes are the default.
            ((int)SearchEncoding.Unicode).ShouldBe(ERC.Utilities.SearchTerm.Unicode);
            ((int)SearchEncoding.ASCII).ShouldBe(ERC.Utilities.SearchTerm.Ascii);
            ((int)SearchEncoding.UTF8).ShouldBe(ERC.Utilities.SearchTerm.Utf8);
            ((int)SearchEncoding.UTF7).ShouldBe(ERC.Utilities.SearchTerm.Utf7);
            ((int)SearchEncoding.UTF32).ShouldBe(ERC.Utilities.SearchTerm.Utf32);
        }

        // ---------------------------------------------------------------------- bytes

        [Theory]
        [InlineData("0x0A0x0D")]
        [InlineData("0A0D")]
        [InlineData("\\x0A\\x0D")]
        public void The_documented_byte_forms_all_parse(string text)
        {
            CommandParser.ParseByteList(text).ShouldBe(new byte[] { 0x0A, 0x0D });
        }

        [Fact]
        public void Byte_parsing_is_case_insensitive()
        {
            CommandParser.ParseByteList("ffe4").ShouldBe(new byte[] { 0xFF, 0xE4 });
            CommandParser.ParseByteList("FFE4").ShouldBe(new byte[] { 0xFF, 0xE4 });
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("0")]        // odd length
        [InlineData("0A0")]      // odd length
        [InlineData("ZZ")]       // not hex
        [InlineData("0xZZ")]
        public void Malformed_byte_lists_are_rejected(string? text)
        {
            CommandParser.ParseByteList(text).ShouldBeNull();
        }

        [Fact]
        public void A_bad_bytes_switch_rejects_the_line_and_names_the_value()
        {
            ErcCommand parsed = CommandParser.Parse("ERC --searchmemory -bytes ZZ", new SessionState());

            parsed.IsValid.ShouldBeFalse();
            parsed.Error!.ShouldContain("ZZ");
        }

        [Fact]
        public void The_bytes_switch_takes_its_value_and_removes_both_tokens()
        {
            ErcCommand parsed = CommandParser.Parse("ERC --searchmemory -bytes 0x000x0A FF E4", new SessionState());

            parsed.Session.Bytes.ShouldBe(new byte[] { 0x00, 0x0A });
            parsed.Arguments.ShouldBe(new[] { "FF", "E4" });
        }

        [Fact]
        public void A_bare_bytes_switch_clears_the_restriction()
        {
            var session = new SessionState { Bytes = new byte[] { 0x00 } };

            ErcCommand parsed = CommandParser.Parse("ERC --searchmemory -bytes", session);

            parsed.IsValid.ShouldBeTrue(parsed.Error);
            parsed.Session.Bytes.ShouldBeEmpty();
        }

        [Fact]
        public void A_bytes_switch_followed_by_another_switch_does_not_swallow_it()
        {
            ErcCommand parsed = CommandParser.Parse("ERC --searchmemory -bytes -aslr", new SessionState());

            parsed.IsValid.ShouldBeTrue(parsed.Error);
            parsed.Session.Bytes.ShouldBeEmpty();
            parsed.Session.Aslr.ShouldBeTrue();
        }

        // ----------------------------------------------------------------- protection

        [Theory]
        [InlineData("read")]
        [InlineData("write")]
        [InlineData("exec")]
        [InlineData("all")]
        [InlineData("read,write")]
        [InlineData("read,write,exec")]
        public void The_documented_protection_values_are_accepted(string protection)
        {
            ErcCommand parsed = CommandParser.Parse("ERC --searchmemory -protection " + protection, new SessionState());

            parsed.IsValid.ShouldBeTrue(parsed.Error);
            parsed.Session.Protection.ShouldBe(protection);
        }

        [Fact]
        public void Protection_is_lower_cased_so_the_library_comparison_matches()
        {
            ErcCommand parsed = CommandParser.Parse("ERC --searchmemory -protection READ,Write", new SessionState());

            parsed.Session.Protection.ShouldBe("read,write");
        }

        [Fact]
        public void Protection_values_must_not_be_separated_by_spaces()
        {
            // --help says "comma separated and without spaces". A space ends the
            // value, so the rest becomes a command argument rather than a filter -
            // which is worth pinning, because it fails quietly.
            ErcCommand parsed = CommandParser.Parse("ERC --searchmemory -protection read write", new SessionState());

            parsed.IsValid.ShouldBeTrue(parsed.Error);
            parsed.Session.Protection.ShouldBe("read");
            parsed.Arguments.ShouldBe(new[] { "write" });
        }

        [Theory]
        [InlineData("execute")]
        [InlineData("read,")]
        [InlineData("rwx")]
        public void An_invalid_protection_value_rejects_the_line(string protection)
        {
            ErcCommand parsed = CommandParser.Parse("ERC --searchmemory -protection " + protection, new SessionState());

            parsed.IsValid.ShouldBeFalse();
            parsed.Error!.ShouldContain("read");
        }

        [Fact]
        public void A_protection_switch_with_no_value_rejects_the_line()
        {
            ErcCommand parsed = CommandParser.Parse("ERC --searchmemory -protection", new SessionState());

            parsed.IsValid.ShouldBeFalse();
        }

        // -------------------------------------------------------------- session state

        [Fact]
        public void A_new_session_has_every_filter_off()
        {
            // These defaults decide what a plain "ERC --moduleinfo" shows, so they are
            // part of the interface rather than an implementation detail.
            var session = new SessionState();

            session.Aslr.ShouldBeFalse();
            session.SafeSeh.ShouldBeFalse();
            session.Rebase.ShouldBeFalse();
            session.NxCompat.ShouldBeFalse();
            session.OsDll.ShouldBeFalse();
            session.Extended.ShouldBeFalse();
            session.Bytes.ShouldBeEmpty();
            session.Encode.ShouldBe(SearchEncoding.ASCII);
            session.Protection.ShouldBe("read,write");
        }

        [Fact]
        public void Reset_restores_the_defaults()
        {
            // --reset promises to clear "all global variables", so every field has to
            // be covered; comparing against a fresh instance means a field added later
            // cannot be forgotten here.
            var session = new SessionState
            {
                Aslr = true,
                SafeSeh = true,
                Rebase = true,
                NxCompat = true,
                OsDll = true,
                Extended = true,
                Encode = SearchEncoding.UTF32,
                Bytes = new byte[] { 0x00 },
                Protection = "all"
            };

            session.Reset();

            var fresh = new SessionState();
            foreach (var property in typeof(SessionState).GetProperties())
            {
                object? actual = property.GetValue(session);
                object? expected = property.GetValue(fresh);

                if (actual is byte[] actualBytes)
                {
                    actualBytes.ShouldBe((byte[])expected!, property.Name);
                }
                else
                {
                    actual.ShouldBe(expected, property.Name);
                }
            }
        }

        [Fact]
        public void A_clone_shares_nothing_with_its_source()
        {
            // Parse() clones, so a mutable array leaking through would let a rejected
            // command still change the session.
            var session = new SessionState { Bytes = new byte[] { 0x00, 0x0A } };

            SessionState clone = session.Clone();
            clone.Bytes[0] = 0xFF;
            clone.Aslr = true;

            session.Bytes[0].ShouldBe((byte)0x00);
            session.Aslr.ShouldBeFalse();
        }

        [Fact]
        public void A_clone_copies_every_property()
        {
            var session = new SessionState
            {
                Aslr = true,
                SafeSeh = true,
                Rebase = true,
                NxCompat = true,
                OsDll = true,
                Extended = true,
                Encode = SearchEncoding.UTF7,
                Bytes = new byte[] { 0x0D },
                Protection = "read,write"
            };

            SessionState clone = session.Clone();

            foreach (var property in typeof(SessionState).GetProperties())
            {
                object? original = property.GetValue(session);
                object? copied = property.GetValue(clone);

                if (original is byte[] originalBytes)
                {
                    ((byte[])copied!).ShouldBe(originalBytes, property.Name);
                }
                else
                {
                    copied.ShouldBe(original, property.Name);
                }
            }
        }
    }
}
