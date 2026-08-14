using System;
using System.Text;
using ERC;
using ERC.Config;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Tests for resolving a search request into the bytes to look for.
    /// </summary>
    /// <remarks>
    /// This rule used to be inlined three times in the search methods, and got the
    /// argument requirements wrong in both directions.
    /// </remarks>
    public class SearchTermTests
    {
        private static ErcCore Core()
        {
            return new ErcCore(new InMemoryConfigStore(), new InMemoryErcLogger());
        }

        // ------------------------------------------------- the defects

        [Theory]
        [InlineData(SearchTerm.Unicode)]
        [InlineData(SearchTerm.Ascii)]
        [InlineData(SearchTerm.Utf8)]
        [InlineData(SearchTerm.Utf7)]
        [InlineData(SearchTerm.Utf32)]
        public void A_text_search_without_a_string_is_reported_not_crashed(int searchType)
        {
            // The old guard only rejected the case where *both* arguments were
            // missing, so supplying bytes together with a text search type reached
            // Encoding.Unicode.GetBytes(null) and raised an ArgumentNullException
            // from inside the encoder, with nothing to say what the caller did wrong.
            ErcResult<byte[]> result = SearchTerm.Resolve(
                Core(), searchType, new byte[] { 0x41 }, null);

            result.Error.ShouldNotBeNull();
            result.Error.Message.ShouldContain("search string must be supplied");
        }

        [Fact]
        public void A_byte_search_without_bytes_is_reported_not_passed_on()
        {
            // The mirror image: search type 0 with only a string left the byte array
            // null and handed it straight to the memory scan.
            ErcResult<byte[]> result = SearchTerm.Resolve(Core(), SearchTerm.Bytes, null, "hello");

            result.Error.ShouldNotBeNull();
            result.Error.Message.ShouldContain("byte array must be supplied");
        }

        [Fact]
        public void The_range_in_the_error_message_matches_the_types_accepted()
        {
            // The message said 0-4 while the switch handled 0-5.
            ErcResult<byte[]> result = SearchTerm.Resolve(Core(), 9, null, "hello");

            result.Error.ShouldNotBeNull();
            result.Error.Message.ShouldContain("0-5");
        }

        // ------------------------------------------------- the encodings

        [Fact]
        public void Raw_bytes_are_passed_through_unchanged()
        {
            byte[] wanted = { 0xFF, 0xE4 };

            ErcResult<byte[]> result = SearchTerm.Resolve(Core(), SearchTerm.Bytes, wanted, null);

            result.Error.ShouldBeNull();
            result.ReturnValue.ShouldBe(wanted);
        }

        [Theory]
        [InlineData(SearchTerm.Unicode)]
        [InlineData(SearchTerm.Ascii)]
        [InlineData(SearchTerm.Utf8)]
        [InlineData(SearchTerm.Utf7)]
        [InlineData(SearchTerm.Utf32)]
        public void Each_text_type_encodes_the_way_Convert_does(int searchType)
        {
            // Keeps the search encodings and the "--convert" command in step; a user
            // who converts a string then searches for those bytes should find it.
            ErcResult<byte[]> result = SearchTerm.Resolve(Core(), searchType, null, "A");

            result.Error.ShouldBeNull();

            byte[] expected =
                searchType == SearchTerm.Unicode ? Encoding.Unicode.GetBytes("A") :
                searchType == SearchTerm.Ascii   ? Encoding.ASCII.GetBytes("A") :
                searchType == SearchTerm.Utf8    ? Encoding.UTF8.GetBytes("A") :
                searchType == SearchTerm.Utf7    ? Encoding.UTF7.GetBytes("A") :
                                                   Encoding.UTF32.GetBytes("A");

            result.ReturnValue.ShouldBe(expected);
        }

        [Fact]
        public void Unicode_text_encodes_to_utf16()
        {
            SearchTerm.Resolve(Core(), SearchTerm.Unicode, null, "A")
                      .ReturnValue.ShouldBe(new byte[] { 0x41, 0x00 });
        }

        [Fact]
        public void Bytes_take_precedence_over_a_string_for_a_byte_search()
        {
            byte[] wanted = { 0x90 };

            SearchTerm.Resolve(Core(), SearchTerm.Bytes, wanted, "ignored")
                      .ReturnValue.ShouldBe(wanted);
        }

        [Theory]
        [InlineData(-1)]
        [InlineData(6)]
        [InlineData(99)]
        public void An_unknown_search_type_is_refused(int searchType)
        {
            SearchTerm.Resolve(Core(), searchType, new byte[] { 0x41 }, "hello")
                      .Error.ShouldNotBeNull();
        }
    }
}
