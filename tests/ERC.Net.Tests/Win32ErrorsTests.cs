using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Characterization tests for the Win32 error-code formatter used in the
    /// library's error paths.
    /// </summary>
    public class Win32ErrorsTests
    {
        [Fact]
        public void GetLastWin32Error_describes_a_known_error_code()
        {
            // 2 == ERROR_FILE_NOT_FOUND
            GetLastWin32Error(2).ShouldContain("cannot find the file");
        }

        [Fact]
        public void GetLastWin32Error_describes_access_denied()
        {
            // 5 == ERROR_ACCESS_DENIED
            GetLastWin32Error(5).ShouldContain("Access is denied");
        }

        [Fact]
        public void GetLastWin32Error_reports_failure_for_an_unknown_code()
        {
            // The formatter has no message for this, and says so rather than
            // returning null or throwing.
            GetLastWin32Error(unchecked((int)0x7FFFFFFF))
                .ShouldContain("Unable to get error code string");
        }

        [Fact]
        public void GetLastWin32Error_never_returns_null()
        {
            GetLastWin32Error(2).ShouldNotBeNull();
            GetLastWin32Error(unchecked((int)0x7FFFFFFF)).ShouldNotBeNull();
        }

        private static string GetLastWin32Error(int code)
        {
            // Trailing newlines come from FormatMessage itself.
            return Win32Errors.GetLastWin32Error(code).Trim();
        }
    }
}
