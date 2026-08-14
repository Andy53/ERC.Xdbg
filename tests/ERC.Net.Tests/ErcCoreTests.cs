using System;
using System.IO;
using ERC;
using ERC.Net.Tests.TestSupport;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Characterization tests for ErcCore, the object every other part of the
    /// library hangs off. Most of what is pinned here is what Phase 02 unpicks.
    /// </summary>
    [Collection(ErcCoreCollection.Name)]
    public class ErcCoreTests
    {
        private readonly ErcCore _core;

        public ErcCoreTests(ErcCoreFixture fixture)
        {
            _core = fixture.Core;
        }

        [Fact]
        public void ErcVersion_reports_the_architecture_of_the_running_process()
        {
            // Derived at run time now rather than by hand-editing the source per
            // build, so the banner is correct in both a 32- and 64-bit debugger.
            string expectedArchitecture = IntPtr.Size == 8 ? "64" : "32";

            _core.ErcVersion.ShouldStartWith("ERC.Xdbg_" + expectedArchitecture + "-");
        }

        [Fact]
        public void ErcVersion_carries_a_version_number()
        {
            string version = _core.ErcVersion.Split('-')[1];

            version.ShouldNotBeNullOrWhiteSpace();
            version.ShouldContain(".");
        }

        [Fact]
        public void WorkingDirectory_is_an_existing_directory_with_a_trailing_separator()
        {
            Directory.Exists(_core.WorkingDirectory).ShouldBeTrue();
            _core.WorkingDirectory.ShouldEndWith("\\");
        }

        [Fact]
        public void Pattern_files_are_generated_on_first_use()
        {
            // Was a pinned defect: the constructor generated ~87 KB of pattern files
            // and wrote a config next to the assembly, so the type could not be used
            // in a read-only directory or tested in isolation. Generation is now
            // deferred to the first read of the path.
            File.Exists(_core.PatternStandardPath).ShouldBeTrue();
            File.Exists(_core.PatternExtendedPath).ShouldBeTrue();

            new FileInfo(_core.PatternStandardPath).Length.ShouldBe(20277);
            new FileInfo(_core.PatternExtendedPath).Length.ShouldBe(66923);
        }

        [Fact]
        public void SetPatternStandardPath_accepts_an_existing_file()
        {
            // Was a pinned defect: the setter validated with Directory.Exists and
            // appended a backslash, even though a *file* path is what the config
            // stores and what PatternOffset later reads. Every correct input was
            // rejected, so "ERC --config SetStandardPattern <file>" could not work.
            string original = _core.PatternStandardPath;
            File.Exists(original).ShouldBeTrue();

            try
            {
                Should.NotThrow(() => _core.SetPatternStandardPath(original));
                _core.PatternStandardPath.ShouldBe(original);
            }
            finally
            {
                _core.SetPatternStandardPath(original);
            }
        }

        [Fact]
        public void SetPatternExtendedPath_accepts_an_existing_file()
        {
            string original = _core.PatternExtendedPath;
            File.Exists(original).ShouldBeTrue();

            try
            {
                Should.NotThrow(() => _core.SetPatternExtendedPath(original));
                _core.PatternExtendedPath.ShouldBe(original);
            }
            finally
            {
                _core.SetPatternExtendedPath(original);
            }
        }

        [Fact]
        public void SetPatternStandardPath_rejects_a_path_that_does_not_exist()
        {
            Should.Throw<ERCException>(
                () => _core.SetPatternStandardPath(Path.Combine(Path.GetTempPath(), "no-such-pattern-file")));
        }

        [Fact]
        public void SetPatternStandardPath_rejects_an_empty_path()
        {
            Should.Throw<ERCException>(() => _core.SetPatternStandardPath(""));
            Should.Throw<ERCException>(() => _core.SetPatternStandardPath(null));
        }

        [Fact]
        public void ErcResult_ToString_returns_the_description_it_builds()
        {
            // Was a pinned defect: ToString assembled a multi-line description into
            // a local and then returned base.ToString(), throwing the work away and
            // handing callers the type name.
            var result = new ErcResult<string>(_core) { ReturnValue = "hello" };

            string text = result.ToString();

            text.ShouldContain("ErcResult Type");
            text.ShouldContain("ErcResult.Error = NULL");
            text.ShouldNotBe(typeof(ErcResult<string>).ToString());
        }

        [Fact]
        public void ErcResult_ToString_handles_a_null_value()
        {
            // The common shape of a failed result: no value, an error set. Calling
            // GetType() on the null value used to throw here.
            var result = new ErcResult<string>(_core) { Error = new ERCException("bang") };

            string text = result.ToString();

            text.ShouldContain("NULL");
            text.ShouldContain("bang");
        }

        [Fact]
        public void LogEvent_gives_up_quietly_when_the_log_is_locked()
        {
            // Was a pinned defect: logging opened the file with File.AppendText,
            // taking an exclusive lock, so a second thread logging at the same time
            // raised an IOException out of the error path and replaced whatever
            // fault was being reported. x64dbg calls plugins from more than one
            // thread, so this was reachable in ordinary use.
            //
            // Logging now fails quietly. Losing a log line beats losing the session.
            var result = new ErcResult<string>(_core)
            {
                Error = new ERCException("boom")
            };

            using (File.Open(_core.SystemErrorLogPath, FileMode.OpenOrCreate,
                             FileAccess.Write, FileShare.None))
            {
                Should.NotThrow(() => result.LogEvent());
            }

            Should.NotThrow(() => result.LogEvent());
        }

        [Fact]
        public void LogEvent_allows_the_log_to_be_read_while_writing()
        {
            // The log is opened sharing read access so it can be tailed live.
            var result = new ErcResult<string>(_core) { Error = new ERCException("readable") };

            using (File.Open(_core.SystemErrorLogPath, FileMode.OpenOrCreate,
                             FileAccess.Read, FileShare.ReadWrite))
            {
                Should.NotThrow(() => result.LogEvent());
            }
        }

        [Fact]
        public void LogEvent_writes_the_error_to_the_log()
        {
            var result = new ErcResult<string>(_core)
            {
                Error = new ERCException("a distinctive marker 4f3a9c")
            };

            result.LogEvent();

            File.ReadAllText(_core.SystemErrorLogPath).ShouldContain("4f3a9c");
        }

        [Fact]
        public void ErcResult_does_not_inherit_from_ErcCore()
        {
            // Was a pinned defect: every result value in the library was-a ErcCore,
            // so constructing one dragged configuration state along and a result
            // exposed nonsense members like SetWorkingDirectory.
            typeof(ErcCore).IsAssignableFrom(typeof(ErcResult<string>)).ShouldBeFalse();
        }

        [Fact]
        public void ErcResult_reports_success_and_failure()
        {
            new ErcResult<string>(_core) { ReturnValue = "ok" }.IsSuccess.ShouldBeTrue();
            new ErcResult<string>(_core) { Error = new ERCException("no") }.IsSuccess.ShouldBeFalse();
        }
    }
}
