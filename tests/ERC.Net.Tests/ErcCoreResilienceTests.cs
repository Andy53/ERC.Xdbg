using System;
using System.IO;
using System.Threading;
using ERC;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Regression tests for the constructor's behaviour when its config file
    /// cannot be created, which is the state a read-only plugin directory produces.
    /// </summary>
    /// <remarks>
    /// These manipulate files next to the assembly, so they run in their own
    /// collection and restore what they touch.
    /// </remarks>
    [Collection("ErcCoreResilience")]
    public class ErcCoreResilienceTests : IDisposable
    {
        private readonly string _assemblyDirectory;
        private readonly string _configPath;
        private readonly string _backupPath;

        public ErcCoreResilienceTests()
        {
            // GetDirectoryName only returns null for a root path, which the path of
            // a loaded assembly never is.
            string codeBase = typeof(ErcCore).Assembly.CodeBase!;
            _assemblyDirectory = Path.GetDirectoryName(new Uri(codeBase).LocalPath)!;
            _configPath = Path.Combine(_assemblyDirectory, "ERC_Config.XML");
            _backupPath = _configPath + ".testbackup";

            if (File.Exists(_configPath))
            {
                File.Copy(_configPath, _backupPath, overwrite: true);
                File.Delete(_configPath);
            }
        }

        [Fact]
        public void Constructor_completes_when_the_config_cannot_be_written()
        {
            // A directory where the config file belongs makes every save fail while
            // leaving everything else writable. File.Exists is false for a
            // directory, so the constructor can never read a config either.
            //
            // This used to spin forever: the retry loop called a save helper that
            // swallowed its own failures, so the exit condition was never met and
            // x64dbg hung at 100% CPU until it was killed. Verified before the fix
            // by a worker that had not returned after six seconds.
            Directory.CreateDirectory(_configPath);

            ErcCore? core = null;
            Exception? thrown = null;

            var worker = new Thread(() =>
            {
                try { core = new ErcCore(); }
                catch (Exception e) { thrown = e; }
            });
            worker.IsBackground = true; // never blocks the test process from exiting
            worker.Start();

            worker.Join(TimeSpan.FromSeconds(20)).ShouldBeTrue(
                "ErcCore did not finish constructing - the config retry loop is spinning again.");

            thrown.ShouldBeNull();
            core.ShouldNotBeNull();
        }

        [Fact]
        public void Constructor_falls_back_to_defaults_when_the_config_cannot_be_written()
        {
            Directory.CreateDirectory(_configPath);

            var core = new ErcCore();

            // The in-memory defaults survive, so the rest of the library still works.
            core.WorkingDirectory.ShouldNotBeNullOrEmpty();
            core.SystemErrorLogPath.ShouldNotBeNullOrEmpty();
            core.ErcVersion.ShouldStartWith("ERC.Xdbg_");
        }

        public void Dispose()
        {
            if (Directory.Exists(_configPath))
            {
                Directory.Delete(_configPath, recursive: true);
            }

            if (File.Exists(_backupPath))
            {
                File.Copy(_backupPath, _configPath, overwrite: true);
                File.Delete(_backupPath);
            }
        }
    }
}
