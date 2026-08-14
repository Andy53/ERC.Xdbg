using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Threading;

namespace ERC.Net.Tests.TestSupport
{
    /// <summary>
    /// Launches the fixture target and exposes where it planted its artefacts.
    /// </summary>
    /// <remarks>
    /// The target prints the address of each artefact, so the tests assert that ERC
    /// finds the exact address the target reported. That is a stronger claim than
    /// matching an address hard-coded in the test, and it avoids needing a fixed
    /// image base or a native toolchain to build the fixture.
    /// </remarks>
    public sealed class TargetProcess : IDisposable
    {
        private const string ReadyMarker = "TARGET-READY";

        private readonly Process _process;
        private readonly Dictionary<string, Artefact> _artefacts =
            new Dictionary<string, Artefact>(StringComparer.OrdinalIgnoreCase);

        private TargetProcess(Process process)
        {
            _process = process;
        }

        /// <summary>
        /// An artefact planted by the target.
        /// </summary>
        public sealed class Artefact
        {
            public Artefact(IntPtr address, IntPtr allocation, int allocationLength)
            {
                Address = address;
                Allocation = allocation;
                AllocationLength = allocationLength;
            }

            /// <summary>Address of the payload itself.</summary>
            public IntPtr Address { get; }

            /// <summary>Start of the allocation the payload sits inside.</summary>
            public IntPtr Allocation { get; }

            /// <summary>Size of that allocation.</summary>
            public int AllocationLength { get; }
        }

        /// <summary>The running target.</summary>
        public Process Process { get { return _process; } }

        /// <summary>Where the target planted the named artefact.</summary>
        public Artefact this[string name] { get { return _artefacts[name]; } }

        /// <summary>
        /// The fixture executable that matches this test run, or null when it is not
        /// present - which is what makes the integration tests skip rather than fail
        /// on a machine that has not built it.
        /// </summary>
        public static string? Locate()
        {
            // Found by walking up to the repository root rather than by referencing
            // the fixture project. A ProjectReference would tie the fixture's target
            // frameworks and runtime identifiers to the test project's, and the two
            // have no reason to match: the fixture is launched, never linked.
            string? root = AppContext.BaseDirectory;

            while (root != null && !File.Exists(Path.Combine(root, "ErcXdbgPlugin.sln")))
            {
                root = Path.GetDirectoryName(root.TrimEnd(Path.DirectorySeparatorChar));
            }

            if (root == null)
            {
                return null;
            }

            // The inspector and the target must be the same bitness, so pick the
            // build that matches this test process.
            string platform = IntPtr.Size == 8 ? "x64" : "x86";
            string baseDirectory = Path.Combine(root, "tests", "Fixtures", "ErcTestTarget", "bin", platform);

            foreach (string configuration in new[] { "Debug", "Release" })
            {
                string candidate = Path.Combine(baseDirectory, configuration, "net472", "ErcTestTarget.exe");
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }

            return null;
        }

        /// <summary>
        /// Starts the target and waits until it reports that everything is planted.
        /// </summary>
        public static TargetProcess Start()
        {
            string? exe = Locate();
            if (exe == null)
            {
                throw new InvalidOperationException(
                    "ErcTestTarget.exe was not found beside the test assembly.");
            }

            var startInfo = new ProcessStartInfo(exe)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardInput = true,
                CreateNoWindow = true
            };

            Process? started = Process.Start(startInfo);
            if (started == null)
            {
                throw new InvalidOperationException("The fixture target did not start.");
            }

            var target = new TargetProcess(started);

            try
            {
                target.ReadUntilReady();
            }
            catch
            {
                target.Dispose();
                throw;
            }

            return target;
        }

        private void ReadUntilReady()
        {
            // The target prints one line per artefact then the ready marker. It is a
            // handful of lines written immediately, so a bounded read is enough.
            DateTime deadline = DateTime.UtcNow.AddSeconds(30);

            while (DateTime.UtcNow < deadline)
            {
                string? line = _process.StandardOutput.ReadLine();

                if (line == null)
                {
                    throw new InvalidOperationException(
                        "The fixture target exited before reporting that it was ready.");
                }

                if (line == ReadyMarker)
                {
                    return;
                }

                // "<name> <payloadAddress:X> <allocationAddress:X> <length>"
                string[] parts = line.Split(' ');
                if (parts.Length == 4)
                {
                    _artefacts[parts[0]] = new Artefact(
                        new IntPtr(long.Parse(parts[1], NumberStyles.HexNumber, CultureInfo.InvariantCulture)),
                        new IntPtr(long.Parse(parts[2], NumberStyles.HexNumber, CultureInfo.InvariantCulture)),
                        int.Parse(parts[3], CultureInfo.InvariantCulture));
                }
            }

            throw new TimeoutException("The fixture target did not become ready within 30 seconds.");
        }

        public void Dispose()
        {
            try
            {
                if (!_process.HasExited)
                {
                    // Closing stdin is the polite exit; killing is the guarantee that
                    // a failed test never leaves a process behind.
                    _process.StandardInput.WriteLine();
                    _process.StandardInput.Flush();

                    if (!_process.WaitForExit(5000))
                    {
                        _process.Kill();
                    }
                }
            }
            catch (Exception)
            {
                try { _process.Kill(); } catch (Exception) { }
            }
            finally
            {
                _process.Dispose();
            }
        }
    }
}
