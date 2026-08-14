using System;
using System.Diagnostics;
using ERC;
using ERC.Config;
using ERC.Native;
using ERC.Output;
using ERC.Net.Tests.TestSupport;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Proves the operating system can be substituted, which is what makes the
    /// process, module, thread and heap code testable at all.
    /// </summary>
    public class NativeApiSeamTests
    {
        [Fact]
        public void ErcCore_uses_the_real_api_by_default()
        {
            var core = new ErcCore(new InMemoryConfigStore(), new InMemoryErcLogger());

            core.Native.ShouldBeOfType<Win32NativeApi>();
        }

        [Fact]
        public void ErcCore_uses_a_supplied_api()
        {
            var fake = new FakeNativeApi();

            var core = new ErcCore(new InMemoryConfigStore(), new InMemoryErcLogger(), fake);

            core.Native.ShouldBeSameAs(fake);
        }

        [Fact]
        public void Derived_objects_inherit_the_supplied_api()
        {
            // ProcessInfo and friends take their settings from a parent core, so the
            // substitute has to travel with them or the seam is useless in practice.
            var fake = new FakeNativeApi();
            var core = new ErcCore(new InMemoryConfigStore(), new InMemoryErcLogger(), fake);

            // ErcResult is the cheapest observable child; ProcessInfo needs a process.
            new ErcResult<string>(core).Logger.ShouldBeSameAs(core.Logger);
            core.Native.ShouldBeSameAs(fake);
        }

        // A substitute that reports "not running under WOW64", i.e. a 64-bit process.
        private sealed class NotWow64 : FakeNativeApi
        {
            public int Calls { get; private set; }

            public override bool IsWow64Process(IntPtr process, out bool wow64Process)
            {
                Calls++;
                wow64Process = false;
                return true;
            }
        }

        private sealed class FailingWow64 : FakeNativeApi
        {
            public override bool IsWow64Process(IntPtr process, out bool wow64Process)
            {
                wow64Process = false;
                return false;   // the API itself failed
            }
        }

        [Fact]
        public void Is64Bit_reads_the_answer_from_the_supplied_api()
        {
            if (!Environment.Is64BitOperatingSystem)
            {
                Assert.Skip("Is64Bit short-circuits to false on a 32-bit OS.");
            }

            var native = new NotWow64();

            bool result = ProcessInfo.Is64Bit(Process.GetCurrentProcess(), native);

            result.ShouldBeTrue();
            native.Calls.ShouldBe(1);
        }

        [Fact]
        public void Is64Bit_surfaces_a_failure_from_the_api()
        {
            if (!Environment.Is64BitOperatingSystem)
            {
                Assert.Skip("Is64Bit short-circuits to false on a 32-bit OS.");
            }

            Should.Throw<ERCException>(
                () => ProcessInfo.Is64Bit(Process.GetCurrentProcess(), new FailingWow64()));
        }

        [Fact]
        public void Is64Bit_rejects_a_missing_process()
        {
            Should.Throw<ERCException>(() => ProcessInfo.Is64Bit(null, new FakeNativeApi()));
        }

        [Fact]
        public void Opcode_helpers_built_from_a_ProcessInfo_keep_its_seams()
        {
            // ProcessInfo's protected copy constructor had no ": base(parent)", so it
            // fell through to the parameterless ErcCore constructor. Building an
            // OpcodeAssembler or OpcodeDisassembler from a ProcessInfo therefore made
            // a second ErcCore that re-read the config from disk and took the default
            // OS access and output sink, silently discarding the parent's.
            //
            // Uses the test process as its own target, so it needs the real Win32 API
            // but no separate debuggee.
            var sink = new InMemoryOutputSink();
            var logger = new InMemoryErcLogger();
            var core = new ErcCore(new InMemoryConfigStore(), logger, null, sink);

            var info = new ProcessInfo(core, Process.GetCurrentProcess());
            info.Output.ShouldBeSameAs(sink);

            var assembler = new ERC.Utilities.OpcodeAssembler(info);
            var disassembler = new ERC.Utilities.OpcodeDisassembler(info);

            assembler.Output.ShouldBeSameAs(sink, "the assembler should share its parent's output sink");
            assembler.Logger.ShouldBeSameAs(logger);
            assembler.Native.ShouldBeSameAs(core.Native);

            disassembler.Output.ShouldBeSameAs(sink);
            disassembler.Logger.ShouldBeSameAs(logger);
        }

        [Fact]
        public void An_unexpected_call_fails_loudly()
        {
            // The default-throws design is deliberate: a substitute that quietly
            // returned zero would let a test pass while the code under test made
            // calls nobody had thought about.
            Should.Throw<NotImplementedException>(
                () => new FakeNativeApi().OpenProcess(default(ERC.Structures.ProcessAccessFlags), false, 0));
        }
    }
}
