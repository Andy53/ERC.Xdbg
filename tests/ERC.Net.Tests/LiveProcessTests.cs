using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using ERC;
using ERC.Config;
using ERC.Net.Tests.TestSupport;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Tests that inspect a real running process.
    /// </summary>
    /// <remarks>
    /// Everything the library does that matters - searching memory, finding
    /// pop/pop/ret sequences, dumping regions - only means anything against a live
    /// target, and none of it could be tested at all before the seams went in.
    ///
    /// The fixture target plants known artefacts and reports their addresses, so
    /// these assert that ERC finds the exact address the target says it wrote to.
    ///
    /// Tagged Integration: slower than the rest of the suite and dependent on
    /// launching a process, so excluded from the fast loop and run in CI.
    /// </remarks>
    [Trait("Category", "Integration")]
    [Collection("LiveProcess")]
    public class LiveProcessTests
    {
        private static ErcCore Core()
        {
            return new ErcCore(new InMemoryConfigStore(), new InMemoryErcLogger());
        }

        private static void SkipIfNoFixture()
        {
            if (TargetProcess.Locate() == null)
            {
                Assert.Skip("ErcTestTarget.exe was not built beside the test assembly.");
            }
        }

        // The signature the fixture plants; kept here rather than referencing the
        // fixture assembly so the test states its own expectation.
        private static readonly byte[] Signature =
        {
            0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xDE, 0x5E, 0x1F,
            0x45, 0x52, 0x43, 0x54, 0x45, 0x53, 0x54
        };

        private const string Needle = "ErcFixtureNeedle7f3a";

        // ------------------------------------------------- attaching

        [Fact]
        public void A_running_process_can_be_inspected()
        {
            SkipIfNoFixture();

            using (var target = TargetProcess.Start())
            using (var info = new ProcessInfo(Core(), target.Process))
            {
                info.ProcessID.ShouldBe(target.Process.Id);
                info.ProcessName.ShouldBe("ErcTestTarget");
                info.ModulesInfo.ShouldNotBeEmpty();
                info.ThreadsInfo.ShouldNotBeEmpty();

                // The inspector and the target must agree on architecture, or nothing
                // below would read the right memory.
                MachineType expected = IntPtr.Size == 8 ? MachineType.x64 : MachineType.I386;
                info.ProcessMachineType.ShouldBe(expected);
            }
        }

        // ------------------------------------------------- reading memory

        [Fact]
        public void A_planted_region_reads_back_byte_for_byte()
        {
            SkipIfNoFixture();

            using (var target = TargetProcess.Start())
            using (var info = new ProcessInfo(Core(), target.Process))
            {
                TargetProcess.Artefact planted = target["signature"];

                ErcResult<byte[]> dump = info.DumpMemoryRegion(planted.Address, Signature.Length);

                dump.Error.ShouldBeNull();
                dump.ReturnValue.ShouldBe(Signature);
            }
        }

        [Fact]
        public void Reading_the_padding_around_a_payload_gives_the_filler()
        {
            SkipIfNoFixture();

            using (var target = TargetProcess.Start())
            using (var info = new ProcessInfo(Core(), target.Process))
            {
                // The fixture surrounds each payload with 0x90 filler; reading just
                // before the payload should therefore be all nops.
                TargetProcess.Artefact planted = target["signature"];
                IntPtr before = new IntPtr(planted.Address.ToInt64() - 16);

                byte[] bytes = info.DumpMemoryRegion(before, 16).ReturnValue;

                bytes.ShouldAllBe(b => b == 0x90);
            }
        }

        // ------------------------------------------------- searching memory

        [Fact]
        public void Searching_for_planted_bytes_finds_the_address_the_target_reported()
        {
            SkipIfNoFixture();

            using (var target = TargetProcess.Start())
            using (var info = new ProcessInfo(Core(), target.Process))
            {
                ErcResult<Dictionary<IntPtr, string>> found =
                    info.SearchMemory(SearchTerm.Bytes, searchBytes: Signature);

                found.Error.ShouldBeNull();
                found.ReturnValue.Keys.ShouldContain(target["signature"].Address);
            }
        }

        [Fact]
        public void Searching_for_ascii_text_finds_the_ascii_copy()
        {
            SkipIfNoFixture();

            using (var target = TargetProcess.Start())
            using (var info = new ProcessInfo(Core(), target.Process))
            {
                ErcResult<Dictionary<IntPtr, string>> found =
                    info.SearchMemory(SearchTerm.Ascii, searchString: Needle);

                found.Error.ShouldBeNull();
                found.ReturnValue.Keys.ShouldContain(target["ascii"].Address);
            }
        }

        [Fact]
        public void Searching_for_unicode_text_finds_the_utf16_copy()
        {
            SkipIfNoFixture();

            using (var target = TargetProcess.Start())
            using (var info = new ProcessInfo(Core(), target.Process))
            {
                // The same text is planted twice, once per encoding. A Unicode search
                // must find the UTF-16 copy, which is the point of the search types.
                ErcResult<Dictionary<IntPtr, string>> found =
                    info.SearchMemory(SearchTerm.Unicode, searchString: Needle);

                found.Error.ShouldBeNull();
                found.ReturnValue.Keys.ShouldContain(target["unicode"].Address);
            }
        }

        [Fact]
        public void A_search_for_something_absent_finds_nothing()
        {
            SkipIfNoFixture();

            using (var target = TargetProcess.Start())
            using (var info = new ProcessInfo(Core(), target.Process))
            {
                byte[] absent = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                  0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
                                  0x13, 0x37, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };

                ErcResult<Dictionary<IntPtr, string>> found =
                    info.SearchMemory(SearchTerm.Bytes, searchBytes: absent);

                found.Error.ShouldBeNull();
                found.ReturnValue.ShouldBeEmpty();
            }
        }

        // ------------------------------------------------- SEH / gadgets

        [Fact]
        public void A_planted_pop_pop_ret_is_found_at_the_reported_offset()
        {
            SkipIfNoFixture();

            using (var target = TargetProcess.Start())
            using (var info = new ProcessInfo(Core(), target.Process))
            {
                TargetProcess.Artefact planted = target["poppopret"];

                byte[] region = info.DumpMemoryRegion(
                    planted.Allocation, planted.AllocationLength).ReturnValue;

                List<int> offsets = Payloads.PopPopRet(region);

                // The fixture writes the sequence 64 bytes into its allocation.
                offsets.ShouldContain(64);
            }
        }

        [Fact]
        public void A_planted_jmp_esp_disassembles_as_expected()
        {
            SkipIfNoFixture();

            using (var target = TargetProcess.Start())
            using (var info = new ProcessInfo(Core(), target.Process))
            {
                byte[] bytes = info.DumpMemoryRegion(target["jmpesp"].Address, 2).ReturnValue;

                bytes.ShouldBe(new byte[] { 0xFF, 0xE4 });

                string text = OpcodeDisassembler
                    .Disassemble(bytes, info.ProcessMachineType).ReturnValue.Trim();

                text.ShouldBe(IntPtr.Size == 8 ? "jmp rsp" : "jmp esp");
            }
        }

        // ------------------------------------------------- modules and threads

        [Fact]
        public void The_targets_own_module_is_listed_with_its_details()
        {
            SkipIfNoFixture();

            using (var target = TargetProcess.Start())
            using (var info = new ProcessInfo(Core(), target.Process))
            {
                ModuleInfo? main = info.ModulesInfo
                    .FirstOrDefault(m => m.ModulePath.EndsWith(
                        "ErcTestTarget.exe", StringComparison.OrdinalIgnoreCase));

                main.ShouldNotBeNull();
                main.ModuleBase.ShouldNotBe(IntPtr.Zero);
                main.ModuleSize.ShouldBeGreaterThan(0);
            }
        }

        [Fact]
        public void Modules_report_their_mitigation_flags()
        {
            SkipIfNoFixture();

            using (var target = TargetProcess.Start())
            using (var info = new ProcessInfo(Core(), target.Process))
            {
                // Every Windows system DLL is built with ASLR and DEP. Before the
                // DllCharacteristics fix these came back false for every module on a
                // 32-bit target, so the exclusion globals silently excluded nothing.
                ModuleInfo? ntdll = info.ModulesInfo
                    .FirstOrDefault(m => m.ModulePath.EndsWith(
                        "ntdll.dll", StringComparison.OrdinalIgnoreCase));

                ntdll.ShouldNotBeNull();
                ntdll.ModuleASLR.ShouldBeTrue("ntdll is always built with ASLR");
                ntdll.ModuleNXCompat.ShouldBeTrue("ntdll is always built DEP compatible");
            }
        }

        [Fact]
        public void Modules_built_with_SafeSEH_report_it()
        {
            SkipIfNoFixture();

            // SafeSEH is a 32-bit mitigation. On x64 exception handling is table
            // driven and there is nothing equivalent to assert.
            if (IntPtr.Size != 4)
            {
                return;
            }

            using (var target = TargetProcess.Start())
            using (var info = new ProcessInfo(Core(), target.Process))
            {
                // The load config directory was read into a local variable and thrown
                // away, so the fields the SafeSEH test compares stayed at their
                // defaults and every module reported false. That is the value the
                // "-SafeSEH" filter tests, so it excluded nothing, and the SafeSEH
                // column of every search result was wrong.
                //
                // Restricted to modules that do NOT set IMAGE_DLLCHARACTERISTICS_NO_SEH:
                // those report SafeSEH through a second, independent path, so including
                // them would let this pass with the load config still unread.
                List<ModuleInfo> withHandlers = info.ModulesInfo
                    .Where(m => !m.ModuleFailed)
                    .Where(m => !PeCharacteristics.HasNoSeh(m.ModuleDllCharacteristics))
                    .ToList();

                withHandlers.ShouldNotBeEmpty(
                    "the target should load at least one 32-bit module that registers SEH handlers");

                withHandlers.ShouldContain(m => m.ModuleSafeSEH,
                    "every module that registers SEH handlers reported SafeSEH as false, " +
                    "which means the load config directory was not read");
            }
        }

        [Fact]
        public void Every_loaded_module_reports_headers_that_agree_with_its_file()
        {
            SkipIfNoFixture();

            using (var target = TargetProcess.Start())
            using (var info = new ProcessInfo(Core(), target.Process))
            {
                // ModuleInfo derives its flags from headers it parses itself. Reading
                // the same files independently is a check that the parsing agrees with
                // a second implementation rather than merely being self-consistent.
                foreach (ModuleInfo module in info.ModulesInfo.Where(m => !m.ModuleFailed))
                {
                    if (!File.Exists(module.ModulePath))
                    {
                        continue;
                    }

                    byte[] image = File.ReadAllBytes(module.ModulePath);

                    ERC.Utilities.PeHeaders? headers;
                    string? error;

                    if (!ERC.Utilities.PeHeaders.TryParse(image, out headers, out error))
                    {
                        continue;
                    }

                    module.ModuleASLR.ShouldBe(headers!.HasAslr, module.ModulePath);
                    module.ModuleNXCompat.ShouldBe(headers.HasNxCompat, module.ModulePath);
                    module.ModuleMachineType.ShouldBe(headers.MachineType, module.ModulePath);
                    module.ModuleSize.ShouldBe((int)headers.SizeOfImage, module.ModulePath);
                    ((ulong)module.ModuleImageBase).ShouldBe(headers.ImageBase, module.ModulePath);
                }
            }
        }

        [Fact]
        public void Threads_are_enumerated_without_one_failure_aborting_the_rest()
        {
            SkipIfNoFixture();

            using (var target = TargetProcess.Start())
            using (var info = new ProcessInfo(Core(), target.Process))
            {
                // A thread that exits mid-enumeration used to throw out of the
                // ThreadInfo constructor and take the whole ProcessInfo with it.
                info.ThreadsInfo.ShouldNotBeEmpty();
                info.ThreadsInfo.ShouldAllBe(t => t.ThreadID != 0);
            }
        }
    }

    /// <summary>
    /// Keeps the live-process tests off each other's toes; each starts its own
    /// target, and running several at once slows the suite for no benefit.
    /// </summary>
    [CollectionDefinition("LiveProcess", DisableParallelization = true)]
    public sealed class LiveProcessCollection
    {
    }
}
