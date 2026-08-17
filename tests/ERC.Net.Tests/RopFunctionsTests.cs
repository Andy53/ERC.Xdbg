using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using ERC.Config;
using ERC.Net.Tests.TestSupport;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers resolving the API addresses a ROP chain is built around.
    /// </summary>
    /// <remarks>
    /// This is the single most important number in a generated chain: the address the
    /// chain calls. It was resolved by passing the target's kernel32 base to
    /// GetProcAddress, which answers for the calling process, and then patched up on
    /// 32-bit targets with hard-coded offsets into one build of kernel32.
    ///
    /// Tagged Integration: resolving against a process needs a process.
    /// </remarks>
    [Trait("Category", "Integration")]
    [Collection("LiveProcess")]
    public class RopFunctionsTests
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetModuleHandle(string moduleName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi, ExactSpelling = true)]
        private static extern IntPtr GetProcAddress(IntPtr module, string procedureName);

        private static void SkipIfNoFixture()
        {
            if (TargetProcess.Locate() == null)
            {
                Assert.Skip("ErcTestTarget.exe was not built beside the test assembly.");
            }
        }

        private static ErcCore Core()
        {
            return new ErcCore(new InMemoryConfigStore(), new InMemoryErcLogger());
        }

        [Fact]
        public void Every_api_a_chain_needs_is_resolved()
        {
            SkipIfNoFixture();

            using (var target = TargetProcess.Start())
            using (var info = new ProcessInfo(Core(), target.Process))
            {
                ErcResult<Dictionary<string, IntPtr>> apis = RopFunctions.ChainApis(info);

                apis.Error.ShouldBeNull();

                foreach (string name in RopFunctions.ChainApiNames)
                {
                    apis.ReturnValue.ContainsKey(name).ShouldBeTrue(name + " should have been resolved");
                    apis.ReturnValue[name].ShouldNotBe(IntPtr.Zero, name);
                }
            }
        }

        [Fact]
        public void The_resolved_addresses_are_the_ones_the_loader_gives()
        {
            SkipIfNoFixture();

            // The fixture and this test process are the same architecture, and a
            // module occupies the same address in every process for the life of a
            // boot, so the loader's answer for our own kernel32 is the right answer
            // for the target's. That equivalence is what the old code relied on
            // without saying so - and it is exactly what fails for a 32-bit target
            // inspected from a 64-bit tool.
            using (var target = TargetProcess.Start())
            using (var info = new ProcessInfo(Core(), target.Process))
            {
                IntPtr kernel32 = GetModuleHandle("kernel32.dll");
                kernel32.ShouldNotBe(IntPtr.Zero);

                Dictionary<string, IntPtr> apis = RopFunctions.ChainApis(info).ReturnValue;

                foreach (string name in RopFunctions.ChainApiNames)
                {
                    IntPtr expected = GetProcAddress(kernel32, name);
                    expected.ShouldNotBe(IntPtr.Zero, name);

                    apis[name].ShouldBe(expected, name);
                }
            }
        }

        [Fact]
        public void A_resolved_address_lies_inside_the_module_that_exports_it()
        {
            SkipIfNoFixture();

            // The failure mode of the hard-coded offsets was an address inside
            // kernel32 but at the wrong function, so being inside the module is
            // necessary rather than sufficient - but an address outside it is
            // unambiguously wrong.
            using (var target = TargetProcess.Start())
            using (var info = new ProcessInfo(Core(), target.Process))
            {
                ModuleInfo? kernel32 = info.ModulesInfo.FirstOrDefault(
                    m => Path.GetFileName(m.ModulePath).Equals("kernel32.dll", StringComparison.OrdinalIgnoreCase));

                kernel32.ShouldNotBeNull();

                long start = kernel32.ModuleBase.ToInt64();
                long end = start + kernel32.ModuleSize;

                foreach (KeyValuePair<string, IntPtr> api in RopFunctions.ChainApis(info).ReturnValue)
                {
                    long address = api.Value.ToInt64();

                    address.ShouldBeGreaterThanOrEqualTo(start, api.Key);
                    address.ShouldBeLessThan(end, api.Key);
                }
            }
        }

        [Fact]
        public void The_chain_places_the_address_the_resolver_found()
        {
            SkipIfNoFixture();

            if (IntPtr.Size != 4)
            {
                Assert.Skip("The 32-bit chain builder needs a 32-bit target.");
            }

            // Joins the two halves: whatever ChainApis resolves is what ends up in the
            // chain, so a correct resolver cannot be undone by the builder.
            using (var target = TargetProcess.Start())
            using (var info = new ProcessInfo(Core(), target.Process))
            {
                IntPtr expected = RopFunctions.ChainApis(info).ReturnValue["VirtualAlloc"];

                var generator = new RopChainGenerator32(info);
                generator.usableX86Opcodes = SyntheticGadgets.Lists32();
                generator.RopNops = new List<IntPtr> { new IntPtr(SyntheticGadgets.RopNop32) };
                generator.ApiAddresses = RopFunctions.ChainApis(info).ReturnValue;

                var chain = generator.GenerateVirtualAllocChain32(info);

                byte[] wanted = BitConverter.GetBytes((int)expected);

                chain.ReturnValue.ShouldContain(e => e.Item1.SequenceEqual(wanted),
                    "the chain should place the resolved VirtualAlloc address on the stack");
            }
        }

        [Fact]
        public void Ropfunc_reports_more_than_the_chain_builders_need()
        {
            SkipIfNoFixture();

            // --RopFunc is a wider list than the four the builders use, because a hand
            // written chain may want SetProcessDEPPolicy or WinExec.
            using (var target = TargetProcess.Start())
            using (var info = new ProcessInfo(Core(), target.Process))
            {
                List<RopFunction> found = RopFunctions.Find(info).ReturnValue;

                found.ShouldNotBeEmpty();
                found.Select(f => f.Name).ShouldContain("VirtualProtect");

                foreach (RopFunction function in found)
                {
                    function.Address.ShouldNotBe(IntPtr.Zero, function.Name);
                    function.Purpose.ShouldNotBeNullOrWhiteSpace();
                    function.Module.ShouldNotBeNullOrWhiteSpace();
                }
            }
        }
    }
}
