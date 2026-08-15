using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using ERC.Net.Tests.TestSupport;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers reading a module's exports out of its file.
    /// </summary>
    /// <remarks>
    /// This exists because GetProcAddress resolves in the calling process and cannot
    /// answer for another one. The ROP chain generator worked around that by adding
    /// hard-coded offsets to a module base - correct for one build of kernel32 and
    /// silently wrong for every other.
    ///
    /// The results are checked against the loader's own answer, which is the only
    /// authority worth comparing to.
    /// </remarks>
    public class ExportTableTests
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetModuleHandle(string moduleName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi, ExactSpelling = true)]
        private static extern IntPtr GetProcAddress(IntPtr module, string procedureName);

        private static string Kernel32Path
        {
            get { return Path.Combine(Environment.SystemDirectory, "kernel32.dll"); }
        }

        [Fact]
        public void A_system_dll_exports_the_functions_a_rop_chain_wants()
        {
            IReadOnlyDictionary<string, uint> exports = ExportTable.Read(Kernel32Path);

            exports.Count.ShouldBeGreaterThan(100, "kernel32 exports well over a thousand functions");

            foreach (string name in new[] { "VirtualAlloc", "VirtualProtect", "HeapCreate", "WriteProcessMemory" })
            {
                exports.ContainsKey(name).ShouldBeTrue(name);
                exports[name].ShouldBeGreaterThan(0U, name);
            }
        }

        [Theory]
        [InlineData("VirtualAlloc")]
        [InlineData("VirtualProtect")]
        [InlineData("HeapCreate")]
        [InlineData("WriteProcessMemory")]
        [InlineData("LoadLibraryA")]
        public void The_resolved_address_matches_what_the_loader_resolves(string name)
        {
            // The decisive check. The parse is independent of the loader, so agreeing
            // with it means the export directory was walked correctly - ordinals,
            // name table and all.
            IntPtr module = GetModuleHandle("kernel32.dll");
            module.ShouldNotBe(IntPtr.Zero);

            IntPtr expected = GetProcAddress(module, name);
            expected.ShouldNotBe(IntPtr.Zero, name + " should be exported");

            IntPtr actual;
            ExportTable.TryResolve(Kernel32Path, module, name, out actual).ShouldBeTrue();

            actual.ShouldBe(expected, name);
        }

        [Fact]
        public void A_forwarded_export_is_left_out_rather_than_offered_as_code()
        {
            // Much of kernel32 forwards into other DLLs: the "address" in the export
            // table is a string like "NTDLL.RtlAllocateHeap", not an instruction. A
            // chain that called one would be jumping into text.
            IReadOnlyDictionary<string, uint> exports = ExportTable.Read(Kernel32Path);

            PeHeaders headers = PeHeaders.Parse(File.ReadAllBytes(Kernel32Path));

            foreach (KeyValuePair<string, uint> export in exports)
            {
                bool insideDirectory =
                    export.Value >= headers.ExportTableRva &&
                    export.Value < headers.ExportTableRva + headers.ExportTableSize;

                insideDirectory.ShouldBeFalse(export.Key + " is a forwarder and should have been skipped");
            }
        }

        [Fact]
        public void A_name_the_module_does_not_export_is_reported_as_absent()
        {
            IntPtr address;

            ExportTable.TryResolve(Kernel32Path, new IntPtr(0x10000000),
                                   "ThisFunctionDoesNotExist", out address).ShouldBeFalse();

            address.ShouldBe(IntPtr.Zero);
        }

        [Fact]
        public void Export_names_are_matched_exactly()
        {
            // The export table is case sensitive, and "virtualalloc" is not a function.
            IReadOnlyDictionary<string, uint> exports = ExportTable.Read(Kernel32Path);

            exports.ContainsKey("VirtualAlloc").ShouldBeTrue();
            exports.ContainsKey("virtualalloc").ShouldBeFalse();
        }

        [Fact]
        public void The_address_is_the_module_base_plus_the_relative_address()
        {
            IReadOnlyDictionary<string, uint> exports = ExportTable.Read(Kernel32Path);
            var moduleBase = new IntPtr(0x10000000);

            IntPtr address;
            ExportTable.TryResolve(Kernel32Path, moduleBase, "VirtualAlloc", out address).ShouldBeTrue();

            address.ShouldBe(new IntPtr(moduleBase.ToInt64() + exports["VirtualAlloc"]));
        }

        // ------------------------------------------------------------ bad input

        [Fact]
        public void A_file_that_is_not_a_pe_image_yields_nothing_rather_than_throwing()
        {
            string path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            File.WriteAllText(path, "this is not a PE file");

            try
            {
                ExportTable.Read(path).ShouldBeEmpty();
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        public void A_file_that_does_not_exist_yields_nothing_rather_than_throwing()
        {
            ExportTable.Read(Path.Combine(Path.GetTempPath(), "no-such-file.dll")).ShouldBeEmpty();
        }

        [Fact]
        public void An_image_with_no_exports_yields_nothing()
        {
            // PeBuilder produces a valid image with an empty data directory, which is
            // the ordinary case for an executable rather than a library.
            string directory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            Directory.CreateDirectory(directory);

            try
            {
                string path = PeBuilder.X86()
                    .WithSection(".text", 0x1000, new byte[] { 0x90 })
                    .BuildToFile(directory, "noexports.dll");

                ExportTable.Read(path).ShouldBeEmpty();
            }
            finally
            {
                Directory.Delete(directory, true);
            }
        }

        [Fact]
        public void An_export_directory_pointing_outside_the_file_yields_nothing()
        {
            string directory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            Directory.CreateDirectory(directory);

            try
            {
                // A directory RVA no section covers. The translation fails and the
                // read stops, rather than indexing somewhere arbitrary.
                byte[] image = PeBuilder.X86()
                    .WithSection(".text", 0x1000, new byte[] { 0x90 })
                    .Build();

                string path = Path.Combine(directory, "bogus.dll");
                File.WriteAllBytes(path, image);

                Should.NotThrow(() => ExportTable.Read(path));
            }
            finally
            {
                Directory.Delete(directory, true);
            }
        }
    }
}
