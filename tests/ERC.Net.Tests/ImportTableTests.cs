using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using ERC.Net.Tests.TestSupport;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers reading a module's import address table from its file.
    /// </summary>
    public class ImportTableTests
    {
        private static string Kernel32Path
        {
            get { return Path.Combine(Environment.SystemDirectory, "kernel32.dll"); }
        }

        [Fact]
        public void A_system_dll_imports_from_ntdll()
        {
            IReadOnlyList<ImportEntry> imports = ImportTable.Read(Kernel32Path);

            imports.Count.ShouldBeGreaterThan(10, "kernel32 imports a great many ntdll functions");
            imports.Any(i => i.Dll.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase))
                   .ShouldBeTrue();
            imports.Any(i => !i.ByOrdinal && i.Name.Length > 0).ShouldBeTrue();
        }

        [Fact]
        public void Iat_slots_are_distinct_and_pointer_sized()
        {
            IReadOnlyList<ImportEntry> imports = ImportTable.Read(Kernel32Path);

            // The first two imports from the same DLL should occupy adjacent IAT slots.
            ImportEntry[] ntdll = imports
                .Where(i => i.Dll.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase))
                .Take(2)
                .ToArray();

            ntdll.Length.ShouldBe(2);
            int stride = (int)(ntdll[1].IatRva - ntdll[0].IatRva);
            (stride == 4 || stride == 8).ShouldBeTrue("IAT slots are pointer-sized, so 4 or 8 bytes apart");
        }

        [Fact]
        public void SlotAddress_adds_the_rva_to_the_module_base()
        {
            ImportTable.SlotAddress((IntPtr)0x10000000, 0x1234)
                       .ShouldBe((IntPtr)0x10001234);
        }

        [Fact]
        public void A_module_with_no_imports_returns_empty()
        {
            byte[] image = PeBuilder.X86().Build();
            string path = Path.GetTempFileName();
            try
            {
                File.WriteAllBytes(path, image);
                ImportTable.Read(path).ShouldBeEmpty();
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        public void The_import_directory_rva_is_read_from_the_headers()
        {
            PeHeaders headers = PeHeaders.Parse(
                PeBuilder.X86().WithImportDirectory(0x2000, 40).Build());

            headers.ImportTableRva.ShouldBe(0x2000U);
            headers.ImportTableSize.ShouldBe(40U);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void A_constructed_import_table_is_read_slot_by_slot(bool is64Bit)
        {
            string path = WriteImage(NamedImport(is64Bit));
            try
            {
                IReadOnlyList<ImportEntry> imports = ImportTable.Read(path, is64Bit);

                imports.Count.ShouldBe(1);
                ImportEntry entry = imports[0];
                entry.Dll.ShouldBe("kernel32.dll");
                entry.Name.ShouldBe("VirtualProtect");
                entry.ByOrdinal.ShouldBeFalse();
                entry.DisplayName.ShouldBe("VirtualProtect");
                entry.IatRva.ShouldBe(IatRva(is64Bit));
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        public void An_ordinal_import_is_reported_as_hash_ordinal()
        {
            string path = WriteImage(OrdinalImport());
            try
            {
                IReadOnlyList<ImportEntry> imports = ImportTable.Read(path, false);

                imports.Count.ShouldBe(1);
                imports[0].ByOrdinal.ShouldBeTrue();
                imports[0].Ordinal.ShouldBe(42U);
                imports[0].DisplayName.ShouldBe("#42");
                imports[0].Name.ShouldBeEmpty();
            }
            finally
            {
                File.Delete(path);
            }
        }

        // IMAGE_IMPORT_DESCRIPTOR at RVA 0x1000, then INT, IAT, names.
        private const uint DescriptorRva = 0x1000;
        private const uint IntRva = 0x1028;
        private const uint DllNameRva = 0x1050;
        private const uint HintNameRva = 0x1060;

        private static uint IatRva(bool is64Bit)
        {
            return IntRva + (uint)(2 * (is64Bit ? 8 : 4));
        }

        private static byte[] NamedImport(bool is64Bit)
        {
            byte[] data = ImportSection(is64Bit, named: true);
            PeBuilder builder = is64Bit ? PeBuilder.X64() : PeBuilder.X86();
            return builder
                .WithImportDirectory(DescriptorRva, 40)
                .WithSection(".idata", DescriptorRva, data)
                .Build();
        }

        private static byte[] OrdinalImport()
        {
            return PeBuilder.X86()
                .WithImportDirectory(DescriptorRva, 40)
                .WithSection(".idata", DescriptorRva, ImportSection(false, named: false))
                .Build();
        }

        private static byte[] ImportSection(bool is64Bit, bool named)
        {
            int pointerSize = is64Bit ? 8 : 4;
            var data = new byte[0x80];

            WriteU32(data, 0, IntRva);                 // OriginalFirstThunk
            WriteU32(data, 12, DllNameRva);            // Name
            WriteU32(data, 16, IatRva(is64Bit));       // FirstThunk
            // bytes 20-39 stay zero: terminator descriptor.

            ulong thunk = named
                ? HintNameRva
                : (is64Bit ? (0x8000000000000000UL | 42UL) : (0x80000000UL | 42UL));

            WritePtr(data, (int)(IntRva - DescriptorRva), thunk, pointerSize);
            WritePtr(data, (int)(IatRva(is64Bit) - DescriptorRva), thunk, pointerSize);

            Encoding.ASCII.GetBytes("kernel32.dll").CopyTo(data, (int)(DllNameRva - DescriptorRva));

            if (named)
            {
                Encoding.ASCII.GetBytes("VirtualProtect")
                       .CopyTo(data, (int)(HintNameRva - DescriptorRva) + 2);
            }

            return data;
        }

        private static string WriteImage(byte[] image)
        {
            string path = Path.GetTempFileName();
            File.WriteAllBytes(path, image);
            return path;
        }

        private static void WriteU32(byte[] data, int offset, uint value)
        {
            data[offset] = (byte)value;
            data[offset + 1] = (byte)(value >> 8);
            data[offset + 2] = (byte)(value >> 16);
            data[offset + 3] = (byte)(value >> 24);
        }

        private static void WritePtr(byte[] data, int offset, ulong value, int pointerSize)
        {
            for (int i = 0; i < pointerSize; i++)
            {
                data[offset + i] = (byte)(value >> (8 * i));
            }
        }
    }
}
