using System;
using System.IO;
using System.Linq;
using ERC.Net.Tests.TestSupport;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Covers reading a PE file's headers.
    /// </summary>
    /// <remarks>
    /// These headers come from files a debugged process loaded, which ERC does not
    /// control. The code this replaces cast a pointer over a fixed-size buffer inside
    /// an unsafe block with no signature checks and no bounds check on the offset it
    /// read out of the file, so a malformed header read outside the buffer.
    ///
    /// Every case here is built by PeBuilder rather than found on the machine, so the
    /// interesting ones - ASLR off, a truncated file, an offset past the end - are
    /// available and repeatable.
    /// </remarks>
    public class PeHeadersTests
    {
        // -------------------------------------------------------- well-formed input

        [Fact]
        public void A_32_bit_image_is_read()
        {
            PeHeaders headers = PeHeaders.Parse(PeBuilder.X86()
                .WithImageBase(0x00400000)
                .WithEntryPoint(0x1234)
                .WithSizeOfImage(0x8000)
                .Build());

            headers.MachineType.ShouldBe(MachineType.I386);
            headers.Is64Bit.ShouldBeFalse();
            headers.ImageBase.ShouldBe(0x00400000UL);
            headers.AddressOfEntryPoint.ShouldBe(0x1234U);
            headers.SizeOfImage.ShouldBe(0x8000U);
        }

        [Fact]
        public void A_64_bit_image_is_read()
        {
            PeHeaders headers = PeHeaders.Parse(PeBuilder.X64()
                .WithImageBase(0x0000000180000000)
                .WithEntryPoint(0x5678)
                .WithSizeOfImage(0x20000)
                .Build());

            headers.MachineType.ShouldBe(MachineType.x64);
            headers.Is64Bit.ShouldBeTrue();
            headers.ImageBase.ShouldBe(0x0000000180000000UL);
            headers.AddressOfEntryPoint.ShouldBe(0x5678U);
            headers.SizeOfImage.ShouldBe(0x20000U);
        }

        [Fact]
        public void A_64_bit_image_base_above_four_gigabytes_is_not_truncated()
        {
            // PE32+ widens ImageBase to eight bytes and drops BaseOfData, so every
            // field after it sits at a different offset than in PE32. Reading a 64-bit
            // header with 32-bit offsets truncates this to zero.
            PeHeaders headers = PeHeaders.Parse(PeBuilder.X64()
                .WithImageBase(0x00007FF6_12340000)
                .Build());

            headers.ImageBase.ShouldBe(0x00007FF6_12340000UL);
        }

        // ------------------------------------------------------- the mitigation bits

        [Fact]
        public void Aslr_is_read_from_the_dynamic_base_bit()
        {
            PeHeaders.Parse(PeBuilder.X86().With(PeBuilder.DynamicBase).Build())
                .HasAslr.ShouldBeTrue();

            PeHeaders.Parse(PeBuilder.X86().Build())
                .HasAslr.ShouldBeFalse();
        }

        [Fact]
        public void NxCompat_is_read_from_its_own_bit()
        {
            PeHeaders.Parse(PeBuilder.X86().With(PeBuilder.NxCompat).Build())
                .HasNxCompat.ShouldBeTrue();

            PeHeaders.Parse(PeBuilder.X86().Build())
                .HasNxCompat.ShouldBeFalse();
        }

        [Fact]
        public void NoSeh_is_read_from_its_own_bit()
        {
            PeHeaders.Parse(PeBuilder.X86().With(PeBuilder.NoSeh).Build())
                .HasNoSeh.ShouldBeTrue();

            PeHeaders.Parse(PeBuilder.X86().Build())
                .HasNoSeh.ShouldBeFalse();
        }

        [Fact]
        public void Each_mitigation_bit_is_read_independently_of_the_others()
        {
            // The bit walk this replaces assigned inside a plain "else", so every
            // iteration past the interesting bit reset the flag, and a module with
            // several flags set reported only whichever was tested last. On a 32-bit
            // target both ASLR and NXCompat always read as false.
            PeHeaders headers = PeHeaders.Parse(PeBuilder.X86()
                .With(PeBuilder.DynamicBase, PeBuilder.NxCompat, PeBuilder.NoSeh)
                .Build());

            headers.HasAslr.ShouldBeTrue();
            headers.HasNxCompat.ShouldBeTrue();
            headers.HasNoSeh.ShouldBeTrue();
        }

        [Fact]
        public void Unrelated_characteristic_bits_do_not_set_the_mitigation_flags()
        {
            // 0x8000 is TERMINAL_SERVER_AWARE, which says nothing about mitigations.
            PeHeaders headers = PeHeaders.Parse(PeBuilder.X86().WithDllCharacteristics(0x8000).Build());

            headers.HasAslr.ShouldBeFalse();
            headers.HasNxCompat.ShouldBeFalse();
            headers.HasNoSeh.ShouldBeFalse();
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void The_mitigation_bits_are_at_the_same_offset_in_both_forms(bool is64Bit)
        {
            PeBuilder builder = is64Bit ? PeBuilder.X64() : PeBuilder.X86();

            PeHeaders headers = PeHeaders.Parse(builder.With(PeBuilder.DynamicBase, PeBuilder.NxCompat).Build());

            headers.HasAslr.ShouldBeTrue();
            headers.HasNxCompat.ShouldBeTrue();
        }

        // ------------------------------------------------------------- load config

        [Fact]
        public void The_load_config_directory_is_read()
        {
            PeHeaders headers = PeHeaders.Parse(PeBuilder.X86().WithLoadConfig(0x3000, 0x40).Build());

            headers.LoadConfigTableRva.ShouldBe(0x3000U);
            headers.LoadConfigTableSize.ShouldBe(0x40U);
        }

        [Fact]
        public void An_image_with_no_load_config_reports_zero()
        {
            PeHeaders headers = PeHeaders.Parse(PeBuilder.X86().Build());

            headers.LoadConfigTableRva.ShouldBe(0U);
            headers.LoadConfigTableSize.ShouldBe(0U);
        }

        [Fact]
        public void An_image_declaring_fewer_directories_is_not_read_past_them()
        {
            // NumberOfRvaAndSizes may be less than 16, and then entry 10 does not
            // exist - what follows the optional header is the section table. Reading
            // it anyway yields a section name as an address.
            PeHeaders headers = PeHeaders.Parse(PeBuilder.X86()
                .WithDataDirectoryCount(2)
                .WithLoadConfig(0x3000, 0x40)
                .WithSection(".text", 0x1000, new byte[] { 0x90 })
                .Build());

            headers.LoadConfigTableRva.ShouldBe(0U);
            headers.LoadConfigTableSize.ShouldBe(0U);
        }

        // ------------------------------------------------------------ malformed input

        [Fact]
        public void A_null_image_is_refused()
        {
            PeHeaders? headers;
            string? error;

            PeHeaders.TryParse(null, out headers, out error).ShouldBeFalse();
            headers.ShouldBeNull();
            error.ShouldNotBeNullOrEmpty();
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(63)]
        public void A_file_too_short_for_a_dos_header_is_refused(int length)
        {
            // The original read a fixed 4096 bytes and ignored how many it actually
            // got, so a short file was parsed with the rest of the buffer left as
            // zeros.
            PeHeaders? headers;
            string? error;

            PeHeaders.TryParse(new byte[length], out headers, out error).ShouldBeFalse();
            error!.ShouldContain("too short");
        }

        [Fact]
        public void A_file_without_the_mz_signature_is_refused()
        {
            PeHeaders? headers;
            string? error;

            byte[] image = PeBuilder.X86().WithDosSignature(0x4242).Build();

            PeHeaders.TryParse(image, out headers, out error).ShouldBeFalse();
            error!.ShouldContain("MZ");
        }

        [Fact]
        public void A_file_without_the_pe_signature_is_refused()
        {
            PeHeaders? headers;
            string? error;

            byte[] image = PeBuilder.X86().WithNtSignature(0x41414141).Build();

            PeHeaders.TryParse(image, out headers, out error).ShouldBeFalse();
            error!.ShouldContain("PE");
        }

        [Theory]
        [InlineData(int.MaxValue)]
        [InlineData(0x7FFFFFF0)]
        [InlineData(100000)]
        [InlineData(-1)]
        [InlineData(int.MinValue)]
        public void A_header_offset_outside_the_file_is_refused_rather_than_followed(int lfanew)
        {
            // This is the read that was unbounded. The offset comes straight out of
            // the file, was added to the buffer pointer with no check, and the result
            // was dereferenced inside a fixed block.
            byte[] image = new byte[512];
            image[0] = 0x4D;                                        // 'M'
            image[1] = 0x5A;                                        // 'Z'
            BitConverter.GetBytes(lfanew).CopyTo(image, 60);

            PeHeaders? headers;
            string? error;

            PeHeaders.TryParse(image, out headers, out error).ShouldBeFalse();
            error!.ShouldContain("outside the file");
        }

        [Fact]
        public void A_header_offset_landing_just_short_of_the_end_is_refused()
        {
            // The bound has to leave room for the signature and the file header, not
            // merely be inside the buffer.
            byte[] image = new byte[512];
            image[0] = 0x4D;
            image[1] = 0x5A;
            BitConverter.GetBytes(image.Length - 8).CopyTo(image, 60);

            PeHeaders? headers;
            string? error;

            PeHeaders.TryParse(image, out headers, out error).ShouldBeFalse();
            error!.ShouldContain("outside the file");
        }

        [Fact]
        public void An_unsupported_machine_type_is_refused_by_name()
        {
            // 0x01C0 is ARM, which ERC has no support for.
            byte[] image = PeBuilder.X86().WithMachine(0x01C0).Build();

            PeHeaders? headers;
            string? error;

            PeHeaders.TryParse(image, out headers, out error).ShouldBeFalse();
            error!.ShouldContain("machine type");
        }

        [Fact]
        public void An_unrecognised_optional_header_magic_is_refused()
        {
            byte[] image = PeBuilder.X86().WithOptionalHeaderMagic(0x0107).Build();  // ROM image

            PeHeaders? headers;
            string? error;

            PeHeaders.TryParse(image, out headers, out error).ShouldBeFalse();
            error!.ShouldContain("magic");
        }

        [Fact]
        public void A_machine_type_disagreeing_with_the_optional_header_form_is_refused()
        {
            // Every field after ImageBase would otherwise be read at the wrong offset,
            // silently, producing plausible-looking nonsense.
            byte[] image = PeBuilder.X86().WithMachine(0x8664).Build();

            PeHeaders? headers;
            string? error;

            PeHeaders.TryParse(image, out headers, out error).ShouldBeFalse();
            error!.ShouldContain("does not match");
        }

        [Fact]
        public void An_optional_header_running_past_the_end_of_the_file_is_refused()
        {
            byte[] image = PeBuilder.X86().WithSizeOfOptionalHeader(4096).Build();

            PeHeaders? headers;
            string? error;

            PeHeaders.TryParse(image, out headers, out error).ShouldBeFalse();
            error!.ShouldContain("past the end");
        }

        [Fact]
        public void An_optional_header_too_short_for_the_fields_read_is_refused()
        {
            byte[] image = PeBuilder.X86().WithSizeOfOptionalHeader(32).Build();

            PeHeaders? headers;
            string? error;

            PeHeaders.TryParse(image, out headers, out error).ShouldBeFalse();
            error!.ShouldContain("too short");
        }

        [Fact]
        public void A_truncated_image_is_refused_at_every_length()
        {
            // Cutting a valid image short at each byte should always produce either
            // headers or an error - never an exception, and never a read past the end.
            byte[] complete = PeBuilder.X64().With(PeBuilder.DynamicBase).Build();

            for (int length = 0; length < complete.Length; length++)
            {
                byte[] truncated = complete.Take(length).ToArray();

                PeHeaders? headers;
                string? error;

                Should.NotThrow(() => PeHeaders.TryParse(truncated, out headers, out error),
                    "length " + length);
            }
        }

        [Fact]
        public void Random_bytes_are_refused_rather_than_parsed()
        {
            // Deterministic, so a failure can be reproduced.
            var random = new Random(20250814);

            for (int i = 0; i < 200; i++)
            {
                byte[] noise = new byte[random.Next(0, 1024)];
                random.NextBytes(noise);

                PeHeaders? headers;
                string? error;

                Should.NotThrow(() => PeHeaders.TryParse(noise, out headers, out error));
            }
        }

        [Fact]
        public void Parse_throws_with_the_reason_when_TryParse_would_have_failed()
        {
            var error = Should.Throw<ERCException>(() => PeHeaders.Parse(new byte[10]));

            error.Message.ShouldContain("too short");
        }

        // -------------------------------------------------------- sections and RVAs

        [Fact]
        public void The_section_table_is_read()
        {
            PeHeaders headers = PeHeaders.Parse(PeBuilder.X86()
                .WithSection(".text", 0x1000, new byte[] { 0x90, 0x90 })
                .WithSection(".rdata", 0x2000, new byte[] { 0xAA })
                .Build());

            headers.Sections.Count.ShouldBe(2);
            headers.Sections[0].Name.ShouldBe(".text");
            headers.Sections[0].VirtualAddress.ShouldBe(0x1000U);
            headers.Sections[1].Name.ShouldBe(".rdata");
            headers.Sections[1].VirtualAddress.ShouldBe(0x2000U);
        }

        [Fact]
        public void An_rva_inside_a_section_translates_to_the_bytes_at_that_address()
        {
            // A data directory records where its contents will be once loaded, not
            // where they are in the file, and the two differ because sections are
            // aligned differently on disk and in memory. Getting this wrong reads the
            // wrong part of the file, which is not an error - just wrong data.
            byte[] payload = { 0x11, 0x22, 0x33, 0x44 };

            byte[] image = PeBuilder.X86()
                .WithSection(".rdata", 0x2000, payload)
                .Build();

            PeHeaders headers = PeHeaders.Parse(image);

            int offset;
            headers.TryRvaToFileOffset(0x2000, out offset).ShouldBeTrue();

            image.Skip(offset).Take(4).ShouldBe(payload);
        }

        [Fact]
        public void An_rva_partway_into_a_section_keeps_its_offset()
        {
            byte[] payload = { 0x11, 0x22, 0x33, 0x44 };

            byte[] image = PeBuilder.X86().WithSection(".rdata", 0x2000, payload).Build();
            PeHeaders headers = PeHeaders.Parse(image);

            int start;
            int middle;
            headers.TryRvaToFileOffset(0x2000, out start).ShouldBeTrue();
            headers.TryRvaToFileOffset(0x2002, out middle).ShouldBeTrue();

            (middle - start).ShouldBe(2);
            image[middle].ShouldBe((byte)0x33);
        }

        [Fact]
        public void An_rva_covered_by_no_section_does_not_translate()
        {
            PeHeaders headers = PeHeaders.Parse(PeBuilder.X86()
                .WithSection(".text", 0x1000, new byte[] { 0x90 })
                .Build());

            int offset;
            headers.TryRvaToFileOffset(0x9000, out offset).ShouldBeFalse();
        }

        [Fact]
        public void A_zero_rva_does_not_translate()
        {
            // Zero means "absent" in a data directory, not "the start of the image".
            PeHeaders headers = PeHeaders.Parse(PeBuilder.X86()
                .WithSection(".text", 0x1000, new byte[] { 0x90 })
                .Build());

            int offset;
            headers.TryRvaToFileOffset(0, out offset).ShouldBeFalse();
        }

        // ------------------------------------------------------------- SafeSEH fields

        [Fact]
        public void The_safeseh_fields_are_read_from_a_load_config_directory()
        {
            byte[] loadConfig = LoadConfig32(handlerTable: 0x10041234, handlerCount: 7);

            uint table;
            uint count;

            PeHeaders.TryReadSafeSehFields(loadConfig, out table, out count).ShouldBeTrue();
            table.ShouldBe(0x10041234U);
            count.ShouldBe(7U);
        }

        [Fact]
        public void The_safeseh_fields_are_read_at_the_documented_offsets()
        {
            // The code this replaces read them at 58 and 62. The correct offsets are
            // 64 and 68, so it was reading the tail of EditList and the whole of
            // SecurityCookie - values that are usually non-zero, which would have made
            // every module look SafeSEH-protected had the result been used.
            byte[] loadConfig = new byte[72];
            BitConverter.GetBytes(72U).CopyTo(loadConfig, 0);          // Size
            BitConverter.GetBytes(0xDEADBEEFU).CopyTo(loadConfig, 60); // SecurityCookie
            BitConverter.GetBytes(0x10041234U).CopyTo(loadConfig, 64); // SEHandlerTable
            BitConverter.GetBytes(7U).CopyTo(loadConfig, 68);          // SEHandlerCount

            uint table;
            uint count;

            PeHeaders.TryReadSafeSehFields(loadConfig, out table, out count).ShouldBeTrue();
            table.ShouldBe(0x10041234U);
            table.ShouldNotBe(0xDEADBEEFU);
            count.ShouldBe(7U);
        }

        [Fact]
        public void A_load_config_too_short_for_the_fields_is_refused()
        {
            uint table;
            uint count;

            PeHeaders.TryReadSafeSehFields(new byte[40], out table, out count).ShouldBeFalse();
            PeHeaders.TryReadSafeSehFields(null, out table, out count).ShouldBeFalse();
        }

        [Fact]
        public void A_load_config_declaring_itself_shorter_than_the_fields_is_refused()
        {
            // The directory grew over the years; one that predates SafeSEH says so in
            // its own Size field even when the buffer around it is longer.
            byte[] loadConfig = new byte[72];
            BitConverter.GetBytes(40U).CopyTo(loadConfig, 0);
            BitConverter.GetBytes(0x10041234U).CopyTo(loadConfig, 64);

            uint table;
            uint count;

            PeHeaders.TryReadSafeSehFields(loadConfig, out table, out count).ShouldBeFalse();
            table.ShouldBe(0U);
        }

        [Fact]
        public void A_module_with_a_handler_table_reports_SafeSEH_end_to_end()
        {
            // Header parsing, RVA translation and the load config read, together:
            // exactly the path ModuleInfo takes for a 32-bit module.
            byte[] loadConfig = LoadConfig32(handlerTable: 0x00401000, handlerCount: 12);

            byte[] image = PeBuilder.X86()
                .WithLoadConfig(0x2000, (uint)loadConfig.Length)
                .WithSection(".rdata", 0x2000, loadConfig)
                .Build();

            PeHeaders headers = PeHeaders.Parse(image);

            int offset;
            headers.TryRvaToFileOffset(headers.LoadConfigTableRva, out offset).ShouldBeTrue();

            uint table;
            uint count;
            PeHeaders.TryReadSafeSehFields(image.Skip(offset).Take(72).ToArray(), out table, out count)
                .ShouldBeTrue();

            PeCharacteristics.HasSafeSeh(headers.DllCharacteristics, table, count).ShouldBeTrue();
        }

        [Fact]
        public void A_module_without_a_handler_table_does_not_report_SafeSEH()
        {
            byte[] loadConfig = LoadConfig32(handlerTable: 0, handlerCount: 0);

            byte[] image = PeBuilder.X86()
                .WithLoadConfig(0x2000, (uint)loadConfig.Length)
                .WithSection(".rdata", 0x2000, loadConfig)
                .Build();

            PeHeaders headers = PeHeaders.Parse(image);

            int offset;
            headers.TryRvaToFileOffset(headers.LoadConfigTableRva, out offset).ShouldBeTrue();

            uint table;
            uint count;
            PeHeaders.TryReadSafeSehFields(image.Skip(offset).Take(72).ToArray(), out table, out count);

            PeCharacteristics.HasSafeSeh(headers.DllCharacteristics, table, count).ShouldBeFalse();
        }

        private static byte[] LoadConfig32(uint handlerTable, uint handlerCount)
        {
            var loadConfig = new byte[72];
            BitConverter.GetBytes((uint)loadConfig.Length).CopyTo(loadConfig, 0);
            BitConverter.GetBytes(handlerTable).CopyTo(loadConfig, 64);
            BitConverter.GetBytes(handlerCount).CopyTo(loadConfig, 68);
            return loadConfig;
        }

        // ----------------------------------------------------------- the real thing

        [Fact]
        public void The_headers_of_a_real_module_on_this_machine_are_read()
        {
            // The synthetic images above are only useful if they agree with what a
            // real linker produces, so one real file is parsed too.
            string kernel32 = Path.Combine(Environment.SystemDirectory, "kernel32.dll");

            if (!File.Exists(kernel32))
            {
                return;
            }

            byte[] image = ReadPrefix(kernel32, 4096);
            PeHeaders headers = PeHeaders.Parse(image);

            // Every Windows system DLL has opted in to both of these for many years.
            headers.HasAslr.ShouldBeTrue();
            headers.HasNxCompat.ShouldBeTrue();
            headers.SizeOfImage.ShouldBeGreaterThan(0U);
            headers.LoadConfigTableRva.ShouldBeGreaterThan(0U);

            // Environment.SystemDirectory is subject to WOW64 redirection: a 32-bit
            // process reading it gets SysWOW64 and therefore the 32-bit kernel32, so
            // the discriminator is this process's pointer size, not the OS bitness.
            headers.MachineType.ShouldBe(IntPtr.Size == 8
                ? MachineType.x64
                : MachineType.I386);
        }

        private static byte[] ReadPrefix(string path, int count)
        {
            using (var file = File.OpenRead(path))
            {
                var buffer = new byte[count];
                int read = 0;

                // Read returns what it has, not what was asked for.
                while (read < count)
                {
                    int got = file.Read(buffer, read, count - read);
                    if (got == 0)
                    {
                        break;
                    }

                    read += got;
                }

                return read == count ? buffer : buffer.Take(read).ToArray();
            }
        }
    }
}
