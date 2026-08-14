using System;
using System.IO;
using ERC;
using ERC.Config;
using ERC.Output;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Tests for the output seam, which lets the display and formatting code be
    /// exercised without writing files.
    /// </summary>
    public class OutputSinkTests
    {
        private static ErcCore CoreWith(InMemoryOutputSink sink, string workingDirectory)
        {
            var config = ErcConfig.CreateDefault(workingDirectory);
            return new ErcCore(new InMemoryConfigStore(config), new InMemoryErcLogger(), null, sink);
        }

        [Fact]
        public void ErcCore_writes_to_the_filesystem_by_default()
        {
            var core = new ErcCore(new InMemoryConfigStore(), new InMemoryErcLogger());

            core.Output.ShouldBeOfType<FileOutputSink>();
        }

        [Fact]
        public void Egg_hunter_output_can_be_captured_without_writing_a_file()
        {
            // Previously this wrote straight to disk, so there was no way to assert on
            // the generated text without creating files in the working directory.
            string scratch = Path.Combine(Path.GetTempPath(), "erc-sink-" + Guid.NewGuid().ToString("N")) + "\\";
            var sink = new InMemoryOutputSink();
            var core = CoreWith(sink, scratch);

            string displayed = DisplayOutput.GenerateEggHunters(core, "ABCD");

            displayed.ShouldContain("Egg Hunter");
            sink.Files.Count.ShouldBe(1);
            sink.ContentMatching("Egg_Hunters_").ShouldContain("Egg Hunter");

            // And nothing reached the filesystem.
            Directory.Exists(scratch).ShouldBeFalse();
        }

        [Fact]
        public void Pattern_output_can_be_captured_without_writing_a_file()
        {
            string scratch = Path.Combine(Path.GetTempPath(), "erc-sink-" + Guid.NewGuid().ToString("N")) + "\\";
            var sink = new InMemoryOutputSink();
            var core = CoreWith(sink, scratch);

            string pattern = DisplayOutput.GeneratePattern(20, core);

            pattern.ShouldContain("Aa0");
            sink.ContentMatching("Pattern_Create_").ShouldContain("Aa0");
            Directory.Exists(scratch).ShouldBeFalse();
        }

        // ------------------------------------------------- file numbering

        [Fact]
        public void NextFilePath_starts_at_one_in_an_empty_directory()
        {
            string directory = Path.Combine(Path.GetTempPath(), "erc-num-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);

            try
            {
                new FileOutputSink().NextFilePath(directory, "modules_", ".txt")
                    .ShouldBe(Path.Combine(directory, "modules_1.txt"));
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public void NextFilePath_follows_the_highest_number_already_present()
        {
            string directory = Path.Combine(Path.GetTempPath(), "erc-num-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);

            try
            {
                File.WriteAllText(Path.Combine(directory, "modules_1.txt"), "x");
                File.WriteAllText(Path.Combine(directory, "modules_7.txt"), "x");

                new FileOutputSink().NextFilePath(directory, "modules_", ".txt")
                    .ShouldBe(Path.Combine(directory, "modules_8.txt"));
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public void NextFilePath_ignores_a_matching_file_with_no_number()
        {
            // The previous implementation ran int.Parse over a possibly-empty regex
            // match, so a file like this threw a FormatException and took the whole
            // command down rather than producing output.
            string directory = Path.Combine(Path.GetTempPath(), "erc-num-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);

            try
            {
                File.WriteAllText(Path.Combine(directory, "modules_backup.txt"), "x");

                string? next = null;
                Should.NotThrow(() => next = new FileOutputSink().NextFilePath(directory, "modules_", ".txt"));
                next.ShouldBe(Path.Combine(directory, "modules_1.txt"));
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public void NextFilePath_joins_the_path_properly_without_a_trailing_separator()
        {
            // The old version concatenated directory + prefix, producing
            // "C:\tempmodules_1.txt" when the directory had no trailing separator.
            string directory = Path.Combine(Path.GetTempPath(), "erc-num-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);

            try
            {
                string next = new FileOutputSink().NextFilePath(directory, "modules_", ".txt");

                Path.GetDirectoryName(next).ShouldBe(directory);
                Path.GetFileName(next).ShouldBe("modules_1.txt");
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public void FileOutputSink_reports_failure_rather_than_throwing()
        {
            string directory = Path.Combine(Path.GetTempPath(), "erc-sink-fail-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            string asDirectory = Path.Combine(directory, "occupied.txt");
            Directory.CreateDirectory(asDirectory);

            try
            {
                var sink = new FileOutputSink();
                sink.WriteText(asDirectory, "content").ShouldBeFalse();
                sink.WriteLines(asDirectory, new[] { "a", "b" }).ShouldBeFalse();
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        // ------------------------------------------------- in-memory sink

        [Fact]
        public void InMemoryOutputSink_numbers_files_independently_per_prefix()
        {
            var sink = new InMemoryOutputSink();

            sink.NextFilePath(@"C:\out", "a_", ".txt").ShouldEndWith("a_1.txt");
            sink.NextFilePath(@"C:\out", "a_", ".txt").ShouldEndWith("a_2.txt");
            sink.NextFilePath(@"C:\out", "b_", ".txt").ShouldEndWith("b_1.txt");
        }

        [Fact]
        public void InMemoryOutputSink_records_lines_with_newlines()
        {
            var sink = new InMemoryOutputSink();

            sink.WriteLines(@"C:\out\f.txt", new[] { "first", "second" });

            sink.ContentMatching("f.txt").ShouldBe("first" + Environment.NewLine + "second" + Environment.NewLine);
        }

        [Fact]
        public void ContentMatching_complains_when_the_fragment_is_ambiguous()
        {
            var sink = new InMemoryOutputSink();
            sink.WriteText(@"C:\out\one.txt", "a");
            sink.WriteText(@"C:\out\two.txt", "b");

            // Better to fail than to silently assert against whichever came first.
            Should.Throw<InvalidOperationException>(() => sink.ContentMatching(".txt"));
            Should.Throw<InvalidOperationException>(() => sink.ContentMatching("nothing"));
        }
    }
}
