using System;
using System.IO;
using ERC;
using ERC.Config;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Tests for the configuration seam introduced in phase 02.
    /// </summary>
    public class ConfigStoreTests
    {
        private static ErcConfig SampleConfig(string directory)
        {
            return new ErcConfig
            {
                WorkingDirectory    = directory,
                Author              = "Test Author",
                PatternStandardPath = Path.Combine(directory, "Pattern_Standard"),
                PatternExtendedPath = Path.Combine(directory, "Pattern_Extended"),
                SystemErrorLogPath  = Path.Combine(directory, "System_Error.LOG")
            };
        }

        // ------------------------------------------------- the phase 02 gate

        [Fact]
        public void ErcCore_can_be_constructed_without_touching_the_filesystem()
        {
            // The central point of phase 02. Constructing an ErcCore used to read and
            // write an XML config, derive its own working directory, and generate two
            // pattern files, which is why nothing that depended on it could be tested.
            var scratch = Path.Combine(Path.GetTempPath(), "erc-config-gate-" + Guid.NewGuid().ToString("N"));

            var store = new InMemoryConfigStore(SampleConfig(scratch));
            var core = new ErcCore(store, new InMemoryErcLogger());

            core.WorkingDirectory.ShouldBe(scratch);
            core.Author.ShouldBe("Test Author");

            // Nothing was created anywhere.
            Directory.Exists(scratch).ShouldBeFalse();
        }

        [Fact]
        public void ErcCore_with_an_empty_store_falls_back_to_defaults_and_saves_them()
        {
            var store = new InMemoryConfigStore();

            var core = new ErcCore(store, new InMemoryErcLogger());

            core.WorkingDirectory.ShouldNotBeNullOrEmpty();
            core.Author.ShouldBe("No_Author_Set");
            store.SaveCount.ShouldBe(1);
            store.Load().ShouldNotBeNull();
        }

        [Fact]
        public void ErcCore_reports_its_version_without_any_store_content()
        {
            var core = new ErcCore(new InMemoryConfigStore(), new InMemoryErcLogger());

            core.ErcVersion.ShouldStartWith("ERC.Xdbg_");
        }

        [Fact]
        public void Setters_persist_through_the_store()
        {
            var store = new InMemoryConfigStore(SampleConfig(Path.GetTempPath()));
            var core = new ErcCore(store, new InMemoryErcLogger());

            core.SetAuthor("Someone Else");

            core.Author.ShouldBe("Someone Else");
            store.Load().ShouldNotBeNull().Author.ShouldBe("Someone Else");
        }

        [Fact]
        public void SetWorkingDirectory_rejects_a_directory_that_does_not_exist()
        {
            var core = new ErcCore(new InMemoryConfigStore(), new InMemoryErcLogger());

            Should.Throw<ERCException>(
                () => core.SetWorkingDirectory(Path.Combine(Path.GetTempPath(), "definitely-not-here-" + Guid.NewGuid().ToString("N"))));
        }

        // ------------------------------------------------- logging seam

        [Fact]
        public void Errors_go_to_the_supplied_logger_rather_than_a_file()
        {
            var logger = new InMemoryErcLogger();
            var core = new ErcCore(new InMemoryConfigStore(), logger);

            core.LogEvent(new ERCException("a distinctive marker 91b2"));

            logger.Messages.Count.ShouldBe(1);
            logger.Messages[0].ShouldContain("91b2");
        }

        [Fact]
        public void A_result_logs_where_its_core_logs()
        {
            var logger = new InMemoryErcLogger();
            var core = new ErcCore(new InMemoryConfigStore(), logger);

            var result = new ErcResult<string>(core) { Error = new ERCException("marker c4d5") };
            result.LogEvent();

            logger.Messages.Count.ShouldBe(1);
            logger.Messages[0].ShouldContain("c4d5");
        }

        [Fact]
        public void FileErcLogger_never_throws_when_the_target_is_unusable()
        {
            // A directory where a file should be: unopenable, but logging must not
            // raise from the error path.
            string path = Path.Combine(Path.GetTempPath(), "erc-logger-dir-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);

            try
            {
                Should.NotThrow(() => new FileErcLogger(path).Log("anything"));
            }
            finally
            {
                Directory.Delete(path, recursive: true);
            }
        }

        // ------------------------------------------------- XML round trip

        [Fact]
        public void XmlConfigStore_round_trips_a_configuration()
        {
            string directory = Path.Combine(Path.GetTempPath(), "erc-xml-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            string file = Path.Combine(directory, "ERC_Config.XML");

            try
            {
                var store = new XmlConfigStore(file);
                store.Load().ShouldBeNull("nothing saved yet");

                ErcConfig written = SampleConfig(directory);
                store.Save(written).ShouldBeTrue();

                ErcConfig? read = store.Load();
                read.ShouldNotBeNull();
                read.WorkingDirectory.ShouldBe(written.WorkingDirectory);
                read.Author.ShouldBe(written.Author);
                read.PatternStandardPath.ShouldBe(written.PatternStandardPath);
                read.PatternExtendedPath.ShouldBe(written.PatternExtendedPath);
                read.SystemErrorLogPath.ShouldBe(written.SystemErrorLogPath);
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public void XmlConfigStore_keeps_the_documented_element_names()
        {
            // The format must stay readable by, and writable for, existing installs.
            string directory = Path.Combine(Path.GetTempPath(), "erc-xml-fmt-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            string file = Path.Combine(directory, "ERC_Config.XML");

            try
            {
                new XmlConfigStore(file).Save(SampleConfig(directory));

                string xml = File.ReadAllText(file);
                xml.ShouldContain("<Working_Directory>");
                xml.ShouldContain("<Author>");
                xml.ShouldContain("<Standard_Pattern>");
                xml.ShouldContain("<Extended_Pattern>");
                xml.ShouldContain("<Error_Log_File>");
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public void XmlConfigStore_treats_a_malformed_file_as_absent()
        {
            string directory = Path.Combine(Path.GetTempPath(), "erc-xml-bad-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            string file = Path.Combine(directory, "ERC_Config.XML");
            File.WriteAllText(file, "this is not xml <<<");

            try
            {
                // Returning null rather than throwing is what stops a corrupt config
                // from preventing the plugin loading.
                new XmlConfigStore(file).Load().ShouldBeNull();
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public void XmlConfigStore_reports_failure_rather_than_throwing_when_it_cannot_save()
        {
            // A directory occupying the config file's path makes saving impossible.
            string directory = Path.Combine(Path.GetTempPath(), "erc-xml-ro-" + Guid.NewGuid().ToString("N"));
            string file = Path.Combine(directory, "ERC_Config.XML");
            Directory.CreateDirectory(file);

            try
            {
                new XmlConfigStore(file).Save(SampleConfig(directory)).ShouldBeFalse();
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public void ErcCore_survives_a_store_that_cannot_save()
        {
            string directory = Path.Combine(Path.GetTempPath(), "erc-core-ro-" + Guid.NewGuid().ToString("N"));
            string file = Path.Combine(directory, "ERC_Config.XML");
            Directory.CreateDirectory(file);

            try
            {
                ErcCore? core = null;
                Should.NotThrow(() => core = new ErcCore(new XmlConfigStore(file), new InMemoryErcLogger()));

                core.ShouldNotBeNull();
                core.WorkingDirectory.ShouldNotBeNullOrEmpty();
                core.SystemError.ShouldNotBeNull("the failure to persist should be recorded");
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        // ------------------------------------------------- config value object

        [Fact]
        public void Clone_produces_an_independent_copy()
        {
            ErcConfig original = SampleConfig(@"C:\somewhere");
            ErcConfig copy = original.Clone();

            copy.Author = "changed";

            original.Author.ShouldBe("Test Author");
        }

        [Fact]
        public void InMemoryConfigStore_does_not_alias_what_it_is_given()
        {
            ErcConfig seed = SampleConfig(@"C:\somewhere");
            var store = new InMemoryConfigStore(seed);

            seed.Author = "mutated after handing over";

            store.Load().ShouldNotBeNull().Author.ShouldBe("Test Author");
        }

        [Fact]
        public void CreateDefault_appends_a_trailing_separator()
        {
            ErcConfig.CreateDefault(@"C:\somewhere").WorkingDirectory.ShouldBe(@"C:\somewhere\");
            ErcConfig.CreateDefault(@"C:\somewhere\").WorkingDirectory.ShouldBe(@"C:\somewhere\");
        }

        [Fact]
        public void DefaultPath_is_a_file_in_the_default_directory()
        {
            // "ERC --reset" deletes this file. It used to build the path itself, and
            // built it wrong: a directory joined to a file name with no separator, and
            // the extension in the wrong case. File.Delete does nothing when the file
            // is absent, so the command reported success and changed nothing.
            string path = XmlConfigStore.DefaultPath();

            Path.IsPathRooted(path).ShouldBeTrue(path);
            Path.GetFileName(path).ShouldNotBeNullOrEmpty();
            Path.GetDirectoryName(path).ShouldBe(
                XmlConfigStore.DefaultDirectory().TrimEnd(Path.DirectorySeparatorChar));
        }

        [Fact]
        public void DefaultPath_is_the_file_a_store_built_from_it_uses()
        {
            // The plugin deletes DefaultPath() while the store loads from its own
            // Path, so the two have to name the same file. This is the path the
            // parameterless ErcCore constructor passes.
            new XmlConfigStore(XmlConfigStore.DefaultPath()).Path
                .ShouldBe(XmlConfigStore.DefaultPath());
        }

        [Fact]
        public void A_store_round_trips_through_its_default_named_file()
        {
            // Deleting DefaultPath() has to actually remove a saved configuration.
            // Exercised in a temporary directory rather than the real one.
            string directory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            Directory.CreateDirectory(directory);

            try
            {
                string path = Path.Combine(directory, Path.GetFileName(XmlConfigStore.DefaultPath()));
                var store = new XmlConfigStore(path);

                store.Save(ErcConfig.CreateDefault(directory)).ShouldBeTrue();
                File.Exists(path).ShouldBeTrue(path);

                File.Delete(path);
                store.Load().ShouldBeNull();
            }
            finally
            {
                Directory.Delete(directory, true);
            }
        }
    }
}
