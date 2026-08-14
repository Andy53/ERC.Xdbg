using System;
using System.IO;
using System.Reflection;
using ERC.Config;
using ERC.Native;
using ERC.Output;
using System.Runtime.CompilerServices;

// The ROP chain builders are internal and depend on a gadget table that is only
// populated by scanning a live process. Exposing them to the test assembly lets a
// test supply a fixed table instead, which is what makes the generated chains
// reproducible enough to compare against a recorded one.
[assembly: InternalsVisibleTo("ERC.Net.Tests")]

namespace ERC
{
    /// <summary>
    /// Holds the library's configuration. A single instance should be created and
    /// shared by the objects that need it.
    /// </summary>
    /// <remarks>
    /// Constructing this no longer touches the filesystem. Settings arrive through
    /// an <see cref="IConfigStore"/>, and the pattern files are generated on first
    /// use rather than up front.
    ///
    /// The old constructor read and wrote an XML file, derived its own working
    /// directory from Assembly.CodeBase, generated ~87 KB of pattern files, and in
    /// some failure modes spun forever or called Environment.Exit. That made the
    /// type impossible to use in a read-only directory and impossible to test.
    /// </remarks>
    public class ErcCore
    {
        #region Class Variables

        private readonly IConfigStore _configStore;
        // Every field of _config is non-null once the constructor has run:
        // a stored config has its gaps filled from ErcConfig.CreateDefault, and
        // an absent one is replaced by CreateDefault outright. That is why the
        // properties below can present them as non-null.
        private readonly ErcConfig _config;
        private bool _patternFilesChecked;

        /// <summary>
        /// The current version of the ERC.Net library.
        /// </summary>
        public string ErcVersion { get; }

        /// <summary>
        /// The directory where output files will be saved.
        /// </summary>
        public string WorkingDirectory
        {
            get { return _config.WorkingDirectory!; }
            internal set { _config.WorkingDirectory = value; }
        }

        /// <summary>
        /// The author to be credited in output files.
        /// </summary>
        public string Author
        {
            get { return _config.Author!; }
            set { _config.Author = value; }
        }

        /// <summary>
        /// Path where error details should be logged.
        /// </summary>
        public string SystemErrorLogPath
        {
            get { return _config.SystemErrorLogPath!; }
            set { _config.SystemErrorLogPath = value; }
        }

        /// <summary>
        /// Path to the file containing the standard pattern.
        /// </summary>
        /// <remarks>
        /// Reading this generates the pattern file if it is missing. Generation is
        /// deferred so that constructing an ErcCore has no side effects.
        /// </remarks>
        public string PatternStandardPath
        {
            get { EnsurePatternFiles(); return _config.PatternStandardPath!; }
            set { _config.PatternStandardPath = value; }
        }

        /// <summary>
        /// Path to the file containing the extended pattern.
        /// </summary>
        /// <remarks>
        /// Reading this generates the pattern file if it is missing.
        /// </remarks>
        public string PatternExtendedPath
        {
            get { EnsurePatternFiles(); return _config.PatternExtendedPath!; }
            set { _config.PatternExtendedPath = value; }
        }

        /// <summary>
        /// Where this instance reports errors.
        /// </summary>
        public IErcLogger Logger { get; }

        /// <summary>
        /// The operating system calls this instance makes.
        /// </summary>
        /// <remarks>
        /// Defaults to the real Win32 API. Supplying a substitute is what allows the
        /// process, module, thread and heap code to be tested without a live target.
        /// </remarks>
        public INativeApi Native { get; }

        /// <summary>
        /// Where generated output is written.
        /// </summary>
        /// <remarks>
        /// Defaults to the filesystem. Supplying a substitute lets the display and
        /// formatting code be exercised without creating files.
        /// </remarks>
        public IOutputSink Output { get; }

        /// <summary>
        /// The most recent internal failure, for diagnostics.
        /// </summary>
        public Exception? SystemError { get; private set; }

        #endregion

        #region Constructors

        /// <summary>
        /// Creates an instance backed by ERC_Config.XML beside the running assembly.
        /// </summary>
        public ErcCore()
            : this(new XmlConfigStore(XmlConfigStore.DefaultPath()), null)
        {
        }

        /// <summary>
        /// Creates an instance backed by the supplied configuration store.
        /// </summary>
        /// <param name="configStore">Where settings are read from and written to.</param>
        public ErcCore(IConfigStore configStore)
            : this(configStore, null)
        {
        }

        /// <summary>
        /// Creates an instance with an explicit configuration store and logger.
        /// </summary>
        /// <param name="configStore">Where settings are read from and written to.</param>
        /// <param name="logger">Where errors are reported. Defaults to the configured log file.</param>
        public ErcCore(IConfigStore configStore, IErcLogger? logger)
            : this(configStore, logger, null)
        {
        }

        /// <summary>
        /// Creates an instance with explicit configuration, logging and OS access.
        /// </summary>
        /// <param name="configStore">Where settings are read from and written to.</param>
        /// <param name="logger">Where errors are reported. Defaults to the configured log file.</param>
        /// <param name="native">The OS calls to use. Defaults to the real Win32 API.</param>
        public ErcCore(IConfigStore configStore, IErcLogger? logger, INativeApi? native)
            : this(configStore, logger, native, null)
        {
        }

        /// <summary>
        /// Creates an instance with explicit configuration, logging, OS access and
        /// output destination.
        /// </summary>
        /// <param name="configStore">Where settings are read from and written to.</param>
        /// <param name="logger">Where errors are reported. Defaults to the configured log file.</param>
        /// <param name="native">The OS calls to use. Defaults to the real Win32 API.</param>
        /// <param name="output">Where output is written. Defaults to the filesystem.</param>
        public ErcCore(IConfigStore configStore, IErcLogger? logger, INativeApi? native, IOutputSink? output)
        {
            if (configStore == null)
            {
                throw new ArgumentNullException("configStore");
            }

            _configStore = configStore;
            ErcVersion = BuildVersionString();

            ErcConfig defaults = ErcConfig.CreateDefault(DefaultWorkingDirectory(configStore));
            ErcConfig? stored = configStore.Load();

            if (stored == null)
            {
                _config = defaults;

                // Best effort. A store that cannot persist - a read-only plugin
                // directory, say - is a normal deployment, not a fatal error.
                if (!configStore.Save(_config))
                {
                    SystemError = new ERCException(
                        "Configuration could not be saved; running with defaults held in memory.");
                }
            }
            else
            {
                stored.FillGapsFrom(defaults);
                _config = stored;
            }

            Logger = logger ?? new FileErcLogger(_config.SystemErrorLogPath);
            Native = native ?? Win32NativeApi.Instance;
            Output = output ?? new FileOutputSink();
        }

        /// <summary>
        /// Constructor used by objects that derive their settings from an existing
        /// instance.
        /// </summary>
        /// <param name="parent">The instance to take settings from.</param>
        protected ErcCore(ErcCore parent)
        {
            if (parent == null)
            {
                throw new ArgumentNullException("parent");
            }

            _configStore = parent._configStore;
            _config = parent._config;             // shared, so setters propagate
            _patternFilesChecked = parent._patternFilesChecked;
            ErcVersion = parent.ErcVersion;
            Logger = parent.Logger;
            Native = parent.Native;
            Output = parent.Output;
        }

        private static string DefaultWorkingDirectory(IConfigStore configStore)
        {
            // An XML store knows where it lives, so its directory is the natural
            // default. Anything else falls back to the assembly's own directory.
            var xmlStore = configStore as XmlConfigStore;
            if (xmlStore != null)
            {
                string? directory = Path.GetDirectoryName(xmlStore.Path);
                if (!string.IsNullOrEmpty(directory))
                {
                    return directory;
                }
            }

            return XmlConfigStore.DefaultDirectory();
        }

        #endregion

        #region Pattern files

        /// <summary>
        /// Generates the pattern files if they are not already present.
        /// </summary>
        /// <remarks>
        /// Deferred rather than done in the constructor, so creating an ErcCore is
        /// free of side effects. Runs at most once per instance.
        ///
        /// Failures are recorded rather than thrown: the previous version called
        /// Environment.Exit(1) here, terminating the debugger from inside a library.
        /// </remarks>
        public void EnsurePatternFiles()
        {
            if (_patternFilesChecked)
            {
                return;
            }

            _patternFilesChecked = true;

            _config.PatternStandardPath = EnsurePatternFile(
                _config.PatternStandardPath, "Pattern_Standard", 20277, false);
            _config.PatternExtendedPath = EnsurePatternFile(
                _config.PatternExtendedPath, "Pattern_Extended", 66923, true);
        }

        private string EnsurePatternFile(string? configuredPath, string defaultFileName, int length, bool extended)
        {
            // The "!" states what IsNullOrEmpty already guarantees. On net472 the base
            // class library carries no nullable annotations, so the compiler cannot
            // infer it from the check alone.
            string path = string.IsNullOrEmpty(configuredPath)
                ? Path.Combine(_config.WorkingDirectory ?? string.Empty, defaultFileName)
                : configuredPath!;

            if (File.Exists(path))
            {
                return path;
            }

            var pattern = Utilities.PatternTools.PatternCreate(length, this, extended);
            if (pattern.Error != null)
            {
                SystemError = pattern.Error;
                pattern.LogEvent();
                return path;
            }

            try
            {
                File.WriteAllText(path, pattern.ReturnValue);
            }
            catch (Exception e)
            {
                SystemError = e;
                LogEvent(e);
            }

            return path;
        }

        #endregion

        #region Variable Setters

        /// <summary>
        /// Changes the working directory, in the config store and in this instance.
        /// </summary>
        /// <param name="path">An existing directory.</param>
        public void SetWorkingDirectory(string? path)
        {
            if (!Directory.Exists(path))
            {
                throw new ERCException(
                    "User Input Error: Value supplied for working directory is not a valid directory: " + path);
            }

            if (path != null && !path.EndsWith("\\", StringComparison.Ordinal))
            {
                path += "\\";
            }

            _config.WorkingDirectory = path;
            Persist();
        }

        /// <summary>
        /// Sets the standard pattern file path. Any pattern can replace the standard
        /// pattern when searching, but it must be written to a file first.
        /// </summary>
        /// <param name="path">The filepath of the new standard pattern file.</param>
        public void SetPatternStandardPath(string? path)
        {
            ValidatePatternPath(path, "standard pattern");
            _config.PatternStandardPath = path;
            Persist();
        }

        /// <summary>
        /// Sets the extended pattern file path.
        /// </summary>
        /// <param name="path">The filepath of the new extended pattern file.</param>
        public void SetPatternExtendedPath(string? path)
        {
            ValidatePatternPath(path, "extended pattern");
            _config.PatternExtendedPath = path;
            Persist();
        }

        /// <summary>
        /// Sets the name of the author, used when writing results to disk.
        /// </summary>
        /// <param name="author">The name to credit.</param>
        public void SetAuthor(string author)
        {
            _config.Author = author;
            Persist();
        }

        /// <summary>
        /// Sets the error log file.
        /// </summary>
        /// <param name="path">
        /// An existing file, a directory to create the log in, or a path whose parent
        /// directory exists. Anything else falls back to the working directory.
        /// </param>
        public void SetErrorFile(string? path)
        {
            string resolved = ResolveLogPath(path);

            if (!File.Exists(resolved))
            {
                // "using" so the handle is closed. The previous version called
                // File.Create without disposing, leaving the new log locked.
                using (File.Create(resolved))
                {
                }
            }

            _config.SystemErrorLogPath = resolved;
            Persist();
        }

        private string ResolveLogPath(string? path)
        {
            if (path != null && File.Exists(path))
            {
                return path;
            }

            if (path != null && Directory.Exists(path))
            {
                return Path.Combine(path, "System_Error.LOG");
            }

            if (path != null && !string.IsNullOrWhiteSpace(path))
            {
                string? parent = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(parent) && Directory.Exists(parent))
                {
                    return path;
                }
            }

            return Path.Combine(WorkingDirectory, "System_Error.LOG");
        }

        /// <summary>
        /// Rejects a pattern path that is not an existing file.
        /// </summary>
        /// <remarks>
        /// Both pattern setters used to validate with Directory.Exists and then
        /// append a trailing backslash, even though what they are given - and what
        /// PatternOffset later reads with File.ReadAllText - is a *file* path. Every
        /// correct input was rejected, so "ERC --config SetStandardPattern" could not
        /// be made to work at all despite being documented.
        /// </remarks>
        private static void ValidatePatternPath(string? path, string description)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ERCException(
                    "User Input Error: No value supplied for the " + description + " file path.");
            }

            if (!File.Exists(path))
            {
                throw new ERCException(
                    "User Input Error: Value supplied for the " + description +
                    " file path is not an existing file: " + path);
            }
        }

        private void Persist()
        {
            if (!_configStore.Save(_config))
            {
                SystemError = new ERCException("Configuration could not be saved.");
            }
        }

        #endregion

        #region Logging

        /// <summary>
        /// Logs an exception. The log is only ever appended to.
        /// </summary>
        /// <param name="e">The exception to log.</param>
        public void LogEvent(Exception e)
        {
            Logger.Log(e == null ? "<null exception>" : e.ToString());
        }

        #endregion

        #region Version

        /// <summary>
        /// Builds the version banner, for example "ERC.Xdbg_64-2.0.3".
        /// </summary>
        /// <remarks>
        /// Both halves are derived rather than hand-edited per build. The bitness
        /// comes from the process this assembly is loaded into, and the version from
        /// the assembly itself, which the build stamps from a single place.
        /// </remarks>
        private static string BuildVersionString()
        {
            string architecture = IntPtr.Size == 8 ? "64" : "32";

            Assembly assembly = Assembly.GetExecutingAssembly();
            string? version = assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;

            if (string.IsNullOrEmpty(version))
            {
                // AssemblyVersion is always stamped, but the reflection API cannot
                // promise it, and a version-less banner is better than a crash.
                Version? assemblyVersion = assembly.GetName().Version;
                version = assemblyVersion == null ? "unknown" : assemblyVersion.ToString();
            }

            // Source-linked builds append "+<commit sha>"; keep the banner readable.
            int metadata = version!.IndexOf('+');
            if (metadata > 0)
            {
                version = version.Substring(0, metadata);
            }

            return "ERC.Xdbg_" + architecture + "-" + version;
        }

        #endregion

        #region Helpers

        /// <summary>
        /// Converts an x64 pointer into an x86 pointer.
        /// </summary>
        /// <param name="ptr64">64 bit pointer to be converted.</param>
        /// <returns>A four byte array containing the modified pointer.</returns>
        internal static byte[] X64toX32PointerModifier(byte[] ptr64)
        {
            byte[] ptr32 = new byte[4];
            Array.Copy(ptr64, 0, ptr32, 0, 4);
            return ptr32;
        }

        #endregion
    }
}
