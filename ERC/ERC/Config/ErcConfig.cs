using System;
using System.IO;

namespace ERC.Config
{
    /// <summary>
    /// The library's persisted settings, as plain data.
    /// </summary>
    /// <remarks>
    /// Separated from <see cref="ErcCore"/> so that configuration can be supplied
    /// rather than discovered. The constructor used to read and write an XML file,
    /// derive its own working directory and generate pattern files, which made the
    /// type impossible to construct without side effects on disk.
    /// </remarks>
    public class ErcConfig
    {
        /// <summary>
        /// Directory where output files are written.
        /// </summary>
        public string? WorkingDirectory { get; set; }

        /// <summary>
        /// Name credited in generated output files.
        /// </summary>
        public string? Author { get; set; }

        /// <summary>
        /// File holding the standard non-repeating pattern.
        /// </summary>
        public string? PatternStandardPath { get; set; }

        /// <summary>
        /// File holding the extended non-repeating pattern.
        /// </summary>
        public string? PatternExtendedPath { get; set; }

        /// <summary>
        /// File that errors are appended to.
        /// </summary>
        public string? SystemErrorLogPath { get; set; }

        /// <summary>
        /// Builds the default settings for a given working directory.
        /// </summary>
        public static ErcConfig CreateDefault(string workingDirectory)
        {
            if (string.IsNullOrEmpty(workingDirectory))
            {
                throw new ArgumentNullException("workingDirectory");
            }

            if (!workingDirectory.EndsWith("\\", StringComparison.Ordinal))
            {
                workingDirectory += "\\";
            }

            return new ErcConfig
            {
                WorkingDirectory = workingDirectory,
                Author = "No_Author_Set",
                PatternStandardPath = Path.Combine(workingDirectory, "Pattern_Standard"),
                PatternExtendedPath = Path.Combine(workingDirectory, "Pattern_Extended"),
                SystemErrorLogPath = Path.Combine(workingDirectory, "System_Error.LOG")
            };
        }

        /// <summary>
        /// Returns a copy, so handing configuration around cannot alias it.
        /// </summary>
        public ErcConfig Clone()
        {
            return (ErcConfig)MemberwiseClone();
        }

        /// <summary>
        /// Replaces any missing value with the default for the working directory.
        /// </summary>
        internal void FillGapsFrom(ErcConfig defaults)
        {
            if (string.IsNullOrEmpty(WorkingDirectory)) WorkingDirectory = defaults.WorkingDirectory;
            if (string.IsNullOrEmpty(Author)) Author = defaults.Author;
            if (string.IsNullOrEmpty(PatternStandardPath)) PatternStandardPath = defaults.PatternStandardPath;
            if (string.IsNullOrEmpty(PatternExtendedPath)) PatternExtendedPath = defaults.PatternExtendedPath;
            if (string.IsNullOrEmpty(SystemErrorLogPath)) SystemErrorLogPath = defaults.SystemErrorLogPath;
        }
    }
}
