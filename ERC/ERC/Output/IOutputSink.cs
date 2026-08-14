using System.Collections.Generic;

namespace ERC.Output
{
    /// <summary>
    /// Where generated output is written.
    /// </summary>
    /// <remarks>
    /// The library's display functions both build text and save it, with
    /// File.WriteAllText scattered across twenty-odd call sites. That is why none of
    /// the formatting could be tested without writing files to disk. Routing every
    /// write through this interface means a test can capture the output instead.
    ///
    /// Implementations must not throw for an unwritable target: producing output the
    /// user can read in the debugger log matters more than saving a copy.
    /// </remarks>
    public interface IOutputSink
    {
        /// <summary>
        /// Picks the next unused file path for a prefix, e.g. "modules_3.txt".
        /// </summary>
        /// <param name="directory">Directory the file belongs in.</param>
        /// <param name="prefix">Filename prefix, e.g. "modules_".</param>
        /// <param name="extension">Extension including the dot, e.g. ".txt".</param>
        string NextFilePath(string directory, string prefix, string extension);

        /// <summary>
        /// Writes text to the given path.
        /// </summary>
        /// <returns>True when the content was stored.</returns>
        bool WriteText(string path, string content);

        /// <summary>
        /// Writes lines to the given path.
        /// </summary>
        /// <returns>True when the content was stored.</returns>
        bool WriteLines(string path, IEnumerable<string> lines);
    }
}
