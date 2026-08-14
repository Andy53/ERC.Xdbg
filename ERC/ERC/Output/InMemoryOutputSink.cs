using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace ERC.Output
{
    /// <summary>
    /// Captures output in memory instead of writing it.
    /// </summary>
    /// <remarks>
    /// Lets the display and formatting code be exercised, and its output asserted on,
    /// without creating files. This is what the snapshot tests of the table and help
    /// output are built on.
    /// </remarks>
    public class InMemoryOutputSink : IOutputSink
    {
        private readonly Dictionary<string, string> _files =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        private readonly Dictionary<string, int> _counters =
            new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Everything written so far, keyed by path.
        /// </summary>
        public IReadOnlyDictionary<string, string> Files { get { return _files; } }

        /// <summary>
        /// Paths written to, in the order they were first written.
        /// </summary>
        public IReadOnlyList<string> Paths { get { return new List<string>(_files.Keys); } }

        /// <summary>
        /// The content written to the single file whose path contains the fragment.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        /// No file, or more than one file, matched - which means the test is not
        /// asserting on what it thinks it is.
        /// </exception>
        public string ContentMatching(string pathFragment)
        {
            var matches = new List<string>();
            foreach (var pair in _files)
            {
                if (pair.Key.IndexOf(pathFragment, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    matches.Add(pair.Value);
                }
            }

            if (matches.Count != 1)
            {
                throw new InvalidOperationException(
                    "Expected exactly one written file matching \"" + pathFragment +
                    "\" but found " + matches.Count + ". Written: " + string.Join(", ", new List<string>(_files.Keys)));
            }

            return matches[0];
        }

        /// <inheritdoc/>
        public string NextFilePath(string directory, string prefix, string extension)
        {
            string key = prefix + extension;
            int next;
            _counters.TryGetValue(key, out next);
            next++;
            _counters[key] = next;

            return Path.Combine(directory ?? string.Empty, prefix + next.ToString() + extension);
        }

        /// <inheritdoc/>
        public bool WriteText(string path, string content)
        {
            _files[path] = content ?? string.Empty;
            return true;
        }

        /// <inheritdoc/>
        public bool WriteLines(string path, IEnumerable<string> lines)
        {
            var builder = new StringBuilder();
            if (lines != null)
            {
                foreach (string line in lines)
                {
                    builder.AppendLine(line);
                }
            }

            _files[path] = builder.ToString();
            return true;
        }
    }
}
