using System;
using System.IO;

namespace ERC.Config
{
    /// <summary>
    /// Where the library reports errors.
    /// </summary>
    /// <remarks>
    /// Exists so <see cref="ErcResult{T}"/> can log without inheriting from
    /// <see cref="ErcCore"/>. Previously every result value was-a ErcCore purely to
    /// reach a log file path.
    /// </remarks>
    public interface IErcLogger
    {
        /// <summary>
        /// Records a message. Must not throw: this is the error path, and an error
        /// reporter that fails replaces the fault being reported with its own.
        /// </summary>
        void Log(string message);
    }

    /// <summary>
    /// Appends to a log file, giving up quietly if it cannot.
    /// </summary>
    public class FileErcLogger : IErcLogger
    {
        private readonly string? _path;

        public FileErcLogger(string? path)
        {
            _path = path;
        }

        /// <summary>
        /// The file being appended to.
        /// </summary>
        public string? Path { get { return _path; } }

        public void Log(string message)
        {
            if (string.IsNullOrEmpty(_path))
            {
                return;
            }

            try
            {
                // FileShare.Read so the log can be tailed while the plugin runs.
                // The old code used File.AppendText, which takes an exclusive lock,
                // so two threads logging at once threw - and x64dbg calls plugins
                // from more than one thread.
                using (var stream = new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.Read))
                using (var writer = new StreamWriter(stream))
                {
                    writer.WriteLine(message);
                }
            }
            catch (IOException)
            {
                // Locked, full, or read-only. Losing a log line beats losing the
                // debugging session.
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    /// <summary>
    /// Keeps log messages in memory, so tests can assert on them.
    /// </summary>
    public class InMemoryErcLogger : IErcLogger
    {
        private readonly System.Collections.Generic.List<string> _messages =
            new System.Collections.Generic.List<string>();

        /// <summary>
        /// Everything logged so far, oldest first.
        /// </summary>
        public System.Collections.Generic.IReadOnlyList<string> Messages
        {
            get { return _messages; }
        }

        public void Log(string message)
        {
            _messages.Add(message);
        }
    }
}
