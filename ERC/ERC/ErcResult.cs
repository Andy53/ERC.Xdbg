using System;
using ERC.Config;

namespace ERC
{
    /// <summary>
    /// The outcome of an operation: either a value or an error.
    /// </summary>
    /// <typeparam name="T">Type of the value returned on success.</typeparam>
    /// <remarks>
    /// This used to derive from <see cref="ErcCore"/>, which meant every result value
    /// in the library was-a configuration object: constructing one dragged the whole
    /// config surface along with it, and a result exposed nonsense members like
    /// SetWorkingDirectory. It now holds only what a result needs, plus a logger.
    ///
    /// The constructor signatures are unchanged, so existing call sites still compile.
    /// </remarks>
    public class ErcResult<T>
    {
        /// <summary>
        /// The value produced on success. Default when <see cref="Error"/> is set.
        /// </summary>
        public T ReturnValue { get; set; }

        /// <summary>
        /// The failure, or null when the operation succeeded.
        /// </summary>
        public Exception Error { get; set; }

        /// <summary>
        /// True when no error was recorded.
        /// </summary>
        public bool IsSuccess { get { return Error == null; } }

        /// <summary>
        /// Where <see cref="LogEvent()"/> writes.
        /// </summary>
        public IErcLogger Logger { get; }

        /// <summary>
        /// Path this result logs to, kept for callers that read it.
        /// </summary>
        public string SystemErrorLogPath { get; }

        /// <summary>
        /// Creates a result that logs wherever the supplied core logs.
        /// </summary>
        /// <param name="core">The core whose logger and log path are adopted.</param>
        public ErcResult(ErcCore core)
        {
            if (core == null)
            {
                throw new ArgumentNullException("core");
            }

            Logger = core.Logger;
            SystemErrorLogPath = core.SystemErrorLogPath;
        }

        /// <summary>
        /// Creates a result that logs to a specific file.
        /// </summary>
        /// <param name="core">The core this result belongs to.</param>
        /// <param name="errorFile">File to log to instead of the core's log.</param>
        public ErcResult(ErcCore core, string errorFile)
        {
            if (core == null)
            {
                throw new ArgumentNullException("core");
            }

            SystemErrorLogPath = errorFile;
            Logger = new FileErcLogger(errorFile);
        }

        /// <summary>
        /// Creates a result with an explicit logger.
        /// </summary>
        /// <param name="logger">Where to report failures.</param>
        public ErcResult(IErcLogger logger)
        {
            Logger = logger ?? new InMemoryErcLogger();
        }

        /// <summary>
        /// Records <see cref="Error"/> in the log. Never throws.
        /// </summary>
        public void LogEvent()
        {
            Logger.Log(Error + " TimeStamp: " + DateTime.Now);
        }

        /// <summary>
        /// Records a specific exception in the log. Never throws.
        /// </summary>
        /// <param name="e">The exception to record.</param>
        /// <remarks>
        /// Callers used to reach ErcCore.LogEvent(Exception) through the inheritance
        /// that has now been removed, so the overload lives here instead.
        /// </remarks>
        public void LogEvent(Exception e)
        {
            Logger.Log((e == null ? "<null exception>" : e.ToString()) + " TimeStamp: " + DateTime.Now);
        }

        /// <summary>
        /// A description of this result, for diagnostics.
        /// </summary>
        /// <returns>A multi-line summary of the value, error and log path.</returns>
        public override string ToString()
        {
            // Returns the description it builds. The previous version assembled this
            // into a local and then returned base.ToString(), throwing the work away
            // and handing callers the type name instead.
            string ret = "";
            ret += "ErcResult Type = " + (ReturnValue == null ? "NULL" : ReturnValue.GetType().ToString()) + Environment.NewLine;
            ret += "ErcResult.Error = " + (Error == null ? "NULL" : Error.ToString()) + Environment.NewLine;
            ret += "ErcResult.ErrorLogFile = " + SystemErrorLogPath + Environment.NewLine;
            return ret;
        }
    }
}
