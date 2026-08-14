using System;
using System.Runtime.Serialization;

namespace ERC
{
    /// <summary>
    /// Custom exception handler.
    /// </summary>
    [Serializable]
    public class ERCException : Exception
    {
        /// <summary>
        /// Constructor for the ERCException class.
        /// </summary>
        /// <param name="message">The message associated with the Exception</param>
        public ERCException(string message)
            : base(message)
        { }

        /// <summary>
        /// Constructor for the ERCException class, preserving the cause.
        /// </summary>
        /// <param name="message">The message associated with the Exception</param>
        /// <param name="innerException">The exception that caused this one.</param>
        /// <remarks>
        /// Added because the update path wraps network failures. Without it the
        /// original exception was flattened to its message, which loses the status
        /// code and the stack, and those are what tell a proxy failure apart from a
        /// missing release.
        /// </remarks>
        public ERCException(string message, Exception innerException)
            : base(message, innerException)
        { }

        /// <summary>
        /// Creates a serializable exception.
        /// </summary>
        /// <param name="info">Stores all the data needed to serialize or deserialize an object.</param>
        /// <param name="ctxt">Describes the source and destination of a given serialized stream, and provides an additional caller-defined context.</param>
        protected ERCException(SerializationInfo info, StreamingContext ctxt)
            : base(info, ctxt)
        { }
    }
}
