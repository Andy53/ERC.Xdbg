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
        /// Creates a serializable exception.
        /// </summary>
        /// <param name="info">Stores all the data needed to serialize or deserialize an object.</param>
        /// <param name="ctxt">Describes the source and destination of a given serialized stream, and provides an additional caller-defined context.</param>
        protected ERCException(SerializationInfo info, StreamingContext ctxt)
            : base(info, ctxt)
        { }
    }
}
