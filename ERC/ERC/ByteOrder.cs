using System;

namespace ERC.Utilities
{
    /// <summary>
    /// Byte ordering helpers for values written into a ROP chain.
    /// </summary>
    /// <remarks>
    /// This exists to name an operation that was previously written as
    /// <c>bytes.Reverse().ToArray()</c>, which is not as unambiguous as it looks.
    ///
    /// With <c>System.Linq</c> imported, an array has two candidate <c>Reverse</c>
    /// extensions: <c>Enumerable.Reverse&lt;T&gt;</c>, which returns a sequence, and
    /// <c>MemoryExtensions.Reverse&lt;T&gt;</c> from System.Memory, which reverses a
    /// <c>Span&lt;T&gt;</c> in place and returns <c>void</c>. Which one an expression
    /// binds to depends on whether System.Memory's reference assembly is in scope,
    /// and that differed between a developer machine with a warm package cache and a
    /// clean restore on CI - so the same source compiled locally and failed with
    /// CS0023 on the build server.
    ///
    /// A method that does one thing and says which is worth more than saving a call.
    /// </remarks>
    internal static class ByteOrder
    {
        /// <summary>
        /// A copy of <paramref name="bytes"/> with the order of the bytes flipped.
        /// </summary>
        /// <param name="bytes">The bytes to reverse. Not modified.</param>
        /// <returns>A new array; the input is left alone.</returns>
        /// <remarks>
        /// Chain entries are built from <see cref="BitConverter"/>, which produces
        /// little-endian output on the platforms ERC runs on, and the generators want
        /// the opposite order when laying an address onto the stack.
        /// </remarks>
        internal static byte[] Reversed(this byte[]? bytes)
        {
            if (bytes == null)
            {
                return new byte[0];
            }

            var reversed = new byte[bytes.Length];

            for (int i = 0; i < bytes.Length; i++)
            {
                reversed[i] = bytes[bytes.Length - 1 - i];
            }

            return reversed;
        }
    }
}
