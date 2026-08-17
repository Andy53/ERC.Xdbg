using System;
using System.Collections.Generic;

namespace ERC.Utilities
{
    /// <summary>
    /// Works out how to get a constant into a register without writing forbidden
    /// bytes onto the stack.
    /// </summary>
    /// <remarks>
    /// A chain sets up its arguments by popping values off the stack, so the value
    /// has to survive being written there. In a string overflow a null byte
    /// terminates the copy, and several of the constants a chain needs are full of
    /// them: VirtualAlloc's flAllocationType is 0x00001000, its flProtect is
    /// 0x00000040.
    ///
    /// The generators dealt with this by never taking the direct route: EDX was only
    /// satisfiable through "xor edx, edx" followed by two "add" gadgets, using a
    /// hard-coded pair of values. That has two problems. A target with a "pop edx"
    /// but no "add edx, reg" gadget could not populate EDX at all, even when nulls
    /// were perfectly acceptable - nothing had asked whether they were. And the
    /// hard-coded pair did not add up: 0xFFFFFFFF and 0x01011101 sum to 0x01011100,
    /// not 0x1000, so the chain was labelled "combined = 0x00001000" and was not.
    ///
    /// This picks the route from what the target actually forbids, and when it needs
    /// a pair it computes one.
    /// </remarks>
    public static class ConstantLoader
    {
        /// <summary>
        /// Whether a 32-bit value can be written to the stack directly.
        /// </summary>
        /// <param name="value">The constant wanted in a register.</param>
        /// <param name="excluded">Bytes the target mangles, or null when none do.</param>
        /// <returns>True when none of the value's four bytes is excluded.</returns>
        public static bool CanWriteDirectly(uint value, byte[]? excluded)
        {
            if (excluded == null || excluded.Length == 0)
            {
                return true;
            }

            foreach (byte b in BitConverter.GetBytes(value))
            {
                if (Array.IndexOf(excluded, b) >= 0)
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Finds two writable values whose sum is the value wanted.
        /// </summary>
        /// <param name="target">The constant wanted in the register.</param>
        /// <param name="excluded">Bytes the target mangles, or null when none do.</param>
        /// <param name="first">The value to load first.</param>
        /// <param name="second">The value to add to it.</param>
        /// <returns>False when no pair of writable values sums to the target.</returns>
        /// <remarks>
        /// Addition is modulo 2^32, which is what the processor does and what makes
        /// this solvable at all: a target full of forbidden bytes can usually be
        /// reached by deliberately overflowing.
        ///
        /// Solved a byte at a time from the least significant end, carrying as
        /// addition does. What makes it cheap is that the only thing a byte position
        /// needs to know about the ones below it is whether they carried - so there
        /// are eight states in total, and the choice of bytes at each position can be
        /// made once per state rather than searched.
        ///
        /// Searching instead is what a first attempt at this did, and it did not
        /// finish. Whether the top byte can produce the required final carry is often
        /// decided by the target alone, and when it cannot the search explores every
        /// combination of the lower three bytes before finding out - around 66 million
        /// dead ends for a value as ordinary as 0x00001000.
        /// </remarks>
        public static bool TryFindAdditivePair(uint target, byte[]? excluded, out uint first, out uint second)
        {
            first = 0;
            second = 0;

            bool[] writable = WritableBytes(excluded);
            byte[] preference = Preference(writable);
            byte[] bytes = BitConverter.GetBytes(target);

            // choice[position, carryIn, carryOut] - the pair to use, or none.
            var choice = new byte[4, 2, 2, 2];
            var possible = new bool[4, 2, 2];

            for (int position = 0; position < 4; position++)
            {
                for (int carryIn = 0; carryIn <= 1; carryIn++)
                {
                    for (int carryOut = 0; carryOut <= 1; carryOut++)
                    {
                        // a + b + carryIn == target + 256 * carryOut, at this byte.
                        int total = bytes[position] + (256 * carryOut) - carryIn;

                        foreach (byte a in preference)
                        {
                            int b = total - a;

                            if (b < 0 || b > 255 || !writable[b])
                            {
                                continue;
                            }

                            choice[position, carryIn, carryOut, 0] = a;
                            choice[position, carryIn, carryOut, 1] = (byte)b;
                            possible[position, carryIn, carryOut] = true;
                            break;
                        }
                    }
                }
            }

            // The carry leaving the top byte is discarded by the wrap, so either value
            // is a legitimate finish; walking the carries is four steps of two.
            var carries = new int[5];

            foreach (int finalCarry in new[] { 0, 1 })
            {
                if (TryWalk(possible, 0, 0, finalCarry, carries))
                {
                    var a = new byte[4];
                    var b = new byte[4];

                    for (int position = 0; position < 4; position++)
                    {
                        a[position] = choice[position, carries[position], carries[position + 1], 0];
                        b[position] = choice[position, carries[position], carries[position + 1], 1];
                    }

                    first = BitConverter.ToUInt32(a, 0);
                    second = BitConverter.ToUInt32(b, 0);
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Finds a sequence of carries that reaches the required final carry.
        /// </summary>
        private static bool TryWalk(bool[,,] possible, int position, int carryIn, int finalCarry, int[] carries)
        {
            carries[position] = carryIn;

            if (position == 4)
            {
                return carryIn == finalCarry;
            }

            for (int carryOut = 0; carryOut <= 1; carryOut++)
            {
                if (possible[position, carryIn, carryOut] &&
                    TryWalk(possible, position + 1, carryOut, finalCarry, carries))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Which byte values may be written, as a lookup rather than a list.
        /// </summary>
        private static bool[] WritableBytes(byte[]? excluded)
        {
            var writable = new bool[256];

            for (int value = 0; value < 256; value++)
            {
                writable[value] = true;
            }

            if (excluded != null)
            {
                foreach (byte b in excluded)
                {
                    writable[b] = false;
                }
            }

            return writable;
        }

        /// <summary>
        /// Writable bytes in the order to try them.
        /// </summary>
        /// <remarks>
        /// 0x00 last, so that when nulls are permitted the pair chosen still avoids
        /// them where it can. The values end up in the chain a person reads.
        /// </remarks>
        private static byte[] Preference(bool[] writable)
        {
            var order = new List<byte>(256);

            for (int value = 1; value < 256; value++)
            {
                if (writable[value])
                {
                    order.Add((byte)value);
                }
            }

            if (writable[0])
            {
                order.Add(0);
            }

            return order.ToArray();
        }

    }
}
