using System;
using System.Collections.Generic;

namespace ERC.Utilities
{
    /// <summary>
    /// A byte sequence that moves the stack pointer, and how far.
    /// </summary>
    public sealed class PivotEncoding
    {
        internal PivotEncoding(byte[] opcodes, string instruction, int distance)
        {
            Opcodes = opcodes;
            Instruction = instruction;
            Distance = distance;
        }

        /// <summary>The bytes to search for.</summary>
        public byte[] Opcodes { get; }

        /// <summary>What those bytes disassemble to, for example "add esp, 0x20".</summary>
        public string Instruction { get; }

        /// <summary>
        /// How far the stack pointer moves, in bytes. Negative moves towards lower
        /// addresses; zero when the distance is not fixed by the instruction.
        /// </summary>
        public int Distance { get; }
    }

    /// <summary>
    /// Finds the instructions that move the stack pointer somewhere useful.
    /// </summary>
    /// <remarks>
    /// A ROP chain has to be reached before it can run. When the overflow gives only
    /// a few bytes at the point of the crash - a common case with SEH overwrites, or
    /// when the chain sits further up the buffer - the chain cannot simply follow the
    /// saved return address. Something has to move the stack pointer to where the
    /// chain actually is, and that something is a pivot.
    ///
    /// ERC could generate chains but had no way to find a pivot, which left the
    /// hardest part of getting one to run entirely to the user.
    ///
    /// Three shapes are worth looking for:
    ///
    ///   xchg reg, esp   swap the stack pointer with a register you control
    ///   add  esp, n     step forwards over what you cannot use
    ///   pop  x n; ret   the same, in units of a word, and often easier to find
    ///
    /// "leave" is included because it is a pivot in disguise: it sets esp from ebp,
    /// which is worth having whenever ebp is under control.
    /// </remarks>
    public static class StackPivot
    {
        /// <summary>
        /// The pivot encodings worth searching for.
        /// </summary>
        /// <param name="machineType">Architecture of the process being searched.</param>
        /// <param name="maximumAdjustment">
        /// Largest "add esp, n" to look for, in bytes. Larger values find more, at the
        /// cost of a search per value.
        /// </param>
        /// <returns>One entry per encoding, largest movements last.</returns>
        public static IReadOnlyList<PivotEncoding> Encodings(MachineType machineType, int maximumAdjustment = 256)
        {
            var encodings = new List<PivotEncoding>();

            bool is64 = machineType == MachineType.x64;
            string sp = is64 ? "rsp" : "esp";
            int word = is64 ? 8 : 4;

            // xchg reg, esp - 0x87 with a ModRM selecting the pair, and the shorter
            // 0x94..0x97 form for the accumulator. Nothing moves a stack pointer more
            // directly than swapping it with a register you already control.
            string[] registers = is64
                ? new[] { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi" }
                : new[] { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };

            for (int r = 0; r < registers.Length; r++)
            {
                if (r == 4)
                {
                    // Swapping the stack pointer with itself does nothing.
                    continue;
                }

                encodings.Add(new PivotEncoding(
                    new byte[] { 0x87, (byte)(0xE0 + r) }, "xchg " + registers[r] + ", " + sp, 0));
            }

            // xchg eax, reg has a one-byte form; only the esp pairing is a pivot.
            encodings.Add(new PivotEncoding(new byte[] { 0x94 }, "xchg " + sp + ", " + registers[0], 0));

            // leave - mov esp, ebp then pop ebp. A pivot whenever ebp is controlled.
            encodings.Add(new PivotEncoding(new byte[] { 0xC9 }, "leave", 0));

            // mov esp, reg - 0x8B with ModRM 0xE0+r, destination esp.
            for (int r = 0; r < registers.Length; r++)
            {
                if (r == 4)
                {
                    continue;
                }

                encodings.Add(new PivotEncoding(
                    new byte[] { 0x8B, (byte)(0xE0 + r) }, "mov " + sp + ", " + registers[r], 0));
            }

            // add esp, n. The 8-bit immediate form covers 0x00 to 0x7F and is by far
            // the most common; the 32-bit form covers the rest.
            for (int adjustment = word; adjustment <= Math.Min(maximumAdjustment, 0x7F); adjustment += word)
            {
                encodings.Add(new PivotEncoding(
                    new byte[] { 0x83, 0xC4, (byte)adjustment },
                    "add " + sp + ", 0x" + adjustment.ToString("X2"), adjustment));
            }

            if (maximumAdjustment > 0x7F)
            {
                for (int adjustment = 0x80; adjustment <= maximumAdjustment; adjustment += word)
                {
                    var opcodes = new byte[6];
                    opcodes[0] = 0x81;
                    opcodes[1] = 0xC4;
                    Array.Copy(BitConverter.GetBytes(adjustment), 0, opcodes, 2, 4);

                    encodings.Add(new PivotEncoding(
                        opcodes, "add " + sp + ", 0x" + adjustment.ToString("X"), adjustment));
                }
            }

            // ret n - returns and then discards n bytes, which is a pivot with the
            // transfer already built in.
            for (int adjustment = word; adjustment <= Math.Min(maximumAdjustment, 0xFFFF); adjustment += word)
            {
                var opcodes = new byte[3];
                opcodes[0] = 0xC2;
                Array.Copy(BitConverter.GetBytes((ushort)adjustment), 0, opcodes, 1, 2);

                encodings.Add(new PivotEncoding(
                    opcodes, "ret 0x" + adjustment.ToString("X"), adjustment));
            }

            return encodings;
        }

        /// <summary>
        /// Searches a process for stack pivots.
        /// </summary>
        /// <param name="info">The process to search.</param>
        /// <param name="minimumDistance">
        /// Ignore adjustments that move the stack pointer less than this. Useful when
        /// the chain is known to be a certain distance away; zero keeps everything.
        /// </param>
        /// <param name="maximumAdjustment">Largest "add esp, n" to look for, in bytes.</param>
        /// <param name="excludes">Modules to leave out of the search.</param>
        /// <param name="ptrsToExclude">Bytes that disqualify an address.</param>
        /// <returns>Address to instruction, for every pivot found.</returns>
        public static ErcResult<Dictionary<IntPtr, string>> Search(
            ProcessInfo info,
            int minimumDistance = 0,
            int maximumAdjustment = 256,
            List<string>? excludes = null,
            byte[]? ptrsToExclude = null)
        {
            if (info == null)
            {
                throw new ArgumentNullException(nameof(info));
            }

            var result = new ErcResult<Dictionary<IntPtr, string>>(info.ProcessCore);
            result.ReturnValue = new Dictionary<IntPtr, string>();

            foreach (PivotEncoding encoding in Encodings(info.ProcessMachineType, maximumAdjustment))
            {
                // A register swap has no fixed distance, so it always qualifies; an
                // adjustment only qualifies if it goes far enough.
                if (encoding.Distance != 0 && encoding.Distance < minimumDistance)
                {
                    continue;
                }

                ErcResult<Dictionary<IntPtr, string>> found = info.SearchMemory(
                    SearchTerm.Bytes,
                    searchBytes: encoding.Opcodes,
                    excludes: excludes,
                    ptrsToExclude: ptrsToExclude);

                if (found.Error != null)
                {
                    result.Error = found.Error;
                    return result;
                }

                foreach (KeyValuePair<IntPtr, string> match in found.ReturnValue)
                {
                    if (!result.ReturnValue.ContainsKey(match.Key))
                    {
                        result.ReturnValue.Add(match.Key, encoding.Instruction + "  (" + match.Value + ")");
                    }
                }
            }

            return result;
        }
    }
}
