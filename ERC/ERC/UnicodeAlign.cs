using System;
using System.Collections.Generic;

namespace ERC.Utilities
{
    /// <summary>
    /// A Venetian alignment stub: the bytes to inject, the same bytes after
    /// UTF-16 expansion, and what the expanded form does.
    /// </summary>
    public sealed class UnicodeAlignment
    {
        internal UnicodeAlignment(
            byte[] asciiBytes,
            byte[] expandedBytes,
            string bufferRegister,
            int delta,
            string description,
            IReadOnlyList<string> instructions)
        {
            AsciiBytes = asciiBytes;
            ExpandedBytes = expandedBytes;
            BufferRegister = bufferRegister;
            Delta = delta;
            Description = description;
            Instructions = instructions;
        }

        /// <summary>
        /// Bytes to place in the exploit before the target widens them to UTF-16.
        /// Each byte becomes that byte followed by 0x00.
        /// </summary>
        public byte[] AsciiBytes { get; }

        /// <summary>
        /// What those bytes look like in memory after UTF-16 expansion. When
        /// a leaked null was requested, the leading 0x00 is included here.
        /// </summary>
        public byte[] ExpandedBytes { get; }

        /// <summary>The register the stub adjusts, for example "eax".</summary>
        public string BufferRegister { get; }

        /// <summary>
        /// How far the buffer register moves, in bytes. Negative moves it down.
        /// </summary>
        public int Delta { get; }

        /// <summary>What the stub assumes and what it leaves behind.</summary>
        public string Description { get; }

        /// <summary>The expanded form, one instruction per line.</summary>
        public IReadOnlyList<string> Instructions { get; }
    }

    /// <summary>
    /// Builds Venetian alignment stubs for Unicode buffer overflows.
    /// </summary>
    /// <remarks>
    /// A Unicode overflow widens every injected byte with a 0x00, so a buffer of
    /// <c>40 6D</c> becomes <c>40 00 6D 00</c>: <c>inc eax</c> followed by
    /// <c>add [ebp], ch</c>. The second instruction is a nop provided EBP is
    /// writable, which is why Venetian stubs ask for a writable EBP the same way
    /// mona's <c>unicodealign</c> does.
    ///
    /// The stub runs at EIP (the alignment code itself). It adjusts a separate
    /// buffer register so that register points at the Unicode shellcode. The
    /// shellcode then follows the stub, or the stub ends by pushing the register
    /// and returning into it.
    /// </remarks>
    public static class UnicodeAlign
    {
        private static readonly string[] Registers =
        {
            "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"
        };

        /// <summary>Largest |delta| this will emit. Larger than this is a different problem.</summary>
        public const int MaximumDelta = 2048;

        /// <summary>
        /// Builds a stub that adds <paramref name="delta"/> to a buffer register.
        /// </summary>
        /// <param name="delta">
        /// How far to move the register, in bytes. Positive uses <c>inc</c>,
        /// negative uses <c>dec</c>.
        /// </param>
        /// <param name="bufferRegister">Register to adjust. Default eax.</param>
        /// <param name="prependNullNop">
        /// True when the instruction before the stub leaks a null byte. The stub
        /// then starts with 0x6D so the leaked 0x00 becomes <c>add [ebp], ch</c>.
        /// </param>
        /// <param name="jumpToBuffer">
        /// True to finish with <c>push buffer; ret</c>, transferring into the
        /// adjusted register.
        /// </param>
        /// <param name="sourceRegister">
        /// If set and different from the buffer register, the stub first copies
        /// this register into the buffer register with a Venetian push/pop.
        /// </param>
        /// <returns>The stub in both ASCII-inject and expanded forms.</returns>
        /// <exception cref="ERCException">The register is unknown or the delta is too large.</exception>
        public static UnicodeAlignment Generate(
            int delta,
            string? bufferRegister = null,
            bool prependNullNop = false,
            bool jumpToBuffer = false,
            string? sourceRegister = null)
        {
            byte bufferNumber = NumberOf(bufferRegister ?? "eax", "buffer register");
            string bufferName = Registers[bufferNumber];

            if (Math.Abs(delta) > MaximumDelta)
            {
                throw new ERCException(
                    "A Venetian stub cannot close a gap of " + delta + " bytes. " +
                    "The limit is " + MaximumDelta +
                    ". Point the buffer register closer to the shellcode, or pass a smaller offset.");
            }

            var ascii = new List<byte>();
            var instructions = new List<string>();

            if (prependNullNop)
            {
                ascii.Add(0x6D);
                instructions.Add("add byte ptr [ebp], ch");
            }

            if (!string.IsNullOrEmpty(sourceRegister))
            {
                byte sourceNumber = NumberOf(sourceRegister, "source register");
                if (sourceNumber != bufferNumber)
                {
                    ascii.Add((byte)(0x50 + sourceNumber));
                    ascii.Add(0x6D);
                    ascii.Add((byte)(0x58 + bufferNumber));
                    ascii.Add(0x6D);
                    instructions.Add("push " + Registers[sourceNumber]);
                    instructions.Add("add byte ptr [ebp], ch");
                    instructions.Add("pop " + bufferName);
                    instructions.Add("add byte ptr [ebp], ch");
                }
            }

            byte adjust = delta >= 0
                ? (byte)(0x40 + bufferNumber)
                : (byte)(0x48 + bufferNumber);
            string mnemonic = delta >= 0 ? "inc " + bufferName : "dec " + bufferName;
            int steps = Math.Abs(delta);

            for (int i = 0; i < steps; i++)
            {
                ascii.Add(adjust);
                ascii.Add(0x6D);
                instructions.Add(mnemonic);
                instructions.Add("add byte ptr [ebp], ch");
            }

            if (jumpToBuffer)
            {
                ascii.Add((byte)(0x50 + bufferNumber));
                ascii.Add(0x6D);
                ascii.Add(0xC3);
                ascii.Add(0x6D);
                instructions.Add("push " + bufferName);
                instructions.Add("add byte ptr [ebp], ch");
                instructions.Add("ret");
                instructions.Add("add byte ptr [ebp], ch");
            }

            if (ascii.Count == 0)
            {
                ascii.Add(0x90);
                ascii.Add(0x6D);
                instructions.Add("nop");
                instructions.Add("add byte ptr [ebp], ch");
            }

            byte[] asciiBytes = ascii.ToArray();
            byte[] expanded = Expand(asciiBytes, prependNullNop);

            string description = Description(bufferName, delta, prependNullNop, jumpToBuffer, sourceRegister);

            return new UnicodeAlignment(asciiBytes, expanded, bufferName, delta, description, instructions);
        }

        /// <summary>
        /// Builds a stub that moves a register from its current value to a target
        /// address, choosing inc or dec according to which path is shorter.
        /// </summary>
        /// <param name="current">Current value of the buffer register.</param>
        /// <param name="target">Address the register should hold afterwards.</param>
        /// <param name="bufferRegister">Register to adjust. Default eax.</param>
        /// <param name="prependNullNop">See <see cref="Generate(int, string, bool, bool, string)"/>.</param>
        /// <param name="jumpToBuffer">See <see cref="Generate(int, string, bool, bool, string)"/>.</param>
        /// <param name="sourceRegister">See <see cref="Generate(int, string, bool, bool, string)"/>.</param>
        /// <returns>The stub in both ASCII-inject and expanded forms.</returns>
        public static UnicodeAlignment GenerateToTarget(
            uint current,
            uint target,
            string? bufferRegister = null,
            bool prependNullNop = false,
            bool jumpToBuffer = false,
            string? sourceRegister = null)
        {
            uint forward = target - current;
            uint backward = current - target;
            int delta;

            if (forward <= backward)
            {
                if (forward > MaximumDelta)
                {
                    throw new ERCException(
                        "0x" + current.ToString("X8") + " is 0x" + forward.ToString("X") +
                        " bytes from 0x" + target.ToString("X8") +
                        ", which is larger than a Venetian stub can close (" + MaximumDelta +
                        "). Copy a register that already points closer, or pass a smaller offset.");
                }

                delta = (int)forward;
            }
            else
            {
                if (backward > MaximumDelta)
                {
                    throw new ERCException(
                        "0x" + current.ToString("X8") + " is 0x" + backward.ToString("X") +
                        " bytes from 0x" + target.ToString("X8") +
                        ", which is larger than a Venetian stub can close (" + MaximumDelta +
                        "). Copy a register that already points closer, or pass a smaller offset.");
                }

                delta = -(int)backward;
            }

            return Generate(delta, bufferRegister, prependNullNop, jumpToBuffer, sourceRegister);
        }

        /// <summary>
        /// The 32-bit registers this can adjust.
        /// </summary>
        public static IReadOnlyList<string> SupportedRegisters
        {
            get { return Registers; }
        }

        private static byte[] Expand(byte[] ascii, bool prependNullNop)
        {
            // Each injected byte is followed by 0x00. A leaked null is already in
            // memory in front of the stub; include it in the expanded view so the
            // bytes shown are what actually execute.
            int leading = prependNullNop ? 1 : 0;
            var expanded = new byte[leading + ascii.Length * 2];
            int i = 0;

            if (prependNullNop)
            {
                expanded[i++] = 0x00;
            }

            foreach (byte b in ascii)
            {
                expanded[i++] = b;
                expanded[i++] = 0x00;
            }

            return expanded;
        }

        private static string Description(
            string buffer,
            int delta,
            bool leak,
            bool jump,
            string? source)
        {
            var parts = new List<string>();
            parts.Add("Venetian alignment for a Unicode overflow.");
            parts.Add("EBP must be writable: each 0x00 becomes 'add [ebp], ch'.");
            if (!string.IsNullOrEmpty(source) &&
                !string.Equals(source, buffer, StringComparison.OrdinalIgnoreCase))
            {
                parts.Add("Copies " + source!.Trim().ToLowerInvariant() + " into " + buffer + " first.");
            }

            if (delta > 0)
            {
                parts.Add("Adds " + delta + " to " + buffer + " with inc.");
            }
            else if (delta < 0)
            {
                parts.Add("Subtracts " + (-delta) + " from " + buffer + " with dec.");
            }
            else
            {
                parts.Add("Leaves " + buffer + " unchanged.");
            }

            if (leak)
            {
                parts.Add("Starts with 0x6D so a leaked null becomes 'add [ebp], ch'.");
            }

            if (jump)
            {
                parts.Add("Ends with push " + buffer + "; ret.");
            }
            else
            {
                parts.Add("Place the Unicode shellcode immediately after this stub, or pass jmp to transfer into " + buffer + ".");
            }

            return string.Join(" ", parts.ToArray());
        }

        private static byte NumberOf(string? register, string role)
        {
            if (string.IsNullOrEmpty(register))
            {
                throw new ERCException("No " + role + " was supplied. Expected one of: " + string.Join(", ", Registers));
            }

            string name = register!.Trim().ToLowerInvariant();
            int index = Array.IndexOf(Registers, name);
            if (index >= 0)
            {
                return (byte)index;
            }

            throw new ERCException(
                "\"" + register + "\" is not a 32-bit register. Venetian alignment is an x86 technique. Expected one of: " +
                string.Join(", ", Registers));
        }
    }
}
