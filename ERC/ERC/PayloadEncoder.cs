using System;
using System.Collections.Generic;
using System.Linq;

namespace ERC.Utilities
{
    /// <summary>
    /// How a payload was encoded.
    /// </summary>
    public enum PayloadEncoding
    {
        /// <summary>Single-byte XOR with a decoder stub in front.</summary>
        Xor,

        /// <summary>
        /// Printable AND/SUB/PUSH encoder. Each original dword is rebuilt in EAX
        /// with two ANDs (which zero it) and three SUBs, then pushed. The same
        /// encoder mona calls alphanum.
        /// </summary>
        Alphanumeric
    }

    /// <summary>
    /// A payload after encoding, ready to paste into an exploit.
    /// </summary>
    public sealed class EncodedPayload
    {
        internal EncodedPayload(
            PayloadEncoding encoding,
            byte[] bytes,
            byte[] original,
            string description,
            IReadOnlyList<string> notes,
            byte xorKey)
        {
            Encoding = encoding;
            Bytes = bytes;
            Original = original;
            Description = description;
            Notes = notes;
            XorKey = xorKey;
        }

        /// <summary>Which encoder produced this.</summary>
        public PayloadEncoding Encoding { get; }

        /// <summary>
        /// The bytes to put in the exploit. For XOR this is decoder then encoded
        /// payload, a standalone sequence. For alphanumeric this is the AND/SUB/PUSH
        /// sequence, which needs a writable stack and EIP pointing at its start.
        /// </summary>
        public byte[] Bytes { get; }

        /// <summary>The bytes that were encoded.</summary>
        public byte[] Original { get; }

        /// <summary>What the result assumes and how to use it.</summary>
        public string Description { get; }

        /// <summary>Extra lines for the log: key, length, restrictions.</summary>
        public IReadOnlyList<string> Notes { get; }

        /// <summary>
        /// The XOR key, or 0 when this is not a XOR encoding.
        /// </summary>
        public byte XorKey { get; }
    }

    /// <summary>
    /// Encodes a payload so it survives a restricted character set.
    /// </summary>
    /// <remarks>
    /// Two encodings, matching what people use mona and msfvenom for at this step:
    ///
    /// XOR puts a short decoder in front of the payload and XORs every byte with a
    /// key chosen so that neither the decoder nor the encoded payload contains a
    /// byte the target mangles. The result is position-independent and runs as-is.
    ///
    /// Alphanumeric rebuilds each original dword in EAX with printable AND and SUB
    /// immediates, then pushes it. After the sequence ESP points at the original
    /// payload. EIP has to start at the sequence, and the stack has to be writable.
    /// This is mona's <c>encode -t alphanum</c>.
    /// </remarks>
    public static class PayloadEncoder
    {
        /// <summary>
        /// Bytes the alphanumeric encoder uses as opcodes or as the two AND
        /// immediates that zero EAX. Marking any of them as bad makes that encoder
        /// unable to emit anything.
        /// </summary>
        public static readonly byte[] AlphanumericReserved =
        {
            0x25, 0x2A, 0x2D, 0x31, 0x32, 0x35, 0x4A, 0x4D, 0x4E, 0x50, 0x55
        };

        /// <summary>
        /// Parses an encoding name from the command line: "xor" or "alphanum".
        /// </summary>
        /// <param name="text">The token the user typed.</param>
        /// <param name="encoding">The matching encoding, or XOR when the name is not recognised.</param>
        /// <returns>True when the name was recognised.</returns>
        public static bool TryParseEncoding(string? text, out PayloadEncoding encoding)
        {
            encoding = PayloadEncoding.Xor;
            if (string.IsNullOrEmpty(text))
            {
                return false;
            }

            switch (text!.Trim().ToLowerInvariant())
            {
                case "xor":
                case "x":
                    encoding = PayloadEncoding.Xor;
                    return true;
                case "alphanum":
                case "alphanumeric":
                case "alpha":
                case "printable":
                case "sub":
                    encoding = PayloadEncoding.Alphanumeric;
                    return true;
                default:
                    return false;
            }
        }

        /// <summary>
        /// Encodes <paramref name="payload"/> so that the result contains none of
        /// <paramref name="badBytes"/>.
        /// </summary>
        /// <param name="payload">The bytes to encode.</param>
        /// <param name="encoding">Which encoder to use.</param>
        /// <param name="machineType">Architecture of the decoder stub. Ignored by alphanumeric, which is x86 only.</param>
        /// <param name="badBytes">Bytes the encoded result must not contain.</param>
        /// <returns>The encoded payload.</returns>
        /// <exception cref="ERCException">The payload is empty, the encoding is not available, or no key/immediates avoid the bad bytes.</exception>
        public static EncodedPayload Encode(
            byte[]? payload,
            PayloadEncoding encoding,
            MachineType machineType = MachineType.I386,
            byte[]? badBytes = null)
        {
            if (payload == null || payload.Length == 0)
            {
                throw new ERCException("Nothing to encode. Pass the payload bytes or a file that contains them.");
            }

            byte[] bad = Distinct(badBytes);

            if (encoding == PayloadEncoding.Xor)
            {
                return EncodeXor(payload, machineType, bad);
            }

            if (encoding == PayloadEncoding.Alphanumeric)
            {
                if (machineType == MachineType.x64)
                {
                    throw new ERCException(
                        "The alphanumeric encoder is 32-bit only. Use XOR on x64, or encode for x86.");
                }

                return EncodeAlphanumeric(payload, bad);
            }

            throw new ERCException("Unknown encoding.");
        }

        /// <summary>
        /// XOR-decodes the encoded portion of a XOR payload using its key.
        /// </summary>
        /// <remarks>
        /// Exists so a test can prove the encoder is reversible without running the
        /// decoder stub.
        /// </remarks>
        public static byte[] XorDecode(byte[] encoded, byte key)
        {
            var decoded = new byte[encoded.Length];
            for (int i = 0; i < encoded.Length; i++)
            {
                decoded[i] = (byte)(encoded[i] ^ key);
            }

            return decoded;
        }

        /// <summary>
        /// Simulates the alphanumeric AND/SUB/PUSH sequence and returns the dwords
        /// it pushed, as bytes in original order.
        /// </summary>
        public static byte[] SimulateAlphanumeric(byte[] encoded)
        {
            uint eax = 0;
            var stack = new List<uint>();
            int i = 0;

            while (i < encoded.Length)
            {
                if (i + 5 <= encoded.Length && encoded[i] == 0x25)
                {
                    eax &= BitConverter.ToUInt32(encoded, i + 1);
                    i += 5;
                    continue;
                }

                if (i + 5 <= encoded.Length && encoded[i] == 0x2D)
                {
                    eax -= BitConverter.ToUInt32(encoded, i + 1);
                    i += 5;
                    continue;
                }

                if (encoded[i] == 0x50)
                {
                    stack.Add(eax);
                    i += 1;
                    continue;
                }

                throw new ERCException("Unexpected opcode 0x" + encoded[i].ToString("X2") +
                                       " at offset " + i + " in the alphanumeric sequence.");
            }

            // Pushes are last-block-first, so the stack as a list is original payload
            // from last dword to first. Reverse it.
            var bytes = new List<byte>(stack.Count * 4);
            for (int n = stack.Count - 1; n >= 0; n--)
            {
                bytes.AddRange(BitConverter.GetBytes(stack[n]));
            }

            return bytes.ToArray();
        }

        #region XOR

        private static EncodedPayload EncodeXor(byte[] payload, MachineType machineType, byte[] bad)
        {
            if (machineType != MachineType.I386 && machineType != MachineType.x64)
            {
                throw new ERCException("XOR encoding is defined for x86 and x64 only.");
            }

            bool is64 = machineType == MachineType.x64;
            Exception? last = null;

            for (int key = 1; key <= 255; key++)
            {
                byte k = (byte)key;
                if (Contains(bad, k))
                {
                    continue;
                }

                byte[] encoded = XorDecode(payload, k);
                if (ContainsAny(encoded, bad))
                {
                    continue;
                }

                byte[] decoder;
                try
                {
                    decoder = BuildXorDecoder(payload.Length, k, is64, bad);
                }
                catch (ERCException e)
                {
                    last = e;
                    continue;
                }

                if (ContainsAny(decoder, bad))
                {
                    continue;
                }

                var combined = new byte[decoder.Length + encoded.Length];
                Array.Copy(decoder, 0, combined, 0, decoder.Length);
                Array.Copy(encoded, 0, combined, decoder.Length, encoded.Length);

                string arch = is64 ? "x64" : "x86";
                var notes = new List<string>
                {
                    "XOR key: 0x" + k.ToString("X2"),
                    "Decoder: " + decoder.Length + " bytes. Encoded payload: " + encoded.Length + " bytes.",
                    "The decoder is position-independent. Place the whole buffer where it will execute;" +
                    " it decrypts in place and jumps to the original payload."
                };

                return new EncodedPayload(
                    PayloadEncoding.Xor,
                    combined,
                    (byte[])payload.Clone(),
                    arch + " XOR-encoded payload. Key 0x" + k.ToString("X2") + ".",
                    notes,
                    k);
            }

            string extra = last == null ? "" : " " + last.Message;
            throw new ERCException(
                "No XOR key produces a decoder and payload that avoid the excluded bytes." + extra +
                " Relax -Bytes, or encode fewer bytes.");
        }

        private static byte[] BuildXorDecoder(int length, byte key, bool is64, byte[] bad)
        {
            var body = new List<byte>();

            // pop esi/rsi
            body.Add(0x5E);

            if (is64)
            {
                body.AddRange(new byte[] { 0x48, 0x31, 0xC9 });
            }
            else
            {
                body.AddRange(new byte[] { 0x31, 0xC9 });
            }

            body.AddRange(AddToEcx(length, bad));

            int loopStart = body.Count;
            body.AddRange(new byte[] { 0x80, 0x36, key });
            if (is64)
            {
                body.AddRange(new byte[] { 0x48, 0xFF, 0xC6 });
            }
            else
            {
                body.Add(0x46);
            }

            // E2 rel8. rel is from the next instruction back to loopStart.
            body.Add(0xE2);
            int afterLoop = body.Count + 1;
            body.Add(unchecked((byte)(loopStart - afterLoop)));

            body.AddRange(SubEsi(length, is64, bad));
            body.AddRange(new byte[] { 0xFF, 0xE6 });

            var result = new List<byte>();
            if (body.Count > 127)
            {
                throw new ERCException("The XOR decoder body is too large for a short jump.");
            }

            result.Add(0xEB);
            result.Add((byte)body.Count);
            result.AddRange(body);

            int callAt = result.Count;
            int popAt = 2;
            int callRel = popAt - (callAt + 5);
            result.Add(0xE8);
            result.AddRange(BitConverter.GetBytes(callRel));

            return result.ToArray();
        }

        private static List<byte> AddToEcx(int length, byte[] bad)
        {
            if (length <= 255 && !Contains(bad, 0xB1) && !Contains(bad, (byte)length))
            {
                return new List<byte> { 0xB1, (byte)length };
            }

            return RepeatImm8(0x83, 0xC1, length, bad, "set the payload length in ecx");
        }

        private static List<byte> SubEsi(int length, bool is64, byte[] bad)
        {
            if (is64)
            {
                if (length <= 127 &&
                    !Contains(bad, 0x48) && !Contains(bad, 0x83) && !Contains(bad, 0xEE) &&
                    !Contains(bad, (byte)length))
                {
                    return new List<byte> { 0x48, 0x83, 0xEE, (byte)length };
                }

                return RepeatImm8(0x48, 0x83, 0xEE, length, bad, "subtract the payload length from rsi");
            }

            if (length <= 127 &&
                !Contains(bad, 0x83) && !Contains(bad, 0xEE) && !Contains(bad, (byte)length))
            {
                return new List<byte> { 0x83, 0xEE, (byte)length };
            }

            return RepeatImm8(0x83, 0xEE, length, bad, "subtract the payload length from esi");
        }

        private static List<byte> RepeatImm8(byte op0, byte op1, int value, byte[] bad, string what)
        {
            return RepeatImm8(0, op0, op1, value, bad, what);
        }

        private static List<byte> RepeatImm8(byte prefix, byte op0, byte op1, int value, byte[] bad, string what)
        {
            if (Contains(bad, op0) || Contains(bad, op1) || (prefix != 0 && Contains(bad, prefix)))
            {
                throw new ERCException(
                    "Cannot " + what + " without using a byte that is excluded.");
            }

            var bytes = new List<byte>();
            int remaining = value;

            while (remaining > 0)
            {
                int chunk = Math.Min(remaining, 127);
                while (chunk > 0 && Contains(bad, (byte)chunk))
                {
                    chunk--;
                }

                if (chunk == 0)
                {
                    throw new ERCException(
                        "Cannot " + what + " of " + value +
                        " without an immediate the excluded bytes allow.");
                }

                if (prefix != 0)
                {
                    bytes.Add(prefix);
                }

                bytes.Add(op0);
                bytes.Add(op1);
                bytes.Add((byte)chunk);
                remaining -= chunk;
            }

            return bytes;
        }

        #endregion

        #region alphanumeric

        private static EncodedPayload EncodeAlphanumeric(byte[] payload, byte[] bad)
        {
            foreach (byte reserved in AlphanumericReserved)
            {
                if (Contains(bad, reserved))
                {
                    throw new ERCException(
                        "Byte 0x" + reserved.ToString("X2") +
                        " cannot be excluded: the alphanumeric encoder uses it as an opcode or as part of the two ANDs that zero EAX.");
                }
            }

            var padded = new List<byte>(payload);
            while (padded.Count % 4 != 0)
            {
                padded.Add(0x90);
            }

            byte[] paddedBytes = padded.ToArray();
            int blockCount = paddedBytes.Length / 4;
            var output = new List<byte>();

            // Last block first, so the first dword of the original ends up at ESP.
            for (int block = blockCount - 1; block >= 0; block--)
            {
                uint value = BitConverter.ToUInt32(paddedBytes, block * 4);
                uint complement = 0u - value;

                byte[] addends;
                try
                {
                    addends = SplitComplement(complement, bad);
                }
                catch (ERCException e)
                {
                    throw new ERCException(
                        "Cannot encode block " + (block + 1) + " of " + blockCount +
                        " (0x" + value.ToString("X8") + ") without excluded bytes. " + e.Message);
                }

                output.AddRange(new byte[] { 0x25, 0x4A, 0x4D, 0x4E, 0x55 });
                output.AddRange(new byte[] { 0x25, 0x35, 0x32, 0x31, 0x2A });
                output.Add(0x2D);
                output.AddRange(Immediate(addends, 0));
                output.Add(0x2D);
                output.AddRange(Immediate(addends, 1));
                output.Add(0x2D);
                output.AddRange(Immediate(addends, 2));
                output.Add(0x50);
            }

            byte[] bytes = output.ToArray();
            if (ContainsAny(bytes, bad))
            {
                throw new ERCException(
                    "The alphanumeric encoder produced a byte that is excluded. Relax -Bytes.");
            }

            var notes = new List<string>
            {
                "Original: " + payload.Length + " bytes, padded to " + padded.Count + " with NOPs.",
                "Result: " + bytes.Length + " bytes of printable AND/SUB/PUSH.",
                "EIP must start at this sequence. The stack must be writable.",
                "After it runs, ESP points at the original payload. jmp esp to execute it."
            };

            if (padded.Count != payload.Length)
            {
                notes.Add("Padded with " + (padded.Count - payload.Length) +
                          " NOP(s) so the length is a multiple of 4.");
            }

            return new EncodedPayload(
                PayloadEncoding.Alphanumeric,
                bytes,
                (byte[])payload.Clone(),
                "x86 alphanumeric (AND/SUB/PUSH) payload.",
                notes,
                0);
        }

        /// <summary>
        /// Splits a 2's-complement dword into three immediates whose bytes avoid
        /// <paramref name="bad"/>, the same way mona does.
        /// </summary>
        /// <returns>
        /// 12 bytes: three addends for each of the four original bytes, stored
        /// MSB-first per addend so Immediate can reassemble little-endian SUBs.
        /// </returns>
        private static byte[] SplitComplement(uint complement, byte[] bad)
        {
            byte[] twobytes =
            {
                (byte)(complement >> 24),
                (byte)(complement >> 16),
                (byte)(complement >> 8),
                (byte)complement
            };

            var opcodes = new byte[12];
            int overflow = 0;

            // LSB to MSB, the same direction addition carries. A byte too small to
            // split into three printable addends is raised by 256 and the next more
            // significant byte is reduced by 1, so the three immediates still sum
            // to the complement as uint32.
            for (int bcnt = 3; bcnt >= 0; bcnt--)
            {
                int currval = twobytes[bcnt] - overflow;
                overflow = 0;
                while (currval < 96)
                {
                    currval += 256;
                    overflow++;
                }

                int val1 = currval / 3;
                int val2 = currval / 3;
                int val3 = currval / 3;
                int sum = val1 + val2 + val3;
                if (sum < currval)
                {
                    val3 += currval - sum;
                }

                int[] fixedVals = FixBadChars(val1, val2, val3, bad);
                opcodes[bcnt * 3] = (byte)fixedVals[0];
                opcodes[bcnt * 3 + 1] = (byte)fixedVals[1];
                opcodes[bcnt * 3 + 2] = (byte)fixedVals[2];
            }

            return opcodes;
        }

        /// <summary>
        /// Builds one SUB immediate from the 12 addend bytes. <paramref name="which"/>
        /// is 0, 1 or 2, selecting the first, second or third SUB.
        /// </summary>
        private static byte[] Immediate(byte[] addends, int which)
        {
            // addends layout, matching mona: for each of the four original bytes
            // starting at the MSB, three addends. SUB EAX, imm32 is little-endian,
            // so the first byte after 2D is the LSB of the immediate, which is the
            // last original byte's addend.
            return new byte[]
            {
                addends[9 + which],
                addends[6 + which],
                addends[3 + which],
                addends[0 + which]
            };
        }

        /// <summary>
        /// Redistributes three addends that sum to the same value until none of
        /// them is in <paramref name="bad"/>. Ported from mona's validatebadchars_enc.
        /// </summary>
        private static int[] FixBadChars(int val1, int val2, int val3, byte[] bad)
        {
            int orig1 = val1;
            int orig2 = val2;
            int orig3 = val3;
            int type = 0;
            int d1 = 0;
            int lastD3 = 0;
            int giveup = 0;
            int allok = 0;

            while (allok == 0 && giveup == 0)
            {
                bool v1ok = !Contains(bad, (byte)val1);
                bool v2ok = !Contains(bad, (byte)val2);
                bool v3ok = !Contains(bad, (byte)val3);
                if (v1ok && v2ok && v3ok && InRange(val1) && InRange(val2) && InRange(val3))
                {
                    allok = 1;
                    break;
                }

                if (type == 0)
                {
                    val1--;
                    val2--;
                    val3 += 2;
                    if (val1 < 1 || val2 == 0 || val3 > 126)
                    {
                        val1 = orig1;
                        val2 = orig2;
                        val3 = orig3;
                        type = 1;
                    }
                }

                if (type == 1)
                {
                    val1++;
                    val2++;
                    val3 -= 2;
                    if (val1 > 126 || val2 > 126 || val3 < 1)
                    {
                        val1 = orig1;
                        val2 = orig2;
                        val3 = orig3;
                        type = 2;
                    }
                }

                if (type == 2)
                {
                    val1 -= 2;
                    val2++;
                    val3++;
                    if (val1 < 1 || val2 > 126 || val3 > 126)
                    {
                        val1 = orig1;
                        val2 = orig2;
                        val3 = orig3;
                        type = 3;
                    }
                }

                if (type == 3)
                {
                    val1 += 2;
                    val2--;
                    val3--;
                    if (val1 > 126 || val2 < 1 || val3 < 1)
                    {
                        val1 = orig1;
                        val2 = orig2;
                        val3 = orig3;
                        type = 4;
                    }
                }

                if (type == 4)
                {
                    if (Contains(bad, (byte)val1))
                    {
                        val1--;
                        d1++;
                    }
                    else if (d1 > 0)
                    {
                        val2++;
                        val3 = orig3 + d1 - 1;
                        d1--;
                    }
                    else
                    {
                        val1 = 0;
                    }

                    if (val1 < 1 || val2 > 126 || val3 > 126)
                    {
                        val1 = orig1;
                        val2 = orig2;
                        val3 = orig3;
                        d1 = 0;
                        type = 5;
                    }
                }

                if (type == 5)
                {
                    if (Contains(bad, (byte)val1))
                    {
                        val1++;
                        d1++;
                    }
                    else if (d1 > 0)
                    {
                        val2--;
                        val3 = orig3 - d1 + 1;
                        d1--;
                    }
                    else
                    {
                        val1 = 255;
                    }

                    if (val1 > 126 || val2 < 1 || val3 < 1)
                    {
                        val1 = orig1;
                        val2 = orig2;
                        val3 = orig3;
                        d1 = 0;
                        type = 6;
                    }
                }

                if (type == 6)
                {
                    if (Contains(bad, (byte)val1))
                    {
                        val1--;
                    }

                    if (Contains(bad, (byte)val2))
                    {
                        val2++;
                    }

                    int d3 = orig1 - val1 + orig2 - val2;
                    val3 = orig3 + d3;
                    if (lastD3 == d3 && d3 > 0)
                    {
                        giveup = 1;
                    }
                    else
                    {
                        lastD3 = d3;
                    }

                    if (val1 < 1 || val2 < 1 || val3 > 126)
                    {
                        giveup = 1;
                    }
                }
            }

            if (Contains(bad, (byte)val1) || Contains(bad, (byte)val2) || Contains(bad, (byte)val3) ||
                !InRange(val1) || !InRange(val2) || !InRange(val3))
            {
                throw new ERCException(
                    "Unable to split 0x" + orig1.ToString("X2") + orig2.ToString("X2") + orig3.ToString("X2") +
                    " into immediates that avoid the excluded bytes.");
            }

            return new[] { val1, val2, val3 };
        }

        private static bool InRange(int value)
        {
            return value >= 1 && value <= 126;
        }

        #endregion

        private static byte[] Distinct(byte[]? bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                return new byte[0];
            }

            return bytes.Distinct().ToArray();
        }

        private static bool Contains(byte[] bad, byte value)
        {
            for (int i = 0; i < bad.Length; i++)
            {
                if (bad[i] == value)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool ContainsAny(byte[] data, byte[] bad)
        {
            for (int i = 0; i < data.Length; i++)
            {
                if (Contains(bad, data[i]))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
