using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using ERC;
using ERC.Cli;
using ERC.Utilities;
using Managed.x64dbg.SDK;

namespace ErcXdbg
{
    /// <summary>
    /// The commands that produce payload bytes: encoding, GetPC, Venetian alignment.
    /// </summary>
    public static partial class RegisteredCommands
    {
        /// <summary>
        /// Encodes a payload so it survives a restricted character set.
        /// </summary>
        private static void EncodePayload(ERC.ErcCore core, ERC.ProcessInfo? info, List<string> parameters, SessionState session)
        {
            parameters.RemoveAll(p => p.Contains("--"));

            MachineType machine = ArchitectureFrom(parameters, info);
            PayloadEncoding encoding;

            if (parameters.Count == 0 || !PayloadEncoder.TryParseEncoding(parameters[0], out encoding))
            {
                PrintHelp("--Encode takes a type (xor or alphanum) and the payload as hex bytes or a file path. " +
                          "Example: ERC --encode xor 9090CC");
                return;
            }

            parameters.RemoveAt(0);
            byte[]? payload = ReadPayload(parameters);
            if (payload == null)
            {
                PrintHelp("--Encode needs the payload as hex bytes or as a file that contains them. " +
                          "Example: ERC --encode xor 9090CC");
                return;
            }

            try
            {
                string output = DisplayOutput.GenerateEncodedPayload(
                    payload, encoding, machine, session.Bytes, core);
                PLog.WriteLine(output);
            }
            catch (Exception e)
            {
                PrintHelp(e.Message);
            }
        }

        /// <summary>
        /// Prints GetPC stubs for a register.
        /// </summary>
        private static void GetPcCommand(ERC.ErcCore core, ERC.ProcessInfo? info, List<string> parameters)
        {
            parameters.RemoveAll(p => p.Contains("--"));
            parameters.RemoveAll(p => p.Equals("-r", StringComparison.OrdinalIgnoreCase));

            MachineType machine = ArchitectureFrom(parameters, info);

            if (parameters.Count != 1)
            {
                PrintHelp("--GetPc takes one register. Example: ERC --getpc eax");
                return;
            }

            try
            {
                string output = DisplayOutput.GenerateGetPc(parameters[0], machine, core);
                PLog.WriteLine(output);
            }
            catch (Exception e)
            {
                PrintHelp(e.Message);
            }
        }

        /// <summary>
        /// Prints a Venetian alignment stub for a Unicode overflow.
        /// </summary>
        private static void UnicodeAlignCommand(ERC.ErcCore core, List<string> parameters)
        {
            parameters.RemoveAll(p => p.Contains("--"));
            parameters.RemoveAll(p => p.Equals("-r", StringComparison.OrdinalIgnoreCase));

            bool leak = RemoveKeyword(parameters, "leak");
            bool jump = RemoveKeyword(parameters, "jmp") || RemoveKeyword(parameters, "jump");
            string? buffer = null;
            string? source = null;
            var numbers = new List<string>();

            foreach (string token in parameters)
            {
                if (IsRegister32(token))
                {
                    if (buffer == null)
                    {
                        buffer = token;
                    }
                    else if (source == null)
                    {
                        // First register is the buffer; the second is copied into it.
                        source = token;
                    }
                    else
                    {
                        PrintHelp("--UnicodeAlign takes at most two registers: the buffer register, then an optional source to copy from.");
                        return;
                    }
                }
                else
                {
                    numbers.Add(token);
                }
            }

            try
            {
                UnicodeAlignment alignment;

                if (numbers.Count == 0)
                {
                    alignment = UnicodeAlign.Generate(0, buffer, leak, jump, source);
                }
                else if (numbers.Count == 1)
                {
                    int delta;
                    if (!TryParseSigned(numbers[0], out delta))
                    {
                        PrintHelp("--UnicodeAlign needs an offset in bytes, or two hex addresses (current, target). " +
                                  "Example: ERC --unicodealign 32");
                        return;
                    }

                    alignment = UnicodeAlign.Generate(delta, buffer, leak, jump, source);
                }
                else if (numbers.Count == 2)
                {
                    uint current;
                    uint target;
                    if (!TryParseAddress(numbers[0], out current) || !TryParseAddress(numbers[1], out target))
                    {
                        PrintHelp("--UnicodeAlign with two values takes the current register value and the target address, both hex. " +
                                  "Example: ERC --unicodealign 0x0012FF00 0x0012FF40");
                        return;
                    }

                    alignment = UnicodeAlign.GenerateToTarget(current, target, buffer, leak, jump, source);
                }
                else
                {
                    PrintHelp("--UnicodeAlign takes an offset, or two hex addresses. Example: ERC --unicodealign 32");
                    return;
                }

                string output = DisplayOutput.GenerateUnicodeAlign(alignment, core);
                PLog.WriteLine(output);
            }
            catch (Exception e)
            {
                PrintHelp(e.Message);
            }
        }

        /// <summary>
        /// True when the option produces payload bytes and does not inspect the
        /// debuggee, so it can run with no process attached.
        /// </summary>
        private static bool DoesNotNeedAProcess(string option)
        {
            switch (option)
            {
                case "--help":
                case "--update":
                case "--config":
                case "--debug":
                case "--reset":
                case "--encode":
                case "--getpc":
                case "--unicodealign":
                    return true;
                default:
                    return false;
            }
        }

        private static MachineType ArchitectureFrom(List<string> parameters, ERC.ProcessInfo? info)
        {
            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i] == "0")
                {
                    parameters.RemoveAt(i);
                    return MachineType.I386;
                }

                if (parameters[i] == "1")
                {
                    parameters.RemoveAt(i);
                    return MachineType.x64;
                }
            }

            if (info != null)
            {
                return info.ProcessMachineType;
            }

            return MachineType.I386;
        }

        private static byte[]? ReadPayload(List<string> parameters)
        {
            if (parameters.Count == 0)
            {
                return null;
            }

            if (parameters.Count == 1 && File.Exists(parameters[0]))
            {
                return File.ReadAllBytes(parameters[0]);
            }

            string joined = string.Join("", parameters.ToArray());
            byte[]? bytes = CommandParser.ParseByteList(joined);
            if (bytes != null && bytes.Length > 0)
            {
                return bytes;
            }

            if (File.Exists(string.Join(" ", parameters.ToArray())))
            {
                return File.ReadAllBytes(string.Join(" ", parameters.ToArray()));
            }

            return null;
        }

        private static bool RemoveKeyword(List<string> parameters, string keyword)
        {
            int index = parameters.FindIndex(p => p.Equals(keyword, StringComparison.OrdinalIgnoreCase));
            if (index < 0)
            {
                return false;
            }

            parameters.RemoveAt(index);
            return true;
        }

        private static bool IsRegister32(string token)
        {
            foreach (string register in UnicodeAlign.SupportedRegisters)
            {
                if (token.Equals(register, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool TryParseSigned(string token, out int value)
        {
            value = 0;
            if (int.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
            {
                return true;
            }

            string hex = StripHexPrefix(token);
            return int.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
        }

        private static bool TryParseAddress(string token, out uint value)
        {
            value = 0;
            string hex = StripHexPrefix(token);
            return uint.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
        }

        private static string StripHexPrefix(string token)
        {
            if (token.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ||
                token.StartsWith("\\x", StringComparison.OrdinalIgnoreCase))
            {
                return token.Substring(2);
            }

            return token;
        }
    }
}
