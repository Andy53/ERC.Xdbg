using System;
using System.Collections.Generic;

namespace ERC.Utilities
{
    /// <summary>
    /// One way of transferring execution to the address held in a register.
    /// </summary>
    public sealed class RegisterJump
    {
        internal RegisterJump(byte[] opcodes, string instruction)
        {
            Opcodes = opcodes;
            Instruction = instruction;
        }

        /// <summary>The bytes to search for.</summary>
        public byte[] Opcodes { get; }

        /// <summary>What those bytes disassemble to, for example "jmp esp".</summary>
        public string Instruction { get; }
    }

    /// <summary>
    /// Finds the instructions that jump to a register.
    /// </summary>
    /// <remarks>
    /// After a stack overflow the usual next step is to find a "jmp esp" - or
    /// something equivalent - in a module without ASLR, and overwrite the saved
    /// return address with it. That is the single most common lookup in the whole
    /// workflow, and it had no command: the addresses could only be found by
    /// searching for the opcode bytes by hand and knowing what they were.
    ///
    /// Three encodings reach the same place and all three are worth having, because
    /// which ones exist in a usable module varies:
    ///
    ///   jmp  reg    FF E0+r
    ///   call reg    FF D0+r
    ///   push reg    50+r, followed by ret (C3)
    ///
    /// where r is the register's number in the ModRM encoding. On x64 the same bytes
    /// address the 64-bit registers, and r8 to r15 are reached by prefixing REX.B
    /// (0x41).
    /// </remarks>
    public static class JumpToRegister
    {
        /// <summary>
        /// Register numbers as they appear in the ModRM byte, for the eight registers
        /// that predate x64.
        /// </summary>
        private static readonly string[] BaseRegisters =
        {
            "ax", "cx", "dx", "bx", "sp", "bp", "si", "di"
        };

        /// <summary>
        /// The registers this understands, for the given architecture.
        /// </summary>
        /// <param name="machineType">Architecture of the process being searched.</param>
        /// <returns>Register names in lower case, for example "esp" or "rsp".</returns>
        public static IReadOnlyList<string> SupportedRegisters(MachineType machineType)
        {
            var names = new List<string>();
            string prefix = machineType == MachineType.x64 ? "r" : "e";

            foreach (string register in BaseRegisters)
            {
                names.Add(prefix + register);
            }

            if (machineType == MachineType.x64)
            {
                for (int i = 8; i <= 15; i++)
                {
                    names.Add("r" + i.ToString());
                }
            }

            return names;
        }

        /// <summary>
        /// The byte sequences that transfer execution to a register.
        /// </summary>
        /// <param name="register">Register name, for example "esp". Case insensitive.</param>
        /// <param name="machineType">Architecture of the process being searched.</param>
        /// <returns>One entry per encoding.</returns>
        /// <exception cref="ERCException">
        /// The register is not one this architecture has.
        /// </exception>
        public static IReadOnlyList<RegisterJump> Encodings(string? register, MachineType machineType)
        {
            byte number;
            byte[] rex;

            Resolve(register, machineType, out number, out rex);

            string name = register!.Trim().ToLowerInvariant();

            var encodings = new List<RegisterJump>
            {
                new RegisterJump(With(rex, 0xFF, (byte)(0xE0 + number)), "jmp " + name),
                new RegisterJump(With(rex, 0xFF, (byte)(0xD0 + number)), "call " + name),

                // "push reg; ret" lands in the same place: the push puts the register
                // on the stack and the ret takes it straight back off into the
                // instruction pointer.
                new RegisterJump(With(rex, (byte)(0x50 + number), 0xC3), "push " + name + " # ret")
            };

            return encodings;
        }

        /// <summary>
        /// Searches a process for every way of jumping to a register.
        /// </summary>
        /// <param name="info">The process to search.</param>
        /// <param name="register">Register name, for example "esp".</param>
        /// <param name="excludes">Modules to leave out of the search.</param>
        /// <param name="ptrsToExclude">
        /// Bytes that disqualify an address. An address containing a byte the target
        /// mangles is of no use, however good the instruction at it.
        /// </param>
        /// <returns>Address to instruction, for every match found.</returns>
        public static ErcResult<Dictionary<IntPtr, string>> Search(
            ProcessInfo info,
            string? register,
            List<string>? excludes = null,
            byte[]? ptrsToExclude = null)
        {
            if (info == null)
            {
                throw new ArgumentNullException(nameof(info));
            }

            var result = new ErcResult<Dictionary<IntPtr, string>>(info.ProcessCore);
            result.ReturnValue = new Dictionary<IntPtr, string>();

            IReadOnlyList<RegisterJump> encodings;

            try
            {
                encodings = Encodings(register, info.ProcessMachineType);
            }
            catch (ERCException e)
            {
                result.Error = e;
                return result;
            }

            foreach (RegisterJump encoding in encodings)
            {
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
                    // The same address cannot hold two different encodings, but a
                    // module mapped twice can produce the same address twice.
                    if (!result.ReturnValue.ContainsKey(match.Key))
                    {
                        result.ReturnValue.Add(match.Key, encoding.Instruction + "  (" + match.Value + ")");
                    }
                }
            }

            return result;
        }

        /// <summary>
        /// Turns a register name into its ModRM number and any REX prefix it needs.
        /// </summary>
        private static void Resolve(string? register, MachineType machineType, out byte number, out byte[] rex)
        {
            number = 0;
            rex = new byte[0];

            if (string.IsNullOrEmpty(register))
            {
                throw new ERCException("No register was supplied. Expected one of: " +
                                       string.Join(", ", Names(machineType)));
            }

            string name = register!.Trim().ToLowerInvariant();

            // r8 to r15 exist only on x64 and need a REX.B prefix to reach.
            if (name.Length >= 2 && name[0] == 'r' && char.IsDigit(name[1]))
            {
                int extended;
                if (machineType == MachineType.x64 &&
                    int.TryParse(name.Substring(1), out extended) &&
                    extended >= 8 && extended <= 15)
                {
                    number = (byte)(extended - 8);
                    rex = new byte[] { 0x41 };
                    return;
                }

                throw new ERCException("\"" + register + "\" is not a register of this process. Expected one of: " +
                                       string.Join(", ", Names(machineType)));
            }

            string expectedPrefix = machineType == MachineType.x64 ? "r" : "e";

            if (name.Length == 3 && name.StartsWith(expectedPrefix, StringComparison.Ordinal))
            {
                int index = Array.IndexOf(BaseRegisters, name.Substring(1));
                if (index >= 0)
                {
                    number = (byte)index;
                    return;
                }
            }

            throw new ERCException("\"" + register + "\" is not a register of this " +
                                   (machineType == MachineType.x64 ? "64" : "32") +
                                   "-bit process. Expected one of: " + string.Join(", ", Names(machineType)));
        }

        private static string[] Names(MachineType machineType)
        {
            var list = new List<string>(SupportedRegisters(machineType));
            return list.ToArray();
        }

        private static byte[] With(byte[] prefix, params byte[] opcodes)
        {
            var bytes = new byte[prefix.Length + opcodes.Length];
            Array.Copy(prefix, bytes, prefix.Length);
            Array.Copy(opcodes, 0, bytes, prefix.Length, opcodes.Length);
            return bytes;
        }
    }
}
