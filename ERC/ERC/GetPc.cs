using System;
using System.Collections.Generic;

namespace ERC.Utilities
{
    /// <summary>
    /// One GetPC stub: a short sequence that leaves the current instruction
    /// pointer in a register.
    /// </summary>
    public sealed class GetPcRoutine
    {
        internal GetPcRoutine(string name, byte[] opcodes, string register, string description)
        {
            Name = name;
            Opcodes = opcodes;
            Register = register;
            Description = description;
        }

        /// <summary>Short name of the technique, for example "fstenv".</summary>
        public string Name { get; }

        /// <summary>The bytes of the stub.</summary>
        public byte[] Opcodes { get; }

        /// <summary>The register that holds the instruction pointer afterwards.</summary>
        public string Register { get; }

        /// <summary>Where the register points, and when this variant is the one to use.</summary>
        public string Description { get; }
    }

    /// <summary>
    /// Builds GetPC stubs, the short sequences that put the current instruction
    /// pointer into a register.
    /// </summary>
    /// <remarks>
    /// Position-independent shellcode, encoders and egg hunters all need to know
    /// where they are running. A GetPC stub is how they find out. mona's
    /// <c>getpc</c> emits three x86 variants for a chosen register; this emits
    /// those three, plus RIP-relative <c>lea</c> on x64.
    /// </remarks>
    public static class GetPc
    {
        private static readonly string[] BaseRegisters =
        {
            "ax", "cx", "dx", "bx", "sp", "bp", "si", "di"
        };

        /// <summary>
        /// The GetPC stubs that put the instruction pointer into a register.
        /// </summary>
        /// <param name="register">Register name, for example "eax" or "rax". Case insensitive.</param>
        /// <param name="machineType">Architecture of the stub.</param>
        /// <returns>One entry per technique that works for this register.</returns>
        /// <exception cref="ERCException">
        /// The register is not one this architecture has.
        /// </exception>
        public static IReadOnlyList<GetPcRoutine> For(string? register, MachineType machineType)
        {
            byte number;
            bool rexB;
            string name = Resolve(register, machineType, out number, out rexB);

            var routines = new List<GetPcRoutine>();

            if (machineType == MachineType.x64)
            {
                routines.Add(LeaRip(name, number, rexB));
            }

            // The jmp-short-back and call-plus-4 sequences are the bytes mona
            // emits, with displacements that assume a one-byte pop and a two-byte
            // call. r8-r15 need a REX prefix on both, which would throw those
            // displacements out, so they only get lea and fstenv.
            if (!rexB)
            {
                routines.Add(JmpShortBack(name, number));
                routines.Add(CallPlusFour(name, number));
            }

            routines.Add(Fstenv(name, number, rexB));

            return routines;
        }

        /// <summary>
        /// The registers this can target, for the given architecture.
        /// </summary>
        public static IReadOnlyList<string> SupportedRegisters(MachineType machineType)
        {
            return JumpToRegister.SupportedRegisters(machineType);
        }

        /// <summary>
        /// jmp-short-back: skip a pop/call, then a relative call lands on the pop
        /// so the register receives the address of the byte after the stub.
        /// </summary>
        /// <remarks>
        /// <c>EB 03</c> + pop + <c>FF D0+r</c> + <c>E8 F8 FF FF FF</c>. After the
        /// pop the register holds the address following the stub, and the following
        /// <c>call</c> transfers into it. This is the first of mona's three x86
        /// variants, reproduced byte for byte.
        /// </remarks>
        private static GetPcRoutine JmpShortBack(string register, byte number)
        {
            var bytes = new List<byte> { 0xEB, 0x03 };
            AddPop(bytes, number, false);
            AddCallReg(bytes, number, false);
            bytes.AddRange(new byte[] { 0xE8, 0xF8, 0xFF, 0xFF, 0xFF });

            return new GetPcRoutine(
                "jmp-short-back",
                bytes.ToArray(),
                register,
                register + " holds the address of the byte after the stub, then the stub calls that address.");
        }

        /// <summary>
        /// call $+4: a call whose displacement overlaps the next instruction, then
        /// a pop. The register holds the address of the <c>ret</c> that is the
        /// last byte of the call.
        /// </summary>
        /// <remarks>
        /// <c>E8 FF FF FF FF C3</c> + pop. mona's "call + 4" variant. The call
        /// target is the last byte of its own displacement, which with the
        /// following <c>C3</c> decodes as a two-byte instruction, then the pop
        /// receives the pushed return address.
        /// </remarks>
        private static GetPcRoutine CallPlusFour(string register, byte number)
        {
            var bytes = new List<byte> { 0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3 };
            AddPop(bytes, number, false);

            return new GetPcRoutine(
                "call-plus-4",
                bytes.ToArray(),
                register,
                register + " holds the address of the ret that overlaps the call. One byte before the pop.");
        }

        /// <summary>
        /// FPU GetPC: fldpi, fnstenv [esp-0xc], pop. The register holds the
        /// address of the fldpi, which is the start of the stub.
        /// </summary>
        /// <remarks>
        /// <c>D9 EB 9B D9 74 24 F4</c> + pop. Null-free, and the register points
        /// at the stub itself rather than after it. On x64 the saved FPU IP is
        /// still 32 bits; the low half of RIP is enough when the stub sits in
        /// the low 4 GB, which a 32-bit-style overflow still does.
        /// </remarks>
        private static GetPcRoutine Fstenv(string register, byte number, bool rexB)
        {
            var bytes = new List<byte> { 0xD9, 0xEB, 0x9B, 0xD9, 0x74, 0x24, 0xF4 };
            AddPop(bytes, number, rexB);

            return new GetPcRoutine(
                "fstenv",
                bytes.ToArray(),
                register,
                register + " holds the address of the stub itself (the fldpi). Null-free.");
        }

        /// <summary>
        /// RIP-relative lea, x64 only. The register holds the address of the
        /// instruction after the lea.
        /// </summary>
        private static GetPcRoutine LeaRip(string register, byte number, bool rexB)
        {
            // REX.W (and REX.R when the register is r8-r15), then 8D, then a
            // ModRM of RIP-relative (rm = 101) with the register in the reg field,
            // then a 32-bit displacement of zero.
            byte rex = (byte)(0x48 | (rexB ? 0x04 : 0x00));
            byte modrm = (byte)(0x05 | (number << 3));
            byte[] bytes = { rex, 0x8D, modrm, 0x00, 0x00, 0x00, 0x00 };

            return new GetPcRoutine(
                "lea-rip",
                bytes,
                register,
                register + " holds the address of the instruction after the lea. Contains nulls.");
        }

        private static void AddPop(List<byte> bytes, byte number, bool rexB)
        {
            if (rexB)
            {
                bytes.Add(0x41);
            }

            bytes.Add((byte)(0x58 + number));
        }

        private static void AddCallReg(List<byte> bytes, byte number, bool rexB)
        {
            if (rexB)
            {
                bytes.Add(0x41);
            }

            bytes.Add(0xFF);
            bytes.Add((byte)(0xD0 + number));
        }

        private static string Resolve(string? register, MachineType machineType, out byte number, out bool rexB)
        {
            number = 0;
            rexB = false;

            if (machineType != MachineType.I386 && machineType != MachineType.x64)
            {
                throw new ERCException("GetPC is defined for x86 and x64 only.");
            }

            if (string.IsNullOrEmpty(register))
            {
                throw new ERCException("No register was supplied. Expected one of: " +
                                       string.Join(", ", JumpToRegister.SupportedRegisters(machineType)));
            }

            string name = register!.Trim().ToLowerInvariant();

            if (name.Length >= 2 && name[0] == 'r' && char.IsDigit(name[1]))
            {
                int extended;
                if (machineType == MachineType.x64 &&
                    int.TryParse(name.Substring(1), out extended) &&
                    extended >= 8 && extended <= 15)
                {
                    number = (byte)(extended - 8);
                    rexB = true;
                    return name;
                }

                throw new ERCException("\"" + register + "\" is not a register of this architecture. Expected one of: " +
                                       string.Join(", ", JumpToRegister.SupportedRegisters(machineType)));
            }

            string expectedPrefix = machineType == MachineType.x64 ? "r" : "e";

            if (name.Length == 3 && name.StartsWith(expectedPrefix, StringComparison.Ordinal))
            {
                int index = Array.IndexOf(BaseRegisters, name.Substring(1));
                if (index >= 0)
                {
                    number = (byte)index;
                    return name;
                }
            }

            throw new ERCException("\"" + register + "\" is not a register of this " +
                                   (machineType == MachineType.x64 ? "64" : "32") +
                                   "-bit architecture. Expected one of: " +
                                   string.Join(", ", JumpToRegister.SupportedRegisters(machineType)));
        }
    }
}
