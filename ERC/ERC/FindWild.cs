using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using ERC.Structures;

namespace ERC.Utilities
{
    /// <summary>
    /// One element of an instruction-sequence search.
    /// </summary>
    public sealed class InstructionPatternElement
    {
        internal InstructionPatternElement(string original, bool anyInstruction, string? mnemonic, bool anyOperand, string exact)
        {
            Original = original;
            AnyInstruction = anyInstruction;
            Mnemonic = mnemonic;
            AnyOperand = anyOperand;
            Exact = exact;
        }

        /// <summary>The text the user typed for this element.</summary>
        public string Original { get; }

        /// <summary>True when this element is <c>*</c> and matches any instruction.</summary>
        public bool AnyInstruction { get; }

        /// <summary>
        /// The mnemonic when the operand is a wildcard, for example "jmp" in
        /// <c>jmp *</c>. Null otherwise.
        /// </summary>
        public string? Mnemonic { get; }

        /// <summary>True when any operand of <see cref="Mnemonic"/> is accepted.</summary>
        public bool AnyOperand { get; }

        /// <summary>Normalised disassembly to match exactly, when this is a concrete instruction.</summary>
        public string Exact { get; }
    }

    /// <summary>
    /// A sequence of instructions to look for, with optional wildcards.
    /// </summary>
    public sealed class InstructionPattern
    {
        internal InstructionPattern(IReadOnlyList<InstructionPatternElement> elements)
        {
            Elements = elements;
        }

        /// <summary>The elements in order.</summary>
        public IReadOnlyList<InstructionPatternElement> Elements { get; }

        /// <summary>How many instructions the sequence occupies.</summary>
        public int Length { get { return Elements.Count; } }
    }

    /// <summary>
    /// One place a pattern matched, with the disassembly of the matching window.
    /// </summary>
    public sealed class InstructionMatch
    {
        internal InstructionMatch(int offset, string disassembly)
        {
            Offset = offset;
            Disassembly = disassembly;
        }

        /// <summary>Byte offset of the first instruction of the match.</summary>
        public int Offset { get; }

        /// <summary>The matching instructions, joined with " # ".</summary>
        public string Disassembly { get; }
    }

    /// <summary>
    /// Finds instruction sequences in a buffer or a live process, with wildcards.
    /// </summary>
    /// <remarks>
    /// This is mona's <c>findwild</c>. <c>--</c>SearchMemory finds bytes;
    /// <c>--Gadget</c> finds one mnemonic ERC already catalogues. Neither answers
    /// "where is <c>push ecx # mov ebx, eax</c>" or "every <c>jmp *</c>". This does.
    ///
    /// <c>*</c> on its own matches any one instruction. <c>jmp *</c> matches any
    /// jump. Instructions are separated with <c>#</c> or <c>;</c>, so a comma inside
    /// <c>mov ebx, eax</c> is left alone.
    /// </remarks>
    public static class FindWild
    {
        /// <summary>
        /// Parses an instruction sequence. Separators are <c>#</c> and <c>;</c>.
        /// </summary>
        /// <param name="text">The sequence, for example "push ecx # mov ebx, eax" or "jmp *".</param>
        /// <returns>The pattern.</returns>
        /// <exception cref="ERCException">The text is empty or an element is empty.</exception>
        public static InstructionPattern Parse(string? text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                throw new ERCException(
                    "No instructions were given. Example: ERC --findwild pop eax # pop ebx # ret");
            }

            string[] parts = text!.Split(new[] { '#', ';' }, StringSplitOptions.None);
            var elements = new List<InstructionPatternElement>();

            foreach (string part in parts)
            {
                string original = part.Trim();
                if (original.Length == 0)
                {
                    continue;
                }

                string normalised = Normalise(original);

                if (normalised == "*")
                {
                    elements.Add(new InstructionPatternElement(original, true, null, false, string.Empty));
                    continue;
                }

                string? mnemonic;
                if (IsOperandWildcard(normalised, out mnemonic))
                {
                    elements.Add(new InstructionPatternElement(original, false, mnemonic, true, string.Empty));
                    continue;
                }

                elements.Add(new InstructionPatternElement(original, false, null, false, normalised));
            }

            if (elements.Count == 0)
            {
                throw new ERCException(
                    "No instructions were given. Example: ERC --findwild pop eax # pop ebx # ret");
            }

            return new InstructionPattern(elements);
        }

        /// <summary>
        /// Finds every place <paramref name="pattern"/> occurs in <paramref name="bytes"/>.
        /// </summary>
        /// <param name="bytes">The buffer to search.</param>
        /// <param name="pattern">The sequence to look for.</param>
        /// <param name="machineType">Architecture of the bytes.</param>
        /// <returns>One match per starting offset, in order.</returns>
        public static IReadOnlyList<InstructionMatch> Match(
            byte[]? bytes, InstructionPattern pattern, MachineType machineType)
        {
            if (bytes == null || bytes.Length == 0 || pattern == null || pattern.Length == 0)
            {
                return new InstructionMatch[0];
            }

            ErcResult<IReadOnlyList<DecodedInstruction>> decoded =
                OpcodeDisassembler.Decode(bytes, machineType);
            if (decoded.Error != null || decoded.ReturnValue == null)
            {
                return new InstructionMatch[0];
            }

            IReadOnlyList<DecodedInstruction> instructions = decoded.ReturnValue;
            var matches = new List<InstructionMatch>();

            for (int i = 0; i <= instructions.Count - pattern.Length; i++)
            {
                if (!MatchesAt(instructions, i, pattern))
                {
                    continue;
                }

                var window = new StringBuilder();
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (j > 0)
                    {
                        window.Append(" # ");
                    }

                    window.Append(instructions[i + j].Text);
                }

                matches.Add(new InstructionMatch(instructions[i].Offset, window.ToString()));
            }

            return matches;
        }

        /// <summary>
        /// Searches a process for the pattern, honouring module excludes, bad
        /// characters and pointer-shape filters.
        /// </summary>
        public static ErcResult<Dictionary<IntPtr, string>> Search(
            ProcessInfo info,
            InstructionPattern pattern,
            List<string>? excludes = null,
            byte[]? ptrsToExclude = null,
            PointerCriteria shape = PointerCriteria.None)
        {
            if (info == null)
            {
                throw new ArgumentNullException("info");
            }

            var result = new ErcResult<Dictionary<IntPtr, string>>(info.ProcessCore);
            result.ReturnValue = new Dictionary<IntPtr, string>();

            foreach (Region region in Regions(info))
            {
                ErcResult<byte[]> dump = info.DumpMemoryRegion(region.Base, region.Size);
                if (dump.Error != null || dump.ReturnValue == null)
                {
                    continue;
                }

                IReadOnlyList<InstructionMatch> matches = Match(dump.ReturnValue, pattern, info.ProcessMachineType);
                foreach (InstructionMatch match in matches)
                {
                    IntPtr address = Add(region.Base, match.Offset);
                    if (result.ReturnValue.ContainsKey(address))
                    {
                        continue;
                    }

                    string owner = Owner(info, address);
                    if (IsExcluded(owner, excludes))
                    {
                        continue;
                    }

                    result.ReturnValue.Add(address, match.Disassembly + "  (" + owner + ")");
                }
            }

            result.ReturnValue = PtrRemover.RemovePointers(
                info.ProcessMachineType, result.ReturnValue, ptrsToExclude);
            result.ReturnValue = PointerShape.Filter(
                info.ProcessMachineType, result.ReturnValue, shape);

            return result;
        }

        private static bool MatchesAt(
            IReadOnlyList<DecodedInstruction> instructions, int start, InstructionPattern pattern)
        {
            for (int i = 0; i < pattern.Length; i++)
            {
                InstructionPatternElement element = pattern.Elements[i];
                string text = instructions[start + i].Text;

                if (element.AnyInstruction)
                {
                    continue;
                }

                if (element.AnyOperand)
                {
                    if (!MnemonicIs(text, element.Mnemonic!))
                    {
                        return false;
                    }

                    continue;
                }

                if (Normalise(text) != element.Exact)
                {
                    return false;
                }
            }

            return true;
        }

        private static bool MnemonicIs(string text, string mnemonic)
        {
            string normalised = Normalise(text);
            return normalised == mnemonic ||
                   normalised.StartsWith(mnemonic + " ", StringComparison.Ordinal);
        }

        private static bool IsOperandWildcard(string normalised, out string? mnemonic)
        {
            mnemonic = null;
            Match match = Regex.Match(normalised, @"^([a-z][a-z0-9]*)\s*\*$");
            if (!match.Success)
            {
                return false;
            }

            mnemonic = match.Groups[1].Value;
            return true;
        }

        private static string Normalise(string text)
        {
            string trimmed = text.Trim().ToLowerInvariant();
            trimmed = Regex.Replace(trimmed, @"\s+", " ");
            trimmed = Regex.Replace(trimmed, @"\s*,\s*", ", ");
            return trimmed;
        }

        private struct Region
        {
            public IntPtr Base;
            public int Size;
        }

        private static IEnumerable<Region> Regions(ProcessInfo info)
        {
            const int chunk = 8 * 1024 * 1024;

            if (info.ProcessMachineType == MachineType.I386)
            {
                foreach (MEMORY_BASIC_INFORMATION32 region in info.MemoryRegions32)
                {
                    if (region.State != StateEnum.MEM_COMMIT || !IsReadable(region.Protect))
                    {
                        continue;
                    }

                    long remaining = (long)region.RegionSize;
                    long start = region.BaseAddress.ToInt64();
                    while (remaining > 0)
                    {
                        int size = remaining > chunk ? chunk : (int)remaining;
                        yield return new Region { Base = new IntPtr(start), Size = size };
                        start += size;
                        remaining -= size;
                    }
                }
            }
            else if (info.ProcessMachineType == MachineType.x64)
            {
                foreach (MEMORY_BASIC_INFORMATION64 region in info.MemoryRegions64)
                {
                    if (region.State != StateEnum.MEM_COMMIT || !IsReadable((uint)region.Protect))
                    {
                        continue;
                    }

                    ulong remaining = region.RegionSize;
                    ulong start = region.BaseAddress;
                    while (remaining > 0)
                    {
                        int size = remaining > (ulong)chunk ? chunk : (int)remaining;
                        yield return new Region { Base = new IntPtr((long)start), Size = size };
                        start += (ulong)size;
                        remaining -= (ulong)size;
                    }
                }
            }
        }

        private static string Owner(ProcessInfo info, IntPtr address)
        {
            ulong value = (ulong)address.ToInt64();
            foreach (ModuleInfo module in info.ModulesInfo)
            {
                ulong start = (ulong)module.ModuleBase.ToInt64();
                ulong end = start + (uint)module.ModuleSize;
                if (value >= start && value < end)
                {
                    return module.ModulePath;
                }
            }

            return info.ProcessPath;
        }

        private static bool IsExcluded(string owner, List<string>? excludes)
        {
            if (excludes == null || excludes.Count == 0)
            {
                return false;
            }

            foreach (string exclude in excludes)
            {
                if (owner.Equals(exclude, StringComparison.OrdinalIgnoreCase) ||
                    System.IO.Path.GetFileName(owner).Equals(exclude, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static IntPtr Add(IntPtr start, int offset)
        {
            return new IntPtr(start.ToInt64() + offset);
        }

        private static bool IsReadable(uint protect)
        {
            // PAGE_NOACCESS 0x01, PAGE_GUARD 0x100: dumping these fails or raises.
            if ((protect & 0x01) != 0 || (protect & 0x100) != 0)
            {
                return false;
            }

            return protect != 0;
        }
    }
}
