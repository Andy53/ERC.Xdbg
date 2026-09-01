using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using ERC.Native;
using ERC.Structures;
using Iced.Intel;

namespace ERC.Utilities
{
    /// <summary>
    /// A call or jump through a pointer that sits in writable memory.
    /// </summary>
    public sealed class FwptrHit
    {
        internal FwptrHit(IntPtr call, IntPtr pointer, string instruction, string module)
        {
            Call = call;
            Pointer = pointer;
            Instruction = instruction;
            Module = module;
        }

        /// <summary>The call or jump instruction.</summary>
        public IntPtr Call { get; }

        /// <summary>
        /// The writable location the instruction dereferences. A 4- or 8-byte write
        /// here redirects the call.
        /// </summary>
        public IntPtr Pointer { get; }

        /// <summary>Disassembly of the call or jump.</summary>
        public string Instruction { get; }

        /// <summary>Module that contains the instruction.</summary>
        public string Module { get; }
    }

    /// <summary>
    /// Finds calls and jumps through a pointer in writable memory.
    /// </summary>
    /// <remarks>
    /// An arbitrary write of pointer width becomes EIP if the overwritten location
    /// is later used as <c>call [ptr]</c> or <c>jmp [ptr]</c>. That is the
    /// four-byte-write-to-code-execution primitive; the instruction is the
    /// trigger, the writable slot is the target.
    ///
    /// Register-relative operands (<c>call [eax]</c>) are skipped: they are not a
    /// fixed location a write can aim at.
    /// </remarks>
    public static class Fwptr
    {
        /// <summary>
        /// The pointer a near-indirect call or jump at the start of
        /// <paramref name="code"/> would dereference, when that operand is a
        /// fixed address (absolute or RIP-relative).
        /// </summary>
        public static bool TryPointer(
            byte[] code, ulong address, MachineType machine, out ulong pointer, out string text)
        {
            pointer = 0;
            text = string.Empty;

            if (code == null || code.Length < 2)
            {
                return false;
            }

            int bitness = machine == MachineType.x64 ? 64 : 32;
            var reader = new ByteArrayCodeReader(code);
            Decoder decoder = Decoder.Create(bitness, reader);
            decoder.IP = address;

            Instruction instruction = decoder.Decode();
            if (instruction.Length <= 0)
            {
                return false;
            }

            if (!PointerOf(instruction, out pointer))
            {
                return false;
            }

            var formatter = CreateFormatter();
            var output = new StringOutput();
            formatter.Format(instruction, output);
            text = output.ToStringAndReset();
            return true;
        }

        private static bool PointerOf(Instruction instruction, out ulong pointer)
        {
            pointer = 0;

            if (instruction.FlowControl != FlowControl.IndirectCall &&
                instruction.FlowControl != FlowControl.IndirectBranch)
            {
                return false;
            }

            if (instruction.Op0Kind != OpKind.Memory)
            {
                return false;
            }

            if (instruction.IsIPRelativeMemoryOperand)
            {
                pointer = instruction.IPRelativeMemoryAddress;
                return true;
            }

            if (instruction.MemoryBase == Register.None && instruction.MemoryDisplSize >= 4)
            {
                pointer = instruction.MemoryDisplacement64;
                return true;
            }

            return false;
        }

        private static Formatter CreateFormatter()
        {
            var formatter = new MasmFormatter();
            formatter.Options.SpaceAfterOperandSeparator = true;
            formatter.Options.UppercaseMnemonics = false;
            formatter.Options.UppercaseRegisters = false;
            formatter.Options.UppercaseKeywords = false;
            formatter.Options.UppercaseDecorators = false;
            formatter.Options.UppercaseAll = false;
            return formatter;
        }

        /// <summary>
        /// Searches loaded modules for calls and jumps through writable memory.
        /// </summary>
        public static ErcResult<List<FwptrHit>> Search(
            ProcessInfo info,
            List<string>? excludes = null,
            byte[]? ptrsToExclude = null,
            PointerCriteria shape = PointerCriteria.None)
        {
            if (info == null)
            {
                throw new ArgumentNullException("info");
            }

            var result = new ErcResult<List<FwptrHit>>(info.ProcessCore);
            result.ReturnValue = new List<FwptrHit>();

            foreach (ModuleInfo module in info.ModulesInfo)
            {
                if (module.ModuleFailed || module.ModuleSize <= 0)
                {
                    continue;
                }

                if (IsExcluded(module, excludes))
                {
                    continue;
                }

                foreach (Span span in ExecutableSpans(info, module))
                {
                    ErcResult<byte[]> dump = info.DumpMemoryRegion(span.Base, span.Size);
                    if (dump.Error != null || dump.ReturnValue == null)
                    {
                        continue;
                    }

                    byte[] bytes = dump.ReturnValue;
                    ulong baseAddress = (ulong)span.Base.ToInt64();
                    int bitness = info.ProcessMachineType == MachineType.x64 ? 64 : 32;
                    var reader = new ByteArrayCodeReader(bytes);
                    Decoder decoder = Decoder.Create(bitness, reader);
                    decoder.IP = baseAddress;
                    ulong end = baseAddress + (uint)bytes.Length;
                    var formatter = CreateFormatter();
                    var output = new StringOutput();

                    while (decoder.IP < end)
                    {
                        ulong ip = decoder.IP;
                        Instruction instruction = decoder.Decode();
                        int length = instruction.Length;
                        if (length <= 0)
                        {
                            break;
                        }

                        ulong pointer;
                        if (!PointerOf(instruction, out pointer))
                        {
                            continue;
                        }

                        formatter.Format(instruction, output);
                        string text = output.ToStringAndReset();
                        IntPtr call = new IntPtr((long)ip);
                        IntPtr slot = new IntPtr((long)pointer);

                        if (IsWritable(info, slot) &&
                            PassesFilters(call, slot, info.ProcessMachineType, ptrsToExclude, shape))
                        {
                            result.ReturnValue.Add(new FwptrHit(
                                call, slot, text, module.ModulePath));
                        }
                    }
                }
            }

            return result;
        }

        private static bool PassesFilters(
            IntPtr call, IntPtr slot, MachineType machine, byte[]? ptrsToExclude, PointerCriteria shape)
        {
            if (ptrsToExclude != null && ptrsToExclude.Length > 0)
            {
                var one = new Dictionary<IntPtr, string> { { slot, string.Empty } };
                if (PtrRemover.RemovePointers(machine, one, ptrsToExclude).Count == 0)
                {
                    return false;
                }

                one = new Dictionary<IntPtr, string> { { call, string.Empty } };
                if (PtrRemover.RemovePointers(machine, one, ptrsToExclude).Count == 0)
                {
                    return false;
                }
            }

            return PointerShape.Matches(slot, machine, shape);
        }

        private static bool IsWritable(ProcessInfo info, IntPtr address)
        {
            INativeApi native = info.ProcessCore.Native;
            IntPtr handle = info.ProcessHandle;

            if (info.ProcessMachineType == MachineType.I386)
            {
                MEMORY_BASIC_INFORMATION32 region;
                if (native.VirtualQueryEx32(handle, address, out region,
                        (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION32))) == 0)
                {
                    return false;
                }

                return region.State == StateEnum.MEM_COMMIT && Writable(region.Protect);
            }

            MEMORY_BASIC_INFORMATION64 region64;
            if (native.VirtualQueryEx64(handle, address, out region64,
                    (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION64))) == 0)
            {
                return false;
            }

            return region64.State == StateEnum.MEM_COMMIT && Writable((uint)region64.Protect);
        }

        private static bool Writable(uint protect)
        {
            if ((protect & 0x01) != 0 || (protect & 0x100) != 0)
            {
                return false;
            }

            // PAGE_READWRITE, WRITECOPY, EXECUTE_READWRITE, EXECUTE_WRITECOPY.
            return (protect & 0x04) != 0 || (protect & 0x08) != 0 ||
                   (protect & 0x40) != 0 || (protect & 0x80) != 0;
        }

        private struct Span
        {
            public IntPtr Base;
            public int Size;
        }

        private static IEnumerable<Span> ExecutableSpans(ProcessInfo info, ModuleInfo module)
        {
            ulong moduleStart = (ulong)module.ModuleBase.ToInt64();
            ulong moduleEnd = moduleStart + (uint)module.ModuleSize;
            INativeApi native = info.ProcessCore.Native;
            IntPtr handle = info.ProcessHandle;

            if (info.ProcessMachineType == MachineType.I386)
            {
                uint infoSize = (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION32));
                ulong address = moduleStart;
                for (int n = 0; n < 4096 && address < moduleEnd; n++)
                {
                    MEMORY_BASIC_INFORMATION32 region;
                    if (native.VirtualQueryEx32(handle, new IntPtr((long)address), out region, infoSize) == 0)
                    {
                        yield break;
                    }

                    ulong start = (ulong)region.BaseAddress.ToInt64();
                    ulong size = (ulong)region.RegionSize.ToInt64();
                    if (size == 0)
                    {
                        yield break;
                    }

                    if (region.State == StateEnum.MEM_COMMIT && Executable(region.Protect))
                    {
                        Span span;
                        if (TryOverlap(start, size, moduleStart, moduleEnd, out span))
                        {
                            yield return span;
                        }
                    }

                    ulong next = start + size;
                    if (next <= address)
                    {
                        yield break;
                    }

                    address = next;
                }
            }
            else if (info.ProcessMachineType == MachineType.x64)
            {
                uint infoSize = (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION64));
                ulong address = moduleStart;
                for (int n = 0; n < 4096 && address < moduleEnd; n++)
                {
                    MEMORY_BASIC_INFORMATION64 region;
                    if (native.VirtualQueryEx64(handle, new IntPtr((long)address), out region, infoSize) == 0)
                    {
                        yield break;
                    }

                    if (region.RegionSize == 0)
                    {
                        yield break;
                    }

                    if (region.State == StateEnum.MEM_COMMIT && Executable((uint)region.Protect))
                    {
                        Span span;
                        if (TryOverlap(region.BaseAddress, region.RegionSize, moduleStart, moduleEnd, out span))
                        {
                            yield return span;
                        }
                    }

                    ulong next = region.BaseAddress + region.RegionSize;
                    if (next <= address)
                    {
                        yield break;
                    }

                    address = next;
                }
            }
        }

        private static bool TryOverlap(ulong start, ulong size, ulong moduleStart, ulong moduleEnd, out Span span)
        {
            span = default(Span);
            ulong end = start + size;
            ulong lo = start > moduleStart ? start : moduleStart;
            ulong hi = end < moduleEnd ? end : moduleEnd;
            if (hi <= lo || hi - lo > int.MaxValue)
            {
                return false;
            }

            span = new Span { Base = new IntPtr((long)lo), Size = (int)(hi - lo) };
            return true;
        }

        private static bool Executable(uint protect)
        {
            if ((protect & 0x01) != 0 || (protect & 0x100) != 0)
            {
                return false;
            }

            return (protect & 0xF0) != 0;
        }

        private static bool IsExcluded(ModuleInfo module, List<string>? excludes)
        {
            if (excludes == null || excludes.Count == 0)
            {
                return false;
            }

            foreach (string exclude in excludes)
            {
                if (module.ModulePath.Equals(exclude, StringComparison.OrdinalIgnoreCase) ||
                    module.ModuleName.Equals(exclude, StringComparison.OrdinalIgnoreCase) ||
                    System.IO.Path.GetFileName(module.ModulePath).Equals(exclude, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
