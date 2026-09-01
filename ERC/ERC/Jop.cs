using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using ERC.Native;
using ERC.Structures;

namespace ERC.Utilities
{
    /// <summary>
    /// Finds jump-oriented-programming gadgets: jmp and call through a memory
    /// operand, the form that does not use the stack to chain.
    /// </summary>
    /// <remarks>
    /// ROP gadgets end in <c>ret</c>. JOP gadgets end in <c>jmp [reg]</c> or
    /// <c>call [reg]</c> (or an IAT-style <c>jmp [rip+disp]</c>). --Jmp already
    /// finds <c>jmp reg</c>; this finds the indirect-through-memory half, which is
    /// what a dispatcher loop is built from.
    ///
    /// Searches loaded modules rather than all process memory: a JOP gadget has to
    /// be executable code, and scanning the heap for one is time spent finding
    /// nothing usable.
    /// </remarks>
    public static class Jop
    {
        /// <summary>
        /// True when disassembly is a memory-indirect jmp or call.
        /// </summary>
        public static bool IsGadget(string? disassembly)
        {
            if (string.IsNullOrEmpty(disassembly))
            {
                return false;
            }

            string text = disassembly!.Trim();
            if (text.IndexOf('[') < 0)
            {
                return false;
            }

            return text.StartsWith("jmp ", StringComparison.Ordinal) ||
                   text.StartsWith("call ", StringComparison.Ordinal);
        }

        /// <summary>
        /// True when the gadget's operand refers to <paramref name="register"/>.
        /// </summary>
        public static bool RefersToRegister(string disassembly, string register)
        {
            if (string.IsNullOrEmpty(register))
            {
                return true;
            }

            string name = register.Trim().ToLowerInvariant();
            string text = disassembly.ToLowerInvariant();

            // "[eax]" / "[eax+" / "[eax-" / "[eax*" rather than a coincidental substring.
            return text.IndexOf("[" + name + "]", StringComparison.Ordinal) >= 0 ||
                   text.IndexOf("[" + name + "+", StringComparison.Ordinal) >= 0 ||
                   text.IndexOf("[" + name + "-", StringComparison.Ordinal) >= 0 ||
                   text.IndexOf("[" + name + "*", StringComparison.Ordinal) >= 0 ||
                   text.IndexOf("[" + name + " ", StringComparison.Ordinal) >= 0;
        }

        /// <summary>
        /// Whether an address is 16-byte aligned, the alignment CFG requires of an
        /// indirect-call target under MSVC.
        /// </summary>
        public static bool IsCfgAligned(IntPtr address)
        {
            return (address.ToInt64() & 0xF) == 0;
        }

        /// <summary>
        /// Searches the process's loaded modules for JOP gadgets.
        /// </summary>
        /// <param name="info">The process to search.</param>
        /// <param name="register">
        /// If set, only gadgets whose operand refers to this register. Null means all.
        /// </param>
        /// <param name="excludes">Modules to leave out.</param>
        /// <param name="ptrsToExclude">Bytes that disqualify a gadget address.</param>
        /// <param name="shape">Pointer-shape filter, as elsewhere.</param>
        /// <returns>Address to instruction, for every match found.</returns>
        public static ErcResult<Dictionary<IntPtr, string>> Search(
            ProcessInfo info,
            string? register = null,
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

                foreach (ExecutableSpan span in ExecutableSpans(info, module))
                {
                    ErcResult<byte[]> dump = info.DumpMemoryRegion(span.Base, span.Size);
                    if (dump.Error != null || dump.ReturnValue == null)
                    {
                        continue;
                    }

                    ErcResult<IReadOnlyList<DecodedInstruction>> decoded =
                        OpcodeDisassembler.Decode(dump.ReturnValue, info.ProcessMachineType);
                    if (decoded.Error != null || decoded.ReturnValue == null)
                    {
                        continue;
                    }

                    foreach (DecodedInstruction instruction in decoded.ReturnValue)
                    {
                        if (!IsGadget(instruction.Text))
                        {
                            continue;
                        }

                        if (!RefersToRegister(instruction.Text, register ?? string.Empty))
                        {
                            continue;
                        }

                        IntPtr address = new IntPtr(span.Base.ToInt64() + instruction.Offset);
                        if (result.ReturnValue.ContainsKey(address))
                        {
                            continue;
                        }

                        string line = instruction.Text + "  (" + module.ModulePath + ")";
                        if (module.ModuleCFG && !IsCfgAligned(address))
                        {
                            line += " [cfg-unaligned]";
                        }

                        result.ReturnValue.Add(address, line);
                    }
                }
            }

            result.ReturnValue = PtrRemover.RemovePointers(
                info.ProcessMachineType, result.ReturnValue, ptrsToExclude);
            result.ReturnValue = PointerShape.Filter(
                info.ProcessMachineType, result.ReturnValue, shape);

            return result;
        }

        private struct ExecutableSpan
        {
            public IntPtr Base;
            public int Size;
        }

        /// <summary>
        /// Executable pages that fall inside a module. JOP gadgets have to be code,
        /// so scanning the rest of the image would only produce coincidences in data.
        /// </summary>
        /// <remarks>
        /// ProcessInfo's region list only keeps MEM_PRIVATE and MEM_MAPPED, so loaded
        /// modules (MEM_IMAGE) never appear there. This walks the module's own range.
        /// </remarks>
        private static IEnumerable<ExecutableSpan> ExecutableSpans(ProcessInfo info, ModuleInfo module)
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

                    if (region.State == StateEnum.MEM_COMMIT && IsExecutable(region.Protect))
                    {
                        ExecutableSpan span;
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

                    if (region.State == StateEnum.MEM_COMMIT && IsExecutable((uint)region.Protect))
                    {
                        ExecutableSpan span;
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

        private static bool TryOverlap(ulong start, ulong size, ulong moduleStart, ulong moduleEnd, out ExecutableSpan span)
        {
            span = default(ExecutableSpan);
            ulong end = start + size;
            ulong lo = start > moduleStart ? start : moduleStart;
            ulong hi = end < moduleEnd ? end : moduleEnd;
            if (hi <= lo || hi - lo > int.MaxValue)
            {
                return false;
            }

            span = new ExecutableSpan { Base = new IntPtr((long)lo), Size = (int)(hi - lo) };
            return true;
        }

        private static bool IsExecutable(uint protect)
        {
            // PAGE_NOACCESS 0x01, PAGE_GUARD 0x100: dumping these fails or raises.
            if ((protect & 0x01) != 0 || (protect & 0x100) != 0)
            {
                return false;
            }

            // PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY.
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
