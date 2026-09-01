using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using ERC.Structures;

namespace ERC.Utilities
{
    /// <summary>
    /// A buffer layout derived from a FindNRP table: where the cyclic pattern
    /// overwrote EIP/RIP or SEH, and where the payload can sit.
    /// </summary>
    public sealed class BufferSuggestion
    {
        internal BufferSuggestion(
            string kind, int threadId, int offset, string? landingRegister,
            int payloadBytes, int stackDelta, string text)
        {
            Kind = kind;
            ThreadId = threadId;
            Offset = offset;
            LandingRegister = landingRegister;
            PayloadBytes = payloadBytes;
            StackDelta = stackDelta;
            Text = text;
        }

        /// <summary><c>eip</c> for a saved return pointer, <c>seh</c> for an SEH record.</summary>
        public string Kind { get; }

        /// <summary>Thread whose context produced this layout.</summary>
        public int ThreadId { get; }

        /// <summary>Offset in the cyclic pattern of the overwritten pointer.</summary>
        public int Offset { get; }

        /// <summary>
        /// Register to jump to after the overwrite, for example <c>esp</c>. Null
        /// when none of the registers point into the pattern.
        /// </summary>
        public string? LandingRegister { get; }

        /// <summary>How many bytes of pattern sit at the landing register, if known.</summary>
        public int PayloadBytes { get; }

        /// <summary>
        /// Distance from the landing register to the start of the pattern, so the
        /// payload is at <c>ESP+n</c>. Zero when the register already points at it.
        /// </summary>
        public int StackDelta { get; }

        /// <summary>The layout, ready to print.</summary>
        public string Text { get; }
    }

    /// <summary>
    /// Turns a FindNRP result into the buffer an exploit actually sends.
    /// </summary>
    /// <remarks>
    /// <c>--FindNRP</c> reports that EIP is overwritten at offset 260 and ESP points
    /// into the pattern. The next question is always the same: junk, then a jump,
    /// then the payload. mona's <c>suggest</c> answers it; this does the same
    /// without emitting a Metasploit module.
    /// </remarks>
    public static class Suggest
    {
        /// <summary>
        /// Builds layouts from a FindNRP result. Pointers for <c>jmp reg</c> and
        /// pop/pop/ret are optional; without them the layout still states what to
        /// put at each offset.
        /// </summary>
        public static IReadOnlyList<BufferSuggestion> From(
            IReadOnlyList<RegisterInfo> nrp,
            MachineType machine = MachineType.I386,
            IReadOnlyDictionary<IntPtr, string>? jumps = null,
            IReadOnlyDictionary<IntPtr, string>? sehJumps = null)
        {
            if (nrp == null)
            {
                throw new ArgumentNullException("nrp");
            }

            var suggestions = new List<BufferSuggestion>();
            int width = machine == MachineType.x64 ? 8 : 4;

            foreach (IGrouping<int, RegisterInfo> thread in nrp.GroupBy(r => r.ThreadID))
            {
                RegisterInfo[] hits = thread.Where(HasPattern).ToArray();
                if (hits.Length == 0)
                {
                    continue;
                }

                RegisterInfo? ip = hits.FirstOrDefault(IsInstructionPointer);
                if (ip != null)
                {
                    suggestions.Add(ForSavedReturn(ip, hits, width, jumps));
                }

                RegisterInfo? seh = hits.FirstOrDefault(IsSeh);
                if (seh != null)
                {
                    suggestions.Add(ForSeh(seh, width, sehJumps));
                }
            }

            return suggestions;
        }

        /// <summary>
        /// Builds layouts from a live process: FindNRP, then the first usable
        /// <c>jmp</c> / pop-pop-ret for each overwrite.
        /// </summary>
        public static IReadOnlyList<BufferSuggestion> FromProcess(
            ProcessInfo info,
            IReadOnlyList<RegisterInfo> nrp,
            List<string>? excludes = null,
            byte[]? ptrsToExclude = null,
            PointerCriteria shape = PointerCriteria.None)
        {
            if (info == null)
            {
                throw new ArgumentNullException("info");
            }

            Dictionary<IntPtr, string>? jumps = null;
            Dictionary<IntPtr, string>? sehJumps = null;

            RegisterInfo? anyIp = nrp.FirstOrDefault(r => HasPattern(r) && IsInstructionPointer(r));
            if (anyIp != null)
            {
                RegisterInfo? landing = ChooseLanding(nrp.Where(HasPattern).ToArray(), anyIp);
                if (landing != null)
                {
                    jumps = FirstJumps(info, landing.Register, excludes, ptrsToExclude, shape);
                }
            }

            if (nrp.Any(r => HasPattern(r) && IsSeh(r)))
            {
                sehJumps = FirstSeh(info, excludes, ptrsToExclude, shape);
            }

            return From(nrp, info.ProcessMachineType, jumps, sehJumps);
        }

        private static BufferSuggestion ForSavedReturn(
            RegisterInfo ip, RegisterInfo[] hits, int width,
            IReadOnlyDictionary<IntPtr, string>? jumps)
        {
            RegisterInfo? landing = ChooseLanding(hits, ip);
            string? landingName = landing == null ? null : landing.Register.ToLowerInvariant();
            int payload = landing == null ? 0 : Math.Max(0, landing.BufferSize);
            int delta = landing == null ? 0 : Math.Max(0, landing.RegisterOffset);

            KeyValuePair<IntPtr, string>? jump = First(jumps);
            var text = new StringBuilder();
            text.AppendLine("Saved return pointer overwrite  thread=" + ip.ThreadID);
            text.AppendLine("  " + ip.Register.ToUpperInvariant() +
                            " overwritten with pattern at offset " + ip.StringOffset);

            if (landing != null)
            {
                text.Append("  " + landing.Register.ToUpperInvariant() +
                            " points into pattern at offset " + landing.StringOffset);
                if (delta > 0)
                {
                    text.Append(" (" + landing.Register.ToUpperInvariant() + "+" + delta + ")");
                }

                if (payload > 0)
                {
                    text.Append(", " + payload + " bytes remain");
                }

                text.AppendLine();
            }

            text.AppendLine();
            text.AppendLine("  [    0 .. " + Pad(ip.StringOffset - 1) + "]  junk");
            text.Append("  [" + Pad(ip.StringOffset) + " .. " +
                        Pad(ip.StringOffset + width - 1) + "]  ");
            if (jump.HasValue)
            {
                text.AppendLine(Hex(jump.Value.Key, width) + "  " + jump.Value.Value);
            }
            else if (landingName != null)
            {
                text.AppendLine("<jmp " + landingName + ">  ERC --jmp " + landingName);
            }
            else
            {
                text.AppendLine("<return address>");
            }

            int payloadAt = ip.StringOffset + width;
            if (delta > 0)
            {
                text.AppendLine("  [" + Pad(payloadAt) + " .. " +
                                Pad(payloadAt + delta - 1) + "]  padding to reach the pattern at " +
                                landingName!.ToUpperInvariant());
                payloadAt += delta;
            }

            string payloadEnd = payload > 0 ? Pad(payloadAt + payload - 1) : "    ";
            text.AppendLine("  [" + Pad(payloadAt) + " .. " + payloadEnd + "]  payload" +
                            (payload > 0 ? "  (" + payload + " bytes)" : ""));
            text.AppendLine();
            text.AppendLine("Python:");
            text.AppendLine("    buf  = b\"A\" * " + ip.StringOffset);
            text.AppendLine("    buf += " + Pack(jump, width, landingName));
            if (delta > 0)
            {
                text.AppendLine("    buf += b\"A\" * " + delta + "  # align to " +
                                landingName!.ToUpperInvariant());
            }

            text.AppendLine("    buf += payload");

            return new BufferSuggestion(
                "eip", ip.ThreadID, ip.StringOffset, landingName, payload, delta, text.ToString());
        }

        private static BufferSuggestion ForSeh(
            RegisterInfo seh, int width, IReadOnlyDictionary<IntPtr, string>? sehJumps)
        {
            KeyValuePair<IntPtr, string>? ppr = First(sehJumps);
            int nseh = seh.StringOffset;
            int handler = nseh + width;
            int payloadAt = handler + width;

            var text = new StringBuilder();
            text.AppendLine("SEH record overwrite  thread=" + seh.ThreadID);
            text.AppendLine("  SEH overwritten with pattern at offset " + nseh);
            text.AppendLine();
            text.AppendLine("  [    0 .. " + Pad(nseh - 1) + "]  junk");
            text.AppendLine("  [" + Pad(nseh) + " .. " + Pad(nseh + width - 1) +
                            "]  nseh     \\xeb\\x06\\x90\\x90  jmp short over the handler");
            text.Append("  [" + Pad(handler) + " .. " + Pad(handler + width - 1) + "]  seh      ");
            if (ppr.HasValue)
            {
                text.AppendLine(Hex(ppr.Value.Key, width) + "  " + ppr.Value.Value);
            }
            else
            {
                text.AppendLine("<pop pop ret>  ERC --seh");
            }

            text.AppendLine("  [" + Pad(payloadAt) + " ..     ]  payload");
            text.AppendLine();
            text.AppendLine("Python:");
            text.AppendLine("    buf  = b\"A\" * " + nseh);
            text.AppendLine("    buf += b\"\\xeb\\x06\\x90\\x90\"  # nseh");
            text.AppendLine("    buf += " + Pack(ppr, width, null));
            text.AppendLine("    buf += payload");

            return new BufferSuggestion(
                "seh", seh.ThreadID, nseh, null, 0, 0, text.ToString());
        }

        private static RegisterInfo? ChooseLanding(RegisterInfo[] hits, RegisterInfo ip)
        {
            RegisterInfo[] candidates = hits
                .Where(r => !IsInstructionPointer(r) && !IsSeh(r) && !IsFramePointer(r))
                .ToArray();

            RegisterInfo? sp = candidates.FirstOrDefault(IsStackPointer);
            if (sp != null)
            {
                return sp;
            }

            RegisterInfo[] after = candidates
                .Where(r => r.StringOffset >= ip.StringOffset)
                .ToArray();
            if (after.Length > 0)
            {
                candidates = after;
            }

            return candidates
                .OrderByDescending(r => r.BufferSize)
                .ThenBy(r => r.StringOffset)
                .FirstOrDefault();
        }

        private static Dictionary<IntPtr, string>? FirstJumps(
            ProcessInfo info, string register, List<string>? excludes,
            byte[]? ptrsToExclude, PointerCriteria shape)
        {
            ErcResult<Dictionary<IntPtr, string>> found =
                JumpToRegister.Search(info, register, excludes, ptrsToExclude);
            if (found.Error != null || found.ReturnValue == null || found.ReturnValue.Count == 0)
            {
                return null;
            }

            return PointerShape.Filter(info.ProcessMachineType, found.ReturnValue, shape);
        }

        private static Dictionary<IntPtr, string>? FirstSeh(
            ProcessInfo info, List<string>? excludes, byte[]? ptrsToExclude, PointerCriteria shape)
        {
            ErcResult<Dictionary<IntPtr, string>> found =
                info.SearchAllMemoryPPR(excludes, ptrsToExclude);
            if (found.Error != null || found.ReturnValue == null || found.ReturnValue.Count == 0)
            {
                return null;
            }

            return PointerShape.Filter(info.ProcessMachineType, found.ReturnValue, shape);
        }

        private static KeyValuePair<IntPtr, string>? First(IReadOnlyDictionary<IntPtr, string>? map)
        {
            if (map == null || map.Count == 0)
            {
                return null;
            }

            return map.OrderBy(kv => kv.Key.ToInt64()).First();
        }

        private static string Pack(KeyValuePair<IntPtr, string>? pointer, int width, string? landing)
        {
            string fmt = width == 8 ? "<Q" : "<I";
            if (pointer.HasValue)
            {
                string comment = pointer.Value.Value;
                return "struct.pack(\"" + fmt + "\", " + Hex(pointer.Value.Key, width) + ")  # " + comment;
            }

            string what = landing != null ? "jmp " + landing : "pop pop ret";
            return "struct.pack(\"" + fmt + "\", 0x" + new string('?', width * 2) + ")  # " + what;
        }

        private static string Hex(IntPtr address, int width)
        {
            string format = width == 8 ? "X16" : "X8";
            return "0x" + address.ToInt64().ToString(format, CultureInfo.InvariantCulture);
        }

        private static string Pad(int value)
        {
            if (value < 0)
            {
                return new string(' ', 4);
            }

            return value.ToString().PadLeft(4);
        }

        private static bool HasPattern(RegisterInfo r)
        {
            return r.StringOffset >= 0 || r.overwritten;
        }

        private static bool IsInstructionPointer(RegisterInfo r)
        {
            string name = r.Register.ToUpperInvariant();
            return name == "EIP" || name == "RIP";
        }

        private static bool IsStackPointer(RegisterInfo r)
        {
            string name = r.Register.ToUpperInvariant();
            return name == "ESP" || name == "RSP";
        }

        private static bool IsFramePointer(RegisterInfo r)
        {
            string name = r.Register.ToUpperInvariant();
            return name == "EBP" || name == "RBP";
        }

        private static bool IsSeh(RegisterInfo r)
        {
            return r.Register.StartsWith("SEH", StringComparison.OrdinalIgnoreCase);
        }
    }
}
