using System;
using System.Collections.Generic;

namespace ERC.Utilities
{
    /// <summary>
    /// One named list of ROP gadgets within an opcode catalogue.
    /// </summary>
    /// <typeparam name="TLists">The catalogue type the entry reads and writes.</typeparam>
    public sealed class GadgetList<TLists>
    {
        internal GadgetList(string name, string mnemonic, bool excludeNumericOperands,
                            Func<TLists, Dictionary<IntPtr, string>> get,
                            Action<TLists, Dictionary<IntPtr, string>> set)
        {
            Name = name;
            Mnemonic = mnemonic;
            ExcludeNumericOperands = excludeNumericOperands;
            Get = get;
            Set = set;
        }

        /// <summary>The field's name, for example "pushEax". Used as a heading in output.</summary>
        public string Name { get; }

        /// <summary>The instruction a gadget in this list must contain, for example "push eax".</summary>
        public string Mnemonic { get; }

        /// <summary>Whether gadgets whose operands include a literal number are rejected.</summary>
        public bool ExcludeNumericOperands { get; }

        /// <summary>Reads this list out of a catalogue.</summary>
        public Func<TLists, Dictionary<IntPtr, string>> Get { get; }

        /// <summary>Writes this list back to a catalogue.</summary>
        public Action<TLists, Dictionary<IntPtr, string>> Set { get; }
    }

    /// <summary>
    /// The gadget lists ERC collects, as data rather than as repeated code.
    /// </summary>
    /// <remarks>
    /// Every list was previously named explicitly at each place that touched it: once
    /// per list in optimiseLists, once per list in each of the two gadget-generating
    /// methods to apply the bad-character filter, and once per list again in the
    /// output formatter. That is four hand-maintained copies of the same list of
    /// lists, per architecture, and a list omitted from one of them fails silently.
    ///
    /// It did. The 64-bit catalogue's "jmpRax" and "callRax" were left out of the
    /// bad-character filter in both places that apply it, so an address containing a
    /// byte the user had excluded could still be selected - and jmpRax is written
    /// directly into the HeapCreate chain.
    /// </remarks>
    public static class GadgetCatalog
    {
        /// <summary>
        /// The 32-bit gadget lists, in the order they are collected and displayed.
        /// </summary>
        public static readonly IReadOnlyList<GadgetList<RopChainGenerator32.X86Lists>> X86Lists =
            new GadgetList<RopChainGenerator32.X86Lists>[]
            {
                new GadgetList<RopChainGenerator32.X86Lists>("pushEax", "push eax",    true,  l => l.pushEax, (l, v) => l.pushEax = v),
                new GadgetList<RopChainGenerator32.X86Lists>("pushEbx", "push ebx",    true,  l => l.pushEbx, (l, v) => l.pushEbx = v),
                new GadgetList<RopChainGenerator32.X86Lists>("pushEcx", "push ecx",    true,  l => l.pushEcx, (l, v) => l.pushEcx = v),
                new GadgetList<RopChainGenerator32.X86Lists>("pushEdx", "push edx",    true,  l => l.pushEdx, (l, v) => l.pushEdx = v),
                new GadgetList<RopChainGenerator32.X86Lists>("pushEsp", "push esp",    true,  l => l.pushEsp, (l, v) => l.pushEsp = v),
                new GadgetList<RopChainGenerator32.X86Lists>("pushEbp", "push ebp",    true,  l => l.pushEbp, (l, v) => l.pushEbp = v),
                new GadgetList<RopChainGenerator32.X86Lists>("pushEsi", "push esi",    true,  l => l.pushEsi, (l, v) => l.pushEsi = v),
                new GadgetList<RopChainGenerator32.X86Lists>("pushEdi", "push edi",    true,  l => l.pushEdi, (l, v) => l.pushEdi = v),
                new GadgetList<RopChainGenerator32.X86Lists>("jmpEsp",  "jmp esp",     false, l => l.jmpEsp, (l, v) => l.jmpEsp = v),
                new GadgetList<RopChainGenerator32.X86Lists>("callEsp", "call esp",    false, l => l.callEsp, (l, v) => l.callEsp = v),
                new GadgetList<RopChainGenerator32.X86Lists>("xorEax",  "xor eax",     false, l => l.xorEax, (l, v) => l.xorEax = v),
                new GadgetList<RopChainGenerator32.X86Lists>("xorEbx",  "xor ebx",     false, l => l.xorEbx, (l, v) => l.xorEbx = v),
                new GadgetList<RopChainGenerator32.X86Lists>("xorEcx",  "xor ecx",     false, l => l.xorEcx, (l, v) => l.xorEcx = v),
                new GadgetList<RopChainGenerator32.X86Lists>("xorEdx",  "xor edx",     false, l => l.xorEdx, (l, v) => l.xorEdx = v),
                new GadgetList<RopChainGenerator32.X86Lists>("xorEsi",  "xor esi",     false, l => l.xorEsi, (l, v) => l.xorEsi = v),
                new GadgetList<RopChainGenerator32.X86Lists>("xorEdi",  "xor edi",     false, l => l.xorEdi, (l, v) => l.xorEdi = v),
                new GadgetList<RopChainGenerator32.X86Lists>("popEax",  "pop eax",     true,  l => l.popEax, (l, v) => l.popEax = v),
                new GadgetList<RopChainGenerator32.X86Lists>("popEbx",  "pop ebx",     true,  l => l.popEbx, (l, v) => l.popEbx = v),
                new GadgetList<RopChainGenerator32.X86Lists>("popEcx",  "pop ecx",     true,  l => l.popEcx, (l, v) => l.popEcx = v),
                new GadgetList<RopChainGenerator32.X86Lists>("popEdx",  "pop edx",     true,  l => l.popEdx, (l, v) => l.popEdx = v),
                new GadgetList<RopChainGenerator32.X86Lists>("popEsp",  "pop esp",     true,  l => l.popEsp, (l, v) => l.popEsp = v),
                new GadgetList<RopChainGenerator32.X86Lists>("popEbp",  "pop ebp",     true,  l => l.popEbp, (l, v) => l.popEbp = v),
                new GadgetList<RopChainGenerator32.X86Lists>("popEsi",  "pop esi",     true,  l => l.popEsi, (l, v) => l.popEsi = v),
                new GadgetList<RopChainGenerator32.X86Lists>("popEdi",  "pop edi",     true,  l => l.popEdi, (l, v) => l.popEdi = v),
                new GadgetList<RopChainGenerator32.X86Lists>("pushad",  "pusha",       true,  l => l.pushad, (l, v) => l.pushad = v),
                new GadgetList<RopChainGenerator32.X86Lists>("incEax",  "inc eax",     false, l => l.incEax, (l, v) => l.incEax = v),
                new GadgetList<RopChainGenerator32.X86Lists>("incEbx",  "inc ebx",     false, l => l.incEbx, (l, v) => l.incEbx = v),
                new GadgetList<RopChainGenerator32.X86Lists>("incEcx",  "inc ecx",     false, l => l.incEcx, (l, v) => l.incEcx = v),
                new GadgetList<RopChainGenerator32.X86Lists>("incEdx",  "inc edx",     false, l => l.incEdx, (l, v) => l.incEdx = v),
                new GadgetList<RopChainGenerator32.X86Lists>("incEbp",  "inc ebp",     false, l => l.incEbp, (l, v) => l.incEbp = v),
                new GadgetList<RopChainGenerator32.X86Lists>("incEsp",  "inc esp",     false, l => l.incEsp, (l, v) => l.incEsp = v),
                new GadgetList<RopChainGenerator32.X86Lists>("incEsi",  "inc esi",     false, l => l.incEsi, (l, v) => l.incEsi = v),
                new GadgetList<RopChainGenerator32.X86Lists>("incEdi",  "inc edi",     false, l => l.incEdi, (l, v) => l.incEdi = v),
                new GadgetList<RopChainGenerator32.X86Lists>("decEax",  "dec eax",     false, l => l.decEax, (l, v) => l.decEax = v),
                new GadgetList<RopChainGenerator32.X86Lists>("decEbx",  "dec ebx",     false, l => l.decEbx, (l, v) => l.decEbx = v),
                new GadgetList<RopChainGenerator32.X86Lists>("decEcx",  "dec ecx",     false, l => l.decEcx, (l, v) => l.decEcx = v),
                new GadgetList<RopChainGenerator32.X86Lists>("decEdx",  "dec edx",     false, l => l.decEdx, (l, v) => l.decEdx = v),
                new GadgetList<RopChainGenerator32.X86Lists>("decEbp",  "dec ebp",     false, l => l.decEbp, (l, v) => l.decEbp = v),
                new GadgetList<RopChainGenerator32.X86Lists>("decEsp",  "dec esp",     false, l => l.decEsp, (l, v) => l.decEsp = v),
                new GadgetList<RopChainGenerator32.X86Lists>("decEsi",  "dec esi",     false, l => l.decEsi, (l, v) => l.decEsi = v),
                new GadgetList<RopChainGenerator32.X86Lists>("decEdi",  "dec edi",     false, l => l.decEdi, (l, v) => l.decEdi = v),
                new GadgetList<RopChainGenerator32.X86Lists>("add",     "add",         true,  l => l.add, (l, v) => l.add = v),
                new GadgetList<RopChainGenerator32.X86Lists>("sub",     "sub",         true,  l => l.sub, (l, v) => l.sub = v),
                new GadgetList<RopChainGenerator32.X86Lists>("mov",     "mov",         true,  l => l.mov, (l, v) => l.mov = v),
                new GadgetList<RopChainGenerator32.X86Lists>("and",     "and",         false, l => l.and, (l, v) => l.and = v)
            };

        /// <summary>
        /// The 64-bit gadget lists, in the order they are collected and displayed.
        /// </summary>
        public static readonly IReadOnlyList<GadgetList<RopChainGenerator64.X64Lists>> X64Lists =
            new GadgetList<RopChainGenerator64.X64Lists>[]
            {
                new GadgetList<RopChainGenerator64.X64Lists>("pushRax", "push rax",    true,  l => l.pushRax, (l, v) => l.pushRax = v),
                new GadgetList<RopChainGenerator64.X64Lists>("pushRbx", "push rbx",    true,  l => l.pushRbx, (l, v) => l.pushRbx = v),
                new GadgetList<RopChainGenerator64.X64Lists>("pushRcx", "push rcx",    true,  l => l.pushRcx, (l, v) => l.pushRcx = v),
                new GadgetList<RopChainGenerator64.X64Lists>("pushRdx", "push rdx",    true,  l => l.pushRdx, (l, v) => l.pushRdx = v),
                new GadgetList<RopChainGenerator64.X64Lists>("pushRsp", "push rsp",    true,  l => l.pushRsp, (l, v) => l.pushRsp = v),
                new GadgetList<RopChainGenerator64.X64Lists>("pushRbp", "push rbp",    true,  l => l.pushRbp, (l, v) => l.pushRbp = v),
                new GadgetList<RopChainGenerator64.X64Lists>("pushRsi", "push rsi",    true,  l => l.pushRsi, (l, v) => l.pushRsi = v),
                new GadgetList<RopChainGenerator64.X64Lists>("pushRdi", "push rdi",    true,  l => l.pushRdi, (l, v) => l.pushRdi = v),
                new GadgetList<RopChainGenerator64.X64Lists>("pushR8",  "push r8",     false, l => l.pushR8, (l, v) => l.pushR8 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("pushR9",  "push r9",     false, l => l.pushR9, (l, v) => l.pushR9 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("pushR10", "push r10",    false, l => l.pushR10, (l, v) => l.pushR10 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("pushR11", "push r11",    false, l => l.pushR11, (l, v) => l.pushR11 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("pushR12", "push r12",    false, l => l.pushR12, (l, v) => l.pushR12 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("pushR13", "push r13",    false, l => l.pushR13, (l, v) => l.pushR13 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("pushR14", "push r14",    false, l => l.pushR14, (l, v) => l.pushR14 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("pushR15", "push r15",    false, l => l.pushR15, (l, v) => l.pushR15 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("jmpRsp",  "jmp rsp",     false, l => l.jmpRsp, (l, v) => l.jmpRsp = v),
                new GadgetList<RopChainGenerator64.X64Lists>("callRsp", "call rsp",    false, l => l.callRsp, (l, v) => l.callRsp = v),
                new GadgetList<RopChainGenerator64.X64Lists>("xorRax",  "xor rax",     false, l => l.xorRax, (l, v) => l.xorRax = v),
                new GadgetList<RopChainGenerator64.X64Lists>("xorRbx",  "xor rbx",     false, l => l.xorRbx, (l, v) => l.xorRbx = v),
                new GadgetList<RopChainGenerator64.X64Lists>("xorRcx",  "xor rcx",     false, l => l.xorRcx, (l, v) => l.xorRcx = v),
                new GadgetList<RopChainGenerator64.X64Lists>("xorRdx",  "xor rdx",     false, l => l.xorRdx, (l, v) => l.xorRdx = v),
                new GadgetList<RopChainGenerator64.X64Lists>("xorRsi",  "xor rsi",     false, l => l.xorRsi, (l, v) => l.xorRsi = v),
                new GadgetList<RopChainGenerator64.X64Lists>("xorRdi",  "xor rdi",     false, l => l.xorRdi, (l, v) => l.xorRdi = v),
                new GadgetList<RopChainGenerator64.X64Lists>("xorR8",   "xor r8",      false, l => l.xorR8, (l, v) => l.xorR8 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("xorR9",   "xor r9",      false, l => l.xorR9, (l, v) => l.xorR9 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("xorR10",  "xor r10",     false, l => l.xorR10, (l, v) => l.xorR10 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("xorR11",  "xor r11",     false, l => l.xorR11, (l, v) => l.xorR11 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("xorR12",  "xor r12",     false, l => l.xorR12, (l, v) => l.xorR12 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("xorR13",  "xor r13",     false, l => l.xorR13, (l, v) => l.xorR13 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("xorR14",  "xor r14",     false, l => l.xorR14, (l, v) => l.xorR14 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("xorR15",  "xor r15",     false, l => l.xorR15, (l, v) => l.xorR15 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("popRax",  "pop rax",     true,  l => l.popRax, (l, v) => l.popRax = v),
                new GadgetList<RopChainGenerator64.X64Lists>("popRbx",  "pop rbx",     true,  l => l.popRbx, (l, v) => l.popRbx = v),
                new GadgetList<RopChainGenerator64.X64Lists>("popRcx",  "pop rcx",     true,  l => l.popRcx, (l, v) => l.popRcx = v),
                new GadgetList<RopChainGenerator64.X64Lists>("popRdx",  "pop rdx",     true,  l => l.popRdx, (l, v) => l.popRdx = v),
                new GadgetList<RopChainGenerator64.X64Lists>("popRsp",  "pop rsp",     true,  l => l.popRsp, (l, v) => l.popRsp = v),
                new GadgetList<RopChainGenerator64.X64Lists>("popRbp",  "pop rbp",     true,  l => l.popRbp, (l, v) => l.popRbp = v),
                new GadgetList<RopChainGenerator64.X64Lists>("popRsi",  "pop rsi",     true,  l => l.popRsi, (l, v) => l.popRsi = v),
                new GadgetList<RopChainGenerator64.X64Lists>("popRdi",  "pop rdi",     true,  l => l.popRdi, (l, v) => l.popRdi = v),
                new GadgetList<RopChainGenerator64.X64Lists>("popR8",   "pop r8",      false, l => l.popR8, (l, v) => l.popR8 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("popR9",   "pop r9",      false, l => l.popR9, (l, v) => l.popR9 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("popR10",  "pop r10",     false, l => l.popR10, (l, v) => l.popR10 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("popR11",  "pop r11",     false, l => l.popR11, (l, v) => l.popR11 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("popR12",  "pop r12",     false, l => l.popR12, (l, v) => l.popR12 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("popR13",  "pop r13",     false, l => l.popR13, (l, v) => l.popR13 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("popR14",  "pop r14",     false, l => l.popR14, (l, v) => l.popR14 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("popR15",  "pop r15",     false, l => l.popR15, (l, v) => l.popR15 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("incRax",  "inc rax",     false, l => l.incRax, (l, v) => l.incRax = v),
                new GadgetList<RopChainGenerator64.X64Lists>("incRbx",  "inc rbx",     false, l => l.incRbx, (l, v) => l.incRbx = v),
                new GadgetList<RopChainGenerator64.X64Lists>("incRcx",  "inc rcx",     false, l => l.incRcx, (l, v) => l.incRcx = v),
                new GadgetList<RopChainGenerator64.X64Lists>("incRdx",  "inc rdx",     false, l => l.incRdx, (l, v) => l.incRdx = v),
                new GadgetList<RopChainGenerator64.X64Lists>("incRbp",  "inc rbp",     false, l => l.incRbp, (l, v) => l.incRbp = v),
                new GadgetList<RopChainGenerator64.X64Lists>("incRsp",  "inc rsp",     false, l => l.incRsp, (l, v) => l.incRsp = v),
                new GadgetList<RopChainGenerator64.X64Lists>("incRsi",  "inc rsi",     false, l => l.incRsi, (l, v) => l.incRsi = v),
                new GadgetList<RopChainGenerator64.X64Lists>("incRdi",  "inc rdi",     false, l => l.incRdi, (l, v) => l.incRdi = v),
                new GadgetList<RopChainGenerator64.X64Lists>("incR8",   "inc r8",      false, l => l.incR8, (l, v) => l.incR8 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("incR9",   "inc r9",      false, l => l.incR9, (l, v) => l.incR9 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("incR10",  "inc r10",     false, l => l.incR10, (l, v) => l.incR10 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("incR11",  "inc r11",     false, l => l.incR11, (l, v) => l.incR11 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("incR12",  "inc r12",     false, l => l.incR12, (l, v) => l.incR12 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("incR13",  "inc r13",     false, l => l.incR13, (l, v) => l.incR13 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("incR14",  "inc r14",     false, l => l.incR14, (l, v) => l.incR14 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("incR15",  "inc r15",     false, l => l.incR15, (l, v) => l.incR15 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("decRax",  "dec rax",     false, l => l.decRax, (l, v) => l.decRax = v),
                new GadgetList<RopChainGenerator64.X64Lists>("decRbx",  "dec rbx",     false, l => l.decRbx, (l, v) => l.decRbx = v),
                new GadgetList<RopChainGenerator64.X64Lists>("decRcx",  "dec rcx",     false, l => l.decRcx, (l, v) => l.decRcx = v),
                new GadgetList<RopChainGenerator64.X64Lists>("decRdx",  "dec rdx",     false, l => l.decRdx, (l, v) => l.decRdx = v),
                new GadgetList<RopChainGenerator64.X64Lists>("decRbp",  "dec rbp",     false, l => l.decRbp, (l, v) => l.decRbp = v),
                new GadgetList<RopChainGenerator64.X64Lists>("decRsp",  "dec rsp",     false, l => l.decRsp, (l, v) => l.decRsp = v),
                new GadgetList<RopChainGenerator64.X64Lists>("decRsi",  "dec rsi",     false, l => l.decRsi, (l, v) => l.decRsi = v),
                new GadgetList<RopChainGenerator64.X64Lists>("decRdi",  "dec rdi",     false, l => l.decRdi, (l, v) => l.decRdi = v),
                new GadgetList<RopChainGenerator64.X64Lists>("decR8",   "dec r8",      false, l => l.decR8, (l, v) => l.decR8 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("decR9",   "dec r9",      false, l => l.decR9, (l, v) => l.decR9 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("decR10",  "dec r10",     false, l => l.decR10, (l, v) => l.decR10 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("decR11",  "dec r11",     false, l => l.decR11, (l, v) => l.decR11 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("decR12",  "dec r12",     false, l => l.decR12, (l, v) => l.decR12 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("decR13",  "dec r13",     false, l => l.decR13, (l, v) => l.decR13 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("decR14",  "dec r14",     false, l => l.decR14, (l, v) => l.decR14 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("decR15",  "dec r15",     false, l => l.decR15, (l, v) => l.decR15 = v),
                new GadgetList<RopChainGenerator64.X64Lists>("add",     "add",         false, l => l.add, (l, v) => l.add = v),
                new GadgetList<RopChainGenerator64.X64Lists>("mov",     "mov",         false, l => l.mov, (l, v) => l.mov = v),
                new GadgetList<RopChainGenerator64.X64Lists>("sub",     "sub",         false, l => l.sub, (l, v) => l.sub = v),
                new GadgetList<RopChainGenerator64.X64Lists>("jmpRax",  "jmp rax",     false, l => l.jmpRax, (l, v) => l.jmpRax = v),
                new GadgetList<RopChainGenerator64.X64Lists>("callRax", "call rax",    false, l => l.callRax, (l, v) => l.callRax = v)
            };
    }
}
