using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace ErcTestTarget
{
    /// <summary>
    /// A process for the integration tests to inspect.
    /// </summary>
    /// <remarks>
    /// Plants known artefacts in unmanaged memory, prints where they are, then waits
    /// to be told to exit.
    ///
    /// Unmanaged rather than managed buffers, for two reasons: the address is stable
    /// without pinning, and Marshal.AllocHGlobal allocates from the process heap, so
    /// the same artefacts are visible to the heap-walking tests as well as the
    /// memory-search ones.
    /// </remarks>
    public static class Program
    {
        /// <summary>
        /// Printed once every artefact is planted, so the test knows the target is ready.
        /// </summary>
        public const string ReadyMarker = "TARGET-READY";

        /// <summary>
        /// A byte sequence that will not occur by chance elsewhere in the process.
        /// </summary>
        public static readonly byte[] Signature =
        {
            0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xDE, 0x5E, 0x1F,
            0x45, 0x52, 0x43, 0x54, 0x45, 0x53, 0x54           // "ERCTEST"
        };

        /// <summary>
        /// pop eax; pop ebx; ret - what "--seh" hunts for.
        /// </summary>
        public static readonly byte[] PopPopRet = { 0x58, 0x5B, 0xC3 };

        /// <summary>
        /// jmp esp / jmp rsp - what the ROP searches look for.
        /// </summary>
        public static readonly byte[] JmpEsp = { 0xFF, 0xE4 };

        /// <summary>
        /// Searched for as both ASCII and UTF-16, to exercise the encodings.
        /// </summary>
        public const string Text = "ErcFixtureNeedle7f3a";

        public static int Main(string[] args)
        {
            var planted = new List<string>();

            // Padding around each artefact so a search cannot succeed by finding an
            // adjacent one, and so a pop/pop/ret is never at offset 0 of its region.
            IntPtr signature = Plant("signature", Pad(Signature), planted);
            IntPtr popPopRet = Plant("poppopret", Pad(PopPopRet), planted);
            IntPtr jmpEsp    = Plant("jmpesp",    Pad(JmpEsp), planted);
            IntPtr ascii     = Plant("ascii",     Pad(Encoding.ASCII.GetBytes(Text)), planted);
            IntPtr unicode   = Plant("unicode",   Pad(Encoding.Unicode.GetBytes(Text)), planted);

            GC.KeepAlive(new object[] { signature, popPopRet, jmpEsp, ascii, unicode });

            foreach (string line in planted)
            {
                Console.Out.WriteLine(line);
            }

            Console.Out.WriteLine(ReadyMarker);
            Console.Out.Flush();

            // Wait to be told to exit. If the test dies without saying so, the pipe
            // closes and ReadLine returns null, so this never becomes a stray process.
            Console.In.ReadLine();
            return 0;
        }

        /// <summary>
        /// Surrounds the payload with filler so searches cannot match by accident and
        /// the payload never sits at the very start of its allocation.
        /// </summary>
        private static byte[] Pad(byte[] payload)
        {
            const int padding = 64;
            var buffer = new byte[padding + payload.Length + padding];

            for (int i = 0; i < buffer.Length; i++)
            {
                buffer[i] = 0x90;   // nop, harmless and distinct from the payloads
            }

            Buffer.BlockCopy(payload, 0, buffer, padding, payload.Length);
            return buffer;
        }

        /// <summary>
        /// Copies a buffer into unmanaged memory and records where the payload landed.
        /// </summary>
        private static IntPtr Plant(string name, byte[] buffer, List<string> planted)
        {
            IntPtr address = Marshal.AllocHGlobal(buffer.Length);
            Marshal.Copy(buffer, 0, address, buffer.Length);

            // The payload starts 64 bytes into the allocation; report that address,
            // since it is what a search should return.
            IntPtr payloadAddress = new IntPtr(address.ToInt64() + 64);

            planted.Add(string.Format(
                CultureInfo.InvariantCulture,
                "{0} {1:X} {2:X} {3}",
                name,
                payloadAddress.ToInt64(),
                address.ToInt64(),
                buffer.Length));

            return address;
        }
    }
}
