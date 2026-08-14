using System;
using System.Text;
using Iced.Intel;

namespace ERC.Utilities
{
    /// <summary>
    /// Disassembles opcodes into instructions. Can be constructed from a ProcessInfo
    /// to take the architecture of the attached process, or called statically.
    /// </summary>
    /// <remarks>
    /// Built on Iced. This previously used SharpDisasm, a udis86 port whose last
    /// release was in 2017 and which does not know about instructions added since.
    ///
    /// The exact text produced here is a contract, not a presentation choice: the ROP
    /// generators find gadgets by searching the disassembly string for things like
    /// "push eax" and "ret", and reject immediates by testing for a digit. The
    /// formatter is configured below to preserve that rendering, and
    /// DisassemblyContractTests pins it.
    /// </remarks>
    public class OpcodeDisassembler : ProcessInfo
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="parent">ProcessInfo object to be inherited from.</param>
        public OpcodeDisassembler(ProcessInfo parent) : base(parent)
        {
        }

        /// <summary>
        /// Disassembles opcodes into the associated instructions, using the
        /// architecture of the attached process.
        /// </summary>
        /// <param name="opcodes">The opcodes to be disassembled</param>
        /// <returns>Returns an ErcResult containing the associated instructions.</returns>
        public ErcResult<string> Disassemble(byte[] opcodes)
        {
            return Run(opcodes, ProcessMachineType, new ErcResult<string>(ProcessCore));
        }

        /// <summary>
        /// Disassembles opcodes into the associated instructions.
        /// </summary>
        /// <param name="opcodes">A byte array containing opcodes to be disassembled</param>
        /// <param name="machineType">An ERC.MachineType of either I386 or x64</param>
        /// <returns>Returns an ErcResult containing the associated instructions.</returns>
        public static ErcResult<string> Disassemble(byte[] opcodes, MachineType machineType)
        {
            return Run(opcodes, machineType, new ErcResult<string>(new ErcCore()));
        }

        /// <summary>
        /// Disassembles opcodes into the associated instructions, reporting errors
        /// through the supplied core.
        /// </summary>
        /// <param name="opcodes">A byte array containing opcodes to be disassembled</param>
        /// <param name="machineType">An ERC.MachineType of either I386 or x64</param>
        /// <param name="core">An ErcCore object</param>
        /// <returns>Returns an ErcResult containing the associated instructions.</returns>
        public static ErcResult<string> Disassemble(byte[] opcodes, MachineType machineType, ErcCore core)
        {
            return Run(opcodes, machineType, new ErcResult<string>(core));
        }

        /// <summary>
        /// The single implementation behind all three overloads, which previously
        /// carried three near-identical copies of this logic.
        /// </summary>
        private static ErcResult<string> Run(byte[] opcodes, MachineType machineType, ErcResult<string> result)
        {
            int bitness;
            if (machineType == MachineType.I386)
            {
                bitness = 32;
            }
            else if (machineType == MachineType.x64)
            {
                bitness = 64;
            }
            else
            {
                result.Error = new ERCException(
                    "User input error: Machine Type is invalid, must be ERC.MachineType.x64 or ERC.MachineType.I386");
                result.LogEvent();
                return result;
            }

            if (opcodes == null)
            {
                result.Error = new ERCException("User input error: No opcodes supplied.");
                result.LogEvent();
                return result;
            }

            result.ReturnValue = string.Empty;

            if (opcodes.Length == 0)
            {
                return result;
            }

            try
            {
                var reader = new ByteArrayCodeReader(opcodes);
                Iced.Intel.Decoder decoder = Iced.Intel.Decoder.Create(bitness, reader);
                decoder.IP = 0;

                Formatter formatter = CreateFormatter();
                var output = new StringOutput();
                var text = new StringBuilder();

                while (decoder.IP < (ulong)opcodes.Length)
                {
                    Instruction instruction = decoder.Decode();
                    formatter.Format(instruction, output);
                    text.Append(output.ToStringAndReset()).Append(Environment.NewLine);
                }

                result.ReturnValue = text.ToString();
            }
            catch (Exception e)
            {
                result.Error = e;
                result.LogEvent(e);
            }

            return result;
        }

        /// <summary>
        /// Builds the formatter, configured to match the rendering the rest of the
        /// library depends on.
        /// </summary>
        private static Formatter CreateFormatter()
        {
            // MASM syntax: closest to what x64dbg shows, and to what SharpDisasm
            // produced, so gadget searches keep matching.
            var formatter = new MasmFormatter();

            // "xor eax, eax" rather than "xor eax,eax". The generators search for
            // strings containing a space after the comma.
            formatter.Options.SpaceAfterOperandSeparator = true;

            // Lower case throughout: the gadget searches compare against lower-case
            // literals such as "push eax".
            formatter.Options.UppercaseMnemonics = false;
            formatter.Options.UppercaseRegisters = false;
            formatter.Options.UppercaseKeywords = false;
            formatter.Options.UppercaseDecorators = false;
            formatter.Options.UppercaseAll = false;

            // MASM would otherwise print a "ds:" segment prefix that SharpDisasm did
            // not, which would change the text the gadget search sees.
            formatter.Options.ShowSymbolAddress = false;

            return formatter;
        }
    }
}
