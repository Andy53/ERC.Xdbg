using System;
using System.Collections.Generic;
using System.Text;
using Iced.Intel;

namespace ERC.Utilities
{
    /// <summary>
    /// One instruction as the disassembler sees it: where it sits in the buffer,
    /// how long it is, and the text the rest of the library matches against.
    /// </summary>
    public sealed class DecodedInstruction
    {
        internal DecodedInstruction(int offset, int length, string text)
        {
            Offset = offset;
            Length = length;
            Text = text;
        }

        /// <summary>Byte offset from the start of the buffer.</summary>
        public int Offset { get; }

        /// <summary>Size of the instruction in bytes.</summary>
        public int Length { get; }

        /// <summary>Disassembly, lower case, space after the comma.</summary>
        public string Text { get; }
    }

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
        /// Disassembles a buffer into individual instructions, with offsets.
        /// </summary>
        /// <param name="opcodes">The bytes to disassemble.</param>
        /// <param name="machineType">Architecture of the bytes.</param>
        /// <returns>One entry per instruction, in order.</returns>
        public static ErcResult<IReadOnlyList<DecodedInstruction>> Decode(byte[] opcodes, MachineType machineType)
        {
            var result = new ErcResult<IReadOnlyList<DecodedInstruction>>(new ErcCore());
            result.ReturnValue = DecodeCore(opcodes, machineType, result)
                                 ?? (IReadOnlyList<DecodedInstruction>)new DecodedInstruction[0];
            return result;
        }

        /// <summary>
        /// The single implementation behind all three overloads, which previously
        /// carried three near-identical copies of this logic.
        /// </summary>
        private static ErcResult<string> Run(byte[] opcodes, MachineType machineType, ErcResult<string> result)
        {
            IReadOnlyList<DecodedInstruction>? decoded = DecodeCore(opcodes, machineType, result);
            if (result.Error != null)
            {
                return result;
            }

            var text = new StringBuilder();
            if (decoded != null)
            {
                foreach (DecodedInstruction instruction in decoded)
                {
                    text.Append(instruction.Text).Append(Environment.NewLine);
                }
            }

            result.ReturnValue = text.ToString();
            return result;
        }

        private static IReadOnlyList<DecodedInstruction>? DecodeCore<T>(
            byte[]? opcodes, MachineType machineType, ErcResult<T> result)
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
                return null;
            }

            if (opcodes == null)
            {
                result.Error = new ERCException("User input error: No opcodes supplied.");
                result.LogEvent();
                return null;
            }

            if (opcodes.Length == 0)
            {
                return new DecodedInstruction[0];
            }

            try
            {
                var reader = new ByteArrayCodeReader(opcodes);
                Iced.Intel.Decoder decoder = Iced.Intel.Decoder.Create(bitness, reader);
                decoder.IP = 0;

                Formatter formatter = CreateFormatter();
                var output = new StringOutput();
                var instructions = new List<DecodedInstruction>();

                while (decoder.IP < (ulong)opcodes.Length)
                {
                    ulong ip = decoder.IP;
                    Instruction instruction = decoder.Decode();
                    int length = instruction.Length;
                    if (length <= 0)
                    {
                        break;
                    }

                    formatter.Format(instruction, output);
                    instructions.Add(new DecodedInstruction((int)ip, length, output.ToStringAndReset()));
                }

                return instructions;
            }
            catch (Exception e)
            {
                result.Error = e;
                result.LogEvent(e);
                return null;
            }
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
