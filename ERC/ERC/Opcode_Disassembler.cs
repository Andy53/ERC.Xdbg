using System;
using System.Linq;

namespace ERC.Utilities
{
    /// <summary>
    /// OpcodeDisassembler class, can be declared and inherit from a ProcessInfo object to inherit the values of the current process or be called as 
    /// a static function to disassemble opcodes.
    /// </summary>
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
        /// Disassembles opcodes into the associated instructions. Takes a byte array containing opcodes. 
        /// </summary>
        /// <param name="opcodes">The opcodes to be disassembled</param>
        /// <returns>Returns an ERC_Result containing associated instructions.</returns>
        public ErcResult<string> Disassemble(byte[] opcodes)
        {
            ErcResult<string> result = new ErcResult<string>(ProcessCore);
            SharpDisasm.Disassembler.Translator.IncludeAddress = true;
            SharpDisasm.Disassembler.Translator.IncludeBinary = true;
            SharpDisasm.Disassembler disasm;
            SharpDisasm.ArchitectureMode mode;

            try
            {
                if (ProcessMachineType == MachineType.I386)
                {
                    mode = SharpDisasm.ArchitectureMode.x86_32;
                }
                else if (ProcessMachineType == MachineType.x64)
                {
                    mode = SharpDisasm.ArchitectureMode.x86_64;
                }
                else
                {
                    throw new ERCException("User input error: Machine Type is invalid, must be ERC.MachineType.x86_64 or ERC.MachineType.x86_32");
                }
            }
            catch (ERCException e)
            {
                result.Error = e;
                result.LogEvent();
                return result;
            }

            try
            {
                disasm = new SharpDisasm.Disassembler(
                HexStringToByteArray(BitConverter.ToString(opcodes).Replace("-", "")),
                mode, 0, true);
            }
            catch (Exception e)
            {
                result.Error = e;
                result.LogEvent(e);
                return result;
            }

            foreach (var insn in disasm.Disassemble())
            {
                var mne = insn.ToString().Split(new string[] { "  " }, StringSplitOptions.None);
                result.ReturnValue += mne[mne.Length - 1].Trim() + Environment.NewLine;
            }

            return result;
        }

        /// <summary>
        /// Disassembles opcodes into the associated instructions. Takes a byte array containing opcodes, a MachineType of I386 or x64, 
        /// an instance of the ERC_Core object and returns an ERC_Result containing associated instructions.
        /// </summary>
        /// <param name="opcodes">A byte array containing opcodes to be disassembled</param>
        /// <param name="machineType">a ERC.MachineType of either I386 or x64</param>
        /// <returns>Returns an ERC_Result containing associated instructions.</returns>
        public static ErcResult<string> Disassemble(byte[] opcodes, MachineType machineType)
        {
            ErcResult<string> result = new ErcResult<string>(new ErcCore());
            SharpDisasm.Disassembler.Translator.IncludeAddress = true;
            SharpDisasm.Disassembler.Translator.IncludeBinary = true;
            SharpDisasm.Disassembler disasm;
            SharpDisasm.ArchitectureMode mode;

            try
            {
                if (machineType == MachineType.I386)
                {
                    mode = SharpDisasm.ArchitectureMode.x86_32;
                }
                else if (machineType == MachineType.x64)
                {
                    mode = SharpDisasm.ArchitectureMode.x86_64;
                }
                else
                {
                    throw new ERCException("User input error: Machine Type is invalid, must be ERC.MachineType.x86_64 or ERC.MachineType.x86_32");
                }
            }
            catch(ERCException e)
            {
                result.Error = e;
                result.LogEvent();
                return result;
            }

            try
            {
                disasm = new SharpDisasm.Disassembler(
                HexStringToByteArray(BitConverter.ToString(opcodes).Replace("-", "")),
                mode, 0, true);
            }
            catch(Exception e)
            {
                result.Error = e;
                result.LogEvent(e);
                return result;
            }

            foreach (var insn in disasm.Disassemble())
            {
                var mne = insn.ToString().Split(new string[] { "  " }, StringSplitOptions.None);
                result.ReturnValue += mne[mne.Length - 1].Trim() + Environment.NewLine;
            }

            return result;
        }

        /// <summary>
        /// Disassembles opcodes into the associated instructions. Takes a byte array containing opcodes, a MachineType of I386 or x64, 
        /// an instance of the ERC_Core object and returns an ERC_Result containing associated instructions.
        /// </summary>
        /// <param name="opcodes">A byte array containing opcodes to be disassembled</param>
        /// <param name="machineType">a ERC.MachineType of either I386 or x64</param>
        /// <param name="core">a ErcCore object</param>
        /// <returns>Returns an ERC_Result containing associated instructions.</returns>
        public static ErcResult<string> Disassemble(byte[] opcodes, MachineType machineType, ErcCore core)
        {
            ErcResult<string> result = new ErcResult<string>(core);
            SharpDisasm.Disassembler.Translator.IncludeAddress = true;
            SharpDisasm.Disassembler.Translator.IncludeBinary = true;
            SharpDisasm.Disassembler disasm;
            SharpDisasm.ArchitectureMode mode;

            try
            {
                if (machineType == MachineType.I386)
                {
                    mode = SharpDisasm.ArchitectureMode.x86_32;
                }
                else if (machineType == MachineType.x64)
                {
                    mode = SharpDisasm.ArchitectureMode.x86_64;
                }
                else
                {
                    throw new ERCException("User input error: Machine Type is invalid, must be ERC.MachineType.x86_64 or ERC.MachineType.x86_32");
                }
            }
            catch (ERCException e)
            {
                result.Error = e;
                result.LogEvent();
                return result;
            }

            try
            {
                disasm = new SharpDisasm.Disassembler(
                HexStringToByteArray(BitConverter.ToString(opcodes).Replace("-", "")),
                mode, 0, true);
            }
            catch (Exception e)
            {
                result.Error = e;
                result.LogEvent(e);
                return result;
            }

            foreach (var insn in disasm.Disassemble())
            {
                var mne = insn.ToString().Split(new string[] { "  " }, StringSplitOptions.None);
                result.ReturnValue += mne[mne.Length - 1].Trim() + Environment.NewLine;
            }

            return result;
        }

        private static byte[] HexStringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => System.Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}
