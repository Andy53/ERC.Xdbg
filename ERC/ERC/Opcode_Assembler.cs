using System;
using System.Collections.Generic;
using Reloaded.Assembler;

namespace ERC.Utilities
{
    /// <summary>
    /// OpcodeAssembler class, can be declared and inherit from a ProcessInfo object to inherit the values of the current process or be called as 
    /// a static function to assemble instructions.
    /// </summary>
    public class OpcodeAssembler : ProcessInfo
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="parent">ProcessInfo object to be inherited from.</param>
        public OpcodeAssembler(ProcessInfo parent) : base(parent)
        {

        }

        /// <summary>
        /// Takes either an array or list of strings containing assembly instructions and returns the associated opcodes.  
        /// </summary>
        /// <param name="instructions">The instructions to be assembled</param>
        /// <returns>Returns an ErcResult byte array containing the assembled instructions</returns>
        public ErcResult<byte[]> AssembleOpcodes(List<string> instructions)
        {
            ErcResult<byte[]> result = new ErcResult<byte[]>(ProcessCore);
            List<string> mnemonics = new List<string>();
            if (ProcessMachineType == MachineType.I386)
            {
                mnemonics.Add("use32");
            }
            else if (ProcessMachineType == MachineType.x64)
            {
                mnemonics.Add("use64");
            }

            for (int i = 0; i < instructions.Count; i++)
            {
                mnemonics.Add(instructions[i]);
            }

            var asm = new Assembler();

            try
            {
                result.ReturnValue = asm.Assemble(mnemonics);
                asm.Dispose();
            }
            catch (Exception e)
            {
                result.Error = e;
                result.LogEvent();
                asm.Dispose();
                return result;
            }
            GC.Collect();
            return result;
        }

        /// <summary>
        /// Takes either an array or list of strings containing assembly instructions, a MachineType of I386 or x64, 
        /// an instance of the ERC_Core object and returns the associated opcodes.  
        /// </summary>
        /// <param name="instructions">The instructions to be assemble=d</param>
        /// <param name="machineType">a ERC.MachineType of either I386 or x64</param>
        /// <returns>Returns an ERC_Result byte array containing the assembled instructions</returns>
        public static ErcResult<byte[]> AssembleOpcodes(List<string> instructions, MachineType machineType)
        {
            ErcResult<byte[]> result = new ErcResult<byte[]>(new ErcCore());
            List<string> mnemonics = new List<string>();
            if (machineType == MachineType.I386)
            {
                mnemonics.Add("use32");
            }
            else if (machineType == MachineType.x64)
            {
                mnemonics.Add("use64");
            }

            for(int i = 0; i < instructions.Count; i++)
            {
                mnemonics.Add(instructions[i]);
            }

            var asm = new Assembler();

            try
            {
                result.ReturnValue = asm.Assemble(mnemonics);
                asm.Dispose();
            }
            catch(Exception e)
            {
                result.Error = e;
                result.LogEvent();
                asm.Dispose();
                return result;
            }
            return result;
        }
    }
}
