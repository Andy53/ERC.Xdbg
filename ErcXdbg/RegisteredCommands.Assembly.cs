using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text.RegularExpressions;
using Managed.x64dbg.SDK;
using System.Management;
using System.Threading;
using ERC.Cli;

namespace ErcXdbg
{
    /// <summary>
    /// The commands for assembling and disassembling.
    /// </summary>
    /// <remarks>
    /// Turning instructions into opcodes and back.
    ///
    /// One part of RegisteredCommands, which was a single 2,100 line file holding
    /// every command. Splitting it by command group leaves the dispatcher in
    /// RegisteredCommands.cs and each group beside the others it shares helpers with.
    /// </remarks>
    public static partial class RegisteredCommands
    {
        private static void Assemble(ERC.ProcessInfo info, List<string> parameters, SessionState session)
        {
            PLog.WriteLine("ERC --Assemble");
            PLog.WriteLine("----------------------------------------------------------------------");
            // Strip the switches, keeping the positional arguments.
            //
            // This was a forward loop calling parameters.Remove(parameters[i]),
            // which shifted the next element into the current index and skipped it,
            // so a switch immediately following another switch survived and was then
            // treated as a positional argument. The same loop was copy-pasted into
            // nearly every command handler.
            parameters.RemoveAll(p => p.Contains("--"));

            if (parameters.Count == 0)
            {
                PLog.WriteLine("No parameters provided. Assemble must be run: ERC --Assemble [1:0] <mnemonics>");
                //return null;
                return;
            }

            int n = -1;
            List<int> elementsToRemove = new List<int>();
            for (int i = 0; i < parameters.Count; i++)
            {
                if (i <= parameters.Count)
                {
                    if (Regex.IsMatch(parameters[i], @"^\d+$"))
                    {
                        if(parameters[i] == "0")
                        {
                            elementsToRemove.Add(i);
                            n = 0;
                        }
                        else if(parameters[i] == "1")
                        {
                            elementsToRemove.Add(i);
                            n = 1;
                        }
                    }
                }               
            }

            // Remove the architecture flag by index, highest first.
            //
            // This used to iterate the collected indices in ascending order and call
            // parameters.Remove(parameters[i]). Each removal shifted everything after
            // it down, so every later index was stale: the wrong argument was dropped,
            // or the lookup ran off the end of the list and threw. Descending order
            // keeps the remaining indices valid.
            foreach (int index in elementsToRemove.OrderByDescending(x => x))
            {
                if (index >= 0 && index < parameters.Count)
                {
                    parameters.RemoveAt(index);
                }
            }

            if(n == -1)
            {
                if(info.ProcessMachineType == ERC.MachineType.I386)
                {
                    n = 0;
                }
                else
                {
                    n = 1;
                }
            }

            try
            {
                List<string> instructions = string.Join(" ", parameters).Split(',').ToList();
                foreach (string s in instructions)
                {
                    List<string> instruction = new List<string>();
                    instruction.Add(s.Trim());
                    var asmResult = ERC.Utilities.OpcodeAssembler.AssembleOpcodes(instruction, info.ProcessMachineType);
                    PLog.WriteLine(instruction[0] + " = " + BitConverter.ToString(asmResult.ReturnValue).Replace("-", " "));
                }
                PLog.WriteLine("Assembly completed at {0} by {1}", DateTime.Now, info.Author);
            }
            catch (Exception e)
            {
                PLog.WriteLine("An error occured calling the assemble method. Error: {0}\nThe command should be structured ERC --assemble [1|0] <mnemonics>.", e.Message);
            }
            //return new List<string>(assembled);
            PLog.WriteLine("----------------------------------------------------------------------");
            return;
        }

        private static void Disassemble(ERC.ProcessInfo info, List<string> parameters, SessionState session)
        {
            PLog.WriteLine("ERC --Disassemble");
            PLog.WriteLine("----------------------------------------------------------------------");
            // Strip the switches, keeping the positional arguments.
            //
            // This was a forward loop calling parameters.Remove(parameters[i]),
            // which shifted the next element into the current index and skipped it,
            // so a switch immediately following another switch survived and was then
            // treated as a positional argument. The same loop was copy-pasted into
            // nearly every command handler.
            parameters.RemoveAll(p => p.Contains("--"));

            if (parameters.Count <= 0)
            {
                PLog.WriteLine("No parameters provided. Disassemble must be run: ERC --Disassemble [1|0] <opcodes>");
                //return null;
                return;
            }

            int n = -1;
            List<int> elementsToRemove = new List<int>();
            for (int i = 0; i < parameters.Count; i++)
            {
                if (i <= parameters.Count)
                {
                    if (Regex.IsMatch(parameters[i], @"^\d+$"))
                    {
                        if (parameters[i] == "0")
                        {
                            elementsToRemove.Add(i);
                            n = 0;
                        }
                        else if (parameters[i] == "1")
                        {
                            elementsToRemove.Add(i);
                            n = 1;
                        }
                    }
                }
            }

            // Remove the architecture flag by index, highest first.
            //
            // This used to iterate the collected indices in ascending order and call
            // parameters.Remove(parameters[i]). Each removal shifted everything after
            // it down, so every later index was stale: the wrong argument was dropped,
            // or the lookup ran off the end of the list and threw. Descending order
            // keeps the remaining indices valid.
            foreach (int index in elementsToRemove.OrderByDescending(x => x))
            {
                if (index >= 0 && index < parameters.Count)
                {
                    parameters.RemoveAt(index);
                }
            }

            if (n == -1)
            {
                if (info.ProcessMachineType == ERC.MachineType.I386)
                {
                    n = 0;
                }
                else
                {
                    n = 1;
                }
            }

            string opcodeChars = string.Join("", parameters.ToArray());
            string allowedChars = "abcdefABCDEF1234567890";
            opcodeChars = opcodeChars.Replace("\\x", "");
            opcodeChars = opcodeChars.Replace("0x", "");
            opcodeChars = opcodeChars.Replace(" ", "");
            string hexChars = "";
            for(int i = 0; i < opcodeChars.Length; i++)
            {
                if (allowedChars.Contains(opcodeChars[i].ToString()))
                {
                    hexChars = hexChars + opcodeChars[i];
                }
            }
            if(hexChars.Length % 2 != 0)
            {
                hexChars += "0";
            }

            List<string> opcodes = new List<string>();

            var bytes = StringToByteArray(hexChars);

            foreach(string s in opcodes)
            {
                PLog.WriteLine(s);
            }

            var disassembled = ERC.DisplayOutput.DisassembleOpcodes(bytes, (uint)n);
            PLog.WriteLine("ERC Disassebled Instructions:");
            foreach (string s in disassembled)
            {
                PLog.WriteLine(s);
            }
            PLog.WriteLine("Disassembly completed at {0} by {1}", DateTime.Now, info.Author);
            //return new List<string>(disassembled);
            PLog.WriteLine("----------------------------------------------------------------------");
            return;
        }
    }
}
