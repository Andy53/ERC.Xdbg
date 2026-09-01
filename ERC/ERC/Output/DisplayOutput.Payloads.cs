using ERC.Utilities;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Convert = ERC.Utilities.Convert;

using ERC.Native;
namespace ERC
{
    /// <summary> Provides output in various human readable formats of data from the library. </summary>
    public static partial class DisplayOutput
    {

        #region GenerateByteArray
        /// <summary>
        /// Generates an array of all possible bytes for use when identifying bad characters. Writes the output to disk in the working directory.
        /// </summary>
        /// <param name="unwantedBytes">An array of bytes to be excluded from the final byte array</param>
        /// <param name="core">An ErcCore object</param>
        /// <returns>Returns a byte array of all possible bytes.</returns>
        public static byte[] GenerateByteArray(ErcCore core, byte[]? unwantedBytes = null)
        {
            string byteFilename = GetFilePath(core.WorkingDirectory, "ByteArray_", ".bin");
            byte[] byteArray = Payloads.ByteArrayConstructor(unwantedBytes);
            FileStream fs1 = new FileStream(byteFilename, FileMode.Create, FileAccess.Write);
            fs1.Write(byteArray, 0, byteArray.Length);
            fs1.Close();

            string outputString = "---------------------------------------------------------------------------------------" + Environment.NewLine;
            if(unwantedBytes != null)
            {
                outputString += "Byte Array generated at:" + DateTime.Now + "  Omitted values: " + BitConverter.ToString(unwantedBytes).Replace("-", ", ") + Environment.NewLine;
            }
            else
            {
                outputString += "Byte Array generated at:" + DateTime.Now + Environment.NewLine;
            }
            outputString += "---------------------------------------------------------------------------------------" + Environment.NewLine;
            outputString += Environment.NewLine;
            outputString += "Raw:" + Environment.NewLine;

            string raw = "\\x" + BitConverter.ToString(byteArray).Replace("-", "\\x");
            string formattedHex = "";
            for(int i = 0; i < raw.Length; i++)
            {
                if(i == 0)
                {
                    formattedHex += raw[i];
                }
                else if(i % 48 == 0)
                {
                    formattedHex += "\n" + raw[i];
                }
                else
                {
                    formattedHex += raw[i];
                }
                
            }

            outputString += formattedHex;

            outputString += Environment.NewLine + Environment.NewLine + "C#:" + Environment.NewLine;
            string CSharp = "byte[] buf = new byte[]" + Environment.NewLine + "{" + Environment.NewLine;
            string CSharpTemp = "0x" + BitConverter.ToString(byteArray).Replace("-", ", 0x");
            string CSharpFormatted = "";
            int counter = 0;
            for(int i = 0; i < CSharpTemp.Length; i++)
            {
                if(i == 0)
                {
                    CSharpFormatted += "    " + CSharpTemp[i];
                    counter++;
                }
                else if(CSharpTemp[i] == ',' && counter % 8 == 0 && counter != 0)
                {
                    CSharpFormatted += CSharpTemp[i] + "\n    ";
                    i++;
                    counter++;
                }
                else if (CSharpTemp[i] == ',')
                {
                    counter++;
                    CSharpFormatted += CSharpTemp[i];
                }
                else
                {
                    CSharpFormatted += CSharpTemp[i];
                }
            }
            outputString += CSharp + CSharpFormatted + Environment.NewLine + "}";
            core.Output.WriteText(byteFilename.Substring(0, (byteFilename.Length - 4)) + ".txt", outputString);

            return byteArray;
        }
        #endregion

        #region CompareByteArrays

        /// <summary>
        /// Compares a the values contained in a memory region to the values in the supplied byte array.
        /// </summary>
        /// <param name="info">The processInfo object that contains the memory region.</param>
        /// <param name="startAddress">The memory address to start the search at.</param>
        /// <param name="byteArray">The byte array the region will be compared against.</param>
        /// <returns>Returns a string detailing differences between the two.</returns>
        public static string[] CompareByteArrayToMemoryRegion(ProcessInfo info, IntPtr startAddress, byte[] byteArray)
        {
            List<string> output = new List<string>();
            byte[] memoryRegion = new byte[byteArray.Length];
            List<byte> mismatchingBytes = new List<byte>();
            int bytesRead = 0;
            output.Add(Convert.htmlWhitespaceFix("                   ----------------------------------------------------"));
            string fromArray  = Convert.htmlWhitespaceFix("        From Array | ");
            string fromRegion = Convert.htmlWhitespaceFix("From Memory Region | "); 
            info.Native.ReadProcessMemory(info.ProcessHandle, startAddress, memoryRegion, byteArray.Length, out bytesRead);
            int counter = 0;
            for (int i = 0; i <= byteArray.Length; i++)
            {
                if (i == byteArray.Length)
                {
                    counter = 0;
                    fromArray += Convert.htmlWhitespaceFix(" | ");
                    fromRegion += Convert.htmlWhitespaceFix(" | ");
                    string newLine = Convert.htmlWhitespaceFix("                   |                                                  | ");
                    output.Add(fromArray);
                    output.Add(fromRegion);
                    output.Add(newLine);
                    fromArray = Convert.htmlWhitespaceFix("        From Array | ");
                    fromRegion = Convert.htmlWhitespaceFix("From Memory Region | ");
                }
                else
                {
                    if (counter == 16)
                    {
                        counter = 0;
                        fromArray += Convert.htmlWhitespaceFix(" | ");
                        fromRegion += Convert.htmlWhitespaceFix(" | ");
                        string newLine = Convert.htmlWhitespaceFix("                   |                                                  | ");
                        output.Add(fromArray);
                        output.Add(fromRegion);
                        output.Add(newLine);
                        fromArray = Convert.htmlWhitespaceFix("        From Array | ");
                        fromRegion = Convert.htmlWhitespaceFix("From Memory Region | ");
                    }

                    byte[] thisByte = new byte[1];
                    thisByte[0] = byteArray[i];
                    if (byteArray[i] != memoryRegion[i])
                    {
                        mismatchingBytes.Add(byteArray[i]);
                        fromArray += "<b><span style='color:red;'>" + BitConverter.ToString(thisByte) + "</span></b>";
                        thisByte[0] = memoryRegion[i];
                        fromRegion += "<b><span style='color:red;'>" + BitConverter.ToString(thisByte) + "</span></b>";
                    }
                    else
                    {
                        fromArray += BitConverter.ToString(thisByte);
                        thisByte[0] = memoryRegion[i];
                        fromRegion += BitConverter.ToString(thisByte);
                    }

                    fromArray += Convert.htmlWhitespaceFix(" ");
                    fromRegion += Convert.htmlWhitespaceFix(" ");
                    counter++;
                }
            }
            output.Add(Convert.htmlWhitespaceFix("                   ----------------------------------------------------"));
            output.Add("Mismatching Bytes: [" + String.Join(", ", mismatchingBytes.Select(b => BitConverter.ToString(new byte[]{b}))) + "]");
            if(mismatchingBytes.Count > 0)
            {
                output.Add("Remove byte 0x" + BitConverter.ToString(new byte[] { mismatchingBytes.ElementAt(0) }) + " and attempt again.");
            }
            return output.ToArray();
        }
        #endregion

        #region GenerateEggHunters
        /// <summary>
        /// Generates a collection of EggHunter payloads.
        /// </summary>
        /// <param name="core">(Optional) If an ErcCore object is provided the output will also be written out to the working directory </param>
        /// <param name="tag">(Optional) If a tag is provided the payloads will be altered to search for that tag, the default tag is ERCD</param>
        /// <returns>Returns a string containing all EggHunters </returns>
        public static string GenerateEggHunters(ErcCore? core = null, string? tag = null)
        {
            return GenerateEggHunters(new EggHunterRequest { Tag = tag ?? Payloads.DefaultEgg }, core);
        }

        /// <summary>
        /// Generates egg hunters with checksum, start-register, WOW64 and DEP options.
        /// </summary>
        public static string GenerateEggHunters(EggHunterRequest request, ErcCore? core = null)
        {
            IReadOnlyList<EggHunterStub> hunters = EggHunter.Generate(request);
            string eggTag = string.IsNullOrEmpty(request.Tag) ? Payloads.DefaultEgg : request.Tag;

            var output = new StringBuilder();
            output.AppendLine("---------------------------------------------------------------------------------------");
            output.AppendLine("EggHunters generated at:" + DateTime.Now + " Tag: " + eggTag);
            output.AppendLine("---------------------------------------------------------------------------------------");
            output.AppendLine();
            output.AppendLine("Put this tag in front of your shellcode: " + eggTag + eggTag);

            byte? checksum = null;
            foreach (EggHunterStub hunter in hunters)
            {
                if (hunter.ChecksumByte.HasValue)
                {
                    checksum = hunter.ChecksumByte;
                    break;
                }
            }

            if (checksum.HasValue)
            {
                output.AppendLine("Append checksum byte 0x" + checksum.Value.ToString("X2") +
                                  " after the payload so a truncated copy is skipped.");
            }

            output.AppendLine();

            foreach (EggHunterStub hunter in hunters)
            {
                output.AppendLine(hunter.Name + " Egg Hunter (" + hunter.Opcodes.Length + " bytes):");
                output.AppendLine(hunter.Description);
                output.AppendLine(FormatPayloadBytes(hunter.Opcodes));
                output.AppendLine();
            }

            string text = output.ToString();
            if (core != null)
            {
                core.Output.WriteText(GetFilePath(core.WorkingDirectory, "Egg_Hunters_", ".txt"), text);
            }

            return text;
        }
        #endregion

        #region GetPC, encode, unicode align

        /// <summary>
        /// Formats bytes as a raw <c>\x</c> string, a C# array and a Python bytes
        /// literal, the three forms an exploit script actually pastes.
        /// </summary>
        public static string FormatPayloadBytes(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                return "(empty)";
            }

            string raw = "\\x" + BitConverter.ToString(bytes).Replace("-", "\\x");
            var wrapped = new StringBuilder();
            for (int i = 0; i < raw.Length; i++)
            {
                if (i > 0 && i % 64 == 0)
                {
                    wrapped.Append(Environment.NewLine);
                }

                wrapped.Append(raw[i]);
            }

            string csharp = "byte[] buf = new byte[] { 0x" +
                            BitConverter.ToString(bytes).Replace("-", ", 0x") + " };";
            string python = "buf = b\"" + raw + "\"";

            return "Raw:" + Environment.NewLine + wrapped + Environment.NewLine +
                   Environment.NewLine + "C#:" + Environment.NewLine + csharp + Environment.NewLine +
                   Environment.NewLine + "Python:" + Environment.NewLine + python;
        }

        /// <summary>
        /// Builds the GetPC stubs for a register and formats them for the log.
        /// </summary>
        /// <param name="register">Register the stubs should leave the instruction pointer in.</param>
        /// <param name="machineType">Architecture of the stubs.</param>
        /// <param name="core">If set, the text is also written to the working directory.</param>
        /// <returns>The formatted stubs.</returns>
        public static string GenerateGetPc(string register, MachineType machineType, ErcCore? core = null)
        {
            IReadOnlyList<GetPcRoutine> routines = GetPc.For(register, machineType);
            var output = new StringBuilder();
            string arch = machineType == MachineType.x64 ? "x64" : "x86";

            output.AppendLine("---------------------------------------------------------------------------------------");
            output.AppendLine("GetPC routines for " + register.Trim().ToLowerInvariant() +
                              " (" + arch + ") generated at " + DateTime.Now);
            output.AppendLine("---------------------------------------------------------------------------------------");
            output.AppendLine();

            foreach (GetPcRoutine routine in routines)
            {
                output.AppendLine(routine.Name + ": " + routine.Description);
                output.AppendLine(FormatPayloadBytes(routine.Opcodes));
                output.AppendLine();
            }

            string text = output.ToString();
            if (core != null)
            {
                core.Output.WriteText(GetFilePath(core.WorkingDirectory, "GetPC_", ".txt"), text);
            }

            return text;
        }

        /// <summary>
        /// Encodes a payload and formats the result for the log.
        /// </summary>
        /// <param name="payload">The bytes to encode.</param>
        /// <param name="encoding">Which encoder to use.</param>
        /// <param name="machineType">Architecture of the decoder stub.</param>
        /// <param name="badBytes">Bytes the result must not contain.</param>
        /// <param name="core">If set, the text is also written to the working directory.</param>
        /// <returns>The formatted encoded payload.</returns>
        public static string GenerateEncodedPayload(
            byte[] payload,
            PayloadEncoding encoding,
            MachineType machineType,
            byte[]? badBytes = null,
            ErcCore? core = null)
        {
            EncodedPayload encoded = PayloadEncoder.Encode(payload, encoding, machineType, badBytes);
            var output = new StringBuilder();

            output.AppendLine("---------------------------------------------------------------------------------------");
            output.AppendLine(encoded.Description + " Generated at " + DateTime.Now);
            output.AppendLine("---------------------------------------------------------------------------------------");
            output.AppendLine();
            foreach (string note in encoded.Notes)
            {
                output.AppendLine(note);
            }

            output.AppendLine();
            output.AppendLine(FormatPayloadBytes(encoded.Bytes));

            string text = output.ToString();
            if (core != null)
            {
                string prefix = encoding == PayloadEncoding.Xor ? "Encoded_XOR_" : "Encoded_Alphanum_";
                core.Output.WriteText(GetFilePath(core.WorkingDirectory, prefix, ".txt"), text);
                string bin = GetFilePath(core.WorkingDirectory, prefix, ".bin");
                System.IO.File.WriteAllBytes(bin, encoded.Bytes);
            }

            return text;
        }

        /// <summary>
        /// Builds a Venetian alignment stub and formats it for the log.
        /// </summary>
        /// <param name="alignment">The stub to print.</param>
        /// <param name="core">If set, the text is also written to the working directory.</param>
        /// <returns>The formatted stub.</returns>
        public static string GenerateUnicodeAlign(UnicodeAlignment alignment, ErcCore? core = null)
        {
            var output = new StringBuilder();

            output.AppendLine("---------------------------------------------------------------------------------------");
            output.AppendLine("Venetian alignment generated at " + DateTime.Now);
            output.AppendLine("---------------------------------------------------------------------------------------");
            output.AppendLine();
            output.AppendLine(alignment.Description);
            output.AppendLine();
            output.AppendLine("Buffer register: " + alignment.BufferRegister +
                              "  Delta: " + alignment.Delta);
            output.AppendLine();
            output.AppendLine("Expanded instructions (what executes after UTF-16 widening):");
            foreach (string instruction in alignment.Instructions)
            {
                output.AppendLine("    " + instruction);
            }

            output.AppendLine();
            output.AppendLine("ASCII bytes to inject (the target widens these with 0x00):");
            output.AppendLine(FormatPayloadBytes(alignment.AsciiBytes));
            output.AppendLine();
            output.AppendLine("Expanded bytes (as they appear in memory):");
            output.AppendLine(FormatPayloadBytes(alignment.ExpandedBytes));

            string text = output.ToString();
            if (core != null)
            {
                core.Output.WriteText(GetFilePath(core.WorkingDirectory, "UnicodeAlign_", ".txt"), text);
            }

            return text;
        }

        #endregion

        #region Assemble Opcodes
        /// <summary>
        /// Converts a collection of instructions into the associated opcodes.
        /// </summary>
        /// <param name="instructions">An array containing either x86 or x64 instructions.</param>
        /// <param name="machine">Uint representing the machine type (x86 = 0, x64 = 1)</param>
        /// <returns>Returns null if the method fails.</returns>
        public static string[] AssembleOpcodes(string[] instructions, uint machine)
        {
            string[]? opcodeArray = null;
            MachineType mt;
            if(machine == 0)
            {
                mt = MachineType.I386;
            }
            else if(machine == 1)
            {
                mt = MachineType.x64;
            }
            else
            {
                throw new ERCException("Invalid machine type provided. Value provided = " + machine + ". Uint 0 = x86, 1 = x64");
            }
            var instructionsList = instructions.ToList();
            var asmResult = OpcodeAssembler.AssembleOpcodes(instructionsList, mt);
            if (asmResult.Error != null)
            {
                throw asmResult.Error;
            }
            string opcodes = BitConverter.ToString(asmResult.ReturnValue).Replace("-", " ");
            opcodeArray = opcodes.Split(' ');
            return opcodeArray;
        }

        /// <summary>
        /// Converts a collection of instructions into the associated opcodes.
        /// </summary>
        /// <param name="instructions">An array containing either x86 or x64 instructions.</param>
        /// <param name="machine">MachineType of the instruction set to be assembled.</param>
        /// <returns>Returns null if the method fails.</returns>
        public static string[] AssembleOpcodes(string[] instructions, MachineType machine)
        {
            string[]? opcodeArray = null;
            if(machine != MachineType.I386 && machine != MachineType.x64)
            {
                throw new ERCException("Invalid machine type provided.");
            }
            var instructionsList = instructions.ToList();
            var asmResult = OpcodeAssembler.AssembleOpcodes(instructionsList, machine);
            if(asmResult.Error != null)
            {
                throw asmResult.Error;
            }
            string opcodes = BitConverter.ToString(asmResult.ReturnValue).Replace("-", " ");
            opcodeArray = opcodes.Split(' ');
            return opcodeArray;
        }
        #endregion

        #region Disassemble Opcodes
        /// <summary>
        /// Converts a collection of opcodes into the associated instructions.
        /// </summary>
        /// <param name="opcodes">An array containing either x86 or x64 opcodes.</param>
        /// <param name="machine">Uint representing the machine type (x86 = 0, x64 = 1)</param>
        /// <returns>Returns null if the method fails.</returns>
        public static string[] DisassembleOpcodes(byte[] opcodes, uint machine)
        {
            string[]? instructionArray = null;
            MachineType mt;
            if (machine == 0)
            {
                mt = MachineType.I386;
            }
            else if (machine == 1)
            {
                mt = MachineType.x64;
            }
            else
            {
                throw new ERCException("Invalid machine type provided. Value provided = " + machine + ". Uint 0 = x86, 1 = x64");
            }
            
            var disassembledInstructions = OpcodeDisassembler.Disassemble(opcodes, mt);
            if (disassembledInstructions.Error != null)
            {
                throw disassembledInstructions.Error;
            }
            instructionArray = disassembledInstructions.ReturnValue.Split('\n');
            return instructionArray;
        }

        /// <summary>
        /// Converts a collection of opcodes into the associated instructions.
        /// </summary>
        /// <param name="opcodes">An array containing either x86 or x64 opcodes.</param>
        /// <param name="machine">MachineType of the instruction set to be assembled.</param>
        /// <returns>Returns null if the method fails.</returns>
        public static string[] DisassembleOpcodes(byte[] opcodes, MachineType machine)
        {
            string[]? instructionArray = null;
            if (machine != MachineType.I386 && machine != MachineType.x64)
            {
                throw new ERCException("Invalid machine type provided.");
            }
            var disassembledInstructions = OpcodeDisassembler.Disassemble(opcodes, machine);
            if(disassembledInstructions.Error != null)
            {
                throw disassembledInstructions.Error;
            }
            instructionArray = disassembledInstructions.ReturnValue.Split('\n');
            return instructionArray;
        }
        #endregion

        #region Dump Memory
        /// <summary>
        /// Reads a set of bytes from process memory and provides a string contianing the results.
        /// </summary>
        /// <param name="info">ProcessInfo object</param>
        /// <param name="startAddress">The address to start reading from.</param>
        /// <param name="length">The number of bytes to read.</param>
        /// <param name="writeToFile">Bool indicating if output should be written to a file.</param>
        /// <returns>A string containing the bytes read from memory</returns>
        public static string DumpMemory(ProcessInfo info, IntPtr startAddress, int length, bool writeToFile = true)
        {
            string dumpFilename = GetFilePath(info.WorkingDirectory, "MemoryDump_", ".txt");
            ErcResult<byte[]> result = info.DumpMemoryRegion(startAddress, length);
            string output = "";

            int bytesPerLine = 0;
            Console.WriteLine("Here 1");
            if (info.ProcessMachineType == MachineType.I386)
            {
                bytesPerLine = 8;
            }
            else 
            {
                bytesPerLine = 16;
            }

            output += "----------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;
            output += "Contents of memory region 0x" + startAddress.ToString("X" + bytesPerLine) + " - 0x" + (startAddress + length).ToString("X" + bytesPerLine)
                + " Created at: " + DateTime.Now + ". Created by: " + info.Author + Environment.NewLine;
            output+= "----------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;

            for (int i = 0; i < result.ReturnValue.Length; i++)
            {
                if (i == 0)
                {
                    output += startAddress.ToString("X" + bytesPerLine) + ": " + result.ReturnValue[i].ToString("X2") + " ";
                }
                else if (i % bytesPerLine == 0)
                {
                    output += Environment.NewLine;
                    output += (startAddress + ((i / bytesPerLine) * bytesPerLine)).ToString("X" + bytesPerLine) + ": " + result.ReturnValue[i].ToString("X2") + " ";
                }
                else
                {
                    output += result.ReturnValue[i].ToString("X2") + " ";
                }
            }

            if (writeToFile == true)
            {
                info.Output.WriteText(dumpFilename, output);
            }
            Console.WriteLine("Here 3");
            return output;
        }
        #endregion
    }
}
