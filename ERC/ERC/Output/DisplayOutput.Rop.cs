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

        #region RopChainGadgets32
        /// <summary>
        /// Produces output files containing information about the associated ROP chain, produces files containing ROP gadgets and the associated ROP chain.
        /// </summary>
        /// <param name="rcg">The ROP chain generator object</param>
        /// <param name="gadgetsOnly">Bool to indicate if ROP chains should be included or just gadget lists generated</param>
        /// <returns>Returns an array of strings</returns>
        public static string[] RopChainGadgets32(RopChainGenerator32 rcg, bool gadgetsOnly = false)
        {
            string output = "";
            List<string> totalGadgets = new List<string>();
            List<string> curatedGadgets = new List<string>();
            string totalGadgetsPath = GetFilePath(rcg.RcgInfo.WorkingDirectory, "total_gadgest_", ".txt");
            string curatedGadgetsPath = GetFilePath(rcg.RcgInfo.WorkingDirectory, "curated_gadgest_", ".txt");
            string ropChainPath = GetFilePath(rcg.RcgInfo.WorkingDirectory, "rop_chain_", ".txt");

            output += "------------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;
            if (rcg.RcgInfo.Author != "No_Author_Set")
            {
                output += "Process Name: " + rcg.RcgInfo.ProcessName + " Gadget list created by: " + rcg.RcgInfo.Author + " " + Environment.NewLine;
            }
            else
            {
                output += "Process Name: " + rcg.RcgInfo.ProcessName + " ROP chain gadget list" + Environment.NewLine;
            }
            output += "------------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;

            totalGadgets.Add(output);
            curatedGadgets.Add(output);

            // One loop over the catalogue in place of 88 copy-pasted blocks. Ten
            // of those blocks looked for an instruction the list never contains, so
            // their sections were always empty - see ERC.Output.RopGadgetReport.
            //
            // The guard stays: this formatter is only meaningful for a 32-bit target.
            if (rcg.RcgInfo.ProcessMachineType == MachineType.I386)
            {
                Output.RopGadgetReport.Append(
                    GadgetCatalog.X86Lists, rcg.x86Opcodes, 8, totalGadgets, curatedGadgets);
            }

            rcg.RcgInfo.Output.WriteLines(totalGadgetsPath, totalGadgets);
            rcg.RcgInfo.Output.WriteLines(curatedGadgetsPath, curatedGadgets);

            List<string> ropChain = new List<string>();
            if (gadgetsOnly == false)
            {
                if(rcg.VirtualAllocChain.Count > 0)
                {
                    ropChain.Add("------------------------------------------------------------------------------------------------------------------------");
                    ropChain.Add("Method: VirtualAlloc Process Name: " + rcg.RcgInfo.ProcessName);
                    ropChain.Add("------------------------------------------------------------------------------------------------------------------------");
                    ropChain.Add("");
                    ropChain.Add("################################################################");
                    ropChain.Add("## VirtualAlloc Template:                                     ##");
                    ropChain.Add("## EAX: 90909090 -> Nop sled                                  ##");
                    ropChain.Add("## ECX: 00000040 -> flProtect                                 ##");
                    ropChain.Add("## EDX: 00001000 -> flAllocationType                          ##");
                    ropChain.Add("## EBX: ???????? -> Int size (area to be set as executable)   ##");
                    ropChain.Add("## ESP: ???????? -> No Change                                 ##");
                    ropChain.Add("## EBP: ???????? -> Jmp Esp # Call Esp                        ##");
                    ropChain.Add("## ESI: ???????? -> ApiAddresses[\"VirtualAlloc\"]              ##");
                    ropChain.Add("## EDI: ???????? -> RopNop                                    ##");
                    ropChain.Add("##                                                            ##");
                    ropChain.Add("## + place ptr to \"jmp esp\" on stack, below PUSHAD            ##");
                    ropChain.Add("################################################################");
                    ropChain.Add("");

                }
                foreach (Tuple<byte[], string> k in rcg.VirtualAllocChain)
                {
                    Array.Reverse(k.Item1, 0, k.Item1.Length);
                    ropChain.Add(BitConverter.ToString(k.Item1).Replace("-", "\\x") + " | " + k.Item2);
                }
                ropChain.Add(Environment.NewLine);

                if (rcg.HeapCreateChain.Count > 0)
                {
                    ropChain.Add("------------------------------------------------------------------------------------------------------------------------");
                    ropChain.Add("Method: HeapCreate Process Name: " + rcg.RcgInfo.ProcessName);
                    ropChain.Add("------------------------------------------------------------------------------------------------------------------------");
                    ropChain.Add("");
                    ropChain.Add("################################################################");
                    ropChain.Add("## HeapCreate Template:                                       ##");
                    ropChain.Add("## EAX: 90909090 -> Nop sled                                  ##");
                    ropChain.Add("## ECX: 00010000 -> dwMaximumSize                             ##");
                    ropChain.Add("## EDX: 00001000 -> dwInitialSize                             ##");
                    ropChain.Add("## EBX: 00040000 -> flOptions                                 ##");
                    ropChain.Add("## ESP: ???????? -> No Change                                 ##");
                    ropChain.Add("## EBP: ???????? -> Jmp Esp # Call Esp                        ##");
                    ropChain.Add("## ESI: ???????? -> ApiAddresses[\"HeapCreate\"]                ##");
                    ropChain.Add("## EDI: ???????? -> RopNop                                    ##");
                    ropChain.Add("################################################################");
                    ropChain.Add("");
                }
                foreach (Tuple<byte[], string> k in rcg.HeapCreateChain)
                {
                    Array.Reverse(k.Item1, 0, k.Item1.Length);
                    ropChain.Add(BitConverter.ToString(k.Item1).Replace("-", "\\x") + " | " + k.Item2);
                }
                ropChain.Add(Environment.NewLine);

                if (rcg.VirtualProtectChain.Count > 0)
                {
                    ropChain.Add("------------------------------------------------------------------------------------------------------------------------");
                    ropChain.Add("Method: VirtualProtect Process Name: " + rcg.RcgInfo.ProcessName);
                    ropChain.Add("------------------------------------------------------------------------------------------------------------------------");
                    ropChain.Add("");
                    ropChain.Add("################################################################");
                    ropChain.Add("## VirtualProtect Template:                                   ##");
                    ropChain.Add("## EAX: 90909090 -> Nop sled                                  ##");
                    ropChain.Add("## ECX: ???????? -> flAllocationType                          ##");
                    ropChain.Add("## EDX: 00000040 -> flNewProtect                              ##");
                    ropChain.Add("## EBX: ???????? -> Int size (area to be set as executable)   ##");
                    ropChain.Add("## ESP: ???????? -> No Change                                 ##");
                    ropChain.Add("## EBP: ???????? -> Jmp Esp # Call Esp                        ##");
                    ropChain.Add("## ESI: ???????? -> ApiAddresses[\"VirtualProtect\"]            ##");
                    ropChain.Add("## EDI: ???????? -> RopNop                                    ##");
                    ropChain.Add("##                                                            ##");
                    ropChain.Add("## + place ptr to \"jmp esp\" on stack, below PUSHAD            ##");
                    ropChain.Add("################################################################");
                    ropChain.Add("");
                }
                foreach (Tuple<byte[], string> k in rcg.VirtualProtectChain)
                {
                    Array.Reverse(k.Item1, 0, k.Item1.Length);
                    ropChain.Add(BitConverter.ToString(k.Item1).Replace("-", "\\x") + " | " + k.Item2);
                }
                ropChain.Add(Environment.NewLine);

                rcg.RcgInfo.Output.WriteLines(ropChainPath, ropChain);
            }

            return ropChain.ToArray();
        }
        #endregion

        #region RopChainGadgets64
        /// <summary>
        /// Produces output files containing information about the associated ROP chain, produces files containing ROP gadgets and the associated ROP chain.
        /// </summary>
        /// <param name="rcg">The ROP chain generator object</param>
        /// <param name="gadgetsOnly">Bool to indicate if ROP chains should be included or just gadget lists generated</param>
        /// <returns>Returns an array of strings</returns>
        public static string[] RopChainGadgets64(RopChainGenerator64 rcg, bool gadgetsOnly = false)
        {
            string output = "";
            List<string> totalGadgets = new List<string>();
            List<string> curatedGadgets = new List<string>();
            string totalGadgetsPath = GetFilePath(rcg.RcgInfo.WorkingDirectory, "total_gadgest_64_", ".txt");
            string curatedGadgetsPath = GetFilePath(rcg.RcgInfo.WorkingDirectory, "curated_gadgest_64_", ".txt");
            string ropChainPath = GetFilePath(rcg.RcgInfo.WorkingDirectory, "rop_chain_64_", ".txt");

            output += "-------------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;
            if (rcg.RcgInfo.Author != "No_Author_Set")
            {
                output += "Process Name: " + rcg.RcgInfo.ProcessName + " Gadget list created by: " + rcg.RcgInfo.Author + " " + Environment.NewLine;
            }
            else
            {
                output += "Process Name: " + rcg.RcgInfo.ProcessName + " ROP chain gadget list" + Environment.NewLine;
            }
            output += "-------------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;

            totalGadgets.Add(output);
            curatedGadgets.Add(output);

            // One loop over the catalogue in place of 84 copy-pasted blocks. Ten
            // of those blocks looked for an instruction the list never contains, so
            // their sections were always empty - see ERC.Output.RopGadgetReport.
            Output.RopGadgetReport.Append(
                GadgetCatalog.X64Lists, rcg.x64Opcodes, 16, totalGadgets, curatedGadgets);
            
            rcg.RcgInfo.Output.WriteLines(totalGadgetsPath, totalGadgets);
            rcg.RcgInfo.Output.WriteLines(curatedGadgetsPath, curatedGadgets);

            List<string> ropChain = new List<string>();
            if (gadgetsOnly == false)
            {
                if (rcg.VirtualAllocChain.Count > 0)
                {
                    ropChain.Add("------------------------------------------------------------------------------------------------------------------------");
                    ropChain.Add("Method: VirtualAlloc Process Name: " + rcg.RcgInfo.ProcessName);
                    ropChain.Add("------------------------------------------------------------------------------------------------------------------------");
                    ropChain.Add("");
                    ropChain.Add("################################################################");
                    ropChain.Add("## VirtualAlloc Template:                                     ##");
                    ropChain.Add("## RCX: 0x???????????????? ->  Pointer (copys RSP)            ##");
                    ropChain.Add("## RDX: 0x0000000000000500 ->  dwSize                         ##");
                    ropChain.Add("## R8 : 0x0000000000001000 ->  flAllocationType               ##");
                    ropChain.Add("## R9 : 0x0000000000000040 ->  flProtect                      ##");
                    ropChain.Add("##                                                            ##");
                    ropChain.Add("## + place a pointer to VirtualAlloc on stack                 ##");
                    ropChain.Add("## + place ptr to \"jmp rsp\" on stack                          ##");
                    ropChain.Add("################################################################");
                    ropChain.Add("");

                }
                foreach (Tuple<byte[], string> k in rcg.VirtualAllocChain)
                {
                    Array.Reverse(k.Item1, 0, k.Item1.Length);
                    ropChain.Add(BitConverter.ToString(k.Item1).Replace("-", "\\x") + " | " + k.Item2);
                }
                ropChain.Add(Environment.NewLine);

                if (rcg.HeapCreateChain.Count > 0)
                {
                    ropChain.Add("------------------------------------------------------------------------------------------------------------------------");
                    ropChain.Add("Method: HeapCreate Process Name: " + rcg.RcgInfo.ProcessName);
                    ropChain.Add("------------------------------------------------------------------------------------------------------------------------");
                    ropChain.Add("");
                    ropChain.Add("################################################################");
                    ropChain.Add("## HeapCreate Template:                                       ##");
                    ropChain.Add("## RCX: 0x0000000000040000 ->  flOptions                      ##");
                    ropChain.Add("## RDX: 0x0000000000000500 ->  dwInitialSize                  ##");
                    ropChain.Add("## R8 : 0x0000000000001000 ->  dwMaximumSize                  ##");
                    ropChain.Add("##                                                            ##");
                    ropChain.Add("## + place a pointer to VirtualAlloc on stack                 ##");
                    ropChain.Add("## + place ptr to \"jmp rax\" on stack                          ##");
                    ropChain.Add("################################################################");
                    ropChain.Add("");
                }
                foreach (Tuple<byte[], string> k in rcg.HeapCreateChain)
                {
                    Array.Reverse(k.Item1, 0, k.Item1.Length);
                    ropChain.Add(BitConverter.ToString(k.Item1).Replace("-", "\\x") + " | " + k.Item2);
                }
                ropChain.Add(Environment.NewLine);

                if (rcg.VirtualProtectChain.Count > 0)
                {
                    ropChain.Add("------------------------------------------------------------------------------------------------------------------------");
                    ropChain.Add("Method: VirtualProtect Process Name: " + rcg.RcgInfo.ProcessName);
                    ropChain.Add("------------------------------------------------------------------------------------------------------------------------");
                    ropChain.Add("");
                    ropChain.Add("################################################################");
                    ropChain.Add("## VirtualProtect Template:                                   ##");
                    ropChain.Add("## RCX: 0x???????????????? ->  Pointer (copys RSP)            ##");
                    ropChain.Add("## RDX: 0x0000000000000500 ->  dwSize                         ##");
                    ropChain.Add("## R8 : 0x0000000000001000 ->  flAllocationType               ##");
                    ropChain.Add("## R9 : 0x???????????????? ->  flProtect (copys RSP)          ##");
                    ropChain.Add("##                                                            ##");
                    ropChain.Add("## + place a pointer to VirtualAlloc on stack                 ##");
                    ropChain.Add("## + place ptr to \"jmp rsp\" on stack                          ##");
                    ropChain.Add("################################################################");
                    ropChain.Add("");
                }
                foreach (Tuple<byte[], string> k in rcg.VirtualProtectChain)
                {
                    Array.Reverse(k.Item1, 0, k.Item1.Length);
                    ropChain.Add(BitConverter.ToString(k.Item1).Replace("-", "\\x") + " | " + k.Item2);
                }
                ropChain.Add(Environment.NewLine);

                rcg.RcgInfo.Output.WriteLines(ropChainPath, ropChain);
            }

            return ropChain.ToArray();
        }

        private static string ConvertRopElementToString(Tuple<IntPtr, string> element)
        {
            string ret = "0x" + element.Item1.ToString("X16") + " | " + element.Item2;
            return ret;
        }
        #endregion
    }
}
