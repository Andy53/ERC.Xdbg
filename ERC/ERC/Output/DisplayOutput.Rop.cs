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

            if (rcg.RcgInfo.ProcessMachineType == MachineType.I386)
            {
                totalGadgets.Add("pushEax: ");
                curatedGadgets.Add("pushEax: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEax)
                {
                    if(k.Value.Contains("push eax") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if(!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                        
                }
                totalGadgets.Add("pushEbx: ");
                curatedGadgets.Add("pushEbx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEbx)
                {
                    if (k.Value.Contains("push ebx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("pushEcx: ");
                curatedGadgets.Add("pushEcx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEcx)
                {
                    if (k.Value.Contains("push ecx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("pushEdx: ");
                curatedGadgets.Add("pushEdx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEdx)
                {
                    if (k.Value.Contains("push edx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("pushEsp: ");
                curatedGadgets.Add("pushEsp: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEsp)
                {
                    if (k.Value.Contains("push esp") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("pushEbp: ");
                curatedGadgets.Add("pushEbp: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEbp)
                {
                    if (k.Value.Contains("push ebp") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("pushEsi: ");
                curatedGadgets.Add("pushEsi: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEsi)
                {
                    if (k.Value.Contains("push esi") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("pushEdi: ");
                curatedGadgets.Add("pushEdi: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEdi)
                {
                    if (k.Value.Contains("push edi") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("JmpEsp: ");
                curatedGadgets.Add("JmpEsp: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.jmpEsp)
                {
                    if (k.Value.Contains("jmp esp"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("CallEsp: ");
                curatedGadgets.Add("CallEsp: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.callEsp)
                {
                    if (k.Value.Contains("call esp"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("xorEax: ");
                curatedGadgets.Add("xorEax: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.xorEax)
                {
                    if (k.Value.Contains("xor eax") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("xorEbx: ");
                curatedGadgets.Add("xorEbx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.xorEbx)
                {
                    if (k.Value.Contains("xor ebx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("xorEcx: ");
                curatedGadgets.Add("xorEcx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.xorEcx)
                {
                    if (k.Value.Contains("xor ecx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("xorEdx: ");
                curatedGadgets.Add("xorEdx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.xorEdx)
                {
                    if (k.Value.Contains("xor edx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("xorEsi: ");
                curatedGadgets.Add("xorEsi: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.xorEsi)
                {
                    if (k.Value.Contains("xor esi") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("xorEdi: ");
                curatedGadgets.Add("xorEdi: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.xorEdi)
                {
                    if (k.Value.Contains("xor edi") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("popEax: ");
                curatedGadgets.Add("popEax: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEax)
                {
                    if (k.Value.Contains("pop eax") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("popEbx: ");
                curatedGadgets.Add("popEbx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEbx)
                {
                    if (k.Value.Contains("pop ebx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("popEcx: ");
                curatedGadgets.Add("popEcx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEcx)
                {
                    if (k.Value.Contains("pop ecx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("popEdx: ");
                curatedGadgets.Add("popEdx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEdx)
                {
                    if (k.Value.Contains("pop edx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("popEsp: ");
                curatedGadgets.Add("popEsp: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEsp)
                {
                    if (k.Value.Contains("pop esp") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("popEbp: ");
                curatedGadgets.Add("popEbp: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEbp)
                {
                    if (k.Value.Contains("pop ebp") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("popEsi: ");
                curatedGadgets.Add("popEsi: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEsi)
                {
                    if (k.Value.Contains("pop esi") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("popEdi: ");
                curatedGadgets.Add("popEdi: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEdi)
                {
                    if (k.Value.Contains("pop edo") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("incEax: ");
                curatedGadgets.Add("incEax: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEax)
                {
                    if (k.Value.Contains("inc eax") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("decEax: ");
                curatedGadgets.Add("decEax: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEax)
                {
                    if (k.Value.Contains("dec eax") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("incEbx: ");
                curatedGadgets.Add("incEbx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEbx)
                {
                    if (k.Value.Contains("inc ebx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("decEbx: ");
                curatedGadgets.Add("decEbx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEbx)
                {
                    if (k.Value.Contains("dec ebx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("incEcx: ");
                curatedGadgets.Add("incEcx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEcx)
                {
                    if (k.Value.Contains("inc ecx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("decEcx: ");
                curatedGadgets.Add("decEcx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEcx)
                {
                    if (k.Value.Contains("dec ecx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("incEdx: ");
                curatedGadgets.Add("incEdx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEdx)
                {
                    if (k.Value.Contains("inc edx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("decEdx: ");
                curatedGadgets.Add("decEdx: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEdx)
                {
                    if (k.Value.Contains("dec edx") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("incEbp: ");
                curatedGadgets.Add("incEbp: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEbp)
                {
                    if (k.Value.Contains("inc ebp") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }

                }
                totalGadgets.Add("decEbp: ");
                curatedGadgets.Add("decEbp: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEbp)
                {
                    if (k.Value.Contains("dec ebp") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("incEsp: ");
                curatedGadgets.Add("incEsp: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEsp)
                {
                    if (k.Value.Contains("inc esp") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("decEsp: ");
                curatedGadgets.Add("decEsp: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEsp)
                {
                    if (k.Value.Contains("dec esp") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("incEsi: ");
                curatedGadgets.Add("incEsi: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEsi)
                {
                    if (k.Value.Contains("inc esi") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("decEsi: ");
                curatedGadgets.Add("decEsi: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEsi)
                {
                    if (k.Value.Contains("dec esi") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("incEdi: ");
                curatedGadgets.Add("incEdi: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEdi)
                {
                    if (k.Value.Contains("inc edi") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("decEdi: ");
                curatedGadgets.Add("decEdi: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEdi)
                {
                    if (k.Value.Contains("dec edi") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("Add: ");
                curatedGadgets.Add("Add: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.add)
                {
                    if (k.Value.Contains("add") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("Sub: ");
                curatedGadgets.Add("Sub: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.sub)
                {
                    if (k.Value.Contains("sub") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("Mov: ");
                curatedGadgets.Add("Mov: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.mov)
                {
                    if (k.Value.Contains("mov") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
                totalGadgets.Add("And: ");
                curatedGadgets.Add("And: ");
                foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.and)
                {
                    if (k.Value.Contains("and") && k.Value.Contains("ret"))
                    {
                        totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                        {
                            curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                        }
                    }
                }
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

            totalGadgets.Add("pushRax: ");
            curatedGadgets.Add("pushRax: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.pushRax)
            {
                if (k.Value.Contains("push rax") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }

            }
            totalGadgets.Add("pushRbx: ");
            curatedGadgets.Add("pushRbx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.pushRbx)
            {
                if (k.Value.Contains("push rbx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("pushRcx: ");
            curatedGadgets.Add("pushRcx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.pushRcx)
            {
                if (k.Value.Contains("push rcx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("pushRdx: ");
            curatedGadgets.Add("pushRdx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.pushRdx)
            {
                if (k.Value.Contains("push rdx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("pushRsp: ");
            curatedGadgets.Add("pushRsp: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.pushRsp)
            {
                if (k.Value.Contains("push rsp") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("pushRbp: ");
            curatedGadgets.Add("pushRbp: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.pushRbp)
            {
                if (k.Value.Contains("push rbp") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("pushRsi: ");
            curatedGadgets.Add("pushRsi: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.pushRsi)
            {
                if (k.Value.Contains("push rsi") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("pushRdi: ");
            curatedGadgets.Add("pushRdi: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.pushRdi)
            {
                if (k.Value.Contains("push rdi") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("JmpRsp: ");
            curatedGadgets.Add("JmpRsp: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.jmpRsp)
            {
                if (k.Value.Contains("jmp rsp"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("CallRsp: ");
            curatedGadgets.Add("CallRsp: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.callRsp)
            {
                if (k.Value.Contains("call rsp"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("xorEax: ");
            curatedGadgets.Add("xorEax: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.xorRax)
            {
                if (k.Value.Contains("xor eax") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("xorRbx: ");
            curatedGadgets.Add("xorRbx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.xorRbx)
            {
                if (k.Value.Contains("xor rbx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("xorRcx: ");
            curatedGadgets.Add("xorRcx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.xorRcx)
            {
                if (k.Value.Contains("xor rcx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("xorRdx: ");
            curatedGadgets.Add("xorRdx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.xorRdx)
            {
                if (k.Value.Contains("xor rdx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("xorRsi: ");
            curatedGadgets.Add("xorRsi: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.xorRsi)
            {
                if (k.Value.Contains("xor rsi") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("xorRdi: ");
            curatedGadgets.Add("xorRdi: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.xorRdi)
            {
                if (k.Value.Contains("xor rdi") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("popRax: ");
            curatedGadgets.Add("popRax: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.popRax)
            {
                if (k.Value.Contains("pop rax") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("popRbx: ");
            curatedGadgets.Add("popRbx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.popRbx)
            {
                if (k.Value.Contains("pop rbx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("popRcx: ");
            curatedGadgets.Add("popRcx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.popRcx)
            {
                if (k.Value.Contains("pop rcx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("popRdx: ");
            curatedGadgets.Add("popRdx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.popRdx)
            {
                if (k.Value.Contains("pop rdx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("popRsp: ");
            curatedGadgets.Add("popRsp: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.popRsp)
            {
                if (k.Value.Contains("pop rsp") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("popRbp: ");
            curatedGadgets.Add("popRbp: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.popRbp)
            {
                if (k.Value.Contains("pop rbp") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("popRsi: ");
            curatedGadgets.Add("popRsi: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.popRsi)
            {
                if (k.Value.Contains("pop rsi") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("popRdi: ");
            curatedGadgets.Add("popRdi: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.popRdi)
            {
                if (k.Value.Contains("pop rdi") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("incRax: ");
            curatedGadgets.Add("incRax: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.incRax)
            {
                if (k.Value.Contains("inc rax") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("decRax: ");
            curatedGadgets.Add("decRax: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.decRax)
            {
                if (k.Value.Contains("dec eax") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("incRbx: ");
            curatedGadgets.Add("incRbx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.incRbx)
            {
                if (k.Value.Contains("inc rbx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("decRbx: ");
            curatedGadgets.Add("decRbx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.decRbx)
            {
                if (k.Value.Contains("dec ebx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("incRcx: ");
            curatedGadgets.Add("incRcx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.incRcx)
            {
                if (k.Value.Contains("inc rcx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("decRcx: ");
            curatedGadgets.Add("decRcx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.decRcx)
            {
                if (k.Value.Contains("dec ecx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("incRdx: ");
            curatedGadgets.Add("incRdx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.incRdx)
            {
                if (k.Value.Contains("inc rdx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("decRdx: ");
            curatedGadgets.Add("decRdx: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.decRdx)
            {
                if (k.Value.Contains("dec edx") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("incRbp: ");
            curatedGadgets.Add("incRbp: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.incRbp)
            {
                if (k.Value.Contains("inc rbp") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }

            }
            totalGadgets.Add("decRbp: ");
            curatedGadgets.Add("decRbp: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.decRbp)
            {
                if (k.Value.Contains("dec ebp") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("incRsp: ");
            curatedGadgets.Add("incRsp: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.incRsp)
            {
                if (k.Value.Contains("inc rsp") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("decRsp: ");
            curatedGadgets.Add("decRsp: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.decRsp)
            {
                if (k.Value.Contains("dec esp") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("incRsi: ");
            curatedGadgets.Add("incRsi: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.incRsi)
            {
                if (k.Value.Contains("inc rsi") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("decRsi: ");
            curatedGadgets.Add("decRsi: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.decRsi)
            {
                if (k.Value.Contains("dec esi") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("incRdi: ");
            curatedGadgets.Add("incRdi: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.incRdi)
            {
                if (k.Value.Contains("inc rdi") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("decRdi: ");
            curatedGadgets.Add("decRdi: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.decRdi)
            {
                if (k.Value.Contains("dec edi") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("Add: ");
            curatedGadgets.Add("Add: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.add)
            {
                if (k.Value.Contains("add") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            totalGadgets.Add("Mov: ");
            curatedGadgets.Add("Mov: ");
            foreach (KeyValuePair<IntPtr, string> k in rcg.x64Opcodes.mov)
            {
                if (k.Value.Contains("mov") && k.Value.Contains("ret"))
                {
                    totalGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    if (!k.Value.Any(char.IsDigit) && !k.Value.ToLower().Contains("invalid"))
                    {
                        curatedGadgets.Add("0x" + k.Key.ToString("X16") + " | " + k.Value);
                    }
                }
            }
            
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
