using ERC.Structures;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

using ERC.Native;
namespace ERC
{
    /// <summary> Contains information needed for the associated functions relating to the process. </summary>
    public partial class ProcessInfo
    {
        #region FindNRP
        /// <summary>
        /// Searches process registers and identifies pointers to buffers in memory containing a non repeating pattern. Functionality to identify SEH overwrites not yet implements.
        /// </summary>
        /// <param name="searchType">(Optional) 0 = search term is system default\n1 = search term is in unicode\n2 = search term is in ASCII\n3 = Search term is in UTF8\n4 = Search term is in UTF7\n5 = Search term is in UTF32</param>
        /// <param name="extended">(Optional) Include additional characters in the pattern (!#$%^ etc) in the to be searched</param>
        /// <returns>Returns a ERC_Result containing a List of RegisterOffset</returns>
        public ErcResult<List<RegisterInfo>> FindNRP(int searchType = 0, bool extended = false)
        {
            ErcResult<List<RegisterInfo>> offsets = new ErcResult<List<RegisterInfo>>(ProcessCore);
            List<string> nrps = new List<string>();
            string pattern = "";
            if(extended == false)
            {
                pattern = File.ReadAllText(ProcessCore.PatternStandardPath);
            }
            else
            {
                pattern = File.ReadAllText(ProcessCore.PatternExtendedPath);
            }

            string nrpHolder = "";
            int counter = 0;
            for(int i = 0; i < pattern.Length; i++)
            {
                if(counter != 2)
                {
                    nrpHolder += pattern[i];
                    counter++;
                }
                else
                {
                    nrpHolder += pattern[i];
                    nrps.Add(nrpHolder);
                    nrpHolder = "";
                    counter = 0;
                }
            }

            for (int i = 0; i < ThreadsInfo.Count; i++)
            {
                var context = ThreadsInfo[i].Get_Context();
                if(context.Error != null)
                {
                    context.LogEvent();
                    offsets.Error = context.Error;
                }
            }

            List<RegisterInfo> registers = new List<RegisterInfo>();
            if(ProcessMachineType == MachineType.I386)
            {
                for (int i = 0; i < ThreadsInfo.Count; i++)
                {
                    RegisterInfo regEdi = new RegisterInfo();
                    regEdi.Register = "EDI";
                    if (ThreadsInfo[i].Context32.Edi > int.MaxValue)
                    {
                        ThreadsInfo[i].Context32.Edi = ThreadsInfo[i].Context32.Edi - int.MaxValue;
                    }
                    regEdi.RegisterValue = (IntPtr)ThreadsInfo[i].Context32.Edi;
                    regEdi.ThreadID = ThreadsInfo[i].ThreadID;
                    regEdi.StringOffset = -1;
                    regEdi.RegisterOffset = -1;
                    registers.Add(regEdi);
                    RegisterInfo regEsi = new RegisterInfo();
                    regEsi.Register = "ESI";
                    if (ThreadsInfo[i].Context32.Esi > int.MaxValue)
                    {
                        ThreadsInfo[i].Context32.Esi = ThreadsInfo[i].Context32.Esi - int.MaxValue;
                    }
                    regEsi.RegisterValue = (IntPtr)ThreadsInfo[i].Context32.Esi;
                    regEsi.ThreadID = ThreadsInfo[i].ThreadID;
                    regEsi.StringOffset = -1;
                    regEsi.RegisterOffset = -1;
                    registers.Add(regEsi);
                    RegisterInfo regEbx = new RegisterInfo();
                    regEbx.Register = "EBX";
                    if (ThreadsInfo[i].Context32.Ebx > int.MaxValue)
                    {
                        ThreadsInfo[i].Context32.Ebx = ThreadsInfo[i].Context32.Ebx - int.MaxValue;
                    }
                    regEbx.RegisterValue = (IntPtr)ThreadsInfo[i].Context32.Ebx;
                    regEbx.ThreadID = ThreadsInfo[i].ThreadID;
                    regEbx.StringOffset = -1;
                    regEbx.RegisterOffset = -1;
                    registers.Add(regEbx);
                    RegisterInfo regEdx = new RegisterInfo();
                    regEdx.Register = "EDX";
                    if (ThreadsInfo[i].Context32.Edx > int.MaxValue)
                    {
                        ThreadsInfo[i].Context32.Edx = ThreadsInfo[i].Context32.Edx - int.MaxValue;
                    }
                    regEdx.RegisterValue = (IntPtr)ThreadsInfo[i].Context32.Edx;
                    regEdx.ThreadID = ThreadsInfo[i].ThreadID;
                    regEdx.StringOffset = -1;
                    regEdx.RegisterOffset = -1;
                    registers.Add(regEdx);
                    RegisterInfo regEcx = new RegisterInfo();
                    regEcx.Register = "ECX";
                    if (ThreadsInfo[i].Context32.Ecx > int.MaxValue)
                    {
                        ThreadsInfo[i].Context32.Ecx = ThreadsInfo[i].Context32.Ecx - int.MaxValue;
                    }
                    regEcx.RegisterValue = (IntPtr)ThreadsInfo[i].Context32.Ecx;
                    regEcx.ThreadID = ThreadsInfo[i].ThreadID;
                    regEcx.StringOffset = -1;
                    regEcx.RegisterOffset = -1;
                    registers.Add(regEcx);
                    RegisterInfo regEax = new RegisterInfo();
                    regEax.Register = "EAX";
                    if(ThreadsInfo[i].Context32.Eax > int.MaxValue)
                    {
                        ThreadsInfo[i].Context32.Eax = ThreadsInfo[i].Context32.Eax - int.MaxValue;
                    }
                    regEax.RegisterValue = (IntPtr)ThreadsInfo[i].Context32.Eax; //Arith problem here
                    regEax.ThreadID = ThreadsInfo[i].ThreadID;
                    regEax.StringOffset = -1;
                    regEax.RegisterOffset = -1;
                    registers.Add(regEax);
                    RegisterInfo regEsp = new RegisterInfo();
                    regEsp.Register = "ESP";
                    if (ThreadsInfo[i].Context32.Esp > int.MaxValue)
                    {
                        ThreadsInfo[i].Context32.Esp = ThreadsInfo[i].Context32.Esp - int.MaxValue;
                    }
                    regEsp.RegisterValue = (IntPtr)ThreadsInfo[i].Context32.Esp;
                    regEsp.ThreadID = ThreadsInfo[i].ThreadID;
                    regEsp.StringOffset = -1;
                    regEsp.RegisterOffset = -1;
                    registers.Add(regEsp);
                    RegisterInfo regEbp = new RegisterInfo();
                    regEbp.Register = "EBP";
                    if (ThreadsInfo[i].Context32.Ebp > int.MaxValue)
                    {
                        ThreadsInfo[i].Context32.Ebp = ThreadsInfo[i].Context32.Ebp - int.MaxValue;
                    }
                    regEbp.RegisterValue = (IntPtr)ThreadsInfo[i].Context32.Ebp;
                    regEbp.ThreadID = ThreadsInfo[i].ThreadID;
                    regEbp.StringOffset = -1;
                    regEbp.RegisterOffset = -1;
                    registers.Add(regEbp);
                    RegisterInfo regEIP = new RegisterInfo();
                    regEIP.Register = "EIP";
                    if (ThreadsInfo[i].Context32.Eip > int.MaxValue)
                    {
                        ThreadsInfo[i].Context32.Eip = ThreadsInfo[i].Context32.Eip - int.MaxValue;
                    }
                    regEIP.RegisterValue = (IntPtr)ThreadsInfo[i].Context32.Eip;
                    regEIP.ThreadID = ThreadsInfo[i].ThreadID;
                    registers.Add(regEIP);
                }

                for (int i = 0; i < registers.Count; i++)
                {
                    for (int j = 0; j < MemoryRegions32.Count; j++)
                    {
                        ulong regionStart = (ulong)MemoryRegions32[j].BaseAddress;
                        ulong regionEnd = (ulong)MemoryRegions32[j].BaseAddress + (ulong)MemoryRegions32[j].RegionSize;

                        if (registers[i].Register != "EIP" && registers[i].Register != "EBP" &&
                            (ulong)registers[i].RegisterValue > regionStart &&
                            (ulong)registers[i].RegisterValue < regionEnd)
                        {
                            ulong bufferSize = ((ulong)MemoryRegions32[j].BaseAddress + (ulong)MemoryRegions32[j].RegionSize) - (ulong)registers[i].RegisterValue;
                            byte[] buffer = new byte[bufferSize];
                            int bytesRead = 0;
                            Native.ReadProcessMemory(ProcessHandle, registers[i].RegisterValue, buffer, (int)bufferSize, out bytesRead);

                            string memoryString = "";
                            switch (searchType)
                            {
                                case 0:
                                    memoryString = Encoding.Default.GetString(buffer);
                                    break;
                                case 1:
                                    memoryString = Encoding.Unicode.GetString(buffer);
                                    break;
                                case 2:
                                    memoryString = Encoding.ASCII.GetString(buffer);
                                    break;
                                case 3:
                                    memoryString = Encoding.UTF8.GetString(buffer);
                                    break;
                                case 4:
                                    memoryString = Encoding.UTF7.GetString(buffer);
                                    break;
                                case 5:
                                    memoryString = Encoding.UTF32.GetString(buffer);
                                    break;
                                default:
                                    memoryString = Encoding.Default.GetString(buffer);
                                    break;
                            }
                            int length = -1;
                            for (int k = 0; k < nrps.Count; k++)
                            {
                                if (memoryString.Contains(nrps[k]) && pattern.Contains(nrps[k]))
                                {
                                    if (registers[i].StringOffset == -1)
                                    {
                                        registers[i].StringOffset = pattern.IndexOf(nrps[k]);
                                    }

                                    int index = memoryString.IndexOf(nrps[k]);
                                    if (registers[i].RegisterOffset == -1)
                                    {
                                        registers[i].RegisterOffset = index;
                                    }
                                    
                                    length += 3;
                                }
                            }
                            registers[i].BufferSize = length;
                        }
                        else if (registers[i].Register == "EIP")
                        {
                            string EIPValue = "";
                            switch (searchType)
                            {
                                case 0:
                                    EIPValue = Encoding.Default.GetString(BitConverter.GetBytes((uint)registers[i].RegisterValue));
                                    break;
                                case 1:
                                    EIPValue = Encoding.Unicode.GetString(BitConverter.GetBytes((uint)registers[i].RegisterValue));
                                    break;
                                case 2:
                                    EIPValue = Encoding.ASCII.GetString(BitConverter.GetBytes((uint)registers[i].RegisterValue));
                                    break;
                                case 3:
                                    EIPValue = Encoding.UTF8.GetString(BitConverter.GetBytes((uint)registers[i].RegisterValue));
                                    break;
                                case 4:
                                    EIPValue = Encoding.UTF7.GetString(BitConverter.GetBytes((uint)registers[i].RegisterValue));
                                    break;
                                case 5:
                                    EIPValue = Encoding.UTF32.GetString(BitConverter.GetBytes((uint)registers[i].RegisterValue));
                                    break;
                                default:
                                    EIPValue = Encoding.Default.GetString(BitConverter.GetBytes((uint)registers[i].RegisterValue));
                                    break;
                            }
                            EIPValue = EIPValue.TrimEnd(null);
                            if (pattern.Contains(EIPValue))
                            {
                                registers[i].StringOffset = pattern.IndexOf(EIPValue);
                            }
                        }
                    }
                    if (Utilities.PatternTools.PatternOffset(Utilities.Convert.HexToAscii(registers[i].RegisterValue.ToString("X")), ProcessCore).ReturnValue != "Value not found in pattern.")
                    {
                        if(Utilities.Convert.HexToAscii(registers[i].RegisterValue.ToString("X")).Length > 0)
                        {
                            string regHex = Utilities.Convert.HexToAscii(registers[i].RegisterValue.ToString("X"));
                            string regPos = Utilities.PatternTools.PatternOffset(Utilities.Convert.HexToAscii(registers[i].RegisterValue.ToString("X")), ProcessCore).ReturnValue;
                            if (!String.IsNullOrEmpty(regPos) && regPos.Any(char.IsDigit))
                            {
                                registers[i].StringOffset = Int32.Parse(Regex.Match(regPos, @"\d+").Value);
                                registers[i].overwritten = true;
                            }
                        }
                    }
                }
                for (int i = 0; i < ThreadsInfo.Count; i++)
                {
                    var pTeb = ThreadsInfo[i].PopulateTEB();
                    if (pTeb.Error == null)
                    {
                        var sehChain = ThreadsInfo[i].BuildSehChain();
                        if (sehChain.Error == null)
                        {
                            if (sehChain.ReturnValue.Count > 0)
                            {
                                for (int j = 0; j < sehChain.ReturnValue.Count; j++)
                                {
                                    string SEHValue = "";
                                    string nSEHValue = "";
                                    switch (searchType)
                                    {
                                        case 0:
                                            SEHValue = Encoding.Default.GetString(sehChain.ReturnValue[j].Item1);
                                            nSEHValue = Encoding.Default.GetString(sehChain.ReturnValue[j].Item2);
                                            break;
                                        case 1:
                                            byte[] sehHolder1 = sehChain.ReturnValue[j].Item1;
                                            byte[] sehHolder2 = sehChain.ReturnValue[j].Item2;
                                            if (sehChain.ReturnValue[j].Item1[0] == 0x00)
                                            {
                                                byte[] newSEH = new byte[sehChain.ReturnValue[j].Item1.Length];
                                                Array.Copy(sehChain.ReturnValue[j].Item1, 1, newSEH, 0, sehChain.ReturnValue[j].Item1.Length - 1);
                                                newSEH[newSEH.Length - 1] = 0x00;
                                                sehHolder1 = newSEH;
                                            }
                                            if (sehChain.ReturnValue[j].Item2[0] == 0x00)
                                            {
                                                byte[] newSEH = new byte[sehChain.ReturnValue[j].Item2.Length];
                                                Array.Copy(sehChain.ReturnValue[j].Item2, 1, newSEH, 0, sehChain.ReturnValue[j].Item2.Length - 1);
                                                newSEH[newSEH.Length - 1] = 0x00;
                                                sehHolder2 = newSEH;
                                            }
                                            SEHValue = Encoding.Unicode.GetString(sehHolder1);
                                            nSEHValue = Encoding.Unicode.GetString(sehHolder2);
                                            break;
                                        case 2:
                                            SEHValue = Encoding.ASCII.GetString(sehChain.ReturnValue[j].Item1);
                                            nSEHValue = Encoding.ASCII.GetString(sehChain.ReturnValue[j].Item2);
                                            break;
                                        case 3:
                                            SEHValue = Encoding.UTF8.GetString(sehChain.ReturnValue[j].Item1);
                                            nSEHValue = Encoding.UTF8.GetString(sehChain.ReturnValue[j].Item2);
                                            break;
                                        case 4:
                                            SEHValue = Encoding.UTF7.GetString(sehChain.ReturnValue[j].Item1);
                                            nSEHValue = Encoding.UTF7.GetString(sehChain.ReturnValue[j].Item2);
                                            break;
                                        case 5:
                                            SEHValue = Encoding.UTF32.GetString(sehChain.ReturnValue[j].Item1);
                                            nSEHValue = Encoding.UTF32.GetString(sehChain.ReturnValue[j].Item2);
                                            break;
                                        default:
                                            SEHValue = Encoding.Default.GetString(sehChain.ReturnValue[j].Item1);
                                            nSEHValue = Encoding.Default.GetString(sehChain.ReturnValue[j].Item2);
                                            break;
                                    }
                                    char[] sehArray = SEHValue.ToCharArray();
                                    Array.Reverse(sehArray);
                                    string ReversedSEHValue = new string(sehArray);
                                    RegisterInfo SEH = new RegisterInfo();
                                    char[] nsehArray = nSEHValue.ToCharArray();
                                    Array.Reverse(nsehArray);
                                    string nReversedSEHValue = new string(nsehArray);
                                    string combinedSeh = SEHValue + nSEHValue;
                                    string reversedCombinedSeh = ReversedSEHValue + nReversedSEHValue;
                                    if (pattern.Contains(combinedSeh) || pattern.Contains(reversedCombinedSeh))
                                    {
                                        SEH.Register = "SEH" + i.ToString();
                                        if (pattern.Contains(reversedCombinedSeh))
                                        {
                                            SEH.StringOffset = pattern.IndexOf(reversedCombinedSeh);
                                        }
                                        else
                                        {
                                            SEH.StringOffset = pattern.IndexOf(combinedSeh);
                                        }
                                        SEH.ThreadID = ThreadsInfo[i].ThreadID;
                                        SEH.RegisterValue = (IntPtr)BitConverter.ToInt32(sehChain.ReturnValue[j].Item1, 0);
                                        registers.Add(SEH);
                                    }
                                    else if (pattern.Contains(SEHValue) || pattern.Contains(ReversedSEHValue) || pattern.Contains(nSEHValue) || pattern.Contains(nReversedSEHValue))
                                    {
                                        SEH.Register = "SEH" + i.ToString();
                                        if (pattern.Contains(ReversedSEHValue))
                                        {
                                            SEH.StringOffset = pattern.IndexOf(ReversedSEHValue);
                                        }
                                        else if(pattern.Contains(SEHValue))
                                        {
                                            SEH.StringOffset = pattern.IndexOf(SEHValue);
                                        }
                                        else if(pattern.Contains(nReversedSEHValue))
                                        {
                                            SEH.StringOffset = pattern.IndexOf(nReversedSEHValue);
                                        }
                                        else
                                        {
                                            SEH.StringOffset = pattern.IndexOf(nSEHValue);
                                        }
                                        SEH.ThreadID = ThreadsInfo[i].ThreadID;
                                        SEH.RegisterValue = (IntPtr)BitConverter.ToInt32(sehChain.ReturnValue[j].Item1, 0);
                                        registers.Add(SEH);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            else if(ProcessMachineType == MachineType.x64)
            {
                for (int i = 0; i < ThreadsInfo.Count; i++)
                {
                    RegisterInfo regRax = new RegisterInfo();
                    regRax.Register = "Rax";
                    regRax.RegisterValue = (IntPtr)ThreadsInfo[i].Context64.Rax;
                    regRax.ThreadID = ThreadsInfo[i].ThreadID;
                    regRax.StringOffset = -1;
                    regRax.RegisterOffset = -1;
                    registers.Add(regRax);
                    RegisterInfo regRbx = new RegisterInfo();
                    regRbx.Register = "RBX";
                    regRbx.RegisterValue = (IntPtr)ThreadsInfo[i].Context64.Rbx;
                    regRbx.ThreadID = ThreadsInfo[i].ThreadID;
                    regRbx.StringOffset = -1;
                    regRbx.RegisterOffset = -1;
                    registers.Add(regRbx);
                    RegisterInfo regRcx = new RegisterInfo();
                    regRcx.Register = "RCX";
                    regRcx.RegisterValue = (IntPtr)ThreadsInfo[i].Context64.Rcx;
                    regRcx.ThreadID = ThreadsInfo[i].ThreadID;
                    regRcx.StringOffset = -1;
                    regRcx.RegisterOffset = -1;
                    registers.Add(regRcx);
                    RegisterInfo regRdx = new RegisterInfo();
                    regRdx.Register = "RDX";
                    regRdx.RegisterValue = (IntPtr)ThreadsInfo[i].Context64.Rdx;
                    regRdx.ThreadID = ThreadsInfo[i].ThreadID;
                    regRdx.StringOffset = -1;
                    regRdx.RegisterOffset = -1;
                    registers.Add(regRdx);
                    RegisterInfo regRsp = new RegisterInfo();
                    regRsp.Register = "RSP";
                    regRsp.RegisterValue = (IntPtr)ThreadsInfo[i].Context64.Rsp;
                    regRsp.ThreadID = ThreadsInfo[i].ThreadID;
                    regRsp.StringOffset = -1;
                    regRsp.RegisterOffset = -1;
                    registers.Add(regRsp);
                    RegisterInfo regRbp = new RegisterInfo();
                    regRbp.Register = "RBP";
                    regRbp.RegisterValue = (IntPtr)ThreadsInfo[i].Context64.Rbp;
                    regRbp.ThreadID = ThreadsInfo[i].ThreadID;
                    regRbp.StringOffset = -1;
                    regRbp.RegisterOffset = -1;
                    registers.Add(regRbp);
                    RegisterInfo regRsi = new RegisterInfo();
                    regRsi.Register = "RSI";
                    regRsi.RegisterValue = (IntPtr)ThreadsInfo[i].Context64.Rsi;
                    regRsi.ThreadID = ThreadsInfo[i].ThreadID;
                    regRsi.StringOffset = -1;
                    regRsi.RegisterOffset = -1;
                    registers.Add(regRsi);
                    RegisterInfo regRdi = new RegisterInfo();
                    regRdi.Register = "RDI";
                    regRdi.RegisterValue = (IntPtr)ThreadsInfo[i].Context64.Rdi;
                    regRdi.ThreadID = ThreadsInfo[i].ThreadID;
                    regRdi.StringOffset = -1;
                    regRdi.RegisterOffset = -1;
                    registers.Add(regRdi);
                    RegisterInfo regR8 = new RegisterInfo();
                    regR8.Register = "R8";
                    regR8.RegisterValue = (IntPtr)ThreadsInfo[i].Context64.R8;
                    regR8.ThreadID = ThreadsInfo[i].ThreadID;
                    regR8.StringOffset = -1;
                    regR8.RegisterOffset = -1;
                    registers.Add(regR8);
                    RegisterInfo regR9 = new RegisterInfo();
                    regR9.Register = "R9";
                    regR9.RegisterValue = (IntPtr)ThreadsInfo[i].Context64.R9;
                    regR9.ThreadID = ThreadsInfo[i].ThreadID;
                    regR9.StringOffset = -1;
                    regR9.RegisterOffset = -1;
                    registers.Add(regR9);
                    RegisterInfo regR10 = new RegisterInfo();
                    regR10.Register = "R10";
                    regR10.RegisterValue = (IntPtr)ThreadsInfo[i].Context64.R10;
                    regR10.ThreadID = ThreadsInfo[i].ThreadID;
                    regR10.StringOffset = -1;
                    regR10.RegisterOffset = -1;
                    registers.Add(regR10);
                    RegisterInfo regR11 = new RegisterInfo();
                    regR11.Register = "R11";
                    regR11.RegisterValue = (IntPtr)ThreadsInfo[i].Context64.R11;
                    regR11.ThreadID = ThreadsInfo[i].ThreadID;
                    regR11.StringOffset = -1;
                    regR11.RegisterOffset = -1;
                    registers.Add(regR11);
                    RegisterInfo regR12 = new RegisterInfo();
                    regR12.Register = "R12";
                    regR12.RegisterValue = (IntPtr)ThreadsInfo[i].Context64.R12;
                    regR12.ThreadID = ThreadsInfo[i].ThreadID;
                    regR12.StringOffset = -1;
                    regR12.RegisterOffset = -1;
                    registers.Add(regR12);
                    RegisterInfo regR13 = new RegisterInfo();
                    regR13.Register = "R13";
                    regR13.RegisterValue = (IntPtr)ThreadsInfo[i].Context64.R13;
                    regR13.ThreadID = ThreadsInfo[i].ThreadID;
                    regR13.StringOffset = -1;
                    regR13.RegisterOffset = -1;
                    registers.Add(regR13);
                    RegisterInfo regR14 = new RegisterInfo();
                    regR14.Register = "R14";
                    regR14.RegisterValue = (IntPtr)ThreadsInfo[i].Context64.R14;
                    regR14.ThreadID = ThreadsInfo[i].ThreadID;
                    regR14.StringOffset = -1;
                    regR14.RegisterOffset = -1;
                    registers.Add(regR14);
                    RegisterInfo regR15 = new RegisterInfo();
                    regR15.Register = "R15";
                    regR15.RegisterValue = (IntPtr)ThreadsInfo[i].Context64.R15;
                    regR15.ThreadID = ThreadsInfo[i].ThreadID;
                    regR15.StringOffset = -1;
                    regR15.RegisterOffset = -1;
                    registers.Add(regR15);
                    RegisterInfo regRIP = new RegisterInfo();
                    regRIP.Register = "RIP";
                    regRIP.RegisterValue = (IntPtr)ThreadsInfo[i].Context64.Rip;
                    regRIP.ThreadID = ThreadsInfo[i].ThreadID;
                    registers.Add(regRIP);
                }

                for (int i = 0; i < registers.Count; i++)
                {
                    for (int j = 0; j < MemoryRegions64.Count; j++)
                    {
                        ulong regionStart = MemoryRegions64[j].BaseAddress;
                        ulong regionEnd = MemoryRegions64[j].BaseAddress + MemoryRegions64[j].RegionSize;

                        if (registers[i].Register != "RIP" && registers[i].Register != "RBP" &&
                            (ulong)registers[i].RegisterValue > regionStart &&
                            (ulong)registers[i].RegisterValue < regionEnd)
                        {
                            ulong bufferSize = (MemoryRegions64[j].BaseAddress + MemoryRegions64[j].RegionSize) - (ulong)registers[i].RegisterValue;
                            byte[] buffer = new byte[bufferSize];
                            int bytesRead = 0;
                            Native.ReadProcessMemory(ProcessHandle, registers[i].RegisterValue, buffer, (int)bufferSize, out bytesRead);

                            string memoryString = "";
                            switch (searchType)
                            {
                                case 0:
                                    memoryString = Encoding.Default.GetString(buffer);
                                    break;
                                case 1:
                                    memoryString = Encoding.Unicode.GetString(buffer);
                                    break;
                                case 2:
                                    memoryString = Encoding.ASCII.GetString(buffer);
                                    break;
                                case 3:
                                    memoryString = Encoding.UTF8.GetString(buffer);
                                    break;
                                case 4:
                                    memoryString = Encoding.UTF7.GetString(buffer);
                                    break;
                                case 5:
                                    memoryString = Encoding.UTF32.GetString(buffer);
                                    break;
                                default:
                                    memoryString = Encoding.Default.GetString(buffer);
                                    break;
                            }
                            int length = 0;
                            for (int k = 0; k < nrps.Count; k++)
                            {
                                if (memoryString.Contains(nrps[k]) && pattern.Contains(nrps[k]))
                                {
                                    if (registers[i].StringOffset == -1)
                                    {
                                        registers[i].StringOffset = pattern.IndexOf(nrps[k]);
                                    }

                                    int index = memoryString.IndexOf(nrps[k]);
                                    if (registers[i].RegisterOffset == -1)
                                    {
                                        registers[i].RegisterOffset = index;
                                    }

                                    length += 3;
                                }
                            }
                            registers[i].BufferSize = length;
                        }
                        else if(registers[i].Register != "RIP")
                        {
                            string RIPValue = "";
                            switch (searchType)
                            {
                                case 0:
                                    RIPValue = Encoding.Default.GetString(BitConverter.GetBytes((ulong)registers[i].RegisterValue));
                                    break;
                                case 1:
                                    RIPValue = Encoding.Unicode.GetString(BitConverter.GetBytes((ulong)registers[i].RegisterValue));
                                    break;
                                case 2:
                                    RIPValue = Encoding.ASCII.GetString(BitConverter.GetBytes((ulong)registers[i].RegisterValue));
                                    break;
                                case 3:
                                    RIPValue = Encoding.UTF8.GetString(BitConverter.GetBytes((ulong)registers[i].RegisterValue));
                                    break;
                                case 4:
                                    RIPValue = Encoding.UTF7.GetString(BitConverter.GetBytes((ulong)registers[i].RegisterValue));
                                    break;
                                case 5:
                                    RIPValue = Encoding.UTF32.GetString(BitConverter.GetBytes((ulong)registers[i].RegisterValue));
                                    break;
                                default:
                                    RIPValue = Encoding.Default.GetString(BitConverter.GetBytes((ulong)registers[i].RegisterValue));
                                    break;
                            }
                            char[] ripArray = RIPValue.ToCharArray();
                            Array.Reverse(ripArray);
                            RIPValue = new string(ripArray);
                            if (pattern.Contains(RIPValue))
                            {
                                registers[i].StringOffset = pattern.IndexOf(RIPValue);
                            }
                        }
                    }
                    if (Utilities.PatternTools.PatternOffset(Utilities.Convert.HexToAscii(registers[i].RegisterValue.ToString("X")), ProcessCore).ReturnValue != "Value not found in pattern.")
                    {
                        if (Utilities.Convert.HexToAscii(registers[i].RegisterValue.ToString("X")).Length > 0)
                        {
                            string regHex = Utilities.Convert.HexToAscii(registers[i].RegisterValue.ToString("X"));
                            string regPos = Utilities.PatternTools.PatternOffset(Utilities.Convert.HexToAscii(registers[i].RegisterValue.ToString("X")), ProcessCore).ReturnValue;
                            if (!String.IsNullOrEmpty(regPos) && regPos.Any(char.IsDigit))
                            {
                                registers[i].StringOffset = Int32.Parse(Regex.Match(regPos, @"\d+").Value);
                                registers[i].overwritten = true;
                            }
                        }
                    }
                }
                for(int i = 0; i < ThreadsInfo.Count; i++)
                {
                    var pTeb = ThreadsInfo[i].PopulateTEB();
                    if(pTeb.Error == null)
                    {
                        var sehChain = ThreadsInfo[i].BuildSehChain();
                        if(sehChain.Error == null)
                        {
                            if(sehChain.ReturnValue.Count > 0)
                            {
                                for(int j = 0; j < sehChain.ReturnValue.Count; j++)
                                {
                                    string SEHValue = "";
                                    string nSEHValue = "";
                                    switch (searchType)
                                    {
                                        case 0:
                                            SEHValue = Encoding.Default.GetString(sehChain.ReturnValue[j].Item1);
                                            nSEHValue = Encoding.Default.GetString(sehChain.ReturnValue[j].Item2);
                                            break;
                                        case 1:
                                            byte[] sehHolder1 = sehChain.ReturnValue[j].Item1;
                                            byte[] sehHolder2 = sehChain.ReturnValue[j].Item2;
                                            if (sehChain.ReturnValue[j].Item1[0] == 0x00)
                                            {
                                                byte[] newSEH = new byte[sehChain.ReturnValue[j].Item1.Length];
                                                Array.Copy(sehChain.ReturnValue[j].Item1, 1, newSEH, 0, sehChain.ReturnValue[j].Item1.Length - 1);
                                                newSEH[newSEH.Length - 1] = 0x00;
                                                sehHolder1 = newSEH;
                                            }
                                            if (sehChain.ReturnValue[j].Item2[0] == 0x00)
                                            {
                                                byte[] newSEH = new byte[sehChain.ReturnValue[j].Item2.Length];
                                                Array.Copy(sehChain.ReturnValue[j].Item2, 1, newSEH, 0, sehChain.ReturnValue[j].Item2.Length - 1);
                                                newSEH[newSEH.Length - 1] = 0x00;
                                                sehHolder2 = newSEH;
                                            }
                                            SEHValue = Encoding.Unicode.GetString(sehHolder1);
                                            nSEHValue = Encoding.Unicode.GetString(sehHolder2);
                                            break;
                                        case 2:
                                            SEHValue = Encoding.ASCII.GetString(sehChain.ReturnValue[j].Item1);
                                            nSEHValue = Encoding.ASCII.GetString(sehChain.ReturnValue[j].Item2);
                                            break;
                                        case 3:
                                            SEHValue = Encoding.UTF8.GetString(sehChain.ReturnValue[j].Item1);
                                            nSEHValue = Encoding.UTF8.GetString(sehChain.ReturnValue[j].Item2);
                                            break;
                                        case 4:
                                            SEHValue = Encoding.UTF7.GetString(sehChain.ReturnValue[j].Item1);
                                            nSEHValue = Encoding.UTF7.GetString(sehChain.ReturnValue[j].Item2);
                                            break;
                                        case 5:
                                            SEHValue = Encoding.UTF32.GetString(sehChain.ReturnValue[j].Item1);
                                            nSEHValue = Encoding.UTF32.GetString(sehChain.ReturnValue[j].Item2);
                                            break;
                                        default:
                                            SEHValue = Encoding.Default.GetString(sehChain.ReturnValue[j].Item1);
                                            nSEHValue = Encoding.Default.GetString(sehChain.ReturnValue[j].Item2);
                                            break;
                                    }
                                    char[] sehArray = SEHValue.ToCharArray();
                                    Array.Reverse(sehArray);
                                    string ReversedSEHValue = new string(sehArray);
                                    RegisterInfo SEH = new RegisterInfo();
                                    char[] nsehArray = nSEHValue.ToCharArray();
                                    Array.Reverse(nsehArray);
                                    string nReversedSEHValue = new string(nsehArray);
                                    string combinedSeh = SEHValue + nSEHValue;
                                    string reversedCombinedSeh = ReversedSEHValue + nReversedSEHValue;
                                    if (pattern.Contains(combinedSeh) || pattern.Contains(reversedCombinedSeh))
                                    {
                                        SEH.Register = "SEH" + i.ToString();
                                        if (pattern.Contains(reversedCombinedSeh))
                                        {
                                            SEH.StringOffset = pattern.IndexOf(reversedCombinedSeh);
                                        }
                                        else
                                        {
                                            SEH.StringOffset = pattern.IndexOf(combinedSeh);
                                        }
                                        SEH.ThreadID = ThreadsInfo[i].ThreadID;
                                        SEH.RegisterValue = (IntPtr)BitConverter.ToInt64(sehChain.ReturnValue[j].Item1, 0);
                                        registers.Add(SEH);
                                    }
                                    else if (pattern.Contains(SEHValue) || pattern.Contains(ReversedSEHValue) || pattern.Contains(nSEHValue) || pattern.Contains(nReversedSEHValue))
                                    {
                                        SEH.Register = "SEH" + i.ToString();
                                        if (pattern.Contains(ReversedSEHValue))
                                        {
                                            SEH.StringOffset = pattern.IndexOf(ReversedSEHValue);
                                        }
                                        else if (pattern.Contains(SEHValue))
                                        {
                                            SEH.StringOffset = pattern.IndexOf(SEHValue);
                                        }
                                        else if (pattern.Contains(nReversedSEHValue))
                                        {
                                            SEH.StringOffset = pattern.IndexOf(nReversedSEHValue);
                                        }
                                        else
                                        {
                                            SEH.StringOffset = pattern.IndexOf(nSEHValue);
                                        }
                                        SEH.ThreadID = ThreadsInfo[i].ThreadID;
                                        SEH.RegisterValue = (IntPtr)BitConverter.ToInt64(sehChain.ReturnValue[j].Item1, 0);
                                        registers.Add(SEH);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                offsets.Error = new ERCException("Critical Error: Process returned incompatible machine type.");
                offsets.LogEvent();
            }
            offsets.ReturnValue = registers;
            return offsets;
        }
        #endregion
    }
}
