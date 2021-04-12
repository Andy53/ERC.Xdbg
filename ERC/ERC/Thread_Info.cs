using ERC.Structures;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace ERC
{
    /// <summary>
    /// Stores information about the current thread.
    /// </summary>
    public class ThreadInfo
    {
        #region Variables
        /// <summary>
        /// A handle for the current thread.
        /// </summary>
        public IntPtr ThreadHandle { get; private set; }
        /// <summary>
        /// The ID number of the current thread.
        /// </summary>
        public int ThreadID { get; private set; }
        /// <summary>
        /// x86 CPU Register values.
        /// </summary>
        public CONTEXT32 Context32;
        /// <summary>
        /// x64 CPU Register values.
        /// </summary>
        public CONTEXT64 Context64;

        internal bool ThreadFailed { get; private set; }

        internal MachineType X64 { get; set; }
        private ProcessThread ThreadCurrent { get; set; }
        private ProcessInfo ThreadProcess { get; set; }
        private ErcCore ThreadCore { get; set; }
        private ThreadBasicInformation ThreadBasicInfo = new ThreadBasicInformation();
        private TEB Teb;
        private List<Tuple<byte[], byte[]>> SehChain;
        #endregion

        #region Constructor
        internal ThreadInfo(ProcessThread thread, ErcCore core, ProcessInfo process)
        {
            ThreadID = thread.Id;
            ThreadCurrent = thread;
            ThreadCore = core;
            ThreadProcess = process;

            if (process.ProcessMachineType == MachineType.x64)
            {
                X64 = MachineType.x64;
            }
            else if(process.ProcessMachineType == MachineType.I386)
            {
                X64 = MachineType.I386;
            }

            try
            {
                ThreadHandle = ErcCore.OpenThread(ThreadAccess.All_ACCESS, false, (uint)thread.Id);
                if(ThreadHandle == null)
                {
                    ThreadFailed = true;
                    
                    throw new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                }
            }
            catch(ERCException e)
            {
                ErcResult<Exception> exceptionThrower = new ErcResult<Exception>(ThreadCore)
                {
                    Error = e
                };
                exceptionThrower.LogEvent();
            }

            PopulateTEB();
        }
        #endregion

        #region Get Thread Context
        /// <summary>
        /// Gets the register values of a thread and populates the CONTEXT structs. Should only be used on a suspended thread, results on an active thread are unreliable.
        /// </summary>
        /// <returns>Returns an ErcResult, the return value can be ignored, the object should only be checked for error values</returns>
        public ErcResult<string> Get_Context()
        {
            ErcResult<string> result = new ErcResult<string>(ThreadCore);
            
            if(X64 == MachineType.x64)
            {
                Context64 = new CONTEXT64();
                Context64.ContextFlags = CONTEXT_FLAGS.CONTEXT_ALL;
                try
                {
                    bool returnVar = ErcCore.GetThreadContext64(ThreadHandle, ref Context64);
                    if (returnVar == false)
                    {
                        throw new ERCException("Win32 Exception encountered when attempting to get thread context: " + 
                            new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    }
                }
                catch (ERCException e)
                {
                    result.Error = e;
                    result.LogEvent();
                    return result;
                }
                catch(Exception e)
                {
                    result.Error = e;
                    result.LogEvent(e);
                }
            }
            else if(Environment.Is64BitOperatingSystem == true && X64 != MachineType.x64)
            {
                Context32 = new CONTEXT32();
                Context32.ContextFlags = CONTEXT_FLAGS.CONTEXT_ALL;
                try
                {
                    bool returnVar = ErcCore.Wow64GetThreadContext(ThreadHandle, ref Context32);
                    if (returnVar == false)
                    {
                        throw new ERCException("Win32 Exception encountered when attempting to get thread context: " +
                            new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    }
                }
                catch (ERCException e)
                {
                    result.Error = e;
                    result.LogEvent();
                    return result;
                }
                catch (Exception e)
                {
                    result.Error = e;
                    result.LogEvent(e);
                }
            }
            else
            {
                Context32 = new CONTEXT32();
                Context32.ContextFlags = CONTEXT_FLAGS.CONTEXT_ALL;
                try
                {
                    bool returnVar = ErcCore.GetThreadContext32(ThreadHandle, ref Context32);
                    if (returnVar == false)
                    {
                        throw new ERCException("Win32 Exception encountered when attempting to get thread context: " +
                            new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    }
                }
                catch (ERCException e)
                {
                    result.Error = e;
                    result.LogEvent();
                    return result;
                }
                catch (Exception e)
                {
                    result.Error = e;
                    result.LogEvent(e);
                }
            }
            return result;
        }
        #endregion

        #region Thread Environment Block

        #region Populate TEB
        internal ErcResult<string> PopulateTEB()
        {
            ErcResult<string> returnString = new ErcResult<string>(ThreadCore);

            var retInt = ErcCore.ZwQueryInformationThread(ThreadHandle, 0,
                ref ThreadBasicInfo, Marshal.SizeOf(typeof(ThreadBasicInformation)), IntPtr.Zero);

            if (retInt != 0)
            {
                Console.WriteLine("NTSTATUS Error was thrown: " + retInt);
                returnString.Error = new ERCException("NTSTATUS Error was thrown: " + retInt);
                return returnString;
            }

            byte[] tebBytes;
            int ret = 0;
            if(X64 == MachineType.x64)
            {
                tebBytes = new byte[0x16A0];
                ErcCore.ReadProcessMemory(ThreadProcess.ProcessHandle, ThreadBasicInfo.TebBaseAdress, tebBytes, 0x16A0, out ret);
            }
            else
            {
                tebBytes = new byte[3888];
                ErcCore.ReadProcessMemory(ThreadProcess.ProcessHandle, ThreadBasicInfo.TebBaseAdress, tebBytes, 3888, out ret);
            }
            

            if (ret == 0)
            {
                ERCException e = new ERCException("System error: An error occured when executing ReadProcessMemory\n Process Handle = 0x" 
                    + ThreadProcess.ProcessHandle.ToString("X") + " TEB Base Address = 0x" + ThreadBasicInfo.TebBaseAdress.ToString("X") + 
                    " Return value = " + ret);
                returnString.Error = e;
                return returnString;
            }

            if (X64 == MachineType.x64)
            {
                PopulateTEBStruct64(tebBytes);
            }
            else
            {
                PopulateTEBStruct32(tebBytes);
            }

            var bSehChain = BuildSehChain();
            if(bSehChain.Error != null)
            {
                returnString.Error = bSehChain.Error;
                return returnString;
            }

            return returnString;
        }
        #endregion

        #region PopulateTebStruct
        private void PopulateTEBStruct32(byte[] tebBytes)
        {
            Teb = new TEB();
            Teb.CurrentSehFrame = (IntPtr)BitConverter.ToInt32(tebBytes, 0x0);
            Teb.TopOfStack = (IntPtr)BitConverter.ToInt32(tebBytes, 0x4);
            Teb.BottomOfStack = (IntPtr)BitConverter.ToInt32(tebBytes, 0x8);
            Teb.SubSystemTeb = (IntPtr)BitConverter.ToInt32(tebBytes, 0xC);
            Teb.FiberData = (IntPtr)BitConverter.ToInt32(tebBytes, 0x10);
            Teb.ArbitraryDataSlot = (IntPtr)BitConverter.ToInt32(tebBytes, 0x14);
            Teb.Teb = (IntPtr)BitConverter.ToInt32(tebBytes, 0x18);
            Teb.EnvironmentPointer = (IntPtr)BitConverter.ToInt32(tebBytes, 0x1C);
            Teb.Identifiers.ProcessId = (IntPtr)BitConverter.ToInt32(tebBytes, 0x20);
            Teb.Identifiers.ThreadId = (IntPtr)BitConverter.ToInt32(tebBytes, 0x24);
            Teb.RpcHandle = (IntPtr)BitConverter.ToInt32(tebBytes, 0x28);
            Teb.Tls = (IntPtr)BitConverter.ToInt32(tebBytes, 0x2C);
            Teb.Peb = (IntPtr)BitConverter.ToInt32(tebBytes, 0x30);
            Teb.LastErrorNumber = BitConverter.ToInt32(tebBytes, 0x34);
            Teb.CriticalSectionsCount = BitConverter.ToInt32(tebBytes, 0x38);
            Teb.CsrClientThread = (IntPtr)BitConverter.ToInt32(tebBytes, 0x3C);
            Teb.Win32ThreadInfo = (IntPtr)BitConverter.ToInt32(tebBytes, 0x40);
            Teb.Win32ClientInfo = new byte[4];
            Array.Copy(tebBytes, 0x44, Teb.Win32ClientInfo, 0, 4);
            Teb.WoW64Reserved = (IntPtr)BitConverter.ToInt32(tebBytes, 0xC0);
            Teb.CurrentLocale = (IntPtr)BitConverter.ToInt32(tebBytes, 0xC4);
            Teb.FpSoftwareStatusRegister = (IntPtr)BitConverter.ToInt32(tebBytes, 0xC8);
            Teb.SystemReserved1 = new byte[216];
            Array.Copy(tebBytes, 0xCC, Teb.SystemReserved1, 0, 216);
            Teb.ExceptionCode = (IntPtr)BitConverter.ToInt32(tebBytes, 0x1A4);
            Teb.ActivationContextStack = new byte[4];
            Array.Copy(tebBytes, 0x1A8, Teb.ActivationContextStack, 0, 4);
            Teb.SpareBytes = new byte[24];
            Array.Copy(tebBytes, 0x1BC, Teb.SpareBytes, 0, 24);
            Teb.SystemReserved2 = new byte[40];
            Array.Copy(tebBytes, 0x1D4, Teb.SystemReserved2, 0, 40);
            Teb.GdiTebBatch = new byte[1248];
            Array.Copy(tebBytes, 0x1FC, Teb.GdiTebBatch, 0, 1248);
            Teb.GdiRegion = (IntPtr)BitConverter.ToInt32(tebBytes, 0x6DC);
            Teb.GdiPen = (IntPtr)BitConverter.ToInt32(tebBytes, 0x6E0);
            Teb.GdiBrush = (IntPtr)BitConverter.ToInt32(tebBytes, 0x6E4);
            Teb.RealProcessId = BitConverter.ToInt32(tebBytes, 0x6E8);
            Teb.RealThreadId = BitConverter.ToInt32(tebBytes, 0x6EC);
            Teb.GdiCachedProcessHandle = (IntPtr)BitConverter.ToInt32(tebBytes, 0x6F0);
            Teb.GdiClientProcessId = (IntPtr)BitConverter.ToInt32(tebBytes, 0x6F4);
            Teb.GdiClientThreadId = (IntPtr)BitConverter.ToInt32(tebBytes, 0x6F8);
            Teb.GdiThreadLocalInfo = (IntPtr)BitConverter.ToInt32(tebBytes, 0x6FC);
            Teb.UserReserved1 = new byte[20];
            Array.Copy(tebBytes, 0x700, Teb.UserReserved1, 0, 20);
            Teb.GlReserved1 = new byte[1248];
            Array.Copy(tebBytes, 0x714, Teb.GlReserved1, 0, 1248);
            Teb.LastStatusValue = BitConverter.ToInt32(tebBytes, 0xBF4);
            Teb.StaticUnicodeString = new byte[214];
            Array.Copy(tebBytes, 0xBF8, Teb.StaticUnicodeString, 0, 214);
            Teb.DeallocationStack = (IntPtr)BitConverter.ToInt32(tebBytes, 0xE0C);
            Teb.TlsSlots = new byte[100];
            Array.Copy(tebBytes, 0xE10, Teb.TlsSlots, 0, 100);
            Teb.TlsLinks = BitConverter.ToInt32(tebBytes, 0xF10);
            Teb.Vdm = (IntPtr)BitConverter.ToInt32(tebBytes, 0xF18);
            Teb.RpcReserved = (IntPtr)BitConverter.ToInt32(tebBytes, 0xF1C);
            Teb.ThreadErrorMode = (IntPtr)BitConverter.ToInt32(tebBytes, 0xF28);
        }

        private void PopulateTEBStruct64(byte[] tebBytes)
        {
            Teb = new TEB();
            Teb.CurrentSehFrame = (IntPtr)BitConverter.ToInt64(tebBytes, 0x0);
            Teb.TopOfStack = (IntPtr)BitConverter.ToInt64(tebBytes, 0x8);
            Teb.BottomOfStack = (IntPtr)BitConverter.ToInt64(tebBytes, 0x10);
            Teb.SubSystemTeb = (IntPtr)BitConverter.ToInt64(tebBytes, 0x18);
            Teb.FiberData = (IntPtr)BitConverter.ToInt64(tebBytes, 0x20);
            Teb.ArbitraryDataSlot = (IntPtr)BitConverter.ToInt64(tebBytes, 0x28);
            Teb.Teb = (IntPtr)BitConverter.ToInt64(tebBytes, 0x30);
            Teb.EnvironmentPointer = (IntPtr)BitConverter.ToInt64(tebBytes, 0x38);
            Teb.Identifiers.ProcessId = (IntPtr)BitConverter.ToInt64(tebBytes, 0x40);
            Teb.Identifiers.ThreadId = (IntPtr)BitConverter.ToInt64(tebBytes, 0x48);
            Teb.RpcHandle = (IntPtr)BitConverter.ToInt64(tebBytes, 0x50);
            Teb.Tls = (IntPtr)BitConverter.ToInt64(tebBytes, 0x58);
            Teb.Peb = (IntPtr)BitConverter.ToInt64(tebBytes, 0x60);
            Teb.LastErrorNumber = BitConverter.ToInt32(tebBytes, 0x68);
            Teb.CriticalSectionsCount = BitConverter.ToInt32(tebBytes, 0x6C);
            Teb.CsrClientThread = (IntPtr)BitConverter.ToInt64(tebBytes, 0x70);
            Teb.Win32ThreadInfo = (IntPtr)BitConverter.ToInt64(tebBytes, 0x78);
            Teb.Win32ClientInfo = new byte[4];
            Array.Copy(tebBytes, 0x80, Teb.Win32ClientInfo, 0, 4);
            Teb.CurrentLocale = (IntPtr)BitConverter.ToInt64(tebBytes, 0x84);
            Teb.FpSoftwareStatusRegister = (IntPtr)BitConverter.ToInt64(tebBytes, 0x8C);
            Teb.SystemReserved1 = new byte[216];
            Array.Copy(tebBytes, 0x94, Teb.SystemReserved1, 0, 216);
            Teb.ExceptionCode = (IntPtr)BitConverter.ToInt64(tebBytes, 0x16C);
            Teb.ActivationContextStack = new byte[4];
            Array.Copy(tebBytes, 0x174, Teb.ActivationContextStack, 0, 4);
            Teb.SpareBytes = new byte[24];
            Array.Copy(tebBytes, 0x178, Teb.SpareBytes, 0, 24);
            Teb.SystemReserved2 = new byte[40];
            Array.Copy(tebBytes, 0x190, Teb.SystemReserved2, 0, 40);
            Teb.GdiTebBatch = new byte[1248];
            Array.Copy(tebBytes, 0x1b8, Teb.GdiTebBatch, 0, 1248);
            Teb.GdiRegion = (IntPtr)BitConverter.ToInt64(tebBytes, 0x698);
            Teb.GdiPen = (IntPtr)BitConverter.ToInt64(tebBytes, 0x6A0);
            Teb.GdiBrush = (IntPtr)BitConverter.ToInt64(tebBytes, 0x6A8);
            Teb.RealProcessId = BitConverter.ToInt32(tebBytes, 0x6B0);
            Teb.RealThreadId = BitConverter.ToInt32(tebBytes, 0x6B4);
            Teb.GdiCachedProcessHandle = (IntPtr)BitConverter.ToInt64(tebBytes, 0x6B8);
            Teb.GdiClientProcessId = (IntPtr)BitConverter.ToInt64(tebBytes, 0x6C0);
            Teb.GdiClientThreadId = (IntPtr)BitConverter.ToInt64(tebBytes, 0x6C8);
            Teb.GdiThreadLocalInfo = (IntPtr)BitConverter.ToInt64(tebBytes, 0x6D0);
            Teb.UserReserved1 = new byte[20];
            Array.Copy(tebBytes, 0x6D8, Teb.UserReserved1, 0, 20);
            Teb.GlReserved1 = new byte[1248];
            Array.Copy(tebBytes, 0x6EC, Teb.GlReserved1, 0, 1248);
            Teb.LastStatusValue = BitConverter.ToInt32(tebBytes, 0x1250);
            Teb.StaticUnicodeString = new byte[214];
            Array.Copy(tebBytes, 0x1258, Teb.StaticUnicodeString, 0, 214);
            Teb.DeallocationStack = (IntPtr)BitConverter.ToInt64(tebBytes, 0x1478);
            Teb.TlsSlots = new byte[520];
            Array.Copy(tebBytes, 0x1480, Teb.TlsSlots, 0, 520);
            Teb.TlsLinks = BitConverter.ToInt64(tebBytes, 0x1680);
            Teb.Vdm = (IntPtr)BitConverter.ToInt64(tebBytes, 0x1688);
            Teb.RpcReserved = (IntPtr)BitConverter.ToInt64(tebBytes, 0x1690);
            Teb.ThreadErrorMode = (IntPtr)BitConverter.ToInt64(tebBytes, 0x1698);
        }
        #endregion

        #region BuildSehChain
        internal ErcResult<List<Tuple<byte[], byte[]>>> BuildSehChain()
        {
            ErcResult<List<Tuple<byte[], byte[]>>> sehList = new ErcResult<List<Tuple<byte[], byte[]>>>(ThreadCore);
            sehList.ReturnValue = new List<Tuple<byte[], byte[]>>();

            if (Teb.Equals(default(TEB)))
            {
                sehList.Error = new Exception("Error: TEB structure for this thread has not yet been populated. Call PopulateTEB first");
                return sehList;
            }

            if(Teb.CurrentSehFrame == IntPtr.Zero)
            {
                sehList.Error = new Exception("Error: No SEH chain has been generated yet. An SEH chain will not be generated until a crash occurs.");
                return sehList;
            }

            byte[] sehEntry;
            byte[] sehFinal;

            int arraySize = 0;
            if(X64 == MachineType.x64)
            {
                arraySize = 8;
                sehEntry = new byte[arraySize];
                sehFinal = new byte[arraySize];
                sehEntry = BitConverter.GetBytes((long)Teb.CurrentSehFrame);
            }
            else
            {
                arraySize = 4;
                sehEntry = new byte[arraySize];
                sehFinal = new byte[arraySize];
                sehEntry = BitConverter.GetBytes((int)Teb.CurrentSehFrame);
            }
            
            for (int i = 0; i < sehFinal.Length; i++)
            {
                sehFinal[i] = 0xFF;
            }

            byte[] prevSEH = new byte[] { 0xFF };
            string pattern_standard = File.ReadAllText(ThreadCore.PatternStandardPath);
            string pattern_extended = File.ReadAllText(ThreadCore.PatternExtendedPath);
            while (!sehEntry.SequenceEqual(sehFinal))
            {
                byte[] reversedSehEntry = new byte[arraySize];
                byte[] nSeh = new byte[arraySize];
                byte[] sehHolder = new byte[arraySize * 2];
                
                int ret = 0;

                if(X64 == MachineType.x64)
                {
                    ret = ErcCore.ReadProcessMemory(ThreadProcess.ProcessHandle, (IntPtr)BitConverter.ToInt64(sehEntry, 0), sehHolder, arraySize * 2, out int retInt);
                    Array.Copy(sehHolder, 0, sehEntry, 0, arraySize);
                    Array.Copy(sehHolder, arraySize, nSeh, 0, arraySize);
                }
                else
                {
                    ret = ErcCore.ReadProcessMemory(ThreadProcess.ProcessHandle, (IntPtr)BitConverter.ToInt32(sehEntry, 0), sehHolder, arraySize * 2, out int retInt);
                    Array.Copy(sehHolder, 0, sehEntry, 0, arraySize);
                    Array.Copy(sehHolder, arraySize, nSeh, 0, arraySize);
                }

                if (ret != 0 && ret != 1)
                {
                    ERCException e = new ERCException("System error: An error occured when executing ReadProcessMemory\n Process Handle = 0x"
                    + ThreadProcess.ProcessHandle.ToString("X") + " TEB Current Seh = 0x" + Teb.CurrentSehFrame.ToString("X") +
                    " Return value = " + ret + Environment.NewLine + "Win32Exception: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    sehList.Error = e;
                    sehList.LogEvent();
                    return sehList;
                }

                Array.Reverse(nSeh);

                for(int i = 0; i < sehEntry.Length; i++)
                {
                    reversedSehEntry[i] = sehEntry[i];
                }

                Array.Reverse(reversedSehEntry, 0, reversedSehEntry.Length);
                if (prevSEH.SequenceEqual(reversedSehEntry))
                {
                    sehEntry = new byte[sehFinal.Length];
                    Array.Copy(sehFinal, 0, sehEntry, 0, sehFinal.Length);
                }
                else if (!sehEntry.SequenceEqual(sehFinal) && !sehList.ReturnValue.Any(e => e.Item1.SequenceEqual(reversedSehEntry)))
                {
                    Tuple<byte[], byte[]> tuple = new Tuple<byte[], byte[]>(reversedSehEntry, nSeh);
                    sehList.ReturnValue.Add(tuple);
                }

                if (pattern_standard.Contains(Encoding.Unicode.GetString(reversedSehEntry)) ||
                    pattern_extended.Contains(Encoding.Unicode.GetString(reversedSehEntry)))
                {
                    sehEntry = new byte[sehFinal.Length];
                    Array.Copy(sehFinal, 0, sehEntry, 0, sehFinal.Length);
                }

                if (pattern_standard.Contains(Encoding.ASCII.GetString(reversedSehEntry)) ||
                    pattern_extended.Contains(Encoding.ASCII.GetString(reversedSehEntry)))
                {
                    sehEntry = new byte[sehFinal.Length];
                    Array.Copy(sehFinal, 0, sehEntry, 0, sehFinal.Length);
                }

                if (pattern_standard.Contains(Encoding.UTF32.GetString(reversedSehEntry)) ||
                    pattern_extended.Contains(Encoding.UTF32.GetString(reversedSehEntry)))
                {
                    sehEntry = new byte[sehFinal.Length];
                    Array.Copy(sehFinal, 0, sehEntry, 0, sehFinal.Length);
                }

                if (pattern_standard.Contains(Encoding.UTF7.GetString(reversedSehEntry)) ||
                    pattern_extended.Contains(Encoding.UTF7.GetString(reversedSehEntry)))
                {
                    sehEntry = new byte[sehFinal.Length];
                    Array.Copy(sehFinal, 0, sehEntry, 0, sehFinal.Length);
                }

                if (pattern_standard.Contains(Encoding.UTF8.GetString(reversedSehEntry)) ||
                    pattern_extended.Contains(Encoding.UTF8.GetString(reversedSehEntry)))
                {
                    sehEntry = new byte[sehFinal.Length];
                    Array.Copy(sehFinal, 0, sehEntry, 0, sehFinal.Length);
                }

                prevSEH = new byte[reversedSehEntry.Length];
                Array.Copy(reversedSehEntry, 0, prevSEH, 0, reversedSehEntry.Length);
            }

            SehChain = new List<Tuple<byte[], byte[]>>(sehList.ReturnValue);
            return sehList;
        }
        #endregion

        #endregion

        #region Accessors
        /// <summary>
        /// Gets the current SEH chain for the process.
        /// </summary>
        /// <returns>Returns a list of IntPtr containing the SEH chain</returns>
        public List<Tuple<IntPtr, IntPtr>> GetSehChain()
        {
            List<Tuple<IntPtr, IntPtr>> SehPtrs = new List<Tuple<IntPtr, IntPtr>>();
            var pteb = PopulateTEB();
            if (pteb.Error != null)
            {
                throw pteb.Error;
            }

            if(SehChain == null)
            {
                throw new Exception("Error: No SEH chain has been generated yet. An SEH chain will not be generated until a crash occurs.");
            }

            if(X64 == MachineType.x64)
            {
                for (int i = 0; i < SehChain.Count; i++)
                {
                    Tuple<IntPtr, IntPtr> tuple = new Tuple<IntPtr, IntPtr>((IntPtr)BitConverter.ToInt64(SehChain[i].Item1, 0), (IntPtr)BitConverter.ToInt64(SehChain[i].Item2, 0));
                    SehPtrs.Add(tuple);
                }
            }
            else
            {
                for (int i = 0; i < SehChain.Count; i++)
                {
                    Tuple<IntPtr, IntPtr> tuple = new Tuple<IntPtr, IntPtr>((IntPtr)BitConverter.ToInt32(SehChain[i].Item1, 0), (IntPtr)BitConverter.ToInt32(SehChain[i].Item2, 0));
                    SehPtrs.Add(tuple);
                }
            }
            return SehPtrs;
        }

        /// <summary>
        /// Gets the Thread environment block of the current thread.
        /// </summary>
        /// <returns>Returns a TEB struct</returns>
        public TEB GetTeb()
        {
            if (Teb.Equals(default(TEB)))
            {
                throw new Exception("Error: TEB structure for this thread has not yet been populated. Call PopulateTEB first");
            }
            return Teb;
        }

        /// <summary>
        /// Gets information specific to the current thread and returns it as a string.
        /// </summary>
        /// <returns>Returns a string</returns>
        public override string ToString()
        {
            string ret = "";
            if(X64 == MachineType.x64)
            {
                ret += "Thread Handle = " + "0x" + ThreadHandle.ToString("x16") + Environment.NewLine;
            }
            else
            {
                ret += "Thread Handle = " + "0x" + ThreadHandle.ToString("x8") + Environment.NewLine;
            }
            ret += "Thread ID = " + ThreadID + Environment.NewLine;
            ret += "Thread is running in a 64 bit process = " + X64 + Environment.NewLine;
            ret += "Thread Parent Process = " + ThreadProcess.ProcessName;
            if(!Context32.Equals(default(CONTEXT32)) && X64 == MachineType.I386)
            {
                ret += "Thread Context32 = Populated" + Environment.NewLine;
            }
            else if(!Context64.Equals(default(CONTEXT64)) && X64 == MachineType.x64)
            {
                ret += "Thread Context64 = Populated" + Environment.NewLine;
            }
            else if(X64 == MachineType.x64)
            {
                ret += "Thread Context64 = Unpopulated" + Environment.NewLine;
            }
            else
            {
                ret += "Thread Context32 = Unpopulated" + Environment.NewLine;
            }

            if (!Teb.Equals(default(TEB)))
            {
                ret += "Thread TEB = Populated" + Environment.NewLine;
            }
            else
            {
                ret += "Thread TEB = Unpopulated" + Environment.NewLine;
            }
            return ret;
        }
        #endregion
    }
}
