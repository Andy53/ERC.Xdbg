using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;

namespace ERC.Utilities
{
    /// <summary> Attempts to create Rop chains from 64 bit processes. </summary>
    public class RopChainGenerator64
    {
        #region Class Variables
        private const int MEM_COMMIT = 0x1000;

        /// <summary>
        /// Contains a ROP chain which calls the VirtualAlloc method.
        /// </summary>
        public List<Tuple<byte[], string>> VirtualAllocChain = new List<Tuple<byte[], string>>();

        /// <summary>
        /// Contains a ROP chain which calls the VirtualAlloc method.
        /// </summary>
        public List<Tuple<byte[], string>> HeapCreateChain = new List<Tuple<byte[], string>>();

        /// <summary>
        /// Contains a ROP chain which calls the VirtualAlloc method.
        /// </summary>
        public List<Tuple<byte[], string>> VirtualProtectChain = new List<Tuple<byte[], string>>();

        /// <summary>
        /// Contains a ROP chain which calls the VirtualAlloc method.
        /// </summary>
        public List<Tuple<byte[], string>> WriteProcessMemoryChain = new List<Tuple<byte[], string>>();

        RopMethod Methods;
        internal X64Lists x64Opcodes;
        internal X64Lists usableX64Opcodes;
        internal ProcessInfo RcgInfo;
        private Dictionary<string, IntPtr> ApiAddresses = new Dictionary<string, IntPtr>();
        private List<IntPtr> RopNops = new List<IntPtr>();
        private List<byte[]> opcodes64 = new List<byte[]>();
        #endregion

        #region Constructor
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="_info">ProcessInfo object for which a ROP chain will be generated</param>
        public RopChainGenerator64(ProcessInfo _info)
        {
            if (_info.ProcessMachineType == MachineType.x64)
            {
                x64Opcodes = new X64Lists();
            }
            else
            {
                throw new ArgumentException("Fatal Error: This is not a 64bit process.");
            }

            RcgInfo = _info;
            byte[] pushRax = new byte[] { 0x50 };
            byte[] pushRcx = new byte[] { 0x51 };
            byte[] pushRdx = new byte[] { 0x51 };
            byte[] pushRbx = new byte[] { 0x53 };
            byte[] pushRsp = new byte[] { 0x54 };
            byte[] pushRbp = new byte[] { 0x55 };
            byte[] pushRsi = new byte[] { 0x56 };
            byte[] pushRdi = new byte[] { 0x57 };
            byte[] pushR8 = new byte[] { 0x41, 0x50 };
            byte[] pushR9 = new byte[] { 0x41, 0x51 };
            byte[] pushR10 = new byte[] { 0x41, 0x52 };
            byte[] pushR11 = new byte[] { 0x41, 0x53 };
            byte[] pushR12 = new byte[] { 0x41, 0x54 };
            byte[] pushR13 = new byte[] { 0x41, 0x55 };
            byte[] pushR14 = new byte[] { 0x41, 0x56 };
            byte[] pushR15 = new byte[] { 0x41, 0x57 };
            byte[] popRax = new byte[] { 0x58 };
            byte[] popRbx = new byte[] { 0x5B };
            byte[] popRcx = new byte[] { 0x59 };
            byte[] popRdx = new byte[] { 0x5A };
            byte[] popRsp = new byte[] { 0x5C };
            byte[] popRbp = new byte[] { 0x5D };
            byte[] popRsi = new byte[] { 0x5E };
            byte[] popRdi = new byte[] { 0x5F };
            byte[] popR8 = new byte[] { 0x41, 0x58 };
            byte[] popR9 = new byte[] { 0x41, 0x59 };
            byte[] popR10 = new byte[] { 0x41, 0x5A };
            byte[] popR11 = new byte[] { 0x41, 0x5B };
            byte[] popR12 = new byte[] { 0x41, 0x5C };
            byte[] popR13 = new byte[] { 0x41, 0x5D };
            byte[] popR14 = new byte[] { 0x41, 0x5E };
            byte[] popR15 = new byte[] { 0x41, 0x5F };
            byte[] xorRax = new byte[] { 0x48, 0x31, 0xC0 };
            byte[] xorRbx = new byte[] { 0x48, 0x31, 0xD8 };
            byte[] xorRcx = new byte[] { 0x48, 0x31, 0xC9 };
            byte[] xorRdx = new byte[] { 0x48, 0x31, 0xD2 };
            byte[] xorRsi = new byte[] { 0x48, 0x31, 0xF6 };
            byte[] xorRdi = new byte[] { 0x48, 0x31, 0xFF };
            byte[] xorRsp = new byte[] { 0x48, 0x31, 0xE4 };
            byte[] xorRbp = new byte[] { 0x48, 0x31, 0xED };
            byte[] xorR8 = new byte[] { 0x48, 0x31, 0xC8 };
            byte[] xorR9 = new byte[] { 0x48, 0x31, 0xC9 };
            byte[] xorR10 = new byte[] { 0x48, 0x31, 0xD2 };
            byte[] xorR11 = new byte[] { 0x48, 0x31, 0xDB };
            byte[] xorR12 = new byte[] { 0x48, 0x31, 0xE4 };
            byte[] xorR13 = new byte[] { 0x48, 0x31, 0xED };
            byte[] xorR14 = new byte[] { 0x48, 0x31, 0xF6 };
            byte[] xorR15 = new byte[] { 0x48, 0x31, 0xFF };
            byte[] jmpRsp = new byte[] { 0xFF, 0xE4 };
            byte[] callRsp = new byte[] { 0xFF, 0xD4 };
            byte[] incRax = new byte[] { 0x48, 0xFF, 0xC0}; 
            byte[] incRbx = new byte[] { 0x48, 0xFF, 0xC3 };
            byte[] incRcx = new byte[] { 0x48, 0xFF, 0xC1 };
            byte[] incRdx = new byte[] { 0x48, 0xFF, 0xC2 };
            byte[] incRbp = new byte[] { 0x48, 0xFF, 0xC5 };
            byte[] incRsp = new byte[] { 0x48, 0xFF, 0xC4 };
            byte[] incRsi = new byte[] { 0x48, 0xFF, 0xC6 };
            byte[] incRdi = new byte[] { 0x48, 0xFF, 0xC7 };
            byte[] incR8 = new byte[] { 0x49, 0xFF, 0xC0 };
            byte[] incR9 = new byte[] { 0x49, 0xFF, 0xC1 };
            byte[] incR10 = new byte[] { 0x49, 0xFF, 0xC2 };
            byte[] incR11 = new byte[] { 0x49, 0xFF, 0xC3 };
            byte[] incR12 = new byte[] { 0x49, 0xFF, 0xC4 };
            byte[] incR13 = new byte[] { 0x49, 0xFF, 0xC5 };
            byte[] incR14 = new byte[] { 0x49, 0xFF, 0xC6 };
            byte[] incR15 = new byte[] { 0x49, 0xFF, 0xC7 };
            byte[] decRax = new byte[] { 0x48, 0xFF, 0xC8 };
            byte[] decRbx = new byte[] { 0x48, 0xFF, 0xCB };
            byte[] decRcx = new byte[] { 0x48, 0xFF, 0xC9 };
            byte[] decRdx = new byte[] { 0x48, 0xFF, 0xCA };
            byte[] decRbp = new byte[] { 0x48, 0xFF, 0xCD }; 
            byte[] decRsp = new byte[] { 0x48, 0xFF, 0xCC };
            byte[] decRsi = new byte[] { 0x48, 0xFF, 0xCE };
            byte[] decRdi = new byte[] { 0x48, 0xFF, 0xCF };
            byte[] decR8 = new byte[] { 0x49, 0xFF, 0xC8 };
            byte[] decR9 = new byte[] { 0x49, 0xFF, 0xC9 };
            byte[] decR10 = new byte[] { 0x49, 0xFF, 0xCA };
            byte[] decR11 = new byte[] { 0x49, 0xFF, 0xCB };
            byte[] decR12 = new byte[] { 0x49, 0xFF, 0xCC };
            byte[] decR13 = new byte[] { 0x49, 0xFF, 0xCD };
            byte[] decR14 = new byte[] { 0x49, 0xFF, 0xCE };
            byte[] decR15 = new byte[] { 0x49, 0xFF, 0xCF };
            byte[] add1 = new byte[] { 0x48, 0x01 };           
            byte[] add2 = new byte[] { 0x4C, 0x01 };
            byte[] add3 = new byte[] { 0x49, 0x01 };
            byte[] add4 = new byte[] { 0x4D, 0x01 };
            byte[] mov1 = new byte[] { 0x48, 0x89 };
            byte[] mov2 = new byte[] { 0x4C, 0x89 };
            byte[] mov3 = new byte[] { 0x49, 0x89 };
            byte[] mov4 = new byte[] { 0x4D, 0x89 };
            byte[] sub1 = new byte[] { 0x48, 0x29 };
            byte[] sub2 = new byte[] { 0x4C, 0x29 };
            byte[] sub3 = new byte[] { 0x49, 0x29 };
            byte[] sub4 = new byte[] { 0x4D, 0x29 };
            byte[] jmpRax = new byte[] { 0xFF, 0xD0 };
            byte[] callRax = new byte[] { 0xFF, 0xE0 };

            opcodes64.Add(pushRax);
            opcodes64.Add(pushRcx);
            opcodes64.Add(pushRdx);
            opcodes64.Add(pushRbx);
            opcodes64.Add(pushRsp);
            opcodes64.Add(pushRbp);
            opcodes64.Add(pushRsi);
            opcodes64.Add(pushRdi);
            opcodes64.Add(pushR8);
            opcodes64.Add(pushR9);
            opcodes64.Add(pushR10);
            opcodes64.Add(pushR11);
            opcodes64.Add(pushR12);
            opcodes64.Add(pushR13);
            opcodes64.Add(pushR14);
            opcodes64.Add(pushR15);
            opcodes64.Add(popRax);
            opcodes64.Add(popRbx);
            opcodes64.Add(popRcx);
            opcodes64.Add(popRdx);
            opcodes64.Add(popRsp);
            opcodes64.Add(popRbp);
            opcodes64.Add(popRsi);
            opcodes64.Add(popRdi);
            opcodes64.Add(popR8);
            opcodes64.Add(popR9);
            opcodes64.Add(popR10);
            opcodes64.Add(popR11);
            opcodes64.Add(popR12);
            opcodes64.Add(popR13);
            opcodes64.Add(popR14);
            opcodes64.Add(popR15);
            opcodes64.Add(xorRax);
            opcodes64.Add(xorRbx);
            opcodes64.Add(xorRcx);
            opcodes64.Add(xorRdx);
            opcodes64.Add(xorRsi);
            opcodes64.Add(xorRdi);
            opcodes64.Add(xorRsp);
            opcodes64.Add(xorRbp);
            opcodes64.Add(xorR8);
            opcodes64.Add(xorR9);
            opcodes64.Add(xorR10);
            opcodes64.Add(xorR11);
            opcodes64.Add(xorR12);
            opcodes64.Add(xorR13);
            opcodes64.Add(xorR14);
            opcodes64.Add(xorR15);
            opcodes64.Add(jmpRsp);
            opcodes64.Add(callRsp);
            opcodes64.Add(incRax);
            opcodes64.Add(incRbx);
            opcodes64.Add(incRcx);
            opcodes64.Add(incRdx);
            opcodes64.Add(incRbp);
            opcodes64.Add(incRsp);
            opcodes64.Add(incRsi);
            opcodes64.Add(incRdi);
            opcodes64.Add(incR8);
            opcodes64.Add(incR9);
            opcodes64.Add(incR10);
            opcodes64.Add(incR11);
            opcodes64.Add(incR12);
            opcodes64.Add(incR13);
            opcodes64.Add(incR14);
            opcodes64.Add(incR15);
            opcodes64.Add(decRax);
            opcodes64.Add(decRbx);
            opcodes64.Add(decRcx);
            opcodes64.Add(decRdx);
            opcodes64.Add(decRbp);
            opcodes64.Add(decRsp);
            opcodes64.Add(decRsi);
            opcodes64.Add(decRdi);
            opcodes64.Add(decR8);
            opcodes64.Add(decR9);
            opcodes64.Add(decR10);
            opcodes64.Add(decR11);
            opcodes64.Add(decR12);
            opcodes64.Add(decR13);
            opcodes64.Add(decR14);
            opcodes64.Add(decR15);
            opcodes64.Add(add1);
            opcodes64.Add(add2);
            opcodes64.Add(add3);
            opcodes64.Add(add4);
            opcodes64.Add(mov1);
            opcodes64.Add(mov2);
            opcodes64.Add(mov3);
            opcodes64.Add(mov4);
            opcodes64.Add(sub1);
            opcodes64.Add(sub2);
            opcodes64.Add(sub3);
            opcodes64.Add(sub4);
            opcodes64.Add(jmpRax);
            opcodes64.Add(callRax);
        }
        #endregion

        #region GenerateRopGadgets64
        /// <summary>
        /// Creates a list of ROP gadgets for a specific process.
        /// </summary>
        /// <param name="ptrsToExclude">Takes a byte array of values used to disqualify ROP gadgets</param>
        /// <param name="excludes">A list of modules to be excluded from the search for ROP gadgets</param>
        /// <returns>Returns an ErcResult string containing</returns>
        public ErcResult<string> GenerateRopGadgets64(byte[] ptrsToExclude = null, List<string> excludes = null)
        {
            ErcResult<string> RopChain = new ErcResult<string>(RcgInfo.ProcessCore);
            x64Opcodes = new X64Lists();

            var ret1 = GetApiAddresses(RcgInfo);
            if (ret1.Error != null && ApiAddresses.Count <= 0)
            {
                ErcResult<string> failed = new ErcResult<string>(RcgInfo.ProcessCore);
                failed.ReturnValue = "An error has occured, check log file for more details.";
                failed.Error = ret1.Error;
            }

            var ret2 = GetRopNops(RcgInfo, excludes);
            if (ret2.Error != null && RopNops.Count <= 0)
            {
                ErcResult<string> failed = new ErcResult<string>(RcgInfo.ProcessCore);
                failed.ReturnValue = "An error has occured, check log file for more details.";
                failed.Error = ret2.Error;
            }

            var ret3 = PopulateOpcodes(RcgInfo);
            if (ret3.Error != null)
            {
                ErcResult<string> failed = new ErcResult<string>(RcgInfo.ProcessCore);
                failed.ReturnValue = "An error has occured, check log file for more details.";
                failed.Error = ret3.Error;
            }

            OptimiseLists(RcgInfo);
            usableX64Opcodes.pushRax = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushRax, ptrsToExclude);
            usableX64Opcodes.pushRcx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushRcx, ptrsToExclude);
            usableX64Opcodes.pushRdx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushRdx, ptrsToExclude);
            usableX64Opcodes.pushRbx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushRbx, ptrsToExclude);
            usableX64Opcodes.pushRsp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushRsp, ptrsToExclude);
            usableX64Opcodes.pushRbp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushRbp, ptrsToExclude);
            usableX64Opcodes.pushRsi = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushRsi, ptrsToExclude);
            usableX64Opcodes.pushRdi = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushRdi, ptrsToExclude);
            usableX64Opcodes.pushR8 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushR8, ptrsToExclude);
            usableX64Opcodes.pushR9 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushR9, ptrsToExclude);
            usableX64Opcodes.pushR10 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushR10, ptrsToExclude);
            usableX64Opcodes.pushR11 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushR11, ptrsToExclude);
            usableX64Opcodes.pushR12 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushR12, ptrsToExclude);
            usableX64Opcodes.pushR13 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushR13, ptrsToExclude);
            usableX64Opcodes.pushR14 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushR14, ptrsToExclude);
            usableX64Opcodes.pushR15 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushR15, ptrsToExclude);
            usableX64Opcodes.popRax = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popRax, ptrsToExclude);
            usableX64Opcodes.popRbx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popRbx, ptrsToExclude);
            usableX64Opcodes.popRcx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popRcx, ptrsToExclude);
            usableX64Opcodes.popRdx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popRdx, ptrsToExclude);
            usableX64Opcodes.popRsp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popRsp, ptrsToExclude);
            usableX64Opcodes.popRbp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popRbp, ptrsToExclude);
            usableX64Opcodes.popRsi = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popRsi, ptrsToExclude);
            usableX64Opcodes.popRdi = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popRdi, ptrsToExclude);
            usableX64Opcodes.popR8 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popR8, ptrsToExclude);
            usableX64Opcodes.popR9 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popR9, ptrsToExclude);
            usableX64Opcodes.popR10 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popR10, ptrsToExclude);
            usableX64Opcodes.popR11 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popR11, ptrsToExclude);
            usableX64Opcodes.popR12 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popR12, ptrsToExclude);
            usableX64Opcodes.popR13 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popR13, ptrsToExclude);
            usableX64Opcodes.popR14 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popR14, ptrsToExclude);
            usableX64Opcodes.popR15 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popR15, ptrsToExclude);
            usableX64Opcodes.xorRax = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorRax, ptrsToExclude);
            usableX64Opcodes.xorRbx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorRbx, ptrsToExclude);
            usableX64Opcodes.xorRcx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorRcx, ptrsToExclude);
            usableX64Opcodes.xorRdx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorRdx, ptrsToExclude);
            usableX64Opcodes.xorRsi = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorRsi, ptrsToExclude);
            usableX64Opcodes.xorRdi = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorRdi, ptrsToExclude);
            usableX64Opcodes.xorRsp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorRsp, ptrsToExclude);
            usableX64Opcodes.xorRbp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorRbp, ptrsToExclude);
            usableX64Opcodes.xorR8 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorR8, ptrsToExclude);
            usableX64Opcodes.xorR9 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorR9, ptrsToExclude);
            usableX64Opcodes.xorR10 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorR10, ptrsToExclude);
            usableX64Opcodes.xorR11 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorR11, ptrsToExclude);
            usableX64Opcodes.xorR12 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorR12, ptrsToExclude);
            usableX64Opcodes.xorR13 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorR13, ptrsToExclude);
            usableX64Opcodes.xorR14 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorR14, ptrsToExclude);
            usableX64Opcodes.xorR15 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorR15, ptrsToExclude);
            usableX64Opcodes.jmpRsp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.jmpRsp, ptrsToExclude);
            usableX64Opcodes.callRsp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.callRsp, ptrsToExclude);
            usableX64Opcodes.incRax = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incRax, ptrsToExclude);
            usableX64Opcodes.incRbx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incRbx, ptrsToExclude);
            usableX64Opcodes.incRcx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incRcx, ptrsToExclude);
            usableX64Opcodes.incRdx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incRdx, ptrsToExclude);
            usableX64Opcodes.incRbp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incRbp, ptrsToExclude);
            usableX64Opcodes.incRsp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incRsp, ptrsToExclude);
            usableX64Opcodes.incRsi = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incRsi, ptrsToExclude);
            usableX64Opcodes.incRdi = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incRdi, ptrsToExclude);
            usableX64Opcodes.incR8 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incR8, ptrsToExclude);
            usableX64Opcodes.incR9 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incR9, ptrsToExclude);
            usableX64Opcodes.incR10 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incR10, ptrsToExclude);
            usableX64Opcodes.incR11 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incR11, ptrsToExclude);
            usableX64Opcodes.incR12 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incR12, ptrsToExclude);
            usableX64Opcodes.incR13 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incR13, ptrsToExclude);
            usableX64Opcodes.incR14 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incR14, ptrsToExclude);
            usableX64Opcodes.incR15 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incR15, ptrsToExclude);
            usableX64Opcodes.decRax = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decRax, ptrsToExclude);
            usableX64Opcodes.decRbx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decRbx, ptrsToExclude);
            usableX64Opcodes.decRcx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decRcx, ptrsToExclude);
            usableX64Opcodes.decRdx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decRdx, ptrsToExclude);
            usableX64Opcodes.decRbp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decRbp, ptrsToExclude);
            usableX64Opcodes.decRsp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decRsp, ptrsToExclude);
            usableX64Opcodes.decRsi = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decRsi, ptrsToExclude);
            usableX64Opcodes.decRdi = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decRdi, ptrsToExclude);
            usableX64Opcodes.decR8 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decR8, ptrsToExclude);
            usableX64Opcodes.decR9 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decR9, ptrsToExclude);
            usableX64Opcodes.decR10 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decR10, ptrsToExclude);
            usableX64Opcodes.decR11 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decR11, ptrsToExclude);
            usableX64Opcodes.decR12 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decR12, ptrsToExclude);
            usableX64Opcodes.decR13 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decR13, ptrsToExclude);
            usableX64Opcodes.decR14 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decR14, ptrsToExclude);
            usableX64Opcodes.decR15 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decR15, ptrsToExclude);
            usableX64Opcodes.add = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.add, ptrsToExclude);
            usableX64Opcodes.mov = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.mov, ptrsToExclude);
            usableX64Opcodes.sub = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.sub, ptrsToExclude);

            DisplayOutput.RopChainGadgets64(this, true);
            return RopChain;
        }
        #endregion 

        #region GenerateRopChain64
        /// <summary>
        /// Creates a RopChain for a specific process.
        /// </summary>
        /// <param name="ptrsToExclude">Takes a byte array of values used to disqualify ROP gadgets</param>
        /// <param name="startAddress">A Address to be used as the start location for which memory will be made executable</param>
        /// <param name="excludes">A list of modules to be excluded from the search for ROP gadgets</param>
        /// <returns>Returns an ErcResult string containing</returns>
        public ErcResult<string> GenerateRopChain64(byte[] ptrsToExclude, byte[] startAddress = null, List<string> excludes = null, RopMethod methods = RopMethod.All)
        {
            Methods = methods;
            ErcResult<string> RopChain = new ErcResult<string>(RcgInfo.ProcessCore);
            x64Opcodes = new X64Lists();

            var ret1 = GetApiAddresses(RcgInfo);
            if (ret1.Error != null && ApiAddresses.Count <= 0)
            {
                ErcResult<string> failed = new ErcResult<string>(RcgInfo.ProcessCore);
                failed.ReturnValue = "An error has occured, check log file for more details.";
                failed.Error = ret1.Error;
            }

            if (excludes != null)
            {
                var ret2 = GetRopNops(RcgInfo, excludes);
                if (ret2.Error != null && RopNops.Count <= 0)
                {
                    ErcResult<string> failed = new ErcResult<string>(RcgInfo.ProcessCore);
                    failed.ReturnValue = "An error has occured, check log file for more details.";
                    failed.Error = ret2.Error;
                    return failed;
                }
            }
            else
            {
                var ret2 = GetRopNops(RcgInfo);
                if (ret2.Error != null && RopNops.Count <= 0)
                {
                    ErcResult<string> failed = new ErcResult<string>(RcgInfo.ProcessCore);
                    failed.ReturnValue = "An error has occured, check log file for more details.";
                    failed.Error = ret2.Error;
                    return failed;
                }
            }

            var ret3 = PopulateOpcodes(RcgInfo);
            if (ret3.Error != null)
            {
                ErcResult<string> failed = new ErcResult<string>(RcgInfo.ProcessCore);
                failed.ReturnValue = "An error has occured, check log file for more details.";
                failed.Error = ret3.Error;
            }

            OptimiseLists(RcgInfo);
            usableX64Opcodes.pushRax = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushRax, ptrsToExclude);
            usableX64Opcodes.pushRcx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushRcx, ptrsToExclude);
            usableX64Opcodes.pushRdx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushRdx, ptrsToExclude);
            usableX64Opcodes.pushRbx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushRbx, ptrsToExclude);
            usableX64Opcodes.pushRsp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushRsp, ptrsToExclude);
            usableX64Opcodes.pushRbp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushRbp, ptrsToExclude);
            usableX64Opcodes.pushRsi = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushRsi, ptrsToExclude);
            usableX64Opcodes.pushRdi = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushRdi, ptrsToExclude);
            usableX64Opcodes.pushR8 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushR8, ptrsToExclude);
            usableX64Opcodes.pushR9 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushR9, ptrsToExclude);
            usableX64Opcodes.pushR10 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushR10, ptrsToExclude);
            usableX64Opcodes.pushR11 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushR11, ptrsToExclude);
            usableX64Opcodes.pushR12 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushR12, ptrsToExclude);
            usableX64Opcodes.pushR13 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushR13, ptrsToExclude);
            usableX64Opcodes.pushR14 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushR14, ptrsToExclude);
            usableX64Opcodes.pushR15 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.pushR15, ptrsToExclude);
            usableX64Opcodes.popRax = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popRax, ptrsToExclude);
            usableX64Opcodes.popRbx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popRbx, ptrsToExclude);
            usableX64Opcodes.popRcx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popRcx, ptrsToExclude);
            usableX64Opcodes.popRdx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popRdx, ptrsToExclude);
            usableX64Opcodes.popRsp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popRsp, ptrsToExclude);
            usableX64Opcodes.popRbp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popRbp, ptrsToExclude);
            usableX64Opcodes.popRsi = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popRsi, ptrsToExclude);
            usableX64Opcodes.popRdi = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popRdi, ptrsToExclude);
            usableX64Opcodes.popR8 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popR8, ptrsToExclude);
            usableX64Opcodes.popR9 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popR9, ptrsToExclude);
            usableX64Opcodes.popR10 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popR10, ptrsToExclude);
            usableX64Opcodes.popR11 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popR11, ptrsToExclude);
            usableX64Opcodes.popR12 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popR12, ptrsToExclude);
            usableX64Opcodes.popR13 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popR13, ptrsToExclude);
            usableX64Opcodes.popR14 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popR14, ptrsToExclude);
            usableX64Opcodes.popR15 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.popR15, ptrsToExclude);
            usableX64Opcodes.xorRax = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorRax, ptrsToExclude);
            usableX64Opcodes.xorRbx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorRbx, ptrsToExclude);
            usableX64Opcodes.xorRcx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorRcx, ptrsToExclude);
            usableX64Opcodes.xorRdx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorRdx, ptrsToExclude);
            usableX64Opcodes.xorRsi = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorRsi, ptrsToExclude);
            usableX64Opcodes.xorRdi = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorRdi, ptrsToExclude);
            usableX64Opcodes.xorRsp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorRsp, ptrsToExclude);
            usableX64Opcodes.xorRbp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorRbp, ptrsToExclude);
            usableX64Opcodes.xorR8 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorR8, ptrsToExclude);
            usableX64Opcodes.xorR9 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorR9, ptrsToExclude);
            usableX64Opcodes.xorR10 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorR10, ptrsToExclude);
            usableX64Opcodes.xorR11 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorR11, ptrsToExclude);
            usableX64Opcodes.xorR12 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorR12, ptrsToExclude);
            usableX64Opcodes.xorR13 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorR13, ptrsToExclude);
            usableX64Opcodes.xorR14 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorR14, ptrsToExclude);
            usableX64Opcodes.xorR15 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.xorR15, ptrsToExclude);
            usableX64Opcodes.jmpRsp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.jmpRsp, ptrsToExclude);
            usableX64Opcodes.callRsp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.callRsp, ptrsToExclude);
            usableX64Opcodes.incRax = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incRax, ptrsToExclude);
            usableX64Opcodes.incRbx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incRbx, ptrsToExclude);
            usableX64Opcodes.incRcx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incRcx, ptrsToExclude);
            usableX64Opcodes.incRdx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incRdx, ptrsToExclude);
            usableX64Opcodes.incRbp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incRbp, ptrsToExclude);
            usableX64Opcodes.incRsp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incRsp, ptrsToExclude);
            usableX64Opcodes.incRsi = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incRsi, ptrsToExclude);
            usableX64Opcodes.incRdi = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incRdi, ptrsToExclude);
            usableX64Opcodes.incR8 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incR8, ptrsToExclude);
            usableX64Opcodes.incR9 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incR9, ptrsToExclude);
            usableX64Opcodes.incR10 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incR10, ptrsToExclude);
            usableX64Opcodes.incR11 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incR11, ptrsToExclude);
            usableX64Opcodes.incR12 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incR12, ptrsToExclude);
            usableX64Opcodes.incR13 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incR13, ptrsToExclude);
            usableX64Opcodes.incR14 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incR14, ptrsToExclude);
            usableX64Opcodes.incR15 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.incR15, ptrsToExclude);
            usableX64Opcodes.decRax = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decRax, ptrsToExclude);
            usableX64Opcodes.decRbx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decRbx, ptrsToExclude);
            usableX64Opcodes.decRcx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decRcx, ptrsToExclude);
            usableX64Opcodes.decRdx = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decRdx, ptrsToExclude);
            usableX64Opcodes.decRbp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decRbp, ptrsToExclude);
            usableX64Opcodes.decRsp = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decRsp, ptrsToExclude);
            usableX64Opcodes.decRsi = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decRsi, ptrsToExclude);
            usableX64Opcodes.decRdi = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decRdi, ptrsToExclude);
            usableX64Opcodes.decR8 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decR8, ptrsToExclude);
            usableX64Opcodes.decR9 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decR9, ptrsToExclude);
            usableX64Opcodes.decR10 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decR10, ptrsToExclude);
            usableX64Opcodes.decR11 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decR11, ptrsToExclude);
            usableX64Opcodes.decR12 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decR12, ptrsToExclude);
            usableX64Opcodes.decR13 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decR13, ptrsToExclude);
            usableX64Opcodes.decR14 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decR14, ptrsToExclude);
            usableX64Opcodes.decR15 = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.decR15, ptrsToExclude);
            usableX64Opcodes.add = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.add, ptrsToExclude);
            usableX64Opcodes.mov = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.mov, ptrsToExclude);
            usableX64Opcodes.sub = PtrRemover.RemovePointers(RcgInfo.ProcessMachineType, usableX64Opcodes.sub, ptrsToExclude);

            if (Methods.HasFlag(RopMethod.VirtualAlloc))
            {
                var vpaChain = GenerateVirtualAllocChain64(RcgInfo);
                if (vpaChain.Error == null)
                {
                    VirtualAllocChain = vpaChain.ReturnValue;
                }
            }

            if (Methods.HasFlag(RopMethod.HeapCreate))
            {
                var hcChain = GenerateHeapCreateChain64(RcgInfo);
                if (hcChain.Error == null)
                {
                    HeapCreateChain = hcChain.ReturnValue;
                }
            }

            if (Methods.HasFlag(RopMethod.VirtualProtect))
            {
                var vpChain = GenerateVirtualProtectChain64(RcgInfo);
                if (vpChain.Error == null)
                {
                    VirtualProtectChain = vpChain.ReturnValue;
                }
            }

            var output = DisplayOutput.RopChainGadgets64(this);
            RopChain.ReturnValue = String.Join("\n", output);
            return RopChain;
        }

        /// <summary>
        /// Creates a RopChain for a specific process.
        /// </summary>
        /// <param name="startAddress">A Address to be used as the start location for which memory will be made executable</param>
        /// <param name="excludes">A list of modules to be excluded from the search for ROP gadgets</param>
        /// <returns>Returns an ErcResult string containing</returns>
        public ErcResult<string> GenerateRopChain64(byte[] startAddress = null, List<string> excludes = null, RopMethod methods = RopMethod.All)
        {
            Methods = methods;
            ErcResult<string> RopChain = new ErcResult<string>(RcgInfo.ProcessCore);
            x64Opcodes = new X64Lists();

            Console.WriteLine("Getting API Addresses...");
            var ret1 = GetApiAddresses(RcgInfo);
            if (ret1.Error != null && ApiAddresses.Count <= 0)
            {
                ErcResult<string> failed = new ErcResult<string>(RcgInfo.ProcessCore);
                failed.ReturnValue = "An error has occured, check log file for more details.";
                failed.Error = ret1.Error;
            }

            Console.WriteLine("Getting RopNops...");
            if(excludes != null)
            {
                var ret2 = GetRopNops(RcgInfo, excludes);
                if (ret2.Error != null && RopNops.Count <= 0)
                {
                    ErcResult<string> failed = new ErcResult<string>(RcgInfo.ProcessCore);
                    failed.ReturnValue = "An error has occured, check log file for more details.";
                    failed.Error = ret2.Error;
                    return failed;
                }
            }
            else
            {
                var ret2 = GetRopNops(RcgInfo);
                if (ret2.Error != null && RopNops.Count <= 0)
                {
                    ErcResult<string> failed = new ErcResult<string>(RcgInfo.ProcessCore);
                    failed.ReturnValue = "An error has occured, check log file for more details.";
                    failed.Error = ret2.Error;
                    return failed;
                }
            }

            Console.WriteLine("Populating Opcodes...");
            var ret3 = PopulateOpcodes(RcgInfo);
            if (ret3.Error != null)
            {
                ErcResult<string> failed = new ErcResult<string>(RcgInfo.ProcessCore);
                failed.ReturnValue = "An error has occured, check log file for more details.";
                failed.Error = ret3.Error;
            }

            Console.WriteLine("Optimizing Lists...");
            OptimiseLists(RcgInfo);

            Console.WriteLine("Generating VirtualAlloc Chain...");
            if (Methods.HasFlag(RopMethod.VirtualAlloc))
            {
                var vpaChain = GenerateVirtualAllocChain64(RcgInfo);
                if (vpaChain.Error == null)
                {
                    VirtualAllocChain = vpaChain.ReturnValue;
                }
            }

            Console.WriteLine("Generating HeapCreate Chain...");
            if (Methods.HasFlag(RopMethod.HeapCreate))
            {
                var hcChain = GenerateHeapCreateChain64(RcgInfo);
                if (hcChain.Error == null)
                {
                    HeapCreateChain = hcChain.ReturnValue;
                }
            }

            if (Methods.HasFlag(RopMethod.VirtualProtect))
            {
                var vpChain = GenerateVirtualProtectChain64(RcgInfo);
                if (vpChain.Error == null)
                {
                    VirtualProtectChain = vpChain.ReturnValue;
                }
            }

            var output = DisplayOutput.RopChainGadgets64(this);
            RopChain.ReturnValue = String.Join("\n", output);
            return RopChain;
        }
        #endregion

        #region GetApiAddresses
        private ErcResult<int> GetApiAddresses(ProcessInfo info)
        {
            ErcResult<int> returnVar = new ErcResult<int>(info.ProcessCore);
            returnVar.ReturnValue = 0;

            IntPtr hModule = IntPtr.Zero;
            for (int i = 0; i < info.ModulesInfo.Count; i++)
            {
                if (info.ModulesInfo[i].ModuleName == "kernel32")
                {
                    hModule = info.ModulesInfo[i].ModuleBase;
                }
            }

            var virtAllocAddress = ErcCore.GetProcAddress(hModule, "VirtualAlloc");
            if (virtAllocAddress == IntPtr.Zero)
            {
                returnVar.Error = new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                returnVar.LogEvent();
            }
            else
            {
                ApiAddresses.Add("VirtualAlloc", virtAllocAddress);
            }

            var HeapCreateAddress = ErcCore.GetProcAddress(hModule, "HeapCreate");
            if (HeapCreateAddress == IntPtr.Zero)
            {
                returnVar.Error = new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                returnVar.LogEvent();
            }
            else
            {
                ApiAddresses.Add("HeapCreate", HeapCreateAddress);
            }

            var VirtualProtectAddress = ErcCore.GetProcAddress(hModule, "VirtualProtect");
            if (VirtualProtectAddress == IntPtr.Zero)
            {
                returnVar.Error = new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                returnVar.LogEvent();
            }
            else
            {
                ApiAddresses.Add("VirtualProtect", VirtualProtectAddress);
            }

            var WriteProcessMemoryAddress = ErcCore.GetProcAddress(hModule, "WriteProcessMemory");
            if (WriteProcessMemoryAddress == IntPtr.Zero)
            {
                returnVar.Error = new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                returnVar.LogEvent();
            }
            else
            {
                ApiAddresses.Add("WriteProcessMemory", WriteProcessMemoryAddress);
            }

            return returnVar;
        }
        #endregion

        #region GetRopNops
        private ErcResult<List<IntPtr>> GetRopNops(ProcessInfo info, List<string> excludes = null)
        {
            ErcResult<List<IntPtr>> ropNopsResult = new ErcResult<List<IntPtr>>(info.ProcessCore);
            ropNopsResult.ReturnValue = new List<IntPtr>();
            byte[] ropNop = new byte[] { 0xC3 };
            var ropPtrs = RcgInfo.SearchModules(0, searchBytes: ropNop, excludedModules: excludes);
            if (ropPtrs.Error != null)
            {
                ropNopsResult.Error = ropPtrs.Error;
            }
            foreach (KeyValuePair<IntPtr, string> k in ropPtrs.ReturnValue)
            {
                ropNopsResult.ReturnValue.Add(k.Key);
                RopNops.Add(k.Key);
            }
            return ropNopsResult;
        }

        private ErcResult<List<IntPtr>> GetRopNops(ProcessInfo info)
        {
            ErcResult<List<IntPtr>> ropNopsResult = new ErcResult<List<IntPtr>>(info.ProcessCore);
            ropNopsResult.ReturnValue = new List<IntPtr>();
            byte[] ropNop = new byte[] { 0xC3 };
            var ropPtrs = info.SearchModules(0, searchBytes: ropNop);
            if (ropPtrs.Error != null)
            {
                ropNopsResult.Error = ropPtrs.Error;
            }
            foreach (KeyValuePair<IntPtr, string> k in ropPtrs.ReturnValue)
            {
                ropNopsResult.ReturnValue.Add(k.Key);
                RopNops.Add(k.Key);
            }
            return ropNopsResult;
        }
        #endregion

        #region PopulateOpcodes
        private ErcResult<int> PopulateOpcodes(ProcessInfo info)
        {
            ErcResult<int> ret = new ErcResult<int>(info.ProcessCore);

            for (int i = 0; i < RopNops.Count; i++)
            {
                byte[] bytes = new byte[20];
                IntPtr baseAddress = RopNops[i] - 19;
                ErcCore.ReadProcessMemory(info.ProcessHandle, baseAddress, bytes, 20, out int bytesRead);
                if (bytesRead != 20)
                {
                    ret.Error = new ERCException("ReadProcessMemory Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    ret.LogEvent();
                }
                var ret1 = ParseByteArrayForRopCodes(bytes, info, baseAddress);
                if (ret1.Error != null)
                {
                    ret.Error = ret1.Error;
                    return ret;
                }
            }
            return ret;
        }
        #endregion

        #region ParseByteArrayForRopCodes
        private ErcResult<int> ParseByteArrayForRopCodes(byte[] bytes, ProcessInfo info, IntPtr baseAddress)
        {
            ErcResult<int> ret = new ErcResult<int>(info.ProcessCore);
            bool pushRaxDone = false;
            bool pushRcxDone = false;
            bool pushRdxDone = false;
            bool pushRbxDone = false;
            bool pushRspDone = false;
            bool pushRbpDone = false;
            bool pushRsiDone = false;
            bool pushRdiDone = false;
            bool pushR8Done = false;
            bool pushR9Done = false;
            bool pushR10Done = false;
            bool pushR11Done = false;
            bool pushR12Done = false;
            bool pushR13Done = false;
            bool pushR14Done = false;
            bool pushR15Done = false;
            bool popRaxDone = false;
            bool popRbxDone = false;
            bool popRcxDone = false;
            bool popRdxDone = false;
            bool popRspDone = false;
            bool popRbpDone = false;
            bool popRsiDone = false;
            bool popRdiDone = false;
            bool popR8Done = false;
            bool popR9Done = false;
            bool popR10Done = false;
            bool popR11Done = false;
            bool popR12Done = false;
            bool popR13Done = false;
            bool popR14Done = false;
            bool popR15Done = false;
            bool xorRaxDone = false;
            bool xorRbxDone = false;
            bool xorRcxDone = false;
            bool xorRdxDone = false;
            bool xorRsiDone = false;
            bool xorRdiDone = false;
            bool xorRspDone = false;
            bool xorRbpDone = false;
            bool xorR8Done = false;
            bool xorR9Done = false;
            bool xorR10Done = false;
            bool xorR11Done = false;
            bool xorR12Done = false;
            bool xorR13Done = false;
            bool xorR14Done = false;
            bool xorR15Done = false;
            bool jmpRspDone = false;
            bool callRspDone = false;
            bool incRaxDone = false;
            bool incRbxDone = false;
            bool incRcxDone = false;
            bool incRdxDone = false;
            bool incRbpDone = false;
            bool incRspDone = false;
            bool incRsiDone = false;
            bool incRdiDone = false;
            bool incR8Done = false;
            bool incR9Done = false;
            bool incR10Done = false;
            bool incR11Done = false;
            bool incR12Done = false;
            bool incR13Done = false;
            bool incR14Done = false;
            bool incR15Done = false;
            bool decRaxDone = false;
            bool decRbxDone = false;
            bool decRcxDone = false;
            bool decRdxDone = false;
            bool decRbpDone = false;
            bool decRspDone = false;
            bool decRsiDone = false;
            bool decRdiDone = false;
            bool decR8Done = false;
            bool decR9Done = false;
            bool decR10Done = false;
            bool decR11Done = false;
            bool decR12Done = false;
            bool decR13Done = false;
            bool decR14Done = false;
            bool decR15Done = false;
            bool addDone = false;
            bool movDone = false;
            bool subDone = false;
            bool jmpRaxDone = false;
            bool callRaxDone = false;

            for (int i = bytes.Length - 1; i > 0; i--)
            {
                for (int j = 0; j < opcodes64.Count; j++)
                {
                    if (bytes[i] == opcodes64[j][0] && opcodes64[j].Length == 1)
                    {
                        byte[] opcodes = new byte[bytes.Length - i];
                        switch (j)
                        {
                            case 0:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x64Opcodes.pushRax.ContainsKey(baseAddress + i) && pushRaxDone == false)
                                {
                                    pushRaxDone = true;
                                    x64Opcodes.pushRax.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 1:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x64Opcodes.pushRbx.ContainsKey(baseAddress + i) && pushRbxDone == false)
                                {
                                    pushRbxDone = true;
                                    x64Opcodes.pushRbx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 2:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x64Opcodes.pushRcx.ContainsKey(baseAddress + i) && pushRcxDone == false)
                                {
                                    pushRcxDone = true;
                                    x64Opcodes.pushRcx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 3:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x64Opcodes.pushRdx.ContainsKey(baseAddress + i) && pushRdxDone == false)
                                {
                                    pushRdxDone = true;
                                    x64Opcodes.pushRdx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 4:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x64Opcodes.pushRsp.ContainsKey(baseAddress + i) && pushRspDone == false)
                                {
                                    pushRspDone = true;
                                    x64Opcodes.pushRsp.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 5:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x64Opcodes.pushRbp.ContainsKey(baseAddress + i) && pushRbpDone == false)
                                {
                                    pushRbpDone = true;
                                    x64Opcodes.pushRbp.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 6:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x64Opcodes.pushRsi.ContainsKey(baseAddress + i) && pushRsiDone == false)
                                {
                                    pushRsiDone = true;
                                    x64Opcodes.pushRsi.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 7:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x64Opcodes.pushRdi.ContainsKey(baseAddress + i) && pushRdiDone == false)
                                {
                                    pushRdiDone = true;
                                    x64Opcodes.pushRdi.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 16:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x64Opcodes.popRax.ContainsKey(baseAddress + i) && popRaxDone == false)
                                {
                                    popRaxDone = true;
                                    x64Opcodes.popRax.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 17:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x64Opcodes.popRbx.ContainsKey(baseAddress + i) && popRbxDone == false)
                                {
                                    popRbxDone = true;
                                    x64Opcodes.popRbx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 18:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x64Opcodes.popRcx.ContainsKey(baseAddress + i) && popRcxDone == false)
                                {
                                    popRcxDone = true;
                                    x64Opcodes.popRcx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 19:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x64Opcodes.popRdx.ContainsKey(baseAddress + i) && popRdxDone == false)
                                {
                                    popRdxDone = true;
                                    x64Opcodes.popRdx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 20:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x64Opcodes.popRsp.ContainsKey(baseAddress + i) && popRspDone == false)
                                {
                                    popRspDone = true;
                                    x64Opcodes.popRsp.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 21:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x64Opcodes.popRbp.ContainsKey(baseAddress + i) && popRbpDone == false)
                                {
                                    popRbpDone = true;
                                    x64Opcodes.popRbp.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 22:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x64Opcodes.popRsi.ContainsKey(baseAddress + i) && popRsiDone == false)
                                {
                                    popRsiDone = true;
                                    x64Opcodes.popRsi.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 23:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x64Opcodes.popRdi.ContainsKey(baseAddress + i) && popRdiDone == false)
                                {
                                    popRdiDone = true;
                                    x64Opcodes.popRdi.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            default:
                                ret.Error = new ERCException("An error has occured in RopChainGenerator.ParseByteArrayForRopCodes whilst parsing single length x64 instructions");
                                break;
                        }
                    }
                    else if (opcodes64[j].Length == 2)
                    {
                        if (bytes[i] == opcodes64[j][0] && i < bytes.Length - 1 && j < opcodes64.Count + 1 && bytes[i + 1] == opcodes64[j][1])
                        {
                            byte[] opcodes = new byte[bytes.Length - i];
                            switch (j)
                            {
                                case 8:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.pushR8.ContainsKey(baseAddress + i) && pushR8Done == false)
                                    {
                                        pushR8Done = true;
                                        x64Opcodes.pushR8.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 9:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.pushR9.ContainsKey(baseAddress + i) && pushR9Done == false)
                                    {
                                        pushR9Done = true;
                                        x64Opcodes.pushR9.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 10:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.pushR10.ContainsKey(baseAddress + i) && pushR10Done == false)
                                    {
                                        pushR10Done = true;
                                        x64Opcodes.pushR10.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 11:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.pushR11.ContainsKey(baseAddress + i) && pushR11Done == false)
                                    {
                                        pushR11Done = true;
                                        x64Opcodes.pushR11.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 12:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.pushR12.ContainsKey(baseAddress + i) && pushR12Done == false)
                                    {
                                        pushR12Done = true;
                                        x64Opcodes.pushR12.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 13:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.pushR13.ContainsKey(baseAddress + i) && pushR13Done == false)
                                    {
                                        pushR13Done = true;
                                        x64Opcodes.pushR13.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 14:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.pushR14.ContainsKey(baseAddress + i) && pushR14Done == false)
                                    {
                                        pushR14Done = true;
                                        x64Opcodes.pushR14.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 15:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.pushR15.ContainsKey(baseAddress + i) && pushR15Done == false)
                                    {
                                        pushR15Done = true;
                                        x64Opcodes.pushR15.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 24:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.popR8.ContainsKey(baseAddress + i) && popR8Done == false)
                                    {
                                        popR8Done = true;
                                        x64Opcodes.popR8.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 25:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.popR9.ContainsKey(baseAddress + i) && popR9Done == false)
                                    {
                                        popR9Done = true;
                                        x64Opcodes.popR9.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 26:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.popR10.ContainsKey(baseAddress + i) && popR10Done == false)
                                    {
                                        popR10Done = true;
                                        x64Opcodes.popR10.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 27:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.popR11.ContainsKey(baseAddress + i) && popR11Done == false)
                                    {
                                        popR11Done = true;
                                        x64Opcodes.popR11.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 28:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.popR12.ContainsKey(baseAddress + i) && popR12Done == false)
                                    {
                                        popR12Done = true;
                                        x64Opcodes.popR12.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 29:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.popR13.ContainsKey(baseAddress + i) && popR13Done == false)
                                    {
                                        popR13Done = true;
                                        x64Opcodes.popR13.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 30:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.popR14.ContainsKey(baseAddress + i) && popR14Done == false)
                                    {
                                        popR14Done = true;
                                        x64Opcodes.popR14.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 31:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.popR15.ContainsKey(baseAddress + i) && popR15Done == false)
                                    {
                                        popR15Done = true;
                                        x64Opcodes.popR15.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 48:
                                    opcodes = new byte[2];
                                    Array.Copy(bytes, i, opcodes, 0, 2);
                                    if (!x64Opcodes.jmpRsp.ContainsKey(baseAddress + i) && jmpRspDone == false)
                                    {
                                        jmpRspDone = true;
                                        x64Opcodes.jmpRsp.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 49:
                                    opcodes = new byte[2];
                                    Array.Copy(bytes, i, opcodes, 0, 2);
                                    if (!x64Opcodes.callRsp.ContainsKey(baseAddress + i) && callRspDone == false)
                                    {
                                        callRspDone = true;
                                        x64Opcodes.callRsp.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 82:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.add.ContainsKey(baseAddress + i) && addDone == false)
                                    {
                                        addDone = true;
                                        x64Opcodes.add.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 83:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.add.ContainsKey(baseAddress + i) && addDone == false)
                                    {
                                        addDone = true;
                                        x64Opcodes.add.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 84:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.add.ContainsKey(baseAddress + i) && addDone == false)
                                    {
                                        addDone = true;
                                        x64Opcodes.add.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 85:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.add.ContainsKey(baseAddress + i) && addDone == false)
                                    {
                                        addDone = true;
                                        x64Opcodes.add.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 86:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.mov.ContainsKey(baseAddress + i) && movDone == false)
                                    {
                                        movDone = true;
                                        x64Opcodes.mov.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 87:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.mov.ContainsKey(baseAddress + i) && movDone == false)
                                    {
                                        movDone = true;
                                        x64Opcodes.mov.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 88:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.mov.ContainsKey(baseAddress + i) && movDone == false)
                                    {
                                        movDone = true;
                                        x64Opcodes.mov.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 89:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.mov.ContainsKey(baseAddress + i) && movDone == false)
                                    {
                                        movDone = true;
                                        x64Opcodes.mov.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 90:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.sub.ContainsKey(baseAddress + i) && subDone == false)
                                    {
                                        subDone = true;
                                        x64Opcodes.sub.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 91:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.sub.ContainsKey(baseAddress + i) && subDone == false)
                                    {
                                        subDone = true;
                                        x64Opcodes.sub.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 92:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.sub.ContainsKey(baseAddress + i) && subDone == false)
                                    {
                                        subDone = true;
                                        x64Opcodes.sub.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 93:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.sub.ContainsKey(baseAddress + i) && subDone == false)
                                    {
                                        subDone = true;
                                        x64Opcodes.sub.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 94:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.callRax.ContainsKey(baseAddress + i) && callRaxDone == false)
                                    {
                                        callRaxDone = true;
                                        x64Opcodes.callRax.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 95:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.jmpRax.ContainsKey(baseAddress + i) && jmpRaxDone == false)
                                    {
                                        jmpRaxDone = true;
                                        x64Opcodes.jmpRax.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                default:
                                    ret.Error = new ERCException("An error has occured in RopChainGenerator.ParseByteArrayForRopCodes whilst parsing double length x64 instructions");
                                    break;
                            }
                        }
                    }
                    else if (opcodes64[j].Length > 2)
                    {
                        if (bytes[i] == opcodes64[j][0] && i < bytes.Length - 2 && j < opcodes64.Count + 2 && bytes[i + 1] == opcodes64[j][1] && bytes[i + 2] == opcodes64[j][2])
                        {
                            byte[] opcodes = new byte[bytes.Length - i];
                            switch (j)
                            {
                                case 50:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.incRax.ContainsKey(baseAddress + i) && incRaxDone == false)
                                    {
                                        incRaxDone = true;
                                        x64Opcodes.incRax.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 51:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.incRbx.ContainsKey(baseAddress + i) && incRbxDone == false)
                                    {
                                        incRbxDone = true;
                                        x64Opcodes.incRbx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 52:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.incRcx.ContainsKey(baseAddress + i) && incRcxDone == false)
                                    {
                                        incRcxDone = true;
                                        x64Opcodes.incRcx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 53:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.incRdx.ContainsKey(baseAddress + i) && incRdxDone == false)
                                    {
                                        incRdxDone = true;
                                        x64Opcodes.incRdx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 54:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.incRbp.ContainsKey(baseAddress + i) && incRbpDone == false)
                                    {
                                        incRbpDone = true;
                                        x64Opcodes.incRbp.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 55:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.incRsp.ContainsKey(baseAddress + i) && incRspDone == false)
                                    {
                                        incRspDone = true;
                                        x64Opcodes.incRsp.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 56:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.incRsi.ContainsKey(baseAddress + i) && incRsiDone == false)
                                    {
                                        incRsiDone = true;
                                        x64Opcodes.incRsi.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 57:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.incRdi.ContainsKey(baseAddress + i) && incRdiDone == false)
                                    {
                                        incRdiDone = true;
                                        x64Opcodes.incRdi.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 58:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.incR8.ContainsKey(baseAddress + i) && incR8Done == false)
                                    {
                                        incR8Done = true;
                                        x64Opcodes.incR8.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 59:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.incR9.ContainsKey(baseAddress + i) && incR9Done == false)
                                    {
                                        incR9Done = true;
                                        x64Opcodes.incR9.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 60:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.incR10.ContainsKey(baseAddress + i) && incR10Done == false)
                                    {
                                        incR10Done = true;
                                        x64Opcodes.incR10.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 61:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.incR11.ContainsKey(baseAddress + i) && incR11Done == false)
                                    {
                                        incR11Done = true;
                                        x64Opcodes.incR11.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 62:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.incR12.ContainsKey(baseAddress + i) && incR12Done == false)
                                    {
                                        incR12Done = true;
                                        x64Opcodes.incR12.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 63:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.incR13.ContainsKey(baseAddress + i) && incR13Done == false)
                                    {
                                        incR13Done = true;
                                        x64Opcodes.incR13.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 64:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.incR14.ContainsKey(baseAddress + i) && incR14Done == false)
                                    {
                                        incR14Done = true;
                                        x64Opcodes.incR14.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 65:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.incR15.ContainsKey(baseAddress + i) && incR15Done == false)
                                    {
                                        incR15Done = true;
                                        x64Opcodes.incR15.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 66:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.decRax.ContainsKey(baseAddress + i) && decRaxDone == false)
                                    {
                                        decRaxDone = true;
                                        x64Opcodes.decRax.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 67:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.decRbx.ContainsKey(baseAddress + i) && decRbxDone == false)
                                    {
                                        decRbxDone = true;
                                        x64Opcodes.decRbx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 68:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.decRcx.ContainsKey(baseAddress + i) && decRcxDone == false)
                                    {
                                        decRcxDone = true;
                                        x64Opcodes.decRcx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 69:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.decRdx.ContainsKey(baseAddress + i) && decRdxDone == false)
                                    {
                                        decRdxDone = true;
                                        x64Opcodes.decRdx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 70:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.decRbp.ContainsKey(baseAddress + i) && decRbpDone == false)
                                    {
                                        decRbpDone = true;
                                        x64Opcodes.decRbp.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 71:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.decRsp.ContainsKey(baseAddress + i) && decRspDone == false)
                                    {
                                        decRspDone = true;
                                        x64Opcodes.decRsp.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 72:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.decRsi.ContainsKey(baseAddress + i) && decRsiDone == false)
                                    {
                                        decRsiDone = true;
                                        x64Opcodes.decRsi.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 73:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.decRdi.ContainsKey(baseAddress + i) && decRdiDone == false)
                                    {
                                        decRdiDone = true;
                                        x64Opcodes.decRdi.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 74:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.decR8.ContainsKey(baseAddress + i) && decR8Done == false)
                                    {
                                        decR8Done = true;
                                        x64Opcodes.decR8.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 75:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.decR9.ContainsKey(baseAddress + i) && decR9Done == false)
                                    {
                                        decR9Done = true;
                                        x64Opcodes.decR9.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 76:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.decR10.ContainsKey(baseAddress + i) && decR10Done == false)
                                    {
                                        decR10Done = true;
                                        x64Opcodes.decR10.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 77:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.decR11.ContainsKey(baseAddress + i) && decR11Done == false)
                                    {
                                        decR11Done = true;
                                        x64Opcodes.decR11.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 78:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.decR12.ContainsKey(baseAddress + i) && decR12Done == false)
                                    {
                                        decR12Done = true;
                                        x64Opcodes.decR12.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 79:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.decR13.ContainsKey(baseAddress + i) && decR13Done == false)
                                    {
                                        decR13Done = true;
                                        x64Opcodes.decR13.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 80:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.decR14.ContainsKey(baseAddress + i) && decR14Done == false)
                                    {
                                        decR14Done = true;
                                        x64Opcodes.decR14.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 81:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.decR15.ContainsKey(baseAddress + i) && decR15Done == false)
                                    {
                                        decR15Done = true;
                                        x64Opcodes.decR15.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 32:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.xorRax.ContainsKey(baseAddress + i) && xorRaxDone == false)
                                    {
                                        xorRaxDone = true;
                                        x64Opcodes.xorRax.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 33:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.xorRbx.ContainsKey(baseAddress + i) && xorRbxDone == false)
                                    {
                                        xorRbxDone = true;
                                        x64Opcodes.xorRbx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 34:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.xorRcx.ContainsKey(baseAddress + i) && xorRcxDone == false)
                                    {
                                        xorRcxDone = true;
                                        x64Opcodes.xorRcx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 35:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.xorRdx.ContainsKey(baseAddress + i) && xorRdxDone == false)
                                    {
                                        xorRdxDone = true;
                                        x64Opcodes.xorRdx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 36:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.xorRsi.ContainsKey(baseAddress + i) && xorRsiDone == false)
                                    {
                                        xorRsiDone = true;
                                        x64Opcodes.xorRsi.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 37:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.xorRdi.ContainsKey(baseAddress + i) && xorRdiDone == false)
                                    {
                                        xorRdiDone = true;
                                        x64Opcodes.xorRdi.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 38:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.xorR8.ContainsKey(baseAddress + i) && xorR8Done == false)
                                    {
                                        xorR8Done = true;
                                        x64Opcodes.xorR8.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 39:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.xorR9.ContainsKey(baseAddress + i) && xorR9Done == false)
                                    {
                                        xorR9Done = true;
                                        x64Opcodes.xorR9.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 40:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.xorR10.ContainsKey(baseAddress + i) && xorR10Done == false)
                                    {
                                        xorR10Done = true;
                                        x64Opcodes.xorR10.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 41:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.xorR11.ContainsKey(baseAddress + i) && xorR11Done == false)
                                    {
                                        xorR11Done = true;
                                        x64Opcodes.xorR11.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 42:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.xorR12.ContainsKey(baseAddress + i) && xorR12Done == false)
                                    {
                                        xorR12Done = true;
                                        x64Opcodes.xorR12.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 43:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.xorR13.ContainsKey(baseAddress + i) && xorR13Done == false)
                                    {
                                        xorR13Done = true;
                                        x64Opcodes.xorR13.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 44:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.xorR14.ContainsKey(baseAddress + i) && xorR14Done == false)
                                    {
                                        xorR14Done = true;
                                        x64Opcodes.xorR14.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 45:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x64Opcodes.xorR15.ContainsKey(baseAddress + i) && xorR15Done == false)
                                    {
                                        xorR15Done = true;
                                        x64Opcodes.xorR15.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, info.ProcessCore).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                default:
                                    ret.Error = new ERCException("An error has occured in RopChainGenerator.ParseByteArrayForRopCodes whilst parsing triple length x64 instructions");
                                    break;
                            }
                        }
                    }
                }
            }
            return ret;
        }
        #endregion

        #region OptimiseLists
        private void OptimiseLists(ProcessInfo info)
        {
            usableX64Opcodes = new X64Lists();
            var thisList = x64Opcodes.pushRax.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push rax") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.pushRax.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.pushRbx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push rbx") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.pushRbx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.pushRcx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push rcx") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.pushRcx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.pushRdx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push rdx") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.pushRdx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.pushRsp.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push rsp") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.pushRsp.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.pushRbp.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push rbp") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.pushRbp.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.pushRsi.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push rsi") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.pushRsi.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.pushRdi.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push rdi") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.pushRdi.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.pushR8.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push r8") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.pushR8.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.pushR9.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push r9") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.pushR9.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.pushR10.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push r10") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.pushR10.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.pushR11.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push r11") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.pushR11.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.pushR12.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push r12") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.pushR12.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.pushR13.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push r13") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.pushR13.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.pushR14.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push r14") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.pushR14.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.pushR15.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push r15") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.pushR15.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.jmpRsp.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("jmp rsp"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.jmpRsp.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.callRsp.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("call rsp"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.callRsp.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.xorRax.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("xor rax") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.xorRax.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.xorRbx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("xor rbx") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.xorRbx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.xorRcx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("xor rcx") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.xorRcx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.xorRdx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("xor rdx") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.xorRdx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.xorRsi.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("xor rsi") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.xorRsi.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.xorRdi.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("xor rdi") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.xorRdi.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.xorR8.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("xor r8") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.xorR8.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.xorR9.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("xor r9") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.xorR9.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.xorR10.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("xor r10") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.xorR10.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.xorR11.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("xor r11") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.xorR11.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.xorR12.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("xor r12") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.xorR12.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.xorR13.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("xor r13") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.xorR13.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.xorR14.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("xor r14") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.xorR14.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.xorR15.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("xor r15") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.xorR15.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.popRax.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop rax") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.popRax.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.popRbx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop rbx") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.popRbx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.popRcx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop rcx") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.popRcx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.popRdx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop rdx") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.popRdx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.popRsp.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop rsp") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.popRsp.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.popRbp.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop rbp") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.popRbp.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.popRsi.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop rsi") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.popRsi.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.popRdi.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop rdi") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.popRdi.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.popR8.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop r8") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.popR8.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.popR9.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop r9") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.popR9.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.popR10.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop r10") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.popR10.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.popR11.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop r11") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.popR11.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.popR12.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop r12") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.popR12.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.popR13.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop r13") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.popR13.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.popR14.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop r14") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.popR14.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.popR15.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop r15") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.popR15.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.incRax.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc rax") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.incRax.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.incRbx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc rbx") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.incRbx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.incRcx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc rcx") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.incRcx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.incRdx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc rdx") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.incRdx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.incRbp.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc rbp") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.incRbp.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.incRsp.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc rsp") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.incRsp.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.incRsi.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc rsi") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.incRsi.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.incRdi.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc rdi") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.incRdi.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.incR8.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc r8") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.incR8.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.incR9.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc r9") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.incR9.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.incR10.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc r10") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.incR10.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.incR11.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc r11") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.incR11.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.incR12.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc r12") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.incR12.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.incR13.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc r13") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.incR13.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.incR14.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc r14") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.incR14.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.incR15.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc r15") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.incR15.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.decRax.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec rax") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.decRax.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.decRbx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec rbx") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.decRbx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.decRcx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec rcx") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.decRcx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.decRdx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec rdx") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.decRdx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.decRbp.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec rbp") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.decRbp.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.decRsp.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec rsp") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.decRsp.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.decRsi.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec rsi") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.decRsi.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.decRdi.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec rdi") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.decRdi.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.decR8.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec r8") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.decR8.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.decR9.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec r9") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.decR9.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.decR10.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec r10") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.decR10.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.decR11.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec r11") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.decR11.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.decR12.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec r12") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.decR12.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.decR13.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec r13") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.decR13.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.decR14.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec r14") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.decR14.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.decR15.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec r15") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.decR15.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.add.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("add") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.add.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.mov.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("mov") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.mov.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.sub.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("sub") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.sub.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.jmpRax.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("jmp rax"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.jmpRax.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x64Opcodes.callRax.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("call rax"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX64Opcodes.callRax.Add(thisList[i].Key, thisList[i].Value);
                }
            }
        }
        #endregion

        #region GenerateVirtualAllocChain64
        private ErcResult<List<Tuple<byte[], string>>> GenerateVirtualAllocChain64(ProcessInfo info)
        {
            ////////////////////////////////////////////////////////////////
            // VirtualAlloc Template:                                     //
            // RCX: 0x???????????????? ->  Pointer                        //
            // RDX: 0x0000000000000500 ->  dwSize                         //
            // R8 : 0x0000000000001000 ->  flAllocationType               //
            // R9 : 0x0000000000000040 ->  flProtect                      //
            //                                                            //
            // + place a pointer to VirtualAlloc on stack                 //
            // + place ptr to "jmp rsp" on stack                          //
            ////////////////////////////////////////////////////////////////

            ErcResult<List<Tuple<byte[], string>>> VirtualAlloc = new ErcResult<List<Tuple<byte[], string>>>(info.ProcessCore);
            VirtualAlloc.ReturnValue = new List<Tuple<byte[], string>>();
            Register64 regState64 = new Register64();
            regState64 |= Register64.RSP;
            RegisterModifiers64 regModified64 = new RegisterModifiers64();

            foreach (Register64 i in Enum.GetValues(typeof(Register64)))
            {
                SetRegisterModifier(regModified64.RSP, i, regModified64);
                SetRegisterModifier(i, regModified64.RSP, regModified64);
            }

            RegisterLists64 regLists64 = new RegisterLists64();

            #region Populate RCX
            regLists64.rcxList = new List<Tuple<byte[], string>>();
            for (int i = 0; i < usableX64Opcodes.popRcx.Count; i++)
            {
                if (!regState64.HasFlag(Register64.RCX))
                {
                    if (usableX64Opcodes.popRcx.ElementAt(i).Value.Length <= 14 && !usableX64Opcodes.popRcx.ElementAt(i).Value.Contains("invalid"))
                    {
                        for (int j = 0; j< usableX64Opcodes.pushRsp.Count; j++)
                        {
                            if (usableX64Opcodes.pushRsp.ElementAt(j).Value.Length <= 15 && !usableX64Opcodes.pushRsp.ElementAt(j).Value.Contains("invalid"))
                            {
                                regLists64.rcxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.pushRsp.ElementAt(j).Key),
                                    usableX64Opcodes.pushRsp.ElementAt(j).Value));
                                regLists64.rcxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popRcx.ElementAt(i).Key),
                                    usableX64Opcodes.popRcx.ElementAt(i).Value));
                                regState64 |= Register64.RCX;
                                i = usableX64Opcodes.popRcx.Count;
                                j = usableX64Opcodes.pushRsp.Count;
                            }
                        }
                    }
                }
                else
                {
                    i = usableX64Opcodes.popRcx.Count;
                }
            }
            if (!regState64.HasFlag(Register64.RCX))
            {
                var movInstruction = GetMovInstruction(Register64.RCX, Register64.RSP, regModified64);
                if (movInstruction != null)
                {
                    regLists64.rcxList.Add(Tuple.Create(movInstruction.Item1, movInstruction.Item2));
                    SetRegisterModifier(Register64.RCX, Register64.RSP, regModified64);
                    regState64 &= ~Register64.RSP;
                    regState64 |= Register64.RCX;
                }
            }
            if (!regState64.HasFlag(Register64.RCX))
            {
                regLists64.rcxList = null;
                regLists64.rcxList = new List<Tuple<byte[], string>>();
                byte[] nullBytes = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                regLists64.rcxList.Add(Tuple.Create(nullBytes,
                    "Unable to find appropriate instruction. RCX must be allocated manually"));
                regState64 |= Register64.RCX;
            }
            #endregion

            #region Populate RDX
            SetRegisterModifier(Register64.RDX, Register64.RCX, regModified64);
            regLists64.rdxList = null;
            regLists64.rdxList = new List<Tuple<byte[], string>>();
            for (int i = 0; i < usableX64Opcodes.popRdx.Count; i++)
            {
                if (!regState64.HasFlag(Register64.RDX))
                {
                    if (usableX64Opcodes.popRdx.ElementAt(i).Value.Length <= 14 && !usableX64Opcodes.popRdx.ElementAt(i).Value.Contains("invalid"))
                    {
                        byte[] dwSize = { 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                        regLists64.rdxList.Add(Tuple.Create(dwSize, "dwSize"));
                        regLists64.rdxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popRdx.ElementAt(i).Key),
                            usableX64Opcodes.popRdx.ElementAt(i).Value));
                        regState64 |= Register64.RDX;
                        i = usableX64Opcodes.popRdx.Count;
                    }
                }
                else
                {
                    i = usableX64Opcodes.popRdx.Count;
                }
            }
            if (!regState64.HasFlag(Register64.RDX))
            {
                var xorEbx = GetXorInstruction(Register64.RDX);
                if (xorEbx != null)
                {
                    regLists64.rdxList.Add(Tuple.Create(xorEbx.Item1, xorEbx.Item2));
                    if (usableX64Opcodes.incRdx.Count > 0)
                    {
                        if (usableX64Opcodes.incRdx.ElementAt(0).Value.Length <= 14)
                        {
                            regLists64.rdxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.incRdx.ElementAt(0).Key),
                                usableX64Opcodes.incRdx.ElementAt(0).Value));
                            regState64 |= Register64.RDX;
                        }
                    }

                }
            }
            if (!regState64.HasFlag(Register64.RDX))
            {
                var zeroEbx = ZeroRegister(Register64.RDX, regModified64);
                if (zeroEbx != null && usableX64Opcodes.incRdx.Count > 0 && usableX64Opcodes.incRdx.ElementAt(0).Value.Length <= 14)
                {
                    for (int i = 0; i < zeroEbx.Count; i++)
                    {
                        regLists64.rdxList.Add(Tuple.Create(zeroEbx[i].Item1, zeroEbx[i].Item2));
                    }
                    regLists64.rdxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.incRdx.ElementAt(0).Key),
                        usableX64Opcodes.incRdx.ElementAt(0).Value));
                    SetRegisterModifier(Register64.RDX, zeroEbx[0].Item3, regModified64);
                    regState64 &= ~zeroEbx[0].Item3;
                    regState64 |= Register64.RDX;
                }
            }
            if (!regState64.HasFlag(Register64.RDX))
            {
                foreach (Register64 i in Enum.GetValues(typeof(Register64)))
                {
                    var popInstruction = GetPopInstruction(Register64.RDX, i, regModified64);
                    if (popInstruction != null)
                    {
                        for (int j = 0; j < usableX64Opcodes.add.Count; j++)
                        {
                            if (!regState64.HasFlag(Register64.RDX))
                            {
                                var strings = usableX64Opcodes.add.ElementAt(j).Value.Split(',');
                                if (strings[0].Contains(" rdx") && strings[1].Contains(i.ToString().ToLower()))
                                {
                                    regLists64.rdxList.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                    byte[] bytes = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
                                    regLists64.rdxList.Add(Tuple.Create(bytes, "To be popped into " + i.ToString()));
                                    regLists64.rdxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.add.ElementAt(j).Key),
                                        usableX64Opcodes.add.ElementAt(j).Value));
                                    regLists64.rdxList.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                    bytes = new byte[] { 0x01, 0x06, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
                                    regLists64.rdxList.Add(Tuple.Create(bytes, "To be popped into " + i.ToString()));
                                    regLists64.rdxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.add.ElementAt(j).Key),
                                        usableX64Opcodes.add.ElementAt(j).Value));
                                    SetRegisterModifier(Register64.RDX, i, regModified64);
                                    regState64 &= ~i;
                                    regState64 |= Register64.RDX;
                                }
                            }
                        }
                    }
                }
            }
            if (!regState64.HasFlag(Register64.RDX))
            {
                regLists64.rdxList = null;
                regLists64.rdxList = new List<Tuple<byte[], string>>();
                byte[] nullBytes = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                regLists64.rdxList.Add(Tuple.Create(nullBytes,
                    "Unable to find appropriate instruction. EBX must be allocated manually"));
                regState64 |= Register64.RDX;
            }
            #endregion

            #region Populate R8
            SetRegisterModifier(Register64.R8, Register64.RCX, regModified64);
            SetRegisterModifier(Register64.R8, Register64.RDX, regModified64);
            regLists64.r8List = null;
            regLists64.r8List = new List<Tuple<byte[], string>>();
            var xorR8 = GetXorInstruction(Register64.R8);
            if (xorR8 != null)
            {
                foreach (Register64 i in Enum.GetValues(typeof(Register64)))
                {
                    if (!regState64.HasFlag(Register64.R8))
                    {
                        var popInstruction = GetPopInstruction(Register64.R8, i, regModified64);
                        if (popInstruction != null)
                        {
                            var addInstruction = GetAddInstruction(Register64.R8, i);
                            if (addInstruction != null)
                            {
                                byte[] add1 = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
                                byte[] add2 = new byte[] { 0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
                                regLists64.r8List.Add(Tuple.Create(xorR8.Item1, xorR8.Item2));
                                regLists64.r8List.Add(Tuple.Create(add1, "To be placed into " + addInstruction.Item3.ToString()));
                                regLists64.r8List.Add(Tuple.Create(addInstruction.Item1, addInstruction.Item2));
                                regLists64.r8List.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                regLists64.r8List.Add(Tuple.Create(add2, "To be placed into " + addInstruction.Item3.ToString() + " combined = 0x0000000000001000"));
                                regLists64.r8List.Add(Tuple.Create(addInstruction.Item1, addInstruction.Item2));
                                regLists64.r8List.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                SetRegisterModifier(Register64.R8, i, regModified64);
                                regState64 &= ~i;
                                regState64 |= Register64.R8;
                            }
                        }
                    }
                }
            }
            if (!regState64.HasFlag(Register64.R8))
            {
                foreach (Register64 i in Enum.GetValues(typeof(Register64)))
                {
                    if (!regState64.HasFlag(Register64.R8))
                    {
                        var popInstruction = GetPopInstruction(Register64.R8, i, regModified64);
                        if (popInstruction != null)
                        {
                            foreach (Register64 j in Enum.GetValues(typeof(Register64)))
                            {
                                if (!regState64.HasFlag(Register64.R8) && i != j)
                                {
                                    var popInstruction2 = GetPopInstruction(Register64.R8, j, regModified64);
                                    if (popInstruction2 != null)
                                    {
                                        var addInstruction = GetAddInstruction(i, j);
                                        if (addInstruction != null)
                                        {
                                            var movInstruction = GetMovInstruction(Register64.R8, i, regModified64);
                                            if (movInstruction != null)
                                            {
                                                byte[] add1 = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
                                                byte[] add2 = new byte[] { 0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
                                                regLists64.r8List.Add(Tuple.Create(add1, "To be placed into " + popInstruction.Item3.ToString()));
                                                regLists64.r8List.Add(Tuple.Create(popInstruction2.Item1, popInstruction2.Item2));
                                                regLists64.r8List.Add(Tuple.Create(add2, "To be placed into " + addInstruction.Item3.ToString() + " combined = 0x0000000000000500"));
                                                regLists64.r8List.Add(Tuple.Create(addInstruction.Item1, addInstruction.Item2));
                                                regLists64.r8List.Add(Tuple.Create(movInstruction.Item1, movInstruction.Item2));
                                                regLists64.r8List.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                                SetRegisterModifier(Register64.R8, i, regModified64);
                                                SetRegisterModifier(Register64.R8, j, regModified64);
                                                regState64 &= ~i;
                                                regState64 &= ~j;
                                                regState64 |= Register64.R8;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (!regState64.HasFlag(Register64.R8))
            {
                for (int i = 0; i < usableX64Opcodes.popR8.Count; i++)
                {
                    if (!regState64.HasFlag(Register64.R8))
                    {
                        if (usableX64Opcodes.popR8.ElementAt(i).Value.Length <= 14 && !usableX64Opcodes.popR8.ElementAt(i).Value.Contains("invalid"))
                        {
                            byte[] flAllocationType = { 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                            regLists64.r8List.Add(Tuple.Create(flAllocationType, "flAllocationType"));
                            regLists64.r8List.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popR8.ElementAt(i).Key),
                                usableX64Opcodes.popR8.ElementAt(i).Value));
                            regState64 |= Register64.R8;
                            i = usableX64Opcodes.popR8.Count;
                        }
                    }
                    else
                    {
                        i = usableX64Opcodes.popR8.Count;
                    }
                }
            }
            if (!regState64.HasFlag(Register64.R8))
            {
                regLists64.r8List = null;
                regLists64.r8List = new List<Tuple<byte[], string>>();
                byte[] nullBytes = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                regLists64.r8List.Add(Tuple.Create(nullBytes,
                    "Unable to find appropriate instruction. R8 must be allocated manually"));
                regState64 |= Register64.R8;
            }
            #endregion

            #region Populate R9
            SetRegisterModifier(Register64.R9, Register64.RCX, regModified64);
            SetRegisterModifier(Register64.R9, Register64.RDX, regModified64);
            SetRegisterModifier(Register64.R9, Register64.R8, regModified64);
            regLists64.r9List = null;
            regLists64.r9List = new List<Tuple<byte[], string>>();
            var xorECX = GetXorInstruction(Register64.R9);
            if (xorECX != null)
            {
                foreach (Register64 i in Enum.GetValues(typeof(Register64)))
                {
                    if (!regState64.HasFlag(Register64.R9))
                    {
                        var popInstruction = GetPopInstruction(Register64.R9, i, regModified64);
                        if (popInstruction != null)
                        {
                            var addInstruction = GetAddInstruction(Register64.R9, i);
                            if (addInstruction != null)
                            {
                                byte[] add1 = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
                                byte[] add2 = new byte[] { 0x41, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
                                regLists64.r9List.Add(Tuple.Create(xorECX.Item1, xorECX.Item2));
                                regLists64.r9List.Add(Tuple.Create(add1, "To be placed into " + addInstruction.Item3.ToString()));
                                regLists64.r9List.Add(Tuple.Create(addInstruction.Item1, addInstruction.Item2));
                                regLists64.r9List.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                regLists64.r9List.Add(Tuple.Create(add2, "To be placed into " + addInstruction.Item3.ToString() + " combined = 0x00000040"));
                                regLists64.r9List.Add(Tuple.Create(addInstruction.Item1, addInstruction.Item2));
                                regLists64.r9List.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                SetRegisterModifier(Register64.R9, i, regModified64);
                                regState64 &= ~i;
                                regState64 |= Register64.R9;
                            }
                        }
                    }
                }
            }
            if (!regState64.HasFlag(Register64.R9))
            {
                foreach (Register64 i in Enum.GetValues(typeof(Register64)))
                {
                    if (!regState64.HasFlag(Register64.R9))
                    {
                        var popInstruction = GetPopInstruction(Register64.R9, i, regModified64);
                        if (popInstruction != null)
                        {
                            foreach (Register64 j in Enum.GetValues(typeof(Register64)))
                            {
                                if (!regState64.HasFlag(Register64.R9) && i != j)
                                {
                                    var popInstruction2 = GetPopInstruction(Register64.R9, j, regModified64);
                                    if (popInstruction2 != null)
                                    {
                                        var addInstruction = GetAddInstruction(i, j);
                                        if (addInstruction != null)
                                        {
                                            var movInstruction = GetMovInstruction(Register64.R9, i, regModified64);
                                            if (movInstruction != null)
                                            {
                                                byte[] add1 = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
                                                byte[] add2 = new byte[] { 0x41, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
                                                regLists64.r9List.Add(Tuple.Create(add1, "To be placed into " + popInstruction.Item3.ToString()));
                                                regLists64.r9List.Add(Tuple.Create(popInstruction2.Item1, popInstruction2.Item2));
                                                regLists64.r9List.Add(Tuple.Create(add2, "To be placed into " + addInstruction.Item3.ToString() + " combined = 0x00000000000040"));
                                                regLists64.r9List.Add(Tuple.Create(addInstruction.Item1, addInstruction.Item2));
                                                regLists64.r9List.Add(Tuple.Create(movInstruction.Item1, movInstruction.Item2));
                                                regLists64.r9List.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                                SetRegisterModifier(Register64.R9, i, regModified64);
                                                SetRegisterModifier(Register64.R9, j, regModified64);
                                                regState64 &= ~i;
                                                regState64 &= ~j;
                                                regState64 |= Register64.R9;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (!regState64.HasFlag(Register64.R9))
            {
                for (int i = 0; i < usableX64Opcodes.popR9.Count; i++)
                {
                    if (!regState64.HasFlag(Register64.R9))
                    {
                        if (usableX64Opcodes.popR9.ElementAt(i).Value.Length <= 14 && !usableX64Opcodes.popR9.ElementAt(i).Value.Contains("invalid"))
                        {
                            byte[] flProtect = { 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                            regLists64.r9List.Add(Tuple.Create(flProtect, "flProtect"));
                            regLists64.r9List.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popR9.ElementAt(i).Key),
                                usableX64Opcodes.popR9.ElementAt(i).Value));
                            regState64 |= Register64.R9;
                            i = usableX64Opcodes.popR9.Count;
                        }
                    }
                    else
                    {
                        i = usableX64Opcodes.popR9.Count;
                    }
                }
            }
            if (!regState64.HasFlag(Register64.R9))
            {
                regLists64.r9List = null;
                regLists64.r9List = new List<Tuple<byte[], string>>();
                byte[] nullBytes = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                regLists64.r9List.Add(Tuple.Create(nullBytes,
                    "Unable to find appropriate instruction. R9 must be allocated manually"));
                regState64 |= Register64.R9;
            }
            #endregion

            VirtualAlloc.ReturnValue = BuildRopChain(RopMethod.VirtualAlloc, regLists64, regModified64);
            return VirtualAlloc;
        }
        #endregion

        #region GenerateHeapCreateChain
        private ErcResult<List<Tuple<byte[], string>>> GenerateHeapCreateChain64(ProcessInfo info)
        {
            ////////////////////////////////////////////////////////////////
            // HeapCreate Template:                                       //
            // RCX: 0x0000000000040000 ->  flOptions                      //
            // RDX: 0x0000000000000500 ->  dwInitialSize                  //
            // R8 : 0x0000000000001000 ->  dwMaximumSize                  //
            //                                                            //
            // + place a pointer to HeapCreate on stack                   //
            // + place ptr to "jmp rsp" on stack                          //
            ////////////////////////////////////////////////////////////////

            ErcResult<List<Tuple<byte[], string>>> HeapCreate = new ErcResult<List<Tuple<byte[], string>>>(info.ProcessCore);
            HeapCreate.ReturnValue = new List<Tuple<byte[], string>>();
            Register64 regState64 = new Register64();
            regState64 |= Register64.RSP;
            RegisterModifiers64 regModified64 = new RegisterModifiers64();

            foreach (Register64 i in Enum.GetValues(typeof(Register64)))
            {
                SetRegisterModifier(regModified64.RSP, i, regModified64);
                SetRegisterModifier(i, regModified64.RSP, regModified64);
            }

            RegisterLists64 regLists64 = new RegisterLists64();

            #region Populate RCX
            regLists64.rcxList = new List<Tuple<byte[], string>>();
            for (int i = 0; i < usableX64Opcodes.popRcx.Count; i++)
            {
                if (!regState64.HasFlag(Register64.RCX))
                {
                    if (usableX64Opcodes.popRcx.ElementAt(i).Value.Length <= 14 && !usableX64Opcodes.popRcx.ElementAt(i).Value.Contains("invalid"))
                    {
                        byte[] flOptions = new byte[] { 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 };
                        regLists64.rcxList.Add(Tuple.Create(flOptions,"flOptions"));
                        regLists64.rcxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popRcx.ElementAt(i).Key),
                            usableX64Opcodes.popRcx.ElementAt(i).Value));
                        regState64 |= Register64.RCX;
                        i = usableX64Opcodes.popRcx.Count;
                    }
                }
                else
                {
                    i = usableX64Opcodes.popRcx.Count;
                }
            }
            if (!regState64.HasFlag(Register64.RCX))
            {
                foreach (Register64 i in Enum.GetValues(typeof(Register64)))
                {
                    var popInstruction = GetPopInstruction(Register64.RCX, i, regModified64);
                    if (popInstruction != null)
                    {
                        for (int j = 0; j < usableX64Opcodes.add.Count; j++)
                        {
                            var strings = usableX64Opcodes.add.ElementAt(j).Value.Split(',');
                            if (strings[0].Contains(" rcx") && strings[1].Contains(i.ToString().ToLower()))
                            {

                                byte[] bytes = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
                                regLists64.rcxList.Add(Tuple.Create(bytes, "To be popped into " + i.ToString()));
                                regLists64.rcxList.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                regLists64.rcxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.add.ElementAt(j).Key),
                                    usableX64Opcodes.add.ElementAt(j).Value));
                                bytes = new byte[] { 0x01, 0x06, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
                                regLists64.rcxList.Add(Tuple.Create(bytes, "To be popped into " + i.ToString()));
                                regLists64.rcxList.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                regLists64.rcxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.add.ElementAt(j).Key),
                                    usableX64Opcodes.add.ElementAt(j).Value));
                                SetRegisterModifier(Register64.RCX, i, regModified64);
                                regState64 &= ~i;
                                regState64 |= Register64.RCX;
                                j = usableX64Opcodes.add.Count + 1;
                            }
                        }
                    }
                }
            }
            if (!regState64.HasFlag(Register64.RCX))
            {
                regLists64.rcxList = null;
                regLists64.rcxList = new List<Tuple<byte[], string>>();
                byte[] nullBytes = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                regLists64.rcxList.Add(Tuple.Create(nullBytes,
                    "Unable to find appropriate instruction. RCX must be allocated manually"));
                regState64 |= Register64.RCX;
            }
            #endregion

            #region Populate RDX
            SetRegisterModifier(Register64.RDX, Register64.RCX, regModified64);
            regLists64.rdxList = null;
            regLists64.rdxList = new List<Tuple<byte[], string>>();
            for (int i = 0; i < usableX64Opcodes.popRdx.Count; i++)
            {
                if (!regState64.HasFlag(Register64.RDX))
                {
                    if (usableX64Opcodes.popRdx.ElementAt(i).Value.Length <= 14 && !usableX64Opcodes.popRdx.ElementAt(i).Value.Contains("invalid"))
                    {
                        byte[] dwSize = { 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                        regLists64.rdxList.Add(Tuple.Create(dwSize, "dwSize"));
                        regLists64.rdxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popRdx.ElementAt(i).Key),
                            usableX64Opcodes.popRdx.ElementAt(i).Value));
                        regState64 |= Register64.RDX;
                        i = usableX64Opcodes.popRdx.Count;
                    }
                }
                else
                {
                    i = usableX64Opcodes.popRdx.Count;
                }
            }
            if (!regState64.HasFlag(Register64.RDX))
            {
                var xorEbx = GetXorInstruction(Register64.RDX);
                if (xorEbx != null)
                {
                    regLists64.rdxList.Add(Tuple.Create(xorEbx.Item1, xorEbx.Item2));
                    if (usableX64Opcodes.incRdx.Count > 0)
                    {
                        if (usableX64Opcodes.incRdx.ElementAt(0).Value.Length <= 14)
                        {
                            regLists64.rdxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.incRdx.ElementAt(0).Key),
                                usableX64Opcodes.incRdx.ElementAt(0).Value));
                            regState64 |= Register64.RDX;
                        }
                    }

                }
            }
            if (!regState64.HasFlag(Register64.RDX))
            {
                var zeroEbx = ZeroRegister(Register64.RDX, regModified64);
                if (zeroEbx != null && usableX64Opcodes.incRdx.Count > 0 && usableX64Opcodes.incRdx.ElementAt(0).Value.Length <= 14)
                {
                    for (int i = 0; i < zeroEbx.Count; i++)
                    {
                        regLists64.rdxList.Add(Tuple.Create(zeroEbx[i].Item1, zeroEbx[i].Item2));
                    }
                    regLists64.rdxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.incRdx.ElementAt(0).Key),
                        usableX64Opcodes.incRdx.ElementAt(0).Value));
                    SetRegisterModifier(Register64.RDX, zeroEbx[0].Item3, regModified64);
                    regState64 &= ~zeroEbx[0].Item3;
                    regState64 |= Register64.RDX;
                }
            }
            if (!regState64.HasFlag(Register64.RDX))
            {
                foreach (Register64 i in Enum.GetValues(typeof(Register64)))
                {
                    var popInstruction = GetPopInstruction(Register64.RDX, i, regModified64);
                    if (popInstruction != null)
                    {
                        for (int j = 0; j < usableX64Opcodes.add.Count; j++)
                        {
                            if (!regState64.HasFlag(Register64.RDX))
                            {
                                var strings = usableX64Opcodes.add.ElementAt(j).Value.Split(',');
                                if (strings[0].Contains(" rdx") && strings[1].Contains(i.ToString().ToLower()))
                                {
                                    
                                    byte[] bytes = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
                                    regLists64.rdxList.Add(Tuple.Create(bytes, "To be popped into " + i.ToString()));
                                    regLists64.rdxList.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                    regLists64.rdxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.add.ElementAt(j).Key),
                                        usableX64Opcodes.add.ElementAt(j).Value));
                                    bytes = new byte[] { 0x01, 0x06, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
                                    regLists64.rdxList.Add(Tuple.Create(bytes, "To be popped into " + i.ToString()));
                                    regLists64.rdxList.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                    regLists64.rdxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.add.ElementAt(j).Key),
                                        usableX64Opcodes.add.ElementAt(j).Value));
                                    SetRegisterModifier(Register64.RDX, i, regModified64);
                                    regState64 &= ~i;
                                    regState64 |= Register64.RDX;
                                }
                            }
                        }
                    }
                }
            }
            if (!regState64.HasFlag(Register64.RDX))
            {
                regLists64.rdxList = null;
                regLists64.rdxList = new List<Tuple<byte[], string>>();
                byte[] nullBytes = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                regLists64.rdxList.Add(Tuple.Create(nullBytes,
                    "Unable to find appropriate instruction. EBX must be allocated manually"));
                regState64 |= Register64.RDX;
            }
            #endregion

            #region Populate R8
            SetRegisterModifier(Register64.R8, Register64.RCX, regModified64);
            SetRegisterModifier(Register64.R8, Register64.RDX, regModified64);
            regLists64.r8List = null;
            regLists64.r8List = new List<Tuple<byte[], string>>();
            var xorR8 = GetXorInstruction(Register64.R8);
            if (xorR8 != null)
            {
                foreach (Register64 i in Enum.GetValues(typeof(Register64)))
                {
                    if (!regState64.HasFlag(Register64.R8))
                    {
                        var popInstruction = GetPopInstruction(Register64.R8, i, regModified64);
                        if (popInstruction != null)
                        {
                            var addInstruction = GetAddInstruction(Register64.R8, i);
                            if (addInstruction != null)
                            {
                                byte[] add1 = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
                                byte[] add2 = new byte[] { 0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
                                regLists64.r8List.Add(Tuple.Create(xorR8.Item1, xorR8.Item2));
                                regLists64.r8List.Add(Tuple.Create(add1, "To be placed into " + addInstruction.Item3.ToString()));
                                regLists64.r8List.Add(Tuple.Create(addInstruction.Item1, addInstruction.Item2));
                                regLists64.r8List.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                regLists64.r8List.Add(Tuple.Create(add2, "To be placed into " + addInstruction.Item3.ToString() + " combined = 0x0000000000001000"));
                                regLists64.r8List.Add(Tuple.Create(addInstruction.Item1, addInstruction.Item2));
                                regLists64.r8List.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                SetRegisterModifier(Register64.R8, i, regModified64);
                                regState64 &= ~i;
                                regState64 |= Register64.R8;
                            }
                        }
                    }
                }
            }
            if (!regState64.HasFlag(Register64.R8))
            {
                foreach (Register64 i in Enum.GetValues(typeof(Register64)))
                {
                    if (!regState64.HasFlag(Register64.R8))
                    {
                        var popInstruction = GetPopInstruction(Register64.R8, i, regModified64);
                        if (popInstruction != null)
                        {
                            foreach (Register64 j in Enum.GetValues(typeof(Register64)))
                            {
                                if (!regState64.HasFlag(Register64.R8) && i != j)
                                {
                                    var popInstruction2 = GetPopInstruction(Register64.R8, j, regModified64);
                                    if (popInstruction2 != null)
                                    {
                                        var addInstruction = GetAddInstruction(i, j);
                                        if (addInstruction != null)
                                        {
                                            var movInstruction = GetMovInstruction(Register64.R8, i, regModified64);
                                            if (movInstruction != null)
                                            {
                                                byte[] add1 = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
                                                byte[] add2 = new byte[] { 0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
                                                regLists64.r8List.Add(Tuple.Create(add1, "To be placed into " + popInstruction.Item3.ToString()));
                                                regLists64.r8List.Add(Tuple.Create(popInstruction2.Item1, popInstruction2.Item2));
                                                regLists64.r8List.Add(Tuple.Create(add2, "To be placed into " + addInstruction.Item3.ToString() + " combined = 0x0000000000000500"));
                                                regLists64.r8List.Add(Tuple.Create(addInstruction.Item1, addInstruction.Item2));
                                                regLists64.r8List.Add(Tuple.Create(movInstruction.Item1, movInstruction.Item2));
                                                regLists64.r8List.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                                SetRegisterModifier(Register64.R8, i, regModified64);
                                                SetRegisterModifier(Register64.R8, j, regModified64);
                                                regState64 &= ~i;
                                                regState64 &= ~j;
                                                regState64 |= Register64.R8;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (!regState64.HasFlag(Register64.R8))
            {
                for (int i = 0; i < usableX64Opcodes.popR8.Count; i++)
                {
                    if (!regState64.HasFlag(Register64.R8))
                    {
                        if (usableX64Opcodes.popR8.ElementAt(i).Value.Length <= 14 && !usableX64Opcodes.popR8.ElementAt(i).Value.Contains("invalid"))
                        {
                            byte[] flAllocationType = { 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                            regLists64.r8List.Add(Tuple.Create(flAllocationType, "flAllocationType"));
                            regLists64.r8List.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popR8.ElementAt(i).Key),
                                usableX64Opcodes.popR8.ElementAt(i).Value));
                            regState64 |= Register64.R8;
                            i = usableX64Opcodes.popR8.Count;
                        }
                    }
                    else
                    {
                        i = usableX64Opcodes.popR8.Count;
                    }
                }
            }
            if (!regState64.HasFlag(Register64.R8))
            {
                regLists64.r8List = null;
                regLists64.r8List = new List<Tuple<byte[], string>>();
                byte[] nullBytes = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                regLists64.r8List.Add(Tuple.Create(nullBytes,
                    "Unable to find appropriate instruction. R8 must be allocated manually"));
                regState64 |= Register64.R8;
            }
            #endregion

            HeapCreate.ReturnValue = BuildRopChain(RopMethod.HeapCreate, regLists64, regModified64);
            return HeapCreate;

        }
        #endregion

        #region GenerateVirtualProtectChain
        private ErcResult<List<Tuple<byte[], string>>> GenerateVirtualProtectChain64(ProcessInfo info)
        {
            ////////////////////////////////////////////////////////////////
            // VirtualProtect Template:                                   //
            // RCX: 0x???????????????? ->  Pointer                        //
            // RDX: 0x0000000000000500 ->  dwSize                         //
            // R8 : 0x0000000000001000 ->  flNewProtect                   //
            // R9 : 0x???????????????? ->  lpflOldProtect                 //
            //                                                            //
            // + place a pointer to VirtualProtect on stack               //
            // + place ptr to "jmp rsp" on stack                          //
            ////////////////////////////////////////////////////////////////

            ErcResult<List<Tuple<byte[], string>>> VirtualProtect = new ErcResult<List<Tuple<byte[], string>>>(info.ProcessCore);
            VirtualProtect.ReturnValue = new List<Tuple<byte[], string>>();
            Register64 regState64 = new Register64();
            regState64 |= Register64.RSP;
            RegisterModifiers64 regModified64 = new RegisterModifiers64();

            foreach (Register64 i in Enum.GetValues(typeof(Register64)))
            {
                SetRegisterModifier(regModified64.RSP, i, regModified64);
                SetRegisterModifier(i, regModified64.RSP, regModified64);
            }

            RegisterLists64 regLists64 = new RegisterLists64();

            #region Populate RCX
            regLists64.rcxList = new List<Tuple<byte[], string>>();
            for (int i = 0; i < usableX64Opcodes.popRcx.Count; i++)
            {
                if (!regState64.HasFlag(Register64.RCX))
                {
                    if (usableX64Opcodes.popRcx.ElementAt(i).Value.Length <= 14 && !usableX64Opcodes.popRcx.ElementAt(i).Value.Contains("invalid"))
                    {
                        for (int j = 0; j < usableX64Opcodes.pushRsp.Count; j++)
                        {
                            if (usableX64Opcodes.pushRsp.ElementAt(j).Value.Length <= 15 && !usableX64Opcodes.pushRsp.ElementAt(j).Value.Contains("invalid"))
                            {
                                regLists64.rcxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.pushRsp.ElementAt(j).Key),
                                    usableX64Opcodes.pushRsp.ElementAt(j).Value));
                                regLists64.rcxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popRcx.ElementAt(i).Key),
                                    usableX64Opcodes.popRcx.ElementAt(i).Value));
                                regState64 |= Register64.RCX;
                                i = usableX64Opcodes.popRcx.Count;
                                j = usableX64Opcodes.pushRsp.Count;
                            }
                        }
                    }
                }
                else
                {
                    i = usableX64Opcodes.popRcx.Count;
                }
            }
            if (!regState64.HasFlag(Register64.RCX))
            {
                var movInstruction = GetMovInstruction(Register64.RCX, Register64.RSP, regModified64);
                if (movInstruction != null)
                {
                    regLists64.rcxList.Add(Tuple.Create(movInstruction.Item1, movInstruction.Item2));
                    SetRegisterModifier(Register64.RCX, Register64.RSP, regModified64);
                    regState64 &= ~Register64.RSP;
                    regState64 |= Register64.RCX;
                }
            }
            if (!regState64.HasFlag(Register64.RCX))
            {
                regLists64.rcxList = null;
                regLists64.rcxList = new List<Tuple<byte[], string>>();
                byte[] nullBytes = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                regLists64.rcxList.Add(Tuple.Create(nullBytes,
                    "Unable to find appropriate instruction. RCX must be allocated manually"));
                regState64 |= Register64.RCX;
            }
            #endregion

            #region Populate RDX
            SetRegisterModifier(Register64.RDX, Register64.RCX, regModified64);
            regLists64.rdxList = null;
            regLists64.rdxList = new List<Tuple<byte[], string>>();
            for (int i = 0; i < usableX64Opcodes.popRdx.Count; i++)
            {
                if (!regState64.HasFlag(Register64.RDX))
                {
                    if (usableX64Opcodes.popRdx.ElementAt(i).Value.Length <= 14 && !usableX64Opcodes.popRdx.ElementAt(i).Value.Contains("invalid"))
                    {
                        byte[] dwSize = { 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                        regLists64.rdxList.Add(Tuple.Create(dwSize, "dwSize"));
                        regLists64.rdxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popRdx.ElementAt(i).Key),
                            usableX64Opcodes.popRdx.ElementAt(i).Value));
                        regState64 |= Register64.RDX;
                        i = usableX64Opcodes.popRdx.Count;
                    }
                }
                else
                {
                    i = usableX64Opcodes.popRdx.Count;
                }
            }
            if (!regState64.HasFlag(Register64.RDX))
            {
                var xorEbx = GetXorInstruction(Register64.RDX);
                if (xorEbx != null)
                {
                    regLists64.rdxList.Add(Tuple.Create(xorEbx.Item1, xorEbx.Item2));
                    if (usableX64Opcodes.incRdx.Count > 0)
                    {
                        if (usableX64Opcodes.incRdx.ElementAt(0).Value.Length <= 14)
                        {
                            regLists64.rdxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.incRdx.ElementAt(0).Key),
                                usableX64Opcodes.incRdx.ElementAt(0).Value));
                            regState64 |= Register64.RDX;
                        }
                    }

                }
            }
            if (!regState64.HasFlag(Register64.RDX))
            {
                var zeroEbx = ZeroRegister(Register64.RDX, regModified64);
                if (zeroEbx != null && usableX64Opcodes.incRdx.Count > 0 && usableX64Opcodes.incRdx.ElementAt(0).Value.Length <= 14)
                {
                    for (int i = 0; i < zeroEbx.Count; i++)
                    {
                        regLists64.rdxList.Add(Tuple.Create(zeroEbx[i].Item1, zeroEbx[i].Item2));
                    }
                    regLists64.rdxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.incRdx.ElementAt(0).Key),
                        usableX64Opcodes.incRdx.ElementAt(0).Value));
                    SetRegisterModifier(Register64.RDX, zeroEbx[0].Item3, regModified64);
                    regState64 &= ~zeroEbx[0].Item3;
                    regState64 |= Register64.RDX;
                }
            }
            if (!regState64.HasFlag(Register64.RDX))
            {
                foreach (Register64 i in Enum.GetValues(typeof(Register64)))
                {
                    var popInstruction = GetPopInstruction(Register64.RDX, i, regModified64);
                    if (popInstruction != null)
                    {
                        for (int j = 0; j < usableX64Opcodes.add.Count; j++)
                        {
                            if (!regState64.HasFlag(Register64.RDX))
                            {
                                var strings = usableX64Opcodes.add.ElementAt(j).Value.Split(',');
                                if (strings[0].Contains(" rdx") && strings[1].Contains(i.ToString().ToLower()))
                                {
                                    regLists64.rdxList.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                    byte[] bytes = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
                                    regLists64.rdxList.Add(Tuple.Create(bytes, "To be popped into " + i.ToString()));
                                    regLists64.rdxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.add.ElementAt(j).Key),
                                        usableX64Opcodes.add.ElementAt(j).Value));
                                    regLists64.rdxList.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                    bytes = new byte[] { 0x01, 0x06, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
                                    regLists64.rdxList.Add(Tuple.Create(bytes, "To be popped into " + i.ToString()));
                                    regLists64.rdxList.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.add.ElementAt(j).Key),
                                        usableX64Opcodes.add.ElementAt(j).Value));
                                    SetRegisterModifier(Register64.RDX, i, regModified64);
                                    regState64 &= ~i;
                                    regState64 |= Register64.RDX;
                                }
                            }
                        }
                    }
                }
            }
            if (!regState64.HasFlag(Register64.RDX))
            {
                regLists64.rdxList = null;
                regLists64.rdxList = new List<Tuple<byte[], string>>();
                byte[] nullBytes = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                regLists64.rdxList.Add(Tuple.Create(nullBytes,
                    "Unable to find appropriate instruction. EBX must be allocated manually"));
                regState64 |= Register64.RDX;
            }
            #endregion

            #region Populate R8
            SetRegisterModifier(Register64.R8, Register64.RCX, regModified64);
            SetRegisterModifier(Register64.R8, Register64.RDX, regModified64);
            regLists64.r8List = null;
            regLists64.r8List = new List<Tuple<byte[], string>>();
            var xorR8 = GetXorInstruction(Register64.R8);
            if (xorR8 != null)
            {
                foreach (Register64 i in Enum.GetValues(typeof(Register64)))
                {
                    if (!regState64.HasFlag(Register64.R8))
                    {
                        var popInstruction = GetPopInstruction(Register64.R8, i, regModified64);
                        if (popInstruction != null)
                        {
                            var addInstruction = GetAddInstruction(Register64.R8, i);
                            if (addInstruction != null)
                            {
                                byte[] add1 = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
                                byte[] add2 = new byte[] { 0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
                                regLists64.r8List.Add(Tuple.Create(xorR8.Item1, xorR8.Item2));
                                regLists64.r8List.Add(Tuple.Create(add1, "To be placed into " + addInstruction.Item3.ToString()));
                                regLists64.r8List.Add(Tuple.Create(addInstruction.Item1, addInstruction.Item2));
                                regLists64.r8List.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                regLists64.r8List.Add(Tuple.Create(add2, "To be placed into " + addInstruction.Item3.ToString() + " combined = 0x0000000000001000"));
                                regLists64.r8List.Add(Tuple.Create(addInstruction.Item1, addInstruction.Item2));
                                regLists64.r8List.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                SetRegisterModifier(Register64.R8, i, regModified64);
                                regState64 &= ~i;
                                regState64 |= Register64.R8;
                            }
                        }
                    }
                }
            }
            if (!regState64.HasFlag(Register64.R8))
            {
                foreach (Register64 i in Enum.GetValues(typeof(Register64)))
                {
                    if (!regState64.HasFlag(Register64.R8))
                    {
                        var popInstruction = GetPopInstruction(Register64.R8, i, regModified64);
                        if (popInstruction != null)
                        {
                            foreach (Register64 j in Enum.GetValues(typeof(Register64)))
                            {
                                if (!regState64.HasFlag(Register64.R8) && i != j)
                                {
                                    var popInstruction2 = GetPopInstruction(Register64.R8, j, regModified64);
                                    if (popInstruction2 != null)
                                    {
                                        var addInstruction = GetAddInstruction(i, j);
                                        if (addInstruction != null)
                                        {
                                            var movInstruction = GetMovInstruction(Register64.R8, i, regModified64);
                                            if (movInstruction != null)
                                            {
                                                byte[] add1 = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
                                                byte[] add2 = new byte[] { 0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
                                                regLists64.r8List.Add(Tuple.Create(add1, "To be placed into " + popInstruction.Item3.ToString()));
                                                regLists64.r8List.Add(Tuple.Create(popInstruction2.Item1, popInstruction2.Item2));
                                                regLists64.r8List.Add(Tuple.Create(add2, "To be placed into " + addInstruction.Item3.ToString() + " combined = 0x0000000000001000"));
                                                regLists64.r8List.Add(Tuple.Create(addInstruction.Item1, addInstruction.Item2));
                                                regLists64.r8List.Add(Tuple.Create(movInstruction.Item1, movInstruction.Item2));
                                                regLists64.r8List.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                                SetRegisterModifier(Register64.R8, i, regModified64);
                                                SetRegisterModifier(Register64.R8, j, regModified64);
                                                regState64 &= ~i;
                                                regState64 &= ~j;
                                                regState64 |= Register64.R8;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (!regState64.HasFlag(Register64.R8))
            {
                for (int i = 0; i < usableX64Opcodes.popR8.Count; i++)
                {
                    if (!regState64.HasFlag(Register64.R8))
                    {
                        if (usableX64Opcodes.popR8.ElementAt(i).Value.Length <= 14 && !usableX64Opcodes.popR8.ElementAt(i).Value.Contains("invalid"))
                        {
                            byte[] flAllocationType = { 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                            regLists64.r8List.Add(Tuple.Create(flAllocationType, "flAllocationType"));
                            regLists64.r8List.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popR8.ElementAt(i).Key),
                                usableX64Opcodes.popR8.ElementAt(i).Value));
                            regState64 |= Register64.R8;
                            i = usableX64Opcodes.popR8.Count;
                        }
                    }
                    else
                    {
                        i = usableX64Opcodes.popR8.Count;
                    }
                }
            }
            if (!regState64.HasFlag(Register64.R8))
            {
                regLists64.r8List = null;
                regLists64.r8List = new List<Tuple<byte[], string>>();
                byte[] nullBytes = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                regLists64.r8List.Add(Tuple.Create(nullBytes,
                    "Unable to find appropriate instruction. R8 must be allocated manually"));
                regState64 |= Register64.R8;
            }
            #endregion

            #region Populate R9
            regLists64.r9List = new List<Tuple<byte[], string>>();
            for (int i = 0; i < usableX64Opcodes.popR9.Count; i++)
            {
                if (!regState64.HasFlag(Register64.R9))
                {
                    if (usableX64Opcodes.popR9.ElementAt(i).Value.Length <= 14 && !usableX64Opcodes.popR9.ElementAt(i).Value.Contains("invalid"))
                    {
                        for (int j = 0; j < usableX64Opcodes.pushRsp.Count; j++)
                        {
                            if (usableX64Opcodes.pushRsp.ElementAt(j).Value.Length <= 15 && !usableX64Opcodes.pushRsp.ElementAt(j).Value.Contains("invalid"))
                            {
                                regLists64.r9List.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.pushRsp.ElementAt(j).Key),
                                    usableX64Opcodes.pushRsp.ElementAt(j).Value));
                                regLists64.r9List.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popR9.ElementAt(i).Key),
                                    usableX64Opcodes.popR9.ElementAt(i).Value));
                                regState64 |= Register64.R9;
                                i = usableX64Opcodes.popR9.Count;
                                j = usableX64Opcodes.pushRsp.Count;
                            }
                        }
                    }
                }
                else
                {
                    i = usableX64Opcodes.popR9.Count;
                }
            }
            if (!regState64.HasFlag(Register64.R9))
            {
                var movInstruction = GetMovInstruction(Register64.R9, Register64.RSP, regModified64);
                if (movInstruction != null)
                {
                    regLists64.r9List.Add(Tuple.Create(movInstruction.Item1, movInstruction.Item2));
                    SetRegisterModifier(Register64.R9, Register64.RSP, regModified64);
                    regState64 &= ~Register64.RSP;
                    regState64 |= Register64.R9;
                }
            }
            if (!regState64.HasFlag(Register64.R9))
            {
                regLists64.r9List = null;
                regLists64.r9List = new List<Tuple<byte[], string>>();
                byte[] nullBytes = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                regLists64.r9List.Add(Tuple.Create(nullBytes,
                    "Unable to find appropriate instruction. R9 must be allocated manually"));
                regState64 |= Register64.R9;
            }
            #endregion

            VirtualProtect.ReturnValue = BuildRopChain(RopMethod.VirtualProtect, regLists64, regModified64);
            return VirtualProtect;
        }
        #endregion

        #region BuildRopChain
            private List<Tuple<byte[], string>> BuildRopChain(RopMethod method, RegisterLists64 regLists64, RegisterModifiers64 regModified64)
        {
            List<Tuple<byte[], string>> ret = new List<Tuple<byte[], string>>();
            List<ushort> order = new List<ushort>();

            for (int i = 0; i < regLists64.rcxList.Count; i++)
            {
                ret.Add(regLists64.rcxList[i]);
            }

            for (int i = 0; i < regLists64.rdxList.Count; i++)
            {
                ret.Add(regLists64.rdxList[i]);
            }

            for (int i = 0; i < regLists64.r8List.Count; i++)
            {
                ret.Add(regLists64.r8List[i]);
            }

            for (int i = 0; i < regLists64.r9List.Count; i++)
            {
                ret.Add(regLists64.r9List[i]);
            }

            switch (method)
            {
                case RopMethod.VirtualAlloc:
                    ret.Add(Tuple.Create(BitConverter.GetBytes((long)ApiAddresses["VirtualAlloc"]), "Pointer to VirtualAlloc."));
                    ret.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.jmpRsp.ElementAt(0).Key),
                        usableX64Opcodes.jmpRsp.ElementAt(0).Value));
                    break;
                case RopMethod.HeapCreate:
                    ret.Add(Tuple.Create(BitConverter.GetBytes((long)ApiAddresses["HeapCreate"]), "Pointer to HeapCreate."));
                    ret.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.jmpRax.ElementAt(0).Key), usableX64Opcodes.jmpRax.ElementAt(0).Value));
                    break;
                case RopMethod.VirtualProtect:
                    ret.Add(Tuple.Create(BitConverter.GetBytes((long)ApiAddresses["VirtualProtect"]), "Pointer to VirtualProtect."));
                    ret.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.jmpRsp.ElementAt(0).Key),
                        usableX64Opcodes.jmpRsp.ElementAt(0).Value));
                    break;
                default:
                    break;
            }

            return ret;
        }
        #endregion

        #region CalculateAddInstructions64
        private byte[] CalculateAddInstructions64(int size)
        {
            byte[] sizeBytes = BitConverter.GetBytes(size);
            byte[] modifiedBytes = new byte[8];

            Array.Copy(sizeBytes, 0, modifiedBytes, modifiedBytes.Length - sizeBytes.Length, sizeBytes.Length);

            for (int i = 0; i < modifiedBytes.Length; i++)
            {
                modifiedBytes[i] += 0x01;
            }
            return modifiedBytes;
        }
        #endregion region

        #region ZeroRegister
        /// <summary>
        /// Checks for a combination of instructions that can be used to zero out a register, this can be a xor instruction on itself or a xor instruction elsewhere
        /// followed by a move to the selected register. This function should be extended with further methods for zeroing a register at a later date.
        /// </summary>
        /// <param name="modifyingReg">The Register64 value for the register to be zeroed.</param>
        /// <param name="regModified64">The RegisterModifiers64 object.</param>
        /// <returns>A dictionary(byte[], string) containing pointers to the instructions and the associated mnemonics</returns>
        private List<Tuple<byte[], string, Register64>> ZeroRegister(Register64 modifyingReg, RegisterModifiers64 regModified64)
        {
            List<Tuple<byte[], string, Register64>> instructions = new List<Tuple<byte[], string, Register64>>();
            var xor = GetXorInstruction(modifyingReg);
            if (xor != null)
            {
                instructions.Add(xor);
                return instructions;
            }

            for (int i = 0; i < usableX64Opcodes.mov.Count; i++)
            {

                string[] gadgetElements = usableX64Opcodes.mov.ElementAt(i).Value.Split(',');
                if (gadgetElements[0].Contains(modifyingReg.ToString().ToLower()))
                {
                    var reg = registerIdentifier64(gadgetElements[1]);
                    if (reg != Register64.NONE && !GetRegisterModified(modifyingReg, reg, regModified64))
                    {
                        var xorReg = GetXorInstruction(reg);
                        if (xorReg != null && !GetRegisterModified(modifyingReg, reg, regModified64))
                        {
                            instructions.Add(xorReg);
                            instructions.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.mov.ElementAt(i).Key).Reverse().ToArray(),
                                usableX64Opcodes.mov.ElementAt(i).Value, reg));
                            return instructions;
                        }
                    }
                }
            }
            return null;
        }
        #endregion

        #region SetRegisterModifier 64 bit
        /// <summary>
        /// Sets the flag of a Register64 enum in a RegisterModifiers64 class. This flag is used to identify whether setting the value of one 
        /// register involved editing another register. For example if setting EAX involved modifying RBX then RegisterModifiers32.RAX will have the RBX flag set. Any
        /// register should not be able to modify the value of any other register twice.
        /// 
        /// The purpose of this is to stop an infitinte loop where each register modifies the other in order to achieve the correct value.
        /// </summary>
        /// <param name="modifiedReg">The Register64 which is being modified</param>
        /// <param name="modifyingReg">The Register64 which is doing the modification</param>
        /// <param name="regModified64">The RegisterModifiers64 object.</param>
        private void SetRegisterModifier(Register64 modifyingReg, Register64 modifiedReg, RegisterModifiers64 regModified64)
        {
            switch (modifyingReg)
            {
                case Register64.RAX:
                    regModified64.RAX |= modifiedReg;
                    return;
                case Register64.RBX:
                    regModified64.RBX |= modifiedReg;
                    return;
                case Register64.RCX:
                    regModified64.RCX |= modifiedReg;
                    return;
                case Register64.RDX:
                    regModified64.RDX |= modifiedReg;
                    return;
                case Register64.RBP:
                    regModified64.RBP |= modifiedReg;
                    return;
                case Register64.RSP:
                    regModified64.RSP |= modifiedReg;
                    return;
                case Register64.RSI:
                    regModified64.RSI |= modifiedReg;
                    return;
                case Register64.RDI:
                    regModified64.RDI |= modifiedReg;
                    return;
                case Register64.R8:
                    regModified64.R8 |= modifiedReg;
                    return;
                case Register64.R9:
                    regModified64.R9 |= modifiedReg;
                    return;
                case Register64.R10:
                    regModified64.R10 |= modifiedReg;
                    return;
                case Register64.R11:
                    regModified64.R11 |= modifiedReg;
                    return;
                case Register64.R12:
                    regModified64.R12 |= modifiedReg;
                    return;
                case Register64.R13:
                    regModified64.R13 |= modifiedReg;
                    return;
                case Register64.R14:
                    regModified64.R14 |= modifiedReg;
                    return;
                case Register64.R15:
                    regModified64.R15 |= modifiedReg;
                    return;
            }
        }
        #endregion

        #region GetRegisterModifier 64 bit
        private bool GetRegisterModified(Register64 modifyingReg, Register64 modifiedReg, RegisterModifiers64 regModified64)
        {
            Register64 thisReg;
            bool modified = false;
            switch (modifyingReg)
            {
                case Register64.RAX:
                    thisReg = regModified64.RAX;
                    break;
                case Register64.RBX:
                    thisReg = regModified64.RBX;
                    break;
                case Register64.RCX:
                    thisReg = regModified64.RCX;
                    break;
                case Register64.RDX:
                    thisReg = regModified64.RDX;
                    break;
                case Register64.RBP:
                    thisReg = regModified64.RBP;
                    break;
                case Register64.RSP:
                    thisReg = regModified64.RSP;
                    break;
                case Register64.RSI:
                    thisReg = regModified64.RSI;
                    break;
                case Register64.RDI:
                    thisReg = regModified64.RDI;
                    break;
                case Register64.R8:
                    thisReg = regModified64.R9;
                    break;
                case Register64.R9:
                    thisReg = regModified64.R9;
                    break;
                case Register64.R10:
                    thisReg = regModified64.R10;
                    break;
                case Register64.R11:
                    thisReg = regModified64.R11;
                    break;
                case Register64.R12:
                    thisReg = regModified64.R12;
                    break;
                case Register64.R13:
                    thisReg = regModified64.R13;
                    break;
                case Register64.R14:
                    thisReg = regModified64.R14;
                    break;
                case Register64.R15:
                    thisReg = regModified64.R15;
                    break;
                default:
                    return true;
            }

            if (thisReg.HasFlag(modifiedReg))
            {
                modified = true;
            }
            return modified;
        }
        #endregion

        #region GetPopInstruction 64 bit
        private Tuple<byte[], string, Register64> GetPopInstruction(Register64 destReg, Register64 srcReg, RegisterModifiers64 regModified64)
        {
            switch (srcReg)
            {
                case Register64.RAX:
                    for (int i = 0; i < usableX64Opcodes.popRax.Count; i++)
                    {
                        if (usableX64Opcodes.popRax.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Register64.RAX, regModified64))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popRax.ElementAt(i).Key).Reverse().ToArray(), usableX64Opcodes.popRax.ElementAt(i).Value, Register64.RAX);
                        }
                    }
                    break;
                case Register64.RBX:
                    for (int i = 0; i < usableX64Opcodes.popRbx.Count; i++)
                    {
                        if (usableX64Opcodes.popRbx.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Register64.RBX, regModified64))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popRbx.ElementAt(i).Key).Reverse().ToArray(), usableX64Opcodes.popRbx.ElementAt(i).Value, Register64.RBX);
                        }
                    }
                    break;
                case Register64.RCX:
                    for (int i = 0; i < usableX64Opcodes.popRcx.Count; i++)
                    {
                        if (usableX64Opcodes.popRcx.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Register64.RCX, regModified64))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popRcx.ElementAt(i).Key).Reverse().ToArray(), usableX64Opcodes.popRcx.ElementAt(i).Value, Register64.RCX);
                        }
                    }
                    break;
                case Register64.RDX:
                    for (int i = 0; i < usableX64Opcodes.popRdx.Count; i++)
                    {
                        if (usableX64Opcodes.popRdx.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Register64.RDX, regModified64))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popRdx.ElementAt(i).Key).Reverse().ToArray(), usableX64Opcodes.popRdx.ElementAt(i).Value, Register64.RDX);
                        }
                    }
                    break;
                case Register64.RBP:
                    for (int i = 0; i < usableX64Opcodes.popRbp.Count; i++)
                    {
                        if (usableX64Opcodes.popRbp.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Register64.RBP, regModified64))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popRbp.ElementAt(i).Key).Reverse().ToArray(), usableX64Opcodes.popRbp.ElementAt(i).Value, Register64.RBP);
                        }
                    }
                    break;
                case Register64.RSP:
                    for (int i = 0; i < usableX64Opcodes.popRsp.Count; i++)
                    {
                        if (usableX64Opcodes.popRsp.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Register64.RSP, regModified64))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popRsp.ElementAt(i).Key).Reverse().ToArray(), usableX64Opcodes.popRsp.ElementAt(i).Value, Register64.RSP);
                        }
                    }
                    break;
                case Register64.RSI:
                    for (int i = 0; i < usableX64Opcodes.popRsi.Count; i++)
                    {
                        if (usableX64Opcodes.popRsi.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Register64.RSI, regModified64))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popRsi.ElementAt(i).Key).Reverse().ToArray(), usableX64Opcodes.popRsi.ElementAt(i).Value, Register64.RSI);
                        }
                    }
                    break;
                case Register64.RDI:
                    for (int i = 0; i < usableX64Opcodes.popRdi.Count; i++)
                    {
                        if (usableX64Opcodes.popRdi.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Register64.RDI, regModified64))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popRdi.ElementAt(i).Key).Reverse().ToArray(), usableX64Opcodes.popRdi.ElementAt(i).Value, Register64.RDI);
                        }
                    }
                    break;
                case Register64.R8:
                    for (int i = 0; i < usableX64Opcodes.popR8.Count; i++)
                    {
                        if (usableX64Opcodes.popR8.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Register64.R8, regModified64))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popR8.ElementAt(i).Key).Reverse().ToArray(), usableX64Opcodes.popR8.ElementAt(i).Value, Register64.R8);
                        }
                    }
                    break;
                case Register64.R9:
                    for (int i = 0; i < usableX64Opcodes.popR9.Count; i++)
                    {
                        if (usableX64Opcodes.popR9.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Register64.R9, regModified64))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popR9.ElementAt(i).Key).Reverse().ToArray(), usableX64Opcodes.popR9.ElementAt(i).Value, Register64.R9);
                        }
                    }
                    break;
                case Register64.R10:
                    for (int i = 0; i < usableX64Opcodes.popR10.Count; i++)
                    {
                        if (usableX64Opcodes.popR10.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Register64.R10, regModified64))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popR10.ElementAt(i).Key).Reverse().ToArray(), usableX64Opcodes.popR10.ElementAt(i).Value, Register64.R10);
                        }
                    }
                    break;
                case Register64.R11:
                    for (int i = 0; i < usableX64Opcodes.popR11.Count; i++)
                    {
                        if (usableX64Opcodes.popR11.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Register64.R11, regModified64))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popR11.ElementAt(i).Key).Reverse().ToArray(), usableX64Opcodes.popR11.ElementAt(i).Value, Register64.R11);
                        }
                    }
                    break;
                case Register64.R12:
                    for (int i = 0; i < usableX64Opcodes.popR12.Count; i++)
                    {
                        if (usableX64Opcodes.popR12.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Register64.R12, regModified64))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popR12.ElementAt(i).Key).Reverse().ToArray(), usableX64Opcodes.popR12.ElementAt(i).Value, Register64.R12);
                        }
                    }
                    break;
                case Register64.R13:
                    for (int i = 0; i < usableX64Opcodes.popR13.Count; i++)
                    {
                        if (usableX64Opcodes.popR13.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Register64.R13, regModified64))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popR13.ElementAt(i).Key).Reverse().ToArray(), usableX64Opcodes.popR13.ElementAt(i).Value, Register64.R13);
                        }
                    }
                    break;
                case Register64.R14:
                    for (int i = 0; i < usableX64Opcodes.popR14.Count; i++)
                    {
                        if (usableX64Opcodes.popR14.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Register64.R14, regModified64))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popR14.ElementAt(i).Key).Reverse().ToArray(), usableX64Opcodes.popR14.ElementAt(i).Value, Register64.R14);
                        }
                    }
                    break;
                case Register64.R15:
                    for (int i = 0; i < usableX64Opcodes.popR15.Count; i++)
                    {
                        if (usableX64Opcodes.popR15.ElementAt(i).Value.Length == 15 && !GetRegisterModified(destReg, Register64.R15, regModified64))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.popR15.ElementAt(i).Key).Reverse().ToArray(), usableX64Opcodes.popR15.ElementAt(i).Value, Register64.R15);
                        }
                    }
                    break;
                default:
                    return null;
            }
            return null;
        }
        #endregion

        #region getXorInstruction 64 bit
        private Tuple<byte[], string, Register64> GetXorInstruction(Register64 reg)
        {
            switch (reg)
            {
                case Register64.RAX:
                    if (usableX64Opcodes.xorRax.Count > 0 && usableX64Opcodes.xorRax.ElementAt(0).Value.Length <= 19)
                    {
                        byte[] gadget1 = BitConverter.GetBytes((long)usableX64Opcodes.xorRax.ElementAt(0).Key).Reverse().ToArray();
                        return Tuple.Create(gadget1, usableX64Opcodes.xorRax.ElementAt(0).Value, Register64.RAX);
                    }
                    break;
                case Register64.RBX:
                    if (usableX64Opcodes.xorRbx.Count > 0 && usableX64Opcodes.xorRbx.ElementAt(0).Value.Length <= 19)
                    {
                        byte[] gadget1 = BitConverter.GetBytes((long)usableX64Opcodes.xorRbx.ElementAt(0).Key).Reverse().ToArray();
                        return Tuple.Create(gadget1, usableX64Opcodes.xorRbx.ElementAt(0).Value, Register64.RBX);
                    }
                    break;
                case Register64.RCX:
                    if (usableX64Opcodes.xorRcx.Count > 0 && usableX64Opcodes.xorRcx.ElementAt(0).Value.Length <= 19)
                    {
                        byte[] gadget1 = BitConverter.GetBytes((long)usableX64Opcodes.xorRcx.ElementAt(0).Key).Reverse().ToArray();
                        return Tuple.Create(gadget1, usableX64Opcodes.xorRcx.ElementAt(0).Value, Register64.RCX);
                    }
                    break;
                case Register64.RDX:
                    if (usableX64Opcodes.xorRdx.Count > 0 && usableX64Opcodes.xorRdx.ElementAt(0).Value.Length <= 19)
                    {
                        byte[] gadget1 = BitConverter.GetBytes((long)usableX64Opcodes.xorRdx.ElementAt(0).Key).Reverse().ToArray();
                        return Tuple.Create(gadget1, usableX64Opcodes.xorRdx.ElementAt(0).Value, Register64.RDX);
                    }
                    break;
                case Register64.RSI:
                    if (usableX64Opcodes.xorRsi.Count > 0 && usableX64Opcodes.xorRsi.ElementAt(0).Value.Length <= 19)
                    {
                        byte[] gadget1 = BitConverter.GetBytes((long)usableX64Opcodes.xorRsi.ElementAt(0).Key).Reverse().ToArray();
                        return Tuple.Create(gadget1, usableX64Opcodes.xorRsi.ElementAt(0).Value, Register64.RSI);
                    }
                    break;
                case Register64.RDI:
                    if (usableX64Opcodes.xorRdi.Count > 0 && usableX64Opcodes.xorRdi.ElementAt(0).Value.Length <= 19)
                    {
                        byte[] gadget1 = BitConverter.GetBytes((long)usableX64Opcodes.xorRdi.ElementAt(0).Key).Reverse().ToArray();
                        return Tuple.Create(gadget1, usableX64Opcodes.xorRdi.ElementAt(0).Value, Register64.RDI);
                    }
                    break;
                default:
                    break;
            }
            return null;
        }
        #endregion

        #region GetAddInstruction
        /// <summary>
        /// Finds a add instruction going from the src register to the destination register
        /// </summary>
        /// <param name="destReg">The destination register</param>
        /// <param name="srcReg">The source register</param>
        /// <returns>Returns a tuple of byte[], string, Register64 containing a pointer to the instruction and the associated mnemonics</returns>
        private Tuple<byte[], string, Register64> GetAddInstruction(Register64 destReg, Register64 srcReg)
        {
            for (int i = 0; i < usableX64Opcodes.add.Count; i++)
            {
                string[] gadgetElements = usableX64Opcodes.add.ElementAt(i).Value.Split(',');
                if (gadgetElements[0].Contains(destReg.ToString().ToLower()))
                {
                    var reg = registerIdentifier64(gadgetElements[1]);
                    if (reg == srcReg)
                    {
                        return Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.add.ElementAt(i).Key).Reverse().ToArray(),
                            usableX64Opcodes.add.ElementAt(i).Value, reg);
                    }
                }
            }
            return null;
        }
        #endregion

        #region GetSubInstruction
        /// <summary>
        /// Finds a sub instruction going from the src register to the destination register
        /// </summary>
        /// <param name="destReg">The destination register</param>
        /// <param name="srcReg">The source register</param>
        /// <returns>Returns a tuple of byte[], string, Register64 containing a pointer to the instruction and the associated mnemonics</returns>
        private Tuple<byte[], string, Register64> GetSubInstruction(Register64 destReg, Register64 srcReg)
        {
            for (int i = 0; i < usableX64Opcodes.sub.Count; i++)
            {
                string[] gadgetElements = usableX64Opcodes.sub.ElementAt(i).Value.Split(',');
                if (gadgetElements[0].Contains(destReg.ToString().ToLower()))
                {
                    var reg = registerIdentifier64(gadgetElements[1]);
                    if (reg == srcReg)
                    {
                        return Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.sub.ElementAt(i).Key).Reverse().ToArray(),
                            usableX64Opcodes.sub.ElementAt(i).Value, reg);
                    }
                }
            }
            return null;
        }
        #endregion

        #region GetMovInstruction 64 bit
        /// <summary>
        /// Finds a mov instruction going from the src register to the destination register
        /// </summary>
        /// <param name="destReg">The destination register</param>
        /// <param name="srcReg">The source register</param>
        /// <param name="regModified64">The RegisterModifiers64 object.</param>
        /// <returns>Returns a dictionary of byte[] string containing a pointer to the instruction and the associated mnemonics</returns>
        private Tuple<byte[], string, Register64> GetMovInstruction(Register64 destReg, Register64 srcReg, RegisterModifiers64 regModified64)
        {
            for (int i = 0; i < usableX64Opcodes.mov.Count; i++)
            {
                string[] gadgetElements = usableX64Opcodes.mov.ElementAt(i).Value.Split(',');
                if (gadgetElements[0].Contains(destReg.ToString()))
                {
                    var reg = registerIdentifier64(gadgetElements[1]);
                    if (reg == srcReg)
                    {
                        return Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.mov.ElementAt(i).Key).Reverse().ToArray(), usableX64Opcodes.mov.ElementAt(i).Value, reg);
                    }
                }
            }
            return null;
        }
        #endregion

        #region registerIdentifier64
        private Register64 registerIdentifier64(string reg)
        {
            switch (reg)
            {
                case " rax":
                    return Register64.RAX;
                case " rbx":
                    return Register64.RBX;
                case " rcx":
                    return Register64.RCX;
                case " rdx":
                    return Register64.RDX;
                case " rbp":
                    return Register64.RBP;
                case " rsp":
                    return Register64.RSP;
                case " rsi":
                    return Register64.RSI;
                case " rdi":
                    return Register64.RDI;
                case " r8":
                    return Register64.R8;
                case " r9":
                    return Register64.R9;
                case " r10":
                    return Register64.R10;
                case " r11":
                    return Register64.R11;
                case " r12":
                    return Register64.R12;
                case " r13":
                    return Register64.R13;
                case " r14":
                    return Register64.R14;
                case " r15":
                    return Register64.R15;
                default:
                    return Register64.NONE;
            }
        }
        #endregion

        #region CompleteRegisters64
        private bool CompleteRegisters64(Register64 regState64)
        {
            bool complete = true;

            if (!regState64.HasFlag(Register64.RAX))
            {
                return false;
            }
            if (!regState64.HasFlag(Register64.RBX))
            {
                return false;
            }
            if (!regState64.HasFlag(Register64.RCX))
            {
                return false;
            }
            if (!regState64.HasFlag(Register64.RDX))
            {
                return false;
            }
            if (!regState64.HasFlag(Register64.RBP))
            {
                return false;
            }
            if (!regState64.HasFlag(Register64.RSP))
            {
                return false;
            }
            if (!regState64.HasFlag(Register64.RSI))
            {
                return false;
            }
            if (!regState64.HasFlag(Register64.RDI))
            {
                return false;
            }
            if (!regState64.HasFlag(Register64.R8))
            {
                return false;
            }
            if (!regState64.HasFlag(Register64.R9))
            {
                return false;
            }
            if (!regState64.HasFlag(Register64.R10))
            {
                return false;
            }
            if (!regState64.HasFlag(Register64.R11))
            {
                return false;
            }
            if (!regState64.HasFlag(Register64.R12))
            {
                return false;
            }
            if (!regState64.HasFlag(Register64.R13))
            {
                return false;
            }
            if (!regState64.HasFlag(Register64.R14))
            {
                return false;
            }
            if (!regState64.HasFlag(Register64.R15))
            {
                return false;
            }

            return complete;
        }
        #endregion

        #region Register64
        private enum Register64
        {
            NONE = 0,
            [Description(" rax")]
            RAX = 1,
            [Description(" rbx")]
            RBX = 2,
            [Description(" rcx")]
            RCX = 4,
            [Description(" rdx")]
            RDX = 8,
            [Description(" rbp")]
            RBP = 16,
            [Description(" rsp")]
            RSP = 32,
            [Description(" rsi")]
            RSI = 64,
            [Description(" rdi")]
            RDI = 128,
            [Description(" r8")]
            R8 = 256,
            [Description(" r9")]
            R9 = 512,
            [Description(" r10")]
            R10 = 1024,
            [Description(" r11")]
            R11 = 2048,
            [Description(" r12")]
            R12 = 4096,
            [Description(" r13")]
            R13 = 8192,
            [Description(" r14")]
            R14 = 16384,
            [Description(" r15")]
            R15 = 32768
        }
        #endregion

        private class RegisterModifiers64
        {
            public Register64 RAX;
            public Register64 RBX;
            public Register64 RCX;
            public Register64 RDX;
            public Register64 RBP;
            public Register64 RSP;
            public Register64 RSI;
            public Register64 RDI;
            public Register64 R8;
            public Register64 R9;
            public Register64 R10;
            public Register64 R11;
            public Register64 R12;
            public Register64 R13;
            public Register64 R14;
            public Register64 R15;
        }

        #region X64Lists
        /// <summary>
        /// Contains lists of instructions for specific registers.
        /// </summary>
        public class X64Lists
        {
            /// <summary>
            /// pushRax list.
            /// </summary>
            public Dictionary<IntPtr, string> pushRax = new Dictionary<IntPtr, string>();
            /// <summary>
            /// pushRcx list.
            /// </summary>
            public Dictionary<IntPtr, string> pushRcx = new Dictionary<IntPtr, string>();
            /// <summary>
            /// pushRdx list.
            /// </summary>
            public Dictionary<IntPtr, string> pushRdx = new Dictionary<IntPtr, string>();
            /// <summary>
            /// pushRbx list.
            /// </summary>
            public Dictionary<IntPtr, string> pushRbx = new Dictionary<IntPtr, string>();
            /// <summary>
            /// pushRsp list.
            /// </summary>
            public Dictionary<IntPtr, string> pushRsp = new Dictionary<IntPtr, string>();
            /// <summary>
            /// pushRbp list.
            /// </summary>
            public Dictionary<IntPtr, string> pushRbp = new Dictionary<IntPtr, string>();
            /// <summary>
            /// pushRsi list.
            /// </summary>
            public Dictionary<IntPtr, string> pushRsi = new Dictionary<IntPtr, string>();
            /// <summary>
            /// pushRdi list.
            /// </summary>
            public Dictionary<IntPtr, string> pushRdi = new Dictionary<IntPtr, string>();
            /// <summary>
            /// pushR8 list.
            /// </summary>
            public Dictionary<IntPtr, string> pushR8 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// pushR9 list.
            /// </summary>
            public Dictionary<IntPtr, string> pushR9 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// pushR10 list.
            /// </summary>
            public Dictionary<IntPtr, string> pushR10 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// pushR11 list.
            /// </summary>
            public Dictionary<IntPtr, string> pushR11 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// pushR12 list.
            /// </summary>
            public Dictionary<IntPtr, string> pushR12 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// pushR13 list.
            /// </summary>
            public Dictionary<IntPtr, string> pushR13 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// pushR14 list.
            /// </summary>
            public Dictionary<IntPtr, string> pushR14 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// pushR15 list.
            /// </summary>
            public Dictionary<IntPtr, string> pushR15 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// popRax list.
            /// </summary>
            public Dictionary<IntPtr, string> popRax = new Dictionary<IntPtr, string>();
            /// <summary>
            /// popRbx list.
            /// </summary>
            public Dictionary<IntPtr, string> popRbx = new Dictionary<IntPtr, string>();
            /// <summary>
            /// popRcx list.
            /// </summary>
            public Dictionary<IntPtr, string> popRcx = new Dictionary<IntPtr, string>();
            /// <summary>
            /// popRdx list.
            /// </summary>
            public Dictionary<IntPtr, string> popRdx = new Dictionary<IntPtr, string>();
            /// <summary>
            /// popRsp list.
            /// </summary>
            public Dictionary<IntPtr, string> popRsp = new Dictionary<IntPtr, string>();
            /// <summary>
            /// popRbp list.
            /// </summary>
            public Dictionary<IntPtr, string> popRbp = new Dictionary<IntPtr, string>();
            /// <summary>
            /// popRsi list.
            /// </summary>
            public Dictionary<IntPtr, string> popRsi = new Dictionary<IntPtr, string>();
            /// <summary>
            /// popRdi list.
            /// </summary>
            public Dictionary<IntPtr, string> popRdi = new Dictionary<IntPtr, string>();
            /// <summary>
            /// popR8 list.
            /// </summary>
            public Dictionary<IntPtr, string> popR8 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// popR9 list.
            /// </summary>
            public Dictionary<IntPtr, string> popR9 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// popR10 list.
            /// </summary>
            public Dictionary<IntPtr, string> popR10 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// popR11 list.
            /// </summary>
            public Dictionary<IntPtr, string> popR11 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// popR12 list.
            /// </summary>
            public Dictionary<IntPtr, string> popR12 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// popR13 list.
            /// </summary>
            public Dictionary<IntPtr, string> popR13 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// popR14 list.
            /// </summary>
            public Dictionary<IntPtr, string> popR14 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// popR15 list.
            /// </summary>
            public Dictionary<IntPtr, string> popR15 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// xorRax list.
            /// </summary>
            public Dictionary<IntPtr, string> xorRax = new Dictionary<IntPtr, string>();
            /// <summary>
            /// xorRbx list.
            /// </summary>
            public Dictionary<IntPtr, string> xorRbx = new Dictionary<IntPtr, string>();
            /// <summary>
            /// xorRcx list.
            /// </summary>
            public Dictionary<IntPtr, string> xorRcx = new Dictionary<IntPtr, string>();
            /// <summary>
            /// xorRdx list.
            /// </summary>
            public Dictionary<IntPtr, string> xorRdx = new Dictionary<IntPtr, string>();
            /// <summary>
            /// xorRsi list.
            /// </summary>
            public Dictionary<IntPtr, string> xorRsi = new Dictionary<IntPtr, string>();
            /// <summary>
            /// xorRdi list.
            /// </summary>
            public Dictionary<IntPtr, string> xorRdi = new Dictionary<IntPtr, string>();
            /// <summary>
            /// xorRsp list.
            /// </summary>
            public Dictionary<IntPtr, string> xorRsp = new Dictionary<IntPtr, string>();
            /// <summary>
            /// xorRbp list.
            /// </summary>
            public Dictionary<IntPtr, string> xorRbp = new Dictionary<IntPtr, string>();
            /// <summary>
            /// xorR8 list.
            /// </summary>
            public Dictionary<IntPtr, string> xorR8 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// xorR9 list.
            /// </summary>
            public Dictionary<IntPtr, string> xorR9 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// xorR10 list.
            /// </summary>
            public Dictionary<IntPtr, string> xorR10 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// xorR11 list.
            /// </summary>
            public Dictionary<IntPtr, string> xorR11 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// xorR12 list.
            /// </summary>
            public Dictionary<IntPtr, string> xorR12 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// xorR13 list.
            /// </summary>
            public Dictionary<IntPtr, string> xorR13 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// xorR14 list.
            /// </summary>
            public Dictionary<IntPtr, string> xorR14 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// xorR15 list.
            /// </summary>
            public Dictionary<IntPtr, string> xorR15 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// jmpRsp list.
            /// </summary>
            public Dictionary<IntPtr, string> jmpRsp = new Dictionary<IntPtr, string>();
            /// <summary>
            /// callRsp list.
            /// </summary>
            public Dictionary<IntPtr, string> callRsp = new Dictionary<IntPtr, string>();
            /// <summary>
            /// incRax list.
            /// </summary>
            public Dictionary<IntPtr, string> incRax = new Dictionary<IntPtr, string>();
            /// <summary>
            /// incRbx list.
            /// </summary>
            public Dictionary<IntPtr, string> incRbx = new Dictionary<IntPtr, string>();
            /// <summary>
            /// incRcx list.
            /// </summary>
            public Dictionary<IntPtr, string> incRcx = new Dictionary<IntPtr, string>();
            /// <summary>
            /// incRdx list.
            /// </summary>
            public Dictionary<IntPtr, string> incRdx = new Dictionary<IntPtr, string>();
            /// <summary>
            /// incRbp list.
            /// </summary>
            public Dictionary<IntPtr, string> incRbp = new Dictionary<IntPtr, string>();
            /// <summary>
            /// incRsp list.
            /// </summary>
            public Dictionary<IntPtr, string> incRsp = new Dictionary<IntPtr, string>();
            /// <summary>
            /// incRsi list.
            /// </summary>
            public Dictionary<IntPtr, string> incRsi = new Dictionary<IntPtr, string>();
            /// <summary>
            /// incRdi list.
            /// </summary>
            public Dictionary<IntPtr, string> incRdi = new Dictionary<IntPtr, string>();
            /// <summary>
            /// incR8 list.
            /// </summary>
            public Dictionary<IntPtr, string> incR8 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// incR9 list.
            /// </summary>
            public Dictionary<IntPtr, string> incR9 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// incR10 list.
            /// </summary>
            public Dictionary<IntPtr, string> incR10 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// incR11 list.
            /// </summary>
            public Dictionary<IntPtr, string> incR11 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// incR12 list.
            /// </summary>
            public Dictionary<IntPtr, string> incR12 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// incR13 list.
            /// </summary>
            public Dictionary<IntPtr, string> incR13 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// incR14 list.
            /// </summary>
            public Dictionary<IntPtr, string> incR14 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// incR15 list.
            /// </summary>
            public Dictionary<IntPtr, string> incR15 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// decRax list.
            /// </summary>
            public Dictionary<IntPtr, string> decRax = new Dictionary<IntPtr, string>();
            /// <summary>
            /// decRbx list.
            /// </summary>
            public Dictionary<IntPtr, string> decRbx = new Dictionary<IntPtr, string>();
            /// <summary>
            /// decRcx list.
            /// </summary>
            public Dictionary<IntPtr, string> decRcx = new Dictionary<IntPtr, string>();
            /// <summary>
            /// decRdx list.
            /// </summary>
            public Dictionary<IntPtr, string> decRdx = new Dictionary<IntPtr, string>();
            /// <summary>
            /// decRbp list.
            /// </summary>
            public Dictionary<IntPtr, string> decRbp = new Dictionary<IntPtr, string>();
            /// <summary>
            /// decRsp list.
            /// </summary>
            public Dictionary<IntPtr, string> decRsp = new Dictionary<IntPtr, string>();
            /// <summary>
            /// decRsi list.
            /// </summary>
            public Dictionary<IntPtr, string> decRsi = new Dictionary<IntPtr, string>();
            /// <summary>
            /// decRdi list.
            /// </summary>
            public Dictionary<IntPtr, string> decRdi = new Dictionary<IntPtr, string>();
            /// <summary>
            /// decR8 list.
            /// </summary>
            public Dictionary<IntPtr, string> decR8 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// decR9 list.
            /// </summary>
            public Dictionary<IntPtr, string> decR9 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// decR10 list.
            /// </summary>
            public Dictionary<IntPtr, string> decR10 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// decR11 list.
            /// </summary>
            public Dictionary<IntPtr, string> decR11 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// decR12 list.
            /// </summary>
            public Dictionary<IntPtr, string> decR12 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// decR13 list.
            /// </summary>
            public Dictionary<IntPtr, string> decR13 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// decR14 list.
            /// </summary>
            public Dictionary<IntPtr, string> decR14 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// decR15 list.
            /// </summary>
            public Dictionary<IntPtr, string> decR15 = new Dictionary<IntPtr, string>();
            /// <summary>
            /// add list.
            /// </summary>
            public Dictionary<IntPtr, string> add = new Dictionary<IntPtr, string>();
            /// <summary>
            /// mov list.
            /// </summary>
            public Dictionary<IntPtr, string> mov = new Dictionary<IntPtr, string>();
            /// <summary>
            /// sub list.
            /// </summary>
            public Dictionary<IntPtr, string> sub = new Dictionary<IntPtr, string>();
            /// <summary>
            /// jmpRax list.
            /// </summary>
            public Dictionary<IntPtr, string> callRax = new Dictionary<IntPtr, string>();
            /// <summary>
            /// callRax list.
            /// </summary>
            public Dictionary<IntPtr, string> jmpRax = new Dictionary<IntPtr, string>();
        }
        #endregion

        private class RegisterLists64
        {
            public List<Tuple<byte[], string>> raxList = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> rbxList = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> rcxList = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> rdxList = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> rbpList = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> rspList = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> rsiList = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> rdiList = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> r8List = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> r9List = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> r10List = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> r11List = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> r12List = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> r13List = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> r14List = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> r15List = new List<Tuple<byte[], string>>();
        }

        /// <summary>
        /// Enum of methods which can be used to generate a ROP chain.
        /// </summary>
        [Flags]
        public enum RopMethod : ushort
        {
            [Description(" VirtualAlloc")] VirtualAlloc = 1,
            [Description(" HeapCreate")] HeapCreate = 2,
            [Description(" VirtualProtect")] VirtualProtect = 4,
            [Description(" WriteProcessMemory")] WriteProcessMemory = 8,
            [Description(" All")] All = 15
        }
    }
}
