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

        #region Dump Heap
        /// <summary>
        /// Reads a set of bytes from a specific heap and provides a string contianing the results. Either HeapID or startAddress must be supplied. If both are supplied HeapID takes precedence.
        /// </summary>
        /// <param name="hi">HeapInfo object</param>
        /// <param name="heapid">The ID of the heap to be dumped. (optional)</param>
        /// <param name="hexStartAddress">The start address of the specific heap block to be dumped in hexadecimal. (optional)</param>
        /// <param name="writeToFile">Bool indicating if output should be written to a file.(optional)</param>
        /// <returns>A string containing the bytes read from memory</returns>
        public static string[] DumpHeap(HeapInfo hi, ulong heapid = 0, string hexStartAddress = "", bool writeToFile = true)
        {
            List<string> output = new List<string>();
            
            if (hexStartAddress.Contains("0x") || hexStartAddress.Contains("0x") || hexStartAddress.Contains("x") || hexStartAddress.Contains("X"))
            {
                hexStartAddress = hexStartAddress.Replace("0x", "");
                hexStartAddress = hexStartAddress.Replace("0X", "");
                hexStartAddress = hexStartAddress.Replace("X", "");
                hexStartAddress = hexStartAddress.Replace("x", "");
            }

            ulong startAddress = 0;
            if (hi.HeapProcess.ProcessMachineType == MachineType.I386)
            {
                try
                {
                    startAddress = (uint)System.Convert.ToInt32(hexStartAddress, 16);
                }
                catch 
                {
                }

            }
            else
            {
                try
                {
                    startAddress = (ulong)System.Convert.ToInt64(hexStartAddress, 16);
                }
                catch 
                {
                }
            }

            if (heapid == 0 && startAddress == 0)
            {
                List<string> ret = new List<string>();
                ret.Add("Neither heapID or start address supplied. One must be supplied in order to utilize this method.");
                return ret.ToArray();
            }

            Dictionary<IntPtr, int> searches = new Dictionary<IntPtr, int>();
            if(heapid != 0)
            {
                foreach (Structures.HEAPENTRY32 he in hi.HeapEntries)
                {
                    if ((ulong)he.th32HeapID == heapid)
                    {
                        if (!searches.ContainsKey(he.dwAddress))
                        {
                            searches.Add(he.dwAddress, (int)he.dwBlockSize);
                        }
                    }
                }
            }
            else
            {
                foreach (Structures.HEAPENTRY32 he in hi.HeapEntries)
                {
                    if ((ulong)he.dwAddress == startAddress)
                    {
                        heapid = (ulong)he.th32HeapID;
                        if (!searches.ContainsKey(he.dwAddress))
                        {
                            searches.Add(he.dwAddress, (int)he.dwBlockSize);
                        }
                    }
                }
            }
            
            
            string dumpFilename = GetFilePath(hi.HeapProcess.WorkingDirectory, "HeapDump_", ".txt");
            int bytesPerLine = 0;

            output.Add("----------------------------------------------------------------------------------------------------------------------" + Environment.NewLine);
            output.Add("Contents of process heap: " + heapid + " Created at: " + DateTime.Now + ". Created by: " + hi.HeapProcess.Author + Environment.NewLine);
            output.Add("----------------------------------------------------------------------------------------------------------------------" + Environment.NewLine);

            if (hi.HeapProcess.ProcessMachineType == MachineType.I386)
            {
                bytesPerLine = 8;
            }
            else 
            {
                bytesPerLine = 16;
            }

            foreach (KeyValuePair<IntPtr, int> kv in searches)
            {
                ErcResult<byte[]> result = hi.HeapProcess.DumpMemoryRegion(kv.Key, kv.Value);

                for (int i = 0; i < result.ReturnValue.Length; i++)
                {
                    if (i == 0)
                    {
                        output.Add(Environment.NewLine + kv.Key.ToString("X" + bytesPerLine) + ": " + result.ReturnValue[i].ToString("X2") + " ");
                    }
                    else if (i % bytesPerLine == 0)
                    {
                        output.Add(Environment.NewLine);
                        output.Add((kv.Key + ((i / bytesPerLine) * bytesPerLine)).ToString("X" + bytesPerLine) + ": " + result.ReturnValue[i].ToString("X2") + " ");
                    }
                    else
                    {
                        output.Add(result.ReturnValue[i].ToString("X2") + " ");
                    }
                }
            }

            if (writeToFile == true)
            {
                hi.HeapProcess.Output.WriteLines(dumpFilename, output);
            }

            return output.ToArray();
        }
        #endregion

        #region Heap Stats
        /// <summary>
        /// Returns statistics about the heap information gathered about the current process.
        /// </summary>
        /// <param name="hi"></param>
        /// <returns>Returns an of strings</returns>
        public static string[] HeapStats(HeapInfo hi, ulong heapID = 0, string hexStartAddress = "", bool extended = false)
        {
            List<string> result = new List<string>();
            result = new List<string>();
            result.Add("----------------------------------------------------------------------------------------------------------------------" + Environment.NewLine);
            result.Add("Heap statistics for process: " + hi.HeapProcess.ProcessName + " Created at: " + DateTime.Now + ". Created by: " + hi.HeapProcess.Author + Environment.NewLine);
            result.Add("----------------------------------------------------------------------------------------------------------------------" + Environment.NewLine);
            foreach (string s in hi.HeapStatistics(extended, heapID, hexStartAddress).ReturnValue)
            {
                result.Add(s);
            }
            return result.ToArray();
        }
        #endregion

        #region Search Heap
        /// <summary>
        /// Searches the process heap for a specific byte patters. If heapID and hexStartAddress are specified heapID takes precedence. Takes an optional bool indicating if output should be written to file.
        /// </summary>
        /// <param name="hi">HeapInfo object.</param>
        /// <param name="searchBytes">Pattern to be searched for.</param>
        /// <param name="heapID">Optional parameter indicating which heap to search.</param>
        /// <param name="hexStartAddress">Optional parameter indicating the start address of the heap object to search</param>
        /// <param name="writeToFile">Bool indicating if the output should be written to file.</param>
        /// <returns>Returns an array of strings.</returns>
        public static string[] SearchHeap(HeapInfo hi, byte[] searchBytes, ulong heapID = 0, string hexStartAddress = "", bool writeToFile = true)
        {
            var output = hi.SearchHeap(searchBytes, heapID, hexStartAddress);
            List<string> result = new List<string>();
            if(output.Error != null)
            {
                result.Add("ERROR: " + output.Error.Message + Environment.NewLine);
            }

            if(output.ReturnValue.Count == 0)
            {
                result.Add(String.Format("Search table on {0} by {1}. Search string: 0x{2}", DateTime.Now, hi.HeapProcess.Author, BitConverter.ToString(searchBytes).Replace("-", "")) + Environment.NewLine);
                result.Add("----------------------------------------------------------------------" + Environment.NewLine);
                result.Add("No instances of the pattern were found." + Environment.NewLine);
                return result.ToArray();
            }

            result.Add(String.Format("Search table created on {0} by {1}. Search string: 0x{2}", DateTime.Now, hi.HeapProcess.Author, BitConverter.ToString(searchBytes).Replace("-", "")) + Environment.NewLine);
            result.Add("----------------------------------------------------------------------" + Environment.NewLine);
            
            if(hi.HeapProcess.ProcessMachineType == MachineType.I386)
            {
                result.Add("  Address   | Heap ID  | Heap Entry Start Address " + Environment.NewLine);
                foreach (Tuple<IntPtr, IntPtr, IntPtr> t in output.ReturnValue)
                {
                    result.Add(" 0x" + t.Item1.ToString("X8") + " | " + (uint)t.Item2 + " | 0x" + t.Item3.ToString("X8") + Environment.NewLine);
                }
            }
            else
            {
                result.Add("       Address      |    Heap ID    | Heap Entry Start Address " + Environment.NewLine);
                foreach (Tuple<IntPtr, IntPtr, IntPtr> t in output.ReturnValue)
                {
                    result.Add(" 0x" + t.Item1.ToString("X16") + " | " + (ulong)t.Item2 + " | 0x" + t.Item3.ToString("X16") + Environment.NewLine);
                }
            }
            result.Add(Environment.NewLine);
            return result.ToArray();
        }
        #endregion
    }
}
