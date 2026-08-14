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
    /// The commands for the heap.
    /// </summary>
    /// <remarks>
    /// Inspecting, searching and dumping the process heaps.
    ///
    /// One part of RegisteredCommands, which was a single 2,100 line file holding
    /// every command. Splitting it by command group leaves the dispatcher in
    /// RegisteredCommands.cs and each group beside the others it shares helpers with.
    /// </remarks>
    public static partial class RegisteredCommands
    {
        private static void HeapInfo(ERC.ProcessInfo info, List<string> parameters, SessionState session)
        {
            bool heapids = false;
            bool dumpheap = false;
            bool heapstats = false;
            bool searchheap = false;

            string hexStartAddress = "";
            ulong heapID = 0;
            bool writeToFile = true;
            byte[]? bytes = null;

            ERC.HeapInfo hi = new ERC.HeapInfo(info);

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
                heapstats = true;
            }

            for (int i = 0; i < parameters.Count && i >= 0; i++)
            {
                if (parameters[i].ToLower() == "ids")
                {
                    heapids = true;
                    parameters.Remove(parameters[i]);
                    i--;
                }
                else if (parameters[i].ToLower() == "stats")
                {
                    heapstats = true;
                    parameters.Remove(parameters[i]);
                    i--;
                }
                else if (parameters[i].ToLower() == "dump")
                {
                    dumpheap = true;
                    parameters.Remove(parameters[i]);
                    i--;
                }
                else if (parameters[i].ToLower() == "search")
                {
                    searchheap = true;
                    parameters.Remove(parameters[i]);
                    i--;
                }
                else if (parameters[i].ToLower() == "true" || parameters[i].ToLower() == "false")
                {
                    writeToFile = parameters[i].ToLower() == "true";
                    parameters.Remove(parameters[i]);
                    i--;
                }
                else if (parameters[i].ToLower() == "1" || parameters[i].ToLower() == "0")
                {
                    writeToFile = parameters[i].ToLower() == "1";
                    parameters.Remove(parameters[i]);
                    i--;
                }
                else if(ulong.TryParse(parameters[i].ToLower(), out heapID))
                {
                    parameters.Remove(parameters[i]);
                    i--;
                }
                else if(Regex.IsMatch(parameters[i], @"\A\b[0-9a-fA-F]+\b\Z"))
                {
                    string searchString = string.Join("", parameters);
                    if (hexStartAddress == "")
                    {
                        hexStartAddress = parameters[i];
                        parameters.Remove(parameters[i]);
                        i--;
                    }
                    else
                    {
                        bytes = ERC.Utilities.Convert.HexToBytes(searchString);
                    }
                }
                else
                {
                    string searchString = string.Join("", parameters);
                    bytes = StringToByteArray(searchString);
                }
            }

            if (searchheap == true)
            {
                if(hexStartAddress != "" && bytes == null)
                {
                    bytes = ERC.Utilities.Convert.HexToBytes(hexStartAddress);
                    hexStartAddress = "";
                }

                if (bytes == null)
                {
                    PrintHelp("Heap search requires a byte pattern to search for. " +
                        "Example: ERC --HeapInfo search FFE4");
                    return;
                }

                var result = ERC.DisplayOutput.SearchHeap(hi, bytes, heapID, hexStartAddress, writeToFile);
                foreach (string s in result)
                {
                    PLog.Write(s);
                }
                PLog.Write(Environment.NewLine);
            }

            if (heapids == true)
            {
                foreach(string s in ERC.DisplayOutput.ListHeapIDs(hi))
                {
                    PLog.Write(s);
                }
                PLog.Write(Environment.NewLine);
            }

            if (heapstats == true)
            {
                var result = ERC.DisplayOutput.HeapStats(hi);
                foreach (string s in result)
                {
                    PLog.Write(s);
                }
                PLog.Write(Environment.NewLine);
            }

            if(dumpheap == true)
            {
                var result = ERC.DisplayOutput.DumpHeap(hi, heapID, hexStartAddress, writeToFile);
                foreach (string s in result)
                {
                    PLog.Write(s);
                }
                PLog.Write(Environment.NewLine);
            }
        }
    }
}
