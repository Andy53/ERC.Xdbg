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

        #region GetFilePath
        /// <summary>
        /// Identifies output files previously created by a the Display_Modules function
        /// and identifies the last number used. Returns the next number to be used as a filename.
        /// </summary>
        /// <param name="directory">The directory to be used</param>
        /// <param name="prefix">A prefix for the file name e.g. "modules_" or "Pattern_" etc</param>
        /// <param name="extension">The file extension to be used e.g. ".txt" </param>
        /// <returns>Returns a string containing the full file path to be used when writing output to disk</returns>
        internal static string GetFilePath(string directory, string prefix, string extension)
        {
            // Kept for compatibility with existing call sites. The numbering logic
            // now lives in FileOutputSink, where it is testable and where two faults
            // were fixed: a FormatException on any matching file without a digit in
            // its name, and a path built by concatenation rather than Path.Combine.
            return new Output.FileOutputSink().NextFilePath(directory, prefix, extension);
        }
        #endregion

        #region WriteToFile
        /// <summary>
        /// Writes a list of strings to a file. Takes a directory, filename and prefix along with a List of strings.
        /// </summary>
        /// <param name="directory">The directory to be used</param>
        /// <param name="prefix">A prefix for the file name e.g. "modules_" or "Pattern_" etc</param>
        /// <param name="extension">The file extension to be used e.g. ".txt" </param>
        /// <param name="content">A list of strings to be written to disk </param>

        public static void WriteToFile(string directory, string prefix, string extension, List<string> content)
        {
            string path = GetFilePath(directory, prefix, extension);
            TextWriter tw = new StreamWriter(path);

            foreach (String s in content)
                tw.WriteLine(s);

            tw.Close();
        }
        #endregion

        #region Generate Pattern
        /// <summary>
        /// Creates a file in the ErcCore working directory containing a string of non repeating characters. 
        /// </summary>
        /// <param name="length">The length of the string to be created</param>
        /// <param name="core">An ErcCore object</param>
        /// <param name="extended">A optional boolean specifying whether to use the extended character set. Default is false.</param>
        /// <returns>Returns a string containing the pattern generated.</returns>
        public static string GeneratePattern(int length, ErcCore core, bool extended = false)
        {
            var patternFilePath = GetFilePath(core.WorkingDirectory, "Pattern_Create_", ".txt");
            var pattern = PatternTools.PatternCreate(length, core, extended);
            if(pattern.Error != null)
            {
                throw pattern.Error;
            }
            var patternOutput = PatternOutputBuilder(pattern.ReturnValue, core);
            core.Output.WriteText(patternFilePath, patternOutput);
            return patternOutput;
        }
        #endregion

        #region Pattern Output
        /// <summary>
        /// Private function, should not be called directly. Takes input from pattern_create and outputs in an easily readable format.
        /// </summary>
        /// <param name="pattern">The pattern to be used</param>
        /// <param name="core">An ErcCore object</param>
        /// <returns>Returns a string containing the human readable output of the pattern create method.</returns>
        private static string PatternOutputBuilder(string pattern, ErcCore core)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(pattern);
            string hexPattern = BitConverter.ToString(bytes);
            string asciiPattern = " ";
            string[] hexArray = hexPattern.Split('-');

            for (int i = 0; i < hexArray.Length; i++)
            {
                asciiPattern += pattern[i];

                if (i % 88 == 0 && i > 0)
                {
                    asciiPattern += "\"";
                    asciiPattern += Environment.NewLine;
                    asciiPattern += "\"";
                }
            }

            hexPattern = " ";
            for (int i = 0; i < hexArray.Length; i++)
            {
                hexPattern += "\\x" + hexArray[i];

                if (i % 22 == 0 && i > 0)
                {
                    hexPattern += Environment.NewLine;
                }
            }

            asciiPattern = asciiPattern.TrimStart(' ');
            hexPattern = hexPattern.TrimStart(' ');

            string output = "";
            output += "------------------------------------------------------------------------------------------" + Environment.NewLine;
            output += "Pattern created at: " + DateTime.Now + ". Pattern created by: " + core.Author + ". Pattern length: " + pattern.Length + Environment.NewLine;
            output += "------------------------------------------------------------------------------------------" + Environment.NewLine;
            output += Environment.NewLine;
            output += "Ascii:" + Environment.NewLine;
            output += "\"" + asciiPattern + "\"" + Environment.NewLine;
            output += Environment.NewLine;
            output += "Hexadecimal:" + Environment.NewLine;
            output += hexPattern;

            return output;
        }
        #endregion

        #region List Local Processes
        /// <summary>
        /// Lists usable processes running on the local machine.
        /// </summary>
        /// <returns>A string containing details of processes running on the local machine.</returns>
        public static string ListLocalProcesses()
        {
            var processes = ProcessInfo.ListLocalProcesses(new ErcCore());
            string processDetails = "";
            if (processes.Error != null)
            {
                return processes.Error.Message;
            }

            foreach(Process p in processes.ReturnValue)
            {
                processDetails += p.ProcessName + " ID: " + p.Id + " Filename: " + p.MainWindowTitle + Environment.NewLine;
            }
            return processDetails;
        }
        #endregion

        #region List Remote Processes
        /// <summary>
        /// Lists usable processes running on the remote machine.
        /// </summary>
        /// <returns>A string containing details of processes running on the remote machine.</returns>
        public static string ListRemoteProcesses(string machineName)
        {
            var processes = ProcessInfo.ListRemoteProcesses(new ErcCore(), machineName);
            string processDetails = "";
            if (processes.Error != null)
            {
                return processes.Error.Message;
            }

            foreach (Process p in processes.ReturnValue)
            {
                processDetails += p.ProcessName + " ID: " + p.Id + " Filename: " + p.MainWindowTitle + Environment.NewLine;
            }
            return processDetails;
        }
        #endregion

        #region StringToByteArray
        /// <summary>
        /// Converts a string of hex characters to a byte array of the associated values.
        /// </summary>
        /// <param name="hex">A string containing hex characters.</param>
        /// <returns>Returns a byte array.</returns>
        private static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => System.Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
        #endregion

        #region ListHeapIDs
        /// <summary>
        /// Returns a list of IDs for each heap associated with the current process.
        /// </summary>
        /// <param name="hi">A HeapInfo object.</param>
        /// <returns>Retruns an array of strings containing the heapIds.</returns>
        public static string[] ListHeapIDs(HeapInfo hi)
        {
            var output = hi.HeapIDs();
            List<string> result = new List<string>();

            result.Add("----------------------------------------------------------------------------------------------------------------------" + Environment.NewLine);
            result.Add("Heap IDs associated with process: " + hi.HeapProcess.ProcessName + " Created at: " + DateTime.Now + ". Created by: " + hi.HeapProcess.Author + Environment.NewLine);
            result.Add("----------------------------------------------------------------------------------------------------------------------" + Environment.NewLine);

            int heapnum = 1;
            foreach(ulong ul in output.ReturnValue)
            {
                result.Add("Heap " + heapnum + " ID = " + ul + Environment.NewLine);
            }

            return result.ToArray();
        }
        #endregion
    }
}
