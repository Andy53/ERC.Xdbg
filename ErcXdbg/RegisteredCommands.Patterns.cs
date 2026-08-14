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
    /// The commands for patterns and byte arrays.
    /// </summary>
    /// <remarks>
    /// Generating patterns and byte arrays, and locating them again in a crash.
    ///
    /// One part of RegisteredCommands, which was a single 2,100 line file holding
    /// every command. Splitting it by command group leaves the dispatcher in
    /// RegisteredCommands.cs and each group beside the others it shares helpers with.
    /// </remarks>
    public static partial class RegisteredCommands
    {
        private static void Pattern(ERC.ErcCore core, List<string> parameters, SessionState session)
        {
            PLog.WriteLine("ERC --Pattern");
            PLog.WriteLine("----------------------------------------------------------------------");
            // Strip the switches, keeping the positional arguments.
            //
            // This was a forward loop calling parameters.Remove(parameters[i]),
            // which shifted the next element into the current index and skipped it,
            // so a switch immediately following another switch survived and was then
            // treated as a positional argument. The same loop was copy-pasted into
            // nearly every command handler.
            parameters.RemoveAll(p => p.Contains("--"));

            int patternLength = 0;
            string search = "";
            bool extended = session.Extended;
            bool offset = false;
            bool create = false;

            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].ToLower() == "create" || parameters[i].ToLower() == "c")
                {
                    create = true;
                }
                else if(parameters[i].ToLower() == "offset" || parameters[i].ToLower() == "o")
                {
                    offset = true;
                }
            }

            if(create == true && offset == true)
            {
                PrintHelp("A pattern create and pattern offset operation can not be executed at the same time. Please choose one or the other.");
                return;
            }

            if (create == false && offset == false)
            {
                PrintHelp("A create or offset operation must be specified as part of the pattern command. ERC --pattern <create(c) or offset(o)> <parameters>");
                return;
            }

            // Drop the sub-command word now that it has been read.
            //
            // This was a forward loop calling Remove without compensating the index,
            // so the argument straight after the sub-command was skipped: in
            // "ERC --pattern create create 100" the second "create" survived and was
            // then parsed as the length.
            parameters.RemoveAll(p => p == "create" || p == "offset" || p == "c" || p == "o");

            if(parameters.Count > 2)
            {
                PrintHelp("Too many parameters provided.");
                return;
            }

            if (create == true)
            {
                for (int i = 0; i < parameters.Count; i++)
                {
                    if (parameters[i] == "true")
                    {
                        extended = true;
                        if (parameters.Count == 1)
                        {
                            PrintHelp("A valid integer must be provided for the pattern length.");
                            return;
                        }
                    }
                    else
                    {
                        if (int.TryParse(parameters[i], out patternLength))
                        {
                            if (patternLength > 20277 && patternLength < 66923)
                            {
                                extended = true;
                            }
                            else if (patternLength > 66923)
                            {
                                PrintHelp("Maximum length of the pattern is 66923.");
                                return;
                            }
                        }  
                        else
                        {
                            PrintHelp("A valid integer must be provided for the pattern length.");
                            return;
                        }
                    }
                }
                var result = ERC.DisplayOutput.GeneratePattern(patternLength, core, extended);
                PLog.Write(result + "\n");
            }
            else if(offset == true)
            {
                for(int i = 0; i < parameters.Count; i++)
                {
                    if(parameters[i] == "true")
                    {
                        extended = true;
                        if (parameters.Count == 1)
                        {
                            PrintHelp("A search string must be provided.");
                            return;
                        }
                    }
                    else
                    {
                        search = parameters[i];
                    }
                }
                string extendedCharSet = ": ,.;+= -_! & ()#@'*^[]%$?";
                foreach (char c in search)
                {
                    if (extendedCharSet.Contains(c))
                    {
                        extended = true;
                    }
                }
                var result = ERC.Utilities.PatternTools.PatternOffset(search, core, extended);
                PLog.WriteLine(result.ReturnValue);
            }
            PLog.WriteLine("----------------------------------------------------------------------");
            return;
        }

        private static void ByteArray(List<string> parameters, ERC.ErcCore core, SessionState session)
        {
            // Strip the switches, keeping the positional arguments.
            //
            // This was a forward loop calling parameters.Remove(parameters[i]),
            // which shifted the next element into the current index and skipped it,
            // so a switch immediately following another switch survived and was then
            // treated as a positional argument. The same loop was copy-pasted into
            // nearly every command handler.
            parameters.RemoveAll(p => p.Contains("--"));

            byte[] byteArray = ERC.DisplayOutput.GenerateByteArray(core, session.Bytes);

            if(session.Bytes.Length > 0)
            {
                PLog.WriteLine("Byte Array excluding: " + BitConverter.ToString(session.Bytes).Replace('-', ' '));
            }
            else
            {
                PLog.WriteLine("Byte Array: ");
            }

            PLog.WriteLine("--------------------------------");
            PLog.Write("|");
            string[] hexBytes = BitConverter.ToString(byteArray).Replace('-', ' ').Split(' ');
            int lineLength = 0;
            for(int i = 0; i < hexBytes.Length; i++)
            {
                if(i % 10 == 0 && i > 1)
                {
                    PLog.Write(" |\n| " + hexBytes[i]);
                    lineLength = 3;
                }
                else
                {
                    PLog.Write(" " + hexBytes[i]);
                    lineLength += 3;
                }
            }

            for(int i = lineLength; i < 32; i++)
            {
                if(i != 31)
                {
                    PLog.Write(" ");
                }
                else
                {
                    PLog.Write("|\n");
                }
            }
            PLog.WriteLine("--------------------------------");
            //return hexBytes;
            return;
        }

        private static void Compare(ERC.ProcessInfo info, List<string> parameters, SessionState session)
        {
            string allowedChars = "abcdefABCDEF1234567890";
            // Strip the switches, keeping the positional arguments.
            //
            // This was a forward loop calling parameters.Remove(parameters[i]),
            // which shifted the next element into the current index and skipped it,
            // so a switch immediately following another switch survived and was then
            // treated as a positional argument. The same loop was copy-pasted into
            // nearly every command handler.
            parameters.RemoveAll(p => p.Contains("--"));

            if (parameters.Count != 2)
            {
                PrintHelp("Incorrect parameters provided. Compare must be run as \"ERC --compare <start address> <file containing bytes>");
                return;
            }

            if(parameters[0].StartsWith("0x") || parameters[0].StartsWith("x") 
                || parameters[0].StartsWith("\\x") || parameters[0].StartsWith("X"))
            {
                parameters[0] = parameters[0].Replace("0x", "");
                parameters[0] = parameters[0].Replace("\\x", "");
                parameters[0] = parameters[0].Replace("X", "");
                parameters[0] = parameters[0].Replace("x", "");
            }

            if (parameters[1].StartsWith("0x") || parameters[1].StartsWith("x")
                || parameters[1].StartsWith("\\x") || parameters[1].StartsWith("X"))
            {
                parameters[1] = parameters[1].Replace("0x", "");
                parameters[1] = parameters[1].Replace("\\x", "");
                parameters[1] = parameters[1].Replace("X", "");
                parameters[1] = parameters[1].Replace("x", "");
            }

            bool validAddress = true;
            string path = "";
            IntPtr address = IntPtr.Zero;
            double addrHolder = 0;
            string memAddress = "";

            if (File.Exists(parameters[0]))
            {
                path = parameters[0];
                if (parameters[1].Length <= 16)
                {
                    foreach (char c in parameters[1])
                    {
                        if (!allowedChars.Contains(c))
                        {
                            validAddress = false;
                        }
                    }
                    if(parameters[1].Length < 16)
                    { 
                        for(int i = parameters[1].Length; i < 16; i++)
                        {
                            memAddress += 0;
                        }
                        parameters[1] = memAddress + parameters[1];
                    }
                    addrHolder = (double)System.Convert.ToInt64(parameters[1], 16);
                    address = (IntPtr)addrHolder;
                }
                else
                {
                    validAddress = false;
                }
            }
            else if(File.Exists(parameters[1]))
            {
                path = parameters[1];
                if (parameters[0].Length <= 16)
                {
                    foreach (char c in parameters[0])
                    {
                        if (!allowedChars.Contains(c))
                        {
                            validAddress = false;
                        }
                    }
                    if (parameters[0].Length < 16)
                    {
                        for (int i = parameters[0].Length; i < 16; i++)
                        {
                            memAddress += 0;
                        }
                        parameters[0] = memAddress + parameters[0];
                    }
                    addrHolder = (double)System.Convert.ToInt64(parameters[0], 16);
                    address = (IntPtr)addrHolder;
                }
                else
                {
                    validAddress = false;
                }
            }
            else
            {
                PrintHelp("Must provide a valid file path for byte array. Compare must be run as \"ERC --compare <start address> <file containing bytes>");
                return;
            }

            if(validAddress == false)
            {
                PrintHelp("Start address may only contain hex characters and must be less than 16 characters. Compare must be run as \"ERC --compare <start address> <file containing bytes>");
                return;
            }

            byte[] bytes = File.ReadAllBytes(path);
            string[] output = ERC.DisplayOutput.CompareByteArrayToMemoryRegion(info, address, bytes);

            PLog.WriteLine("Comparing memory region starting at 0x{0} to bytes in file {1}", 
                address.ToString("X"), path);
            PLog.WriteHtml(String.Join("<br>", output));
            /* Sleep upon completion so ERC register/unregister messages don't collide with above */
            Thread.Sleep(200);
            return;
        }

        private static void Convert(ERC.ProcessInfo info, List<string> parameters, SessionState session)
        {
            PLog.WriteLine("ERC --Convert");
            PLog.WriteLine("----------------------------------------------------------------------");
            // Strip the switches, keeping the positional arguments.
            //
            // This was a forward loop calling parameters.Remove(parameters[i]),
            // which shifted the next element into the current index and skipped it,
            // so a switch immediately following another switch survived and was then
            // treated as a positional argument. The same loop was copy-pasted into
            // nearly every command handler.
            parameters.RemoveAll(p => p.Contains("--"));

            string output = "";

            switch (parameters[0].ToLower())
            {
                case "atoh":
                    parameters.Remove(parameters[0]);
                    output = "The string " + String.Join(" ", parameters) + " encoded as ASCII has the following byte sequence:\n";
                    output += "0x" + ERC.Utilities.Convert.AsciiToHex(String.Join(" ", parameters)).Replace(" ", " 0x");
                    PLog.WriteLine(output);
                    break;
                case "utoh":
                    parameters.Remove(parameters[0]);
                    output = "The string " + String.Join(" ", parameters) + " encoded as Unicode has the following byte sequence:\n";
                    output += "0x" + ERC.Utilities.Convert.UnicodeToHex(String.Join(" ", parameters)).Replace(" ", " 0x");
                    PLog.WriteLine(output);
                    break;
                case "7toh":
                    parameters.Remove(parameters[0]);
                    output = "The string " + String.Join(" ", parameters) + " encoded as UTF-7 has the following byte sequence:\n";
                    output += "0x" + ERC.Utilities.Convert.UTF7ToHex(String.Join(" ", parameters)).Replace(" ", " 0x");
                    PLog.WriteLine(output);
                    break;
                case "8toh":
                    parameters.Remove(parameters[0]);
                    output = "The string " + String.Join(" ", parameters) + " encoded as UTF-8 has the following byte sequence:\n";
                    output += "0x" + ERC.Utilities.Convert.UTF8ToHex(String.Join(" ", parameters)).Replace(" ", " 0x");
                    PLog.WriteLine(output);
                    break;
                case "32toh":
                    parameters.Remove(parameters[0]);
                    output = "The string " + String.Join(" ", parameters) + " encoded as UTF-32 has the following byte sequence:\n";
                    output += "0x" + ERC.Utilities.Convert.UTF32ToHex(String.Join(" ", parameters)).Replace(" ", " 0x");
                    PLog.WriteLine(output);
                    break;
                default:
                    PLog.WriteLine("Incorrect parameters provided. Convert must be run as \"ERC --convert <conversion type> <input>");
                    PLog.WriteLine("Valid conversion types:\n    Ascii to Hex = AtoH\n    Unicdoe to Hex = UtoH\n    UTF-7 to Hex = 7toH\n" +
                        "    UTF-8 to Hex = 8toH\n    UTF-32 to Hex = 32toH\n");
                    PLog.WriteLine("----------------------------------------------------------------------");
                    return;
            }
            PLog.WriteLine("----------------------------------------------------------------------");
        }

        private static void FindNRP(ERC.ProcessInfo info, List<string> parameters, SessionState session)
        {
            if((int)session.Encode < 0 || (int)session.Encode > 5)
            {
                session.Encode = SearchEncoding.ASCII;
            }

            List<string> nrpInfo = new List<string>();
            nrpInfo = ERC.DisplayOutput.GenerateFindNRPTable(info, (int)session.Encode, session.Extended).ToList();

            foreach (string s in nrpInfo)
            {
                PLog.WriteLine(s);
            }
            //return nrpInfo;
            return;
        }

        private static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => System.Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        private static string ByteArrayToString(byte[] ba)
        {
            return BitConverter.ToString(ba).Replace("-", "");
        }
    }
}
