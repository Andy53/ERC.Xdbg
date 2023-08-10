using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace ERC.Utilities
{
    /// <summary>
    /// Static class used to build a non repeating pattern and identify the position of a string in a non repeating pattern.
    /// </summary>
    public static class PatternTools
    {
        #region string Constants
        private const string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private const string lowercase = "abcdefghijklmnopqrstuvwxyz";

        #endregion

        #region Pattern Create
        /// <summary>
        /// Creates a string of non repeating characters.
        /// </summary>
        /// <param name="length">The length of the pattern to be created as integer</param>
        /// <param name="core">An ErcCore object</param>
        /// <param name="extended">(Optional) bool specifying whether the extended character set should be used</param>
        /// <returns>Returns an ErcResult string containing the generated pattern</returns>
        public static ErcResult<string> PatternCreate(int length, ErcCore core, bool extended = false)
        {
            string digits = "0123456789";
            ErcResult<string> result = new ErcResult<string>(core);

            if (extended == true)
            {
                digits += ": ,.;+=-_!&()#@'*^[]%$?";
                if(length > 66923)
                {
                    result.Error = new ERCException("User input error: Pattern length must be less that 66923");
                    result.LogEvent();
                    return result;
                }
            }
            else
            {
                if(length > 20277)
                {
                    result.Error = new ERCException("User input error: Pattern length must be less that 20277. Add the extended flag to create larger strings.");
                    result.LogEvent();
                    return result;
                }
            }
                
            result.ReturnValue = "";

            if (length < 1)
            {
                result.Error = new ERCException("User Input Error: Pattern length must be greate than 0.");
                result.LogEvent();
                return result;
            }

            for (int i = 0; i < uppercase.Length; i++)
            {
                for (int j = 0; j < lowercase.Length; j++)
                {
                    for (int k = 0; k < digits.Length; k++)
                    {
                        char pos1 = uppercase[i];
                        char pos2 = lowercase[j];
                        char pos3 = digits[k];

                        if (result.ReturnValue.Length > length)
                        {
                            result.Error = new ERCException("Procedural Error: Pattern string has exceeded the length supplied");
                            result.ReturnValue = "";
                            return result;
                        }

                        if (result.ReturnValue.Length == length)
                        {
                            return result;
                        }

                        if (result.ReturnValue.Length < length - 2)
                        {
                            result.ReturnValue += pos1;
                            result.ReturnValue += pos2;
                            result.ReturnValue += pos3;
                            if (result.ReturnValue.Length == length)
                            {
                                return result;
                            }
                        }
                        else if (result.ReturnValue.Length < length - 1)
                        {
                            result.ReturnValue += pos1;
                            result.ReturnValue += pos2;
                            if (result.ReturnValue.Length == length)
                            {
                                return result;
                            }
                        }
                        else if (result.ReturnValue.Length < length)
                        {
                            result.ReturnValue += pos1;
                            if (result.ReturnValue.Length == length)
                            {
                                return result;
                            }
                        }
                    }
                }
            }
            result.Error = new ERCException("An unknown error has occured. Function exited incorrectly. Function: ERC.Pattern_Tools.Pattern_Create");
            result.LogEvent();
            return result;
        }
        #endregion

        #region Pattern Offset
        /// <summary>
        /// Takes a string of characters and returns the location of the first character in a pattern created by Pattern_Create.
        /// </summary>
        /// <param name="pattern">The pattern to be searched for.</param>
        /// <param name="core">An ErcCore object</param>
        /// <param name="extended">(Optional) bool specifying whether the extended character set should be used</param>
        /// <returns>Returns an ErcResult int containing the offset of the supplied pattern within the generated pattern</returns>
        public static ErcResult<string> PatternOffset(string pattern, ErcCore core, bool extended = false)
        {
            //create string with reversed version of pattern to be searched for.
            char[] reversedChars = pattern.ToCharArray();
            Array.Reverse(reversedChars);
            string reversed = new string(reversedChars);

            //Create pattern to search within. Either extended or normal.
            string digits = "0123456789";
            string patternFull;
            if (extended == true)
            {
                digits += ": ,.;+=-_!&()#@'*^[]%$?";
                patternFull = File.ReadAllText(core.PatternExtendedPath);
            }
            else
            {
                patternFull = File.ReadAllText(core.PatternStandardPath);
            }
            ErcResult<string> result = new ErcResult<string>(core);

            if (pattern.Length < 3)
            {
                result.Error = new ERCException("User Input Error: Pattern length must be 3 characters or longer.");
                result.LogEvent();
                return result;
            }

            if (patternFull.Contains(pattern))
            {
                result.ReturnValue = "Value found at position " + patternFull.IndexOf(pattern).ToString() + " in pattern.";
                return result;
            }
            else if (patternFull.Contains(reversed))
            {
                result.ReturnValue = "Value found reversed at position " + patternFull.IndexOf(reversed).ToString() + " in pattern.";
                return result;
            }

            bool validHexString = true;
            foreach(char c in pattern)
            {
                if((c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F'))
                {
                    validHexString = false;
                }
            }

            if(validHexString == true)
            {
                byte[] patternBytes = ERC.Utilities.Convert.HexToBytes(pattern);
                byte[] patternBytesReversed = ERC.Utilities.Convert.HexToBytes(reversed);
                byte[] patternFullBytes = Encoding.ASCII.GetBytes(patternFull);

                string hexString = BitConverter.ToString(patternBytes).Replace("-", "");
                string hexStringReversed = BitConverter.ToString(patternBytesReversed).Replace("-", "");
                string hexPatternFull = BitConverter.ToString(patternFullBytes).Replace("-", "");

                if (hexPatternFull.Contains(hexString))
                {
                    result.ReturnValue = "Value found at position " + (hexPatternFull.IndexOf(hexString) / 2).ToString()  + " in pattern.";
                    return result;
                }
                else if (hexPatternFull.Contains(hexStringReversed))
                {
                    result.ReturnValue = "Value found reversed at position " + (hexPatternFull.IndexOf(hexStringReversed) / 2).ToString() + " in pattern.";
                    return result;
                }
            }
                
            result.Error = new ERCException("Error: Value not found.");
            result.ReturnValue = "Value not found in pattern.";
            return result;
        }
        #endregion
    }
}
