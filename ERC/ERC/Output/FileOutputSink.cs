using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace ERC.Output
{
    /// <summary>
    /// Writes output to the filesystem.
    /// </summary>
    public class FileOutputSink : IOutputSink
    {
        /// <summary>
        /// Picks the next unused file path for a prefix.
        /// </summary>
        /// <remarks>
        /// Numbering follows the highest number already present, so existing output
        /// is never overwritten.
        ///
        /// Two faults from the previous implementation are fixed here. It parsed the
        /// number with int.Parse on a possibly-empty regex match, so any file that
        /// matched the prefix without containing a digit - "modules_backup.txt" -
        /// threw a FormatException and took the whole command with it. And it joined
        /// the path by string concatenation, which produced a broken path whenever
        /// the directory had no trailing separator.
        /// </remarks>
        public string NextFilePath(string directory, string prefix, string extension)
        {
            int highest = 0;

            try
            {
                var info = new DirectoryInfo(directory);
                if (info.Exists)
                {
                    foreach (FileInfo file in info.GetFiles(prefix + "*"))
                    {
                        Match match = Regex.Match(file.Name, @"\d+");
                        int number;
                        if (match.Success && int.TryParse(match.Value, out number) && number > highest)
                        {
                            highest = number;
                        }
                    }
                }
            }
            catch (IOException)
            {
                // Unreadable directory: fall back to 1 rather than failing the command.
            }
            catch (UnauthorizedAccessException)
            {
            }

            return Path.Combine(directory ?? string.Empty,
                                prefix + (highest + 1).ToString() + extension);
        }

        public bool WriteText(string path, string content)
        {
            try
            {
                File.WriteAllText(path, content);
                return true;
            }
            catch (IOException)
            {
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }

        public bool WriteLines(string path, IEnumerable<string> lines)
        {
            try
            {
                File.WriteAllLines(path, new List<string>(lines));
                return true;
            }
            catch (IOException)
            {
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }
    }
}
