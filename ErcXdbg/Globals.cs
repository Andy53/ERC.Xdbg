using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ErcXdbg
{
    public enum Encoding : int
    {
        [Description("Unicode")]
        Unicode = 1,
        [Description("ASCII")]
        ASCII = 2,
        [Description("UTF8")]
        UTF8 = 3,
        [Description("UTF7")]
        UTF7 = 4,
        [Description("UTF32")]
        UTF32 =5
    }
    public static class Globals
    {
        public static bool aslr = false;
        public static bool safeseh = false;
        public static bool rebase = false;
        public static bool nxcompat = false;
        public static bool osdll = false;
        public static bool extended = false;
        public static Encoding encode = Encoding.ASCII;
        public static byte[] bytes = new byte[0];
        public static string protection = "read,write";
    }
}
