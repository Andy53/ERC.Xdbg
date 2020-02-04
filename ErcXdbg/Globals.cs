using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ErcXdbg
{
    static class Globals
    {
        public static bool aslr = false;
        public static bool safeseh = false;
        public static bool rebase = false;
        public static bool nxcompat = false;
        public static bool osdll = false;
        public static byte[] bytes = new byte[0];
        public static string protection = "read,write";

    }
}
