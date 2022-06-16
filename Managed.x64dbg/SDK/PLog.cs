using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Managed.x64dbg.SDK
{
    public static class PLog
    {
        public static void WriteLine(string format, params object[] args)
        {
            Write(string.Format(format.Replace("%", "%%") + "\n", args));
        }

        public static void Write(string format, params object[] args)
        {
            Plugins._plugin_logprintf(string.Format(format.Replace("%", "%%"), args));
        }
        public static void WriteLineHtml(string format, params object[] args)
        {
            WriteHtml(format + "<br>", args);
        }

        public static void WriteHtml(string format, params object[] args)
        {
            Plugins._plugin_lograw_html(string.Format(format, args));
        }

    }

    public class TextWriterPLog : TextWriter
    {
        public override Encoding Encoding { get { return Encoding.UTF8; } }

        public override void Write(string value)
        {
            PLog.Write(value);
        }
    }
}
