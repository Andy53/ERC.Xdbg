using System;
using System.Runtime.InteropServices;

namespace Managed.x64dbg.SDK
{
    public static class Plugins
    {
        public const int PLUG_SDKVERSION = 1;
        public static int pluginHandle;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate bool CBPLUGINCOMMAND(
            int argc,
            [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPStr, SizeParamIndex = 0)]
            string[] argv);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void CBPLUGIN(CBTYPE cbType, ref IntPtr callbackInfo);


        //private const string dll = "x64dbg.dll";   //Uncomment for 64bit
        private const string dll = "x32dbg.dll"; //Uncomment for 32bit

        private const CallingConvention cdecl = CallingConvention.Cdecl;

        [DllImport(dll, CallingConvention = cdecl)]
        public static extern void _plugin_logprintf(string format);

        [DllImport(dll, CallingConvention = cdecl)]
        public static extern void _plugin_logputs(string text);

        [DllImport(dll, CallingConvention = cdecl)]
        public static extern void _plugin_registercallback(int pluginHandle, CBTYPE cbType, CBPLUGIN cbPlugin);

        [DllImport(dll, CallingConvention = cdecl)]
        public static extern bool _plugin_unregistercallback(int pluginHandle, CBTYPE cbType);

        [DllImport(dll, CallingConvention = cdecl)]
        public static extern bool _plugin_menuaddentry(int hMenu, int hEntry, string title);

        [DllImport(dll, CallingConvention = cdecl)]
        public static extern int _plugin_menuadd(int hMenu, string title);

        [DllImport(dll, CallingConvention = cdecl)]
        public static extern bool _plugin_menuclear(int hMenu);

        [DllImport(dll, CallingConvention = cdecl)]
        public static extern bool _plugin_registercommand(int pluginHandle, string command, CBPLUGINCOMMAND cbCommand, bool debugonly);

        [DllImport(dll, CallingConvention = cdecl)]
        public static extern bool _plugin_unregistercommand(int pluginHandle, string command);

        public struct PLUG_INITSTRUCT
        {
            public int pluginHandle;
            public int sdkVersion;
            public int pluginVersion;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string pluginName;

            public override string ToString()
            {
                string ret = "";
                ret += "pluginHandle:  " + pluginHandle.ToString("X") + Environment.NewLine;
                ret += "sdkVersion:    " + sdkVersion + Environment.NewLine;
                ret += "pluginVersion: " + pluginVersion + Environment.NewLine;
                ret += "pluginName:    " + pluginName + Environment.NewLine;
                return ret;
            }
        }

        public struct PLUG_SETUPSTRUCT
        {
            public IntPtr hwndDlg;
            public int hMenu;
            public int hMenuDisasm;
            public int hMenuDump;
            public int hMenuStack;

            public override string ToString()
            {
                string ret = "";
                ret += "hwndDlg:      " + hwndDlg.ToString("X") + Environment.NewLine;
                ret += "hMenu:        " + hMenu + Environment.NewLine;
                ret += "hMenuDisasmn: " + hMenuDisasm + Environment.NewLine;
                ret += "hMenuStack:   " + hMenuStack + Environment.NewLine;
                return ret;
            }
        }

        public enum CBTYPE
        {
            CB_INITDEBUG, //PLUG_CB_INITDEBUG
            CB_STOPDEBUG, //PLUG_CB_STOPDEBUG
            CB_CREATEPROCESS, //PLUG_CB_CREATEPROCESS
            CB_EXITPROCESS, //PLUG_CB_EXITPROCESS
            CB_CREATETHREAD, //PLUG_CB_CREATETHREAD
            CB_EXITTHREAD, //PLUG_CB_EXITTHREAD
            CB_SYSTEMBREAKPOINT, //PLUG_CB_SYSTEMBREAKPOINT
            CB_LOADDLL, //PLUG_CB_LOADDLL
            CB_UNLOADDLL, //PLUG_CB_UNLOADDLL
            CB_OUTPUTDEBUGSTRING, //PLUG_CB_OUTPUTDEBUGSTRING
            CB_EXCEPTION, //PLUG_CB_EXCEPTION
            CB_BREAKPOINT, //PLUG_CB_BREAKPOINT
            CB_PAUSEDEBUG, //PLUG_CB_PAUSEDEBUG
            CB_RESUMEDEBUG, //PLUG_CB_RESUMEDEBUG
            CB_STEPPED, //PLUG_CB_STEPPED
            CB_ATTACH, //PLUG_CB_ATTACHED (before attaching, after CB_INITDEBUG)
            CB_DETACH, //PLUG_CB_DETACH (before detaching, before CB_STOPDEBUG)
            CB_DEBUGEVENT, //PLUG_CB_DEBUGEVENT (called on any debug event)
            CB_MENUENTRY, //PLUG_CB_MENUENTRY
            CB_WINEVENT, //PLUG_CB_WINEVENT
            CB_WINEVENTGLOBAL, //PLUG_CB_WINEVENTGLOBAL
            CB_LOADDB, //PLUG_CB_LOADSAVEDB
            CB_SAVEDB, //PLUG_CB_LOADSAVEDB
            CB_FILTERSYMBOL, //PLUG_CB_FILTERSYMBOL
            CB_LAST
        }

        public struct PLUG_CB_INITDEBUG
        {
            public IntPtr szFileName; //string
        }

        public struct PLUG_CB_STOPDEBUG
        {
            public IntPtr reserved;
        }

        public struct PLUG_CB_CREATEPROCESS
        {
            public IntPtr CreateProcessInfo; //WAPI.CREATE_PROCESS_DEBUG_INFO
            public IntPtr modInfo; //WAPI.IMAGEHLP_MODULE64
            public IntPtr DebugFileName; //string
            public IntPtr fdProcessInfo; //WAPI.PROCESS_INFORMATION
        }

        public struct PLUG_CB_EXITPROCESS
        {
            public WAPI.EXIT_PROCESS_DEBUG_INFO ExitProcess;
        }

        public struct PLUG_CB_LOADDLL
        {
            public IntPtr LoadDll; //WAPI.LOAD_DLL_DEBUG_INFO
            public IntPtr modInfo; //WAPI.IMAGEHLP_MODULE64
            public IntPtr modname; //string
        }

        public struct PLUG_CB_MENUENTRY
        {
            public int hEntry;
        }
    }
}
