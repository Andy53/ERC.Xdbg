using System;
using System.Runtime.InteropServices;
using Managed.x64dbg.SDK;
using RGiesecke.DllExport;

namespace ErcXdbg
{
    public static class ErcMain
    {
        private const string plugin_name = "ErcXdbg";
        private const int plugin_version = 1;

        [DllExport("pluginit", CallingConvention.Cdecl)]
        public static bool pluginit(ref Plugins.PLUG_INITSTRUCT initStruct)
        {
            Plugins.pluginHandle = initStruct.pluginHandle;
            initStruct.sdkVersion = Plugins.PLUG_SDKVERSION;
            initStruct.pluginVersion = plugin_version;
            initStruct.pluginName = plugin_name;
            Console.SetOut(new TextWriterPLog());
            return ErcXdbg.PluginInit(initStruct);
        }

        [DllExport("plugstop", CallingConvention.Cdecl)]
        private static bool plugstop()
        {
            ErcXdbg.PluginStop();
            return true;
        }

        [DllExport("plugsetup", CallingConvention.Cdecl)]
        private static void plugsetup(ref Plugins.PLUG_SETUPSTRUCT setupStruct)
        {
            ErcXdbg.PluginSetup(setupStruct);
        }
    }
}
