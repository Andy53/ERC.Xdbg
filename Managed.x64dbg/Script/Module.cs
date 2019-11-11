using System;
using System.Runtime.InteropServices;
using Managed.x64dbg.SDK;

namespace Managed.x64dbg.Script
{
    public static class Module
    {
        public struct ModuleInfo
        {
            public IntPtr @base;
            public IntPtr size;
            public IntPtr entry;
            public int sectionCount;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Bridge.MAX_MODULE_SIZE)]
            public string name;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WAPI.MAX_PATH)]
            public string path;
        }

        public struct ModuleSectionInfo
        {
            public IntPtr addr;
            public IntPtr size;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Bridge.MAX_SECTION_SIZE * 5)]
            public string name;
        }

        private const string dll = "x64dbg.dll";   //uncomment for 64bit
        //private const string dll = "x32dbg.dll"; //uncomment for 32bit
        private const CallingConvention cdecl = CallingConvention.Cdecl;

        [DllImport(dll, CallingConvention = cdecl,
             EntryPoint = "?GetList@Module@Script@@YA_NPEAUListInfo@@@Z")]
        private static extern bool ScriptModuleGetList(ref Bridge.ListInfo listInfo);

        public static ModuleInfo[] GetList()
        {
            var listInfo = new Bridge.ListInfo();
            return listInfo.ToArray<ModuleInfo>(ScriptModuleGetList(ref listInfo));
        }

        [DllImport(dll, CallingConvention = cdecl,
             EntryPoint = "?SectionListFromAddr@Module@Script@@YA_N_KPEAUListInfo@@@Z")]
        private static extern bool ScriptModuleSectionListFromAddr(IntPtr addr, ref Bridge.ListInfo listInfo);

        public static ModuleSectionInfo[] SectionListFromAddr(IntPtr addr)
        {
            var listInfo = new Bridge.ListInfo();
            return listInfo.ToArray<ModuleSectionInfo>(ScriptModuleSectionListFromAddr(addr, ref listInfo));
        }

        [DllImport(dll, CallingConvention = cdecl,
             EntryPoint = "?InfoFromAddr@Module@Script@@YA_N_KPEAUModuleInfo@12@@Z")]
        private static extern bool ScriptModuleInfoFromAddr(IntPtr addr, ref ModuleInfo info);

        public static bool InfoFromAddr(IntPtr addr, ref ModuleInfo info)
        {
            return ScriptModuleInfoFromAddr(addr, ref info);
        }
    }
}
