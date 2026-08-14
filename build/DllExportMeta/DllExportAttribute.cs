using System;
using System.Runtime.InteropServices;

namespace ErcXdbg
{
    /// <summary>
    /// Marks a static method for export from the compiled plugin as a native
    /// entry point, which is how x64dbg discovers a plugin.
    /// </summary>
    /// <remarks>
    /// This attribute is a compile-time marker only. After the C# compiler runs,
    /// the DllExport build step rewrites the assembly's IL to add a real native
    /// export table and strips every trace of this attribute, so the shipped
    /// plugin carries no reference to this assembly at run time.
    ///
    /// It is matched by full name (<c>ErcXdbg.DllExportAttribute</c>, configured
    /// via the <c>DllExportNamespace</c> MSBuild property), which is why defining
    /// it here in source works and lets the build avoid the DllExport wizard.
    /// The wizard would otherwise generate this same assembly into a machine-local
    /// cache, making the build depend on state that is not in the repository.
    /// </remarks>
    [AttributeUsage(AttributeTargets.Method)]
    public sealed class DllExportAttribute : Attribute
    {
        public DllExportAttribute()
        {
        }

        public DllExportAttribute(string exportName)
        {
            ExportName = exportName;
        }

        public DllExportAttribute(CallingConvention callingConvention)
        {
            CallingConvention = callingConvention;
        }

        public DllExportAttribute(string exportName, CallingConvention callingConvention)
        {
            ExportName = exportName;
            CallingConvention = callingConvention;
        }

        /// <summary>
        /// The name the method is exported under. Defaults to the method name.
        /// </summary>
        public string? ExportName { get; set; }

        /// <summary>
        /// The calling convention of the exported entry point. x64dbg expects Cdecl.
        /// </summary>
        public CallingConvention CallingConvention { get; set; }
    }
}
