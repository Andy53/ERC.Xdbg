using System;
using System.Runtime.InteropServices;

namespace Managed.x64dbg.SDK
{
    public static class Extensions
    {
        public static string ToHexString(this IntPtr intPtr)
        {
            return intPtr.ToString("X");
        }

        public static string ToPtrString(this IntPtr intPtr)
        {
            return IntPtr.Size == 4 ? intPtr.ToString("X8") : intPtr.ToString("X16");
        }

        public static string MarshalToString(this IntPtr intPtr)
        {
            if (intPtr == IntPtr.Zero)
                return "";
            return Marshal.PtrToStringAnsi(intPtr);
        }

        public static T ToStruct<T>(this IntPtr intPtr) where T : new()
        {
            if (intPtr == IntPtr.Zero)
                return new T();
            return (T)Marshal.PtrToStructure(intPtr, typeof(T));
        }
    }
}
