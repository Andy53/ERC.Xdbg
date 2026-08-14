using System.ComponentModel;

namespace ERC
{
    #region MachineType
    /// <summary>
    /// Enum containing types of machine architectures.
    /// </summary>
    public enum MachineType
    {
        /// <summary>
        /// Native.
        /// </summary>
        [Description("Native")]
        Native = 0,
        /// <summary>
        /// x86.
        /// </summary>
        [Description("I386")]
        I386 = 0x014c,
        /// <summary>
        /// Itanium.
        /// </summary>
        [Description("Itanium")]
        Itanium = 0x0200,
        /// <summary>
        /// x64.
        /// </summary>
        [Description("x64")]
        x64 = 0x8664,
        /// <summary>
        /// Type is unknown or unset.
        /// </summary>
        [Description("Error")]
        error = -1
    }
    #endregion
}
