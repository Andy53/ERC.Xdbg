namespace ERC.Utilities
{
    /// <summary>
    /// Reads the mitigation flags out of a PE header's DllCharacteristics field.
    /// </summary>
    /// <remarks>
    /// These decide which modules the "-ASLR", "-NXCompat" and "-SafeSEH" globals
    /// exclude from search results, so getting them wrong quietly changes which
    /// pointers a user is offered.
    ///
    /// The derivation used to be written out twice, once per architecture, as a loop
    /// over a BitArray. The 64-bit copy was correct; the 32-bit copy assigned inside
    /// a plain "else", so every iteration after the interesting bit reset the flag
    /// back to false. On a 32-bit target - the common case for this tool - ASLR and
    /// NXCompat therefore always read as false, and the exclusions built from them
    /// never excluded anything.
    /// </remarks>
    public static class PeCharacteristics
    {
        /// <summary>
        /// IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: the module can be relocated, i.e.
        /// it participates in ASLR.
        /// </summary>
        public const ushort DynamicBase = 0x0040;

        /// <summary>
        /// IMAGE_DLLCHARACTERISTICS_NX_COMPAT: the module is compatible with DEP.
        /// </summary>
        public const ushort NxCompat = 0x0100;

        /// <summary>
        /// IMAGE_DLLCHARACTERISTICS_NO_SEH: the module uses no structured exception
        /// handlers.
        /// </summary>
        public const ushort NoSeh = 0x0400;

        /// <summary>
        /// Whether the module opts in to ASLR.
        /// </summary>
        /// <param name="dllCharacteristics">The PE optional header's DllCharacteristics.</param>
        public static bool HasAslr(ushort dllCharacteristics)
        {
            return (dllCharacteristics & DynamicBase) != 0;
        }

        /// <summary>
        /// Whether the module is marked DEP compatible.
        /// </summary>
        /// <param name="dllCharacteristics">The PE optional header's DllCharacteristics.</param>
        public static bool HasNxCompat(ushort dllCharacteristics)
        {
            return (dllCharacteristics & NxCompat) != 0;
        }

        /// <summary>
        /// Whether the module declares that it contains no SEH handlers.
        /// </summary>
        /// <param name="dllCharacteristics">The PE optional header's DllCharacteristics.</param>
        public static bool HasNoSeh(ushort dllCharacteristics)
        {
            return (dllCharacteristics & NoSeh) != 0;
        }

        /// <summary>
        /// Whether a 32-bit module was built with SafeSEH.
        /// </summary>
        /// <param name="dllCharacteristics">The PE optional header's DllCharacteristics.</param>
        /// <param name="sehHandlerTable">SEHandlerTable from the load config directory.</param>
        /// <param name="sehHandlerCount">SEHandlerCount from the load config directory.</param>
        /// <returns>
        /// True when an SEH overwrite in this module would be caught, either because
        /// the module registers a table of permitted handlers or because it declares
        /// that it uses no structured exception handling at all.
        /// </returns>
        /// <remarks>
        /// A module built with /SAFESEH publishes the addresses of its legal exception
        /// handlers in the load config directory, and the loader refuses to dispatch to
        /// any handler not in that list. A module marked IMAGE_DLLCHARACTERISTICS_NO_SEH
        /// registers no handlers at all, which is equally not-exploitable by an SEH
        /// overwrite, so both count as protected.
        ///
        /// The NO_SEH half of this was not previously considered, and the table half
        /// never ran: the values were read into a local variable that was discarded, so
        /// the fields this compares were left at their defaults and every module on
        /// every architecture reported SafeSEH as false. That is what the "-SafeSEH"
        /// filter tested, so it excluded nothing, and the SafeSEH column in every
        /// search result read false regardless of the module.
        /// </remarks>
        public static bool HasSafeSeh(ushort dllCharacteristics, uint sehHandlerTable, uint sehHandlerCount)
        {
            if (HasNoSeh(dllCharacteristics))
            {
                return true;
            }

            return sehHandlerTable != 0 && sehHandlerCount != 0;
        }
    }
}
