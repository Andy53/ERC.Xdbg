namespace ERC.Config
{
    /// <summary>
    /// Where the library's settings are read from and written to.
    /// </summary>
    /// <remarks>
    /// The seam that lets <see cref="ErcCore"/> be constructed without touching the
    /// filesystem: production uses <see cref="XmlConfigStore"/>, tests use
    /// <see cref="InMemoryConfigStore"/>.
    /// </remarks>
    public interface IConfigStore
    {
        /// <summary>
        /// The stored settings, or null when nothing has been stored yet.
        /// </summary>
        /// <remarks>
        /// Returns null rather than throwing when the store is unreadable. Callers
        /// fall back to defaults; a debugger plugin must not fail to load because a
        /// config file is missing or malformed.
        /// </remarks>
        ErcConfig? Load();

        /// <summary>
        /// Persists the settings.
        /// </summary>
        /// <returns>
        /// True when the settings were stored. False when they could not be - an
        /// unwritable directory, for example - which callers treat as "carry on with
        /// what is in memory" rather than as a fatal error.
        /// </returns>
        bool Save(ErcConfig config);
    }
}
