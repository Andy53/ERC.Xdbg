using System;

namespace ERC.Config
{
    /// <summary>
    /// Holds settings in memory and never touches disk.
    /// </summary>
    /// <remarks>
    /// Lets tests construct an <see cref="ErcCore"/> with no filesystem side
    /// effects at all, and lets a caller run the library entirely from a config it
    /// supplies. Also useful in a read-only plugin directory.
    /// </remarks>
    public class InMemoryConfigStore : IConfigStore
    {
        private ErcConfig? _config;

        /// <summary>
        /// Creates an empty store, so the first Load returns null and the caller
        /// falls back to defaults.
        /// </summary>
        public InMemoryConfigStore()
        {
        }

        /// <summary>
        /// Creates a store already holding the supplied settings.
        /// </summary>
        public InMemoryConfigStore(ErcConfig config)
        {
            if (config == null)
            {
                throw new ArgumentNullException("config");
            }

            _config = config.Clone();
        }

        /// <summary>
        /// Number of times Save has been called, so a test can assert that
        /// persistence was attempted.
        /// </summary>
        public int SaveCount { get; private set; }

        public ErcConfig? Load()
        {
            return _config == null ? null : _config.Clone();
        }

        public bool Save(ErcConfig config)
        {
            if (config == null)
            {
                throw new ArgumentNullException("config");
            }

            _config = config.Clone();
            SaveCount++;
            return true;
        }
    }
}
