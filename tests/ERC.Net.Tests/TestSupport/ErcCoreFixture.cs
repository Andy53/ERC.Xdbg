using ERC;
using Xunit;

namespace ERC.Net.Tests.TestSupport
{
    /// <summary>
    /// Shares one <see cref="ErcCore"/> across the tests that need it.
    /// </summary>
    /// <remarks>
    /// Constructing an ErcCore is expensive and has side effects: it reads and
    /// writes an XML config and generates two pattern files totalling ~87 KB into
    /// the assembly's directory. That is exactly the coupling Phase 02 removes, and
    /// until then tests have to live with it, so they pay the cost once.
    /// </remarks>
    public sealed class ErcCoreFixture
    {
        public ErcCore Core { get; }

        public ErcCoreFixture()
        {
            Core = new ErcCore();
        }
    }

    [CollectionDefinition(Name)]
    public sealed class ErcCoreCollection : ICollectionFixture<ErcCoreFixture>
    {
        public const string Name = "ErcCore";
    }
}
