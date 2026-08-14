namespace ERC.Net.Tests.TestSupport
{
    /// <summary>
    /// Marks a test that pins behaviour known to be wrong.
    /// </summary>
    /// <remarks>
    /// These assert what the code does today, not what it should do, so that a
    /// refactor cannot change it by accident. When the defect is fixed the test
    /// must be rewritten to assert the correct behaviour - which is the point:
    /// the fix has to be deliberate.
    ///
    /// Run just these with:  dotnet test --filter "Category=PinnedDefect"
    /// </remarks>
    public static class Defect
    {
        public const string Category = "Category";
        public const string Pinned = "PinnedDefect";
    }
}
