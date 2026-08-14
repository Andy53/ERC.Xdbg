using Xunit;

// The library is not thread safe: ErcCore and ErcResult both append to a single
// shared System_Error.LOG using File.AppendText, which takes an exclusive lock,
// and several types share mutable static state. Running test collections in
// parallel therefore produces spurious IOExceptions that say nothing about the
// code under test.
//
// This is pinned as a defect in ErcCoreTests.LogEvent_cannot_write_concurrently.
// Once error logging is made safe, this can be removed and the suite parallelized.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
