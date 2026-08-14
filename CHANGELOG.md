# Changelog

Notable changes to ERC.Xdbg. Dates are ISO 8601.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - unreleased

A modernisation of the whole codebase, and the defects that surfaced while doing it.

The major version reflects breaking changes to the `ERC.Net` library API. The
plugin's own command line is unchanged apart from the corrections noted under
Fixed, so an existing user's muscle memory still works.

### Security

- **Update downloads are verified.** The plugin's own updater downloads a DLL and
  installs it where x64dbg will load it, which makes an unverified download
  arbitrary code execution. Every release now publishes a SHA-256 beside the
  archive, and an update whose hash is missing or does not match is discarded
  rather than installed.
- **TLS certificate validation is no longer disabled.** `--update` used to install
  a callback that accepted every certificate. Because it did so with `+=` on a
  process-wide static, validation stayed off for the rest of the session and for
  every other component in the debugger, not just for the update.
- **Archive entries can no longer escape the plugins directory.** The extractor
  computed each entry's full destination and carried a comment explaining that a
  malicious archive could otherwise write outside the directory - but never
  compared the result against the directory, so the check the comment described
  was not performed.
- **PE headers are parsed safely.** Module headers were read by casting a pointer
  over a fixed buffer inside an `unsafe` block, with no signature checks and no
  bounds check on the file's own `e_lfanew` field. A module whose header claimed
  an offset of `0x7FFFFFFF` read whatever happened to be at that address. Parsing
  is now bounds-checked throughout, and unsafe code is disabled repository-wide.

### Fixed

#### Commands

- `--rop` ignored the bad characters given to `-Bytes`. Two `GenerateRopChain`
  overloads took `ptrsToExclude` and `startAddress` in the first position
  respectively; the plugin's call bound to the second, so the bad-character list
  was passed as the address to make executable and nothing was excluded.
- `--reset` never deleted the stored configuration. It built the path itself,
  joining a directory to a file name with no separator and spelling the extension
  in the wrong case, and `File.Delete` does nothing when the file is absent - so
  the command reported success and changed nothing.
- `--ropgadgets` never listed `pop edi` gadgets: the filter looked for `pop edo`.
  Nine further sections of the 64-bit listing were empty for the same reason -
  `decRax` through `decRdi` looked for the 32-bit register names, and `xorRax` was
  printed under the heading `xorEax`.
- `--update` failed the second time it was run. The backup routine read the number
  out of an existing backup and then renamed the current plugin to that same name,
  so the move failed and aborted the update. It also read only the first digit, so
  `-OLD_10.txt` was treated as `1`.
- `--assemble` and `--disassemble` now use [Iced](https://github.com/icedland/iced)
  in place of SharpDisasm, a udis86 port last released in 2017 that did not know
  about instructions added since.

#### Generated ROP chains

- The VirtualAlloc chain loaded EDI and ESI with the wrong values. A chain executes
  by returning into each address in turn, so a `pop esi` consumes the slot after
  itself - but this chain placed the value before the gadget. The HeapCreate and
  VirtualProtect chains placed them the right way round.
- The 32-bit VirtualProtect chain called VirtualAlloc. Its own template comment
  says ESI should hold `ApiAddresses["VirtualProtect"]`; both load sites said
  `VirtualAlloc`.
- Zeroing EBX or EDX emitted an eight-byte entry into a 32-bit chain, shifting
  every stack slot after it. Three of the five sites that consume a `xor` gadget
  had omitted the narrowing that the other two applied.
- The `push esp; pop ecx` fallback could only throw. It was reached precisely when
  no `mov` gadget was found, and then dereferenced the null `mov` result; had it
  survived that, both loops added the `mov` gadget rather than the push and the pop
  they had just found, and the success flag was never set.
- An empty gadget list or an unresolved API crashed the command with an argument
  error naming nothing actionable. Both now produce a chain with a clearly marked
  gap.
- `jmp rax` and `call rax` were never filtered for bad characters, and `jmp rax` is
  written directly into the HeapCreate chain.

#### Module and memory information

- ASLR and NXCompat were reported as `false` for every module on a 32-bit target.
  The flag derivation was written out twice; the 32-bit copy assigned inside a
  plain `else`, so each iteration past the interesting bit reset the flag. The
  `-ASLR` and `-NXCompat` filters built on those flags therefore excluded nothing.
- SafeSEH was reported as `false` for every module on every target. The load config
  directory was read into a local variable and discarded, so the fields the test
  compares stayed at their defaults. Present since the first commit.
- `PtrRemover` threw an `OverflowException` on 64-bit targets and silently removed
  too many pointers on 32-bit ones.
- Enumerating threads aborted the whole command if any single thread failed, which
  a thread exiting mid-enumeration reliably caused.
- Handles were never closed. A `ProcessInfo` is built per command and a `ModuleInfo`
  per loaded module, so a session leaked steadily.
- The GitHub release response was parsed by splitting the raw JSON on commas,
  which picked the wrong URL whenever a release name or body contained one.

#### Documentation

- `--SearchMemory` and `--SearchModules` documented the wrong search-type numbers
  (`5 = UTF8`, when 5 is UTF-32 and 3 is UTF-8), contradicting `--FindNrp` three
  sections later and the library itself. Corrected in both the help text and the
  README.
- Six implemented global switches were undocumented: `-Extended`, `-Unicode`,
  `-Ascii`, `-UTF7`, `-UTF8` and `-UTF32`.
- The `-Protection` default was documented as `exec`; it is `read,write`.

### Changed

- **Breaking, library.** `ProcessInfo.SearchMemory`, `SearchModules` and
  `SearchAllMemoryPPR` are now one method each, sharing a parameter order with
  `ptrsToExclude` optional and last. The two `SearchMemory` overloads previously
  differed only in whether they applied that filter, and their second positional
  parameter meant `searchBytes` in one and `ptrsToExclude` in the other, so a
  two-argument call was ambiguous.
- **Breaking, library.** `RopChainGenerator32.GenerateRopChain32` and its 64-bit
  counterpart are likewise one method each.
- **Breaking, library.** `ErcCore` takes its configuration, logging, native API and
  output through interfaces, and its constructor no longer touches the filesystem.
- **Breaking, library.** `X64Lists.xorRsp` and `xorRbp` are gone. They were declared
  and scanned for, but nothing ever populated them.
- Global switches are held in a `SessionState` object threaded through the command
  handlers, in place of a static mutable class written from x64dbg's command thread
  with no synchronisation.
- Command-line parsing is a pure function in `ERC.Cli.CommandParser`, separate from
  executing the command.
- The library multi-targets `net472` and `net8.0-windows`.
- `WebClient` has been replaced by `HttpClient` behind an interface.

### Added

- A test suite: 542 tests across both architectures and both target frameworks,
  including tests that inspect a real running process.
- `build.ps1`, `test.ps1` and `package.ps1`, and GitHub Actions workflows that
  build, test, package and publish. `build.ps1` verifies that the plugin really
  exports the entry points x64dbg needs and really binds to the debugger for the
  architecture it was built for.
- Nullable reference types throughout, with warnings as errors.

### Removed

- The hand-edited "uncomment for 64bit" blocks. Architecture follows from the
  platform being built, and a CI job fails the build if one reappears.

## [2.0.3] and earlier

See the commit history.
