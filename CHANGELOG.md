
<!-- Refer to https://keepachangelog.com/en/1.0.0/ for guidance -->

# [Unreleased]

## Added
- Added this changelog.

## Changed
- Changed several code segments in Util.cs, WinInternals.cs, PpkFormatter.cs, and PpkFormatterTest.cs to conform to the project's code style.

## Fixed
- Fixed using incorrect unmanaged memory free function in `PagentClent.SendMessage()`.
- Fixed `PagentAgent.Dispose()` returning before all resources have been freed.

## Removed
- Removed Qt widgets.

[Unreleased]: https://github.com/dlech/SshAgentLib/compare/v1.9.4...HEAD
