
<!-- Refer to https://keepachangelog.com/en/1.0.0/ for guidance -->

# [Unreleased]

## Added
- Added this changelog.
- Added PuTTY private key v3 support.
- Added Window UNIX socket for WSL `ssh-agent` support.

## Fixed
- Fixed using incorrect unmanaged memory free function in `PageantClient.SendMessage()`.
- Fixed `PageantAgent.Dispose()` returning before all resources have been freed.
- Fixed `WindowsOpenSshPipe` starting a new server after `Dispose()`.

## Removed
- Removed Qt widgets.

[Unreleased]: https://github.com/dlech/SshAgentLib/compare/v1.9.4...HEAD
