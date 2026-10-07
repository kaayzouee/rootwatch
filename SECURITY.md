# Security Policy

## Supported versions

Security fixes are developed against the current development branch and the latest published release. Older releases are not guaranteed to receive backports; upgrading to the latest release is the recommended remediation path.

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue with exploit details.

Use GitHub's private vulnerability-reporting / security-advisory mechanism for this repository when it is available. If private reporting is not enabled, contact the repository owner privately through GitHub and include enough information to reproduce and assess the issue.

Please include the affected version or commit, the relevant command or configuration, the expected security boundary, the observed behavior, and any minimal reproduction that can be shared safely.

Do not include secrets, personal data, or destructive proof-of-concept material.

## Security-sensitive behavior

rootwatch is designed to be a read-only Linux filesystem scanner. The main security-sensitive areas are:

- Filesystem-derived names and paths are rendered in text and TUI output and must not be able to inject terminal control sequences.
- `--privileged` re-runs the selected scan configuration through an elevation command and compares the result with the unprivileged scan. The worker receives the scan root plus the user's explicit scope, include, exclude, and pruning options; it is not a separate arbitrary filesystem-query interface.
- `--elevate-with` selects the elevation program and its whitespace-separated arguments. Arguments are passed directly to the requested elevation program rather than through a shell.
- `--nix-gc` invokes Nix helper commands for a read-only garbage-collectable-size estimate. When root executes these helpers, rootwatch does not trust arbitrary inherited `PATH` entries: relative, non-root-owned, or group/other-writable locations are rejected.
- The Nix operation never performs garbage collection.

## Threat model and limitations

rootwatch may inspect filesystem names and metadata that were not authored by a trusted user. Terminal-facing dynamic text is therefore treated as untrusted data.

The project does not claim that every visually deceptive Unicode character, such as bidirectional or zero-width formatting characters, is neutralized. These are defense-in-depth concerns for display integrity rather than a claim of command execution.

Report security issues that cross a privilege boundary, execute unintended commands, corrupt the terminal in a security-relevant way, expose data outside the requested scan configuration, or otherwise violate the read-only or privilege-isolation expectations described above.
