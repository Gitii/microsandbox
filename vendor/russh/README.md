# Russh Receive Windows

Vendored from `warp-tech/russh`, tag `v0.62.5`, directory `russh/`, under Apache-2.0.
Upstream commit: `4882af71cf27ea5293636bf4985ef296dcf20896`.
The manifest is standalone; dependencies keep the upstream versions.

The local patch adds opt-in server receive-window accounting for TCP forwarding.
Automatic window replenishment remains the default. Manual channels replenish
only after their consumer reports progress, and dispatch refuses window overruns
instead of blocking the SSH connection on a full channel queue.
