# Russh Flow Control and Open Replies

Vendored from `warp-tech/russh`, tag `v0.62.5`, directory `russh/`, under Apache-2.0.
Upstream commit: `4882af71cf27ea5293636bf4985ef296dcf20896`.
The manifest is standalone; dependency requirements follow upstream. The root
workspace lockfile controls shipped artifacts. The lockfile here pins the
standalone vendor regression test's dependencies.

The local patch adds opt-in server receive-window accounting for TCP forwarding.
Automatic window replenishment remains the default. Manual channels replenish
only after their consumer reports progress, and dispatch refuses window overruns
instead of blocking the SSH connection on a full channel queue.

The patch also preserves queued send reservations across window adjustments and
makes asynchronous server opens definitive: a reply is enqueued or the transport
is terminated independently of application queue congestion.

## Patched Source

- `src/channels/mod.rs`: one signed send ledger for reserved writes and admitted
  non-reserving writes, with additive checked replenishment. Reservation guards
  refund bytes if a write is cancelled before admission.
- `src/channels/io/tx.rs`: carry a reservation with queued data rather than lose
  it on cancellation; refuse an invalid zero packet limit without spinning.
- `src/server/encrypted.rs` and `src/client/encrypted.rs`: add advertised credit
  instead of replacing reservations with the wire-window total; initialize credit
  once before publishing open confirmation and reject duplicates. The server has
  manual receive windows; the client honors its handler's receive-window target.
- `src/server/session.rs`: consumption-driven receive credit and an out-of-band
  transport abort handle; distinguish reserved admission from `Handle::data`
  admission; remove delayed initialization by the open waiter.
- `src/client/mod.rs` and `src/client/session.rs`: the same admission distinction
  for client sends, and no delayed initialization by the open waiter.
- `src/lib_inner.rs`: cancellation-safe `respond(&mut self, ...)`, reserving queue
  capacity before relinquishing pending ownership. Server drop-based rejection
  aborts the connection if it cannot enqueue.
- `src/server/mod.rs`: manual receive-window hook and an abort signal around the
  entire session future, including callbacks and socket writes.

The deterministic queued-reservation regression lives beside the server packet
handler. Real SSH regressions, including saturated open-reply queues and TCP reset
races, live in `sdk/rust/lib/sandbox/ssh_tcp_tests.rs` in the parent workspace.
