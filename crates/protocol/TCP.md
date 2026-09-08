# TCP Byte Windows

The fork TCP protocol uses `core.tcp.credit` (generation 7). TCP peers must be
upgraded together; the fork does not retain an uncredited TCP path.

After `core.tcp.connected`, each direction starts with 65,536 bytes of credit.
A `core.tcp.data` payload contains 1 through 16,384 bytes. Sending subtracts its
length from that direction's credit. Sending more bytes than the remaining
credit is a protocol error, not a request to wait in the agent dispatch loop.

The receiver returns `core.tcp.credit` with CBOR payload `{ bytes: u32 }` only
after consuming bytes. The guest returns credit after writing to the destination
socket. A host reader returns credit after delivering bytes to its consuming
reader, not when a transport queue accepts the frame. Returned credit must be
nonzero and must not raise the sender's available credit above 65,536 bytes.
Data and credit accounting are independent in the two directions.

`core.tcp.eof` consumes no credit and is ordered after previously accepted data.
It is sent once per direction; data after EOF and duplicate EOF are errors.
A peer EOF does not prevent writes in the opposite direction. Once both halves
finish, the guest releases the socket and sends terminal `core.tcp.closed`.

`core.tcp.close` cancels connect, read, and write without entering the data
queue. The guest drops the entire socket-owning future before sending terminal
`core.tcp.closed`. A socket error or rejected data/credit similarly releases the
socket before terminal `core.tcp.failed`. Dropping a session owner requests the
same cancellation, including on relay-client disconnect or agent-state teardown.

An observed terminal message confirms that the guest socket has been released.
A local close timeout or transport loss does not: remote cleanup is unknown to
the caller under a partition. Host close implementations must keep those outcomes
distinct and bound their local wait.

Each guest session accepts at most one input window of queued data and emits at
most one unconsumed output window. Input frames are nonempty, so byte accounting
also bounds queue metadata even when a sender uses one-byte frames. Shared relay
and consumer routing must preserve this backpressure without blocking unrelated
connections or their cancellation controls.

## Transport Ownership

Rust relay and client mailboxes charge encoded payload bytes plus per-message
metadata against a 32 MiB budget. A shared dispatcher never waits on a mailbox.
Exhaustion explicitly disconnects the offending transport; it does not drop a
frame and continue the stream. The budget accommodates both TCP windows even
when they arrive as one-byte data frames and one-byte credit returns.

The relay keeps a disconnected client's ID range reserved until the guest emits
`core.relay.client.released` on ID zero, with the same `{ id_start,
id_end_exclusive }` payload as `core.relay.client.disconnected`. This internal
generation-7 barrier is queued after all of that owner's TCP supervisors have
ended and after their queued TCP output. It prevents late TCP terminal frames
from reaching a new client with a recycled ID range. SDK consumers do not send or
receive this relay-internal barrier.
Client-originated ownership controls are rejected by the relay, even when their
frame header uses a correlation ID within the caller's own range.

SSH forwarding uses the same initial 64 KiB window and maximum 16 KiB frame.
The vendored russh receive-window extension returns SSH receive credit only after
guest TCP credit arrives. Guest output uses russh's window-reserving channel
writer; credit is not returned merely because an unbounded SSH output list
accepted bytes. Channel cancellation independently stops all forwarding futures
and waits up to two seconds for a terminal guest acknowledgment. Failure to
observe it is reported as unknown remote cleanup.
Pending guest connects run outside SSH callbacks, and channel confirmation is
queued before forwarding data. The opening write is bounded by two seconds;
the guest's 30-second connect attempt has a 32-second response deadline at SSH.
