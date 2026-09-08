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
