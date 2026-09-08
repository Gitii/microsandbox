//! Byte-windowed guest TCP forwarding with cancellation independent of data.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc, watch};
use tokio::task::JoinHandle;

use microsandbox_protocol::codec;
use microsandbox_protocol::message::{Message, MessageType};
use microsandbox_protocol::tcp::{
    TCP_MAX_DATA_BYTES, TCP_WINDOW_BYTES, TcpClosed, TcpConnect, TcpConnected, TcpCredit, TcpData,
    TcpEof, TcpFailed,
};

use crate::session::{RawActivity, RawSessionCompletion, RawSessionOutput, SessionOutput};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A socket owner with bounded byte credit and an out-of-band stop signal.
pub struct TcpSession {
    owner_id: u32,
    commands: mpsc::UnboundedSender<TcpCommand>,
    input_credit: Arc<AtomicUsize>,
    output_credit: Arc<AtomicUsize>,
    credit_ready: Arc<Notify>,
    write_eof: bool,
    stop: watch::Sender<Option<Result<(), String>>>,
    task: JoinHandle<()>,
}

enum TcpCommand {
    Data(Vec<u8>),
    Eof,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TcpSession {
    /// Correlation ID whose relay client owns this stream.
    pub fn owner_id(&self) -> u32 {
        self.owner_id
    }

    /// Accept bytes without waiting on socket progress. The byte window bounds
    /// this queue even for one-byte frames; empty frames cannot consume metadata.
    pub fn write_data(&mut self, data: Vec<u8>) -> Result<(), String> {
        // Defend the guest against a caller exceeding its advertised byte window.
        if self.write_eof || data.is_empty() || data.len() > TCP_MAX_DATA_BYTES {
            return self.fail("invalid TCP data length or data after EOF");
        }
        if self
            .input_credit
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                n.checked_sub(data.len())
            })
            .is_err()
        {
            return self.fail("TCP data exceeds available credit");
        }
        self.commands
            .send(TcpCommand::Data(data))
            .map_err(|_| "TCP session is closed".to_string())
    }

    /// Return consumed guest-to-host bytes without queuing behind socket writes.
    pub fn credit(&self, bytes: u32) -> Result<(), String> {
        // Defend the guest against duplicate, overflowing, or unsolicited credit.
        if bytes == 0
            || self
                .output_credit
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    n.checked_add(bytes as usize)
                        .filter(|n| *n <= TCP_WINDOW_BYTES)
                })
                .is_err()
        {
            return self.fail("invalid TCP credit");
        }
        self.credit_ready.notify_one();
        Ok(())
    }

    /// Queue one ordered half-close after all previously accepted bytes.
    pub fn close_write(&mut self) -> Result<(), String> {
        // A caller may send EOF once; repeated EOF must not grow the queue.
        if self.write_eof {
            return self.fail("duplicate TCP EOF");
        }
        self.write_eof = true;
        self.commands
            .send(TcpCommand::Eof)
            .map_err(|_| "TCP session is closed".to_string())
    }

    /// Reject a caller frame; the supervisor reports failure after socket cleanup.
    pub fn fail(&self, error: &str) -> Result<(), String> {
        self.stop.send_replace(Some(Err(error.to_string())));
        Err(error.to_string())
    }

    /// Cancel connect, read, and write together. Completion is acknowledged by
    /// the supervisor only after the owning future (and socket) has been dropped.
    pub fn close(&self) {
        self.stop.send_if_modified(|state| {
            if state.is_none() {
                *state = Some(Ok(()));
                true
            } else {
                false
            }
        });
    }

    /// Whether the socket supervisor has exited.
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// Connect asynchronously and relay independently in each direction.
    pub fn open(
        id: u32,
        req: TcpConnect,
        session_tx: &mpsc::UnboundedSender<(u32, SessionOutput)>,
    ) -> Self {
        let (commands, mut commands_rx) = mpsc::unbounded_channel();
        let input_credit = Arc::new(AtomicUsize::new(TCP_WINDOW_BYTES));
        let output_credit = Arc::new(AtomicUsize::new(TCP_WINDOW_BYTES));
        let credit_ready = Arc::new(Notify::new());
        let (stop, mut stop_rx) = watch::channel(None);
        let tx = session_tx.clone();
        let input = Arc::clone(&input_credit);
        let output = Arc::clone(&output_credit);
        let ready = Arc::clone(&credit_ready);
        let task = tokio::spawn(async move {
            // The select owns the entire relay future. Leaving this scope drops
            // both socket halves before any terminal acknowledgment is queued.
            let result = tokio::select! {
                biased;
                _ = stop_rx.changed() => stop_rx.borrow().clone().unwrap_or(Ok(())),
                result = async {
                    let stream = tokio::time::timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect((req.host.as_str(), req.port)))
                        .await.map_err(|_| "TCP connect timed out".to_string())?
                        .map_err(|e| format!("connect {}:{}: {e}", req.host, req.port))?;
                    send(id, MessageType::TcpConnected, &TcpConnected {}, 0, None, &tx)?;
                    let (mut reader, mut writer) = stream.into_split();
                    let read = async {
                        let mut buf = vec![0; TCP_MAX_DATA_BYTES];
                        loop {
                            let available = output.load(Ordering::SeqCst).min(buf.len());
                            if available == 0 {
                                ready.notified().await;
                                continue;
                            }
                            let n = reader.read(&mut buf[..available]).await.map_err(|e| format!("read TCP: {e}"))?;
                            if n == 0 {
                                send(id, MessageType::TcpEof, &TcpEof {}, 0, None, &tx)?;
                                return Ok::<(), String>(());
                            }
                            output.fetch_sub(n, Ordering::SeqCst);
                            send(id, MessageType::TcpData, &TcpData { data: buf[..n].to_vec() }, n, None, &tx)?;
                        }
                    };
                    let write = async {
                        while let Some(command) = commands_rx.recv().await {
                            match command {
                                TcpCommand::Data(data) => {
                                    writer.write_all(&data).await.map_err(|e| format!("write TCP: {e}"))?;
                                    input.fetch_add(data.len(), Ordering::SeqCst);
                                    send(id, MessageType::TcpCredit, &TcpCredit { bytes: data.len() as u32 }, 0, None, &tx)?;
                                }
                                TcpCommand::Eof => {
                                    writer.shutdown().await.map_err(|e| format!("shutdown TCP: {e}"))?;
                                    return Ok::<(), String>(());
                                }
                            }
                        }
                        Ok(())
                    };
                    tokio::try_join!(read, write)?;
                    Ok(())
                } => result,
            };
            let terminal = match result {
                Ok(()) => send(
                    id,
                    MessageType::TcpClosed,
                    &TcpClosed {},
                    0,
                    Some(RawSessionCompletion::Tcp),
                    &tx,
                ),
                Err(error) => send(
                    id,
                    MessageType::TcpFailed,
                    &TcpFailed { error },
                    0,
                    Some(RawSessionCompletion::Tcp),
                    &tx,
                ),
            };
            if let Err(error) = terminal {
                eprintln!("TCP {id} terminal delivery failed: {error}");
            }
        });
        Self {
            owner_id: id,
            commands,
            input_credit,
            output_credit,
            credit_ready,
            write_eof: false,
            stop,
            task,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for TcpSession {
    fn drop(&mut self) {
        self.close();
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn send<T: serde::Serialize>(
    id: u32,
    t: MessageType,
    payload: &T,
    bytes: usize,
    completion: Option<RawSessionCompletion>,
    tx: &mpsc::UnboundedSender<(u32, SessionOutput)>,
) -> Result<(), String> {
    let msg = Message::with_payload(t, id, payload).map_err(|e| format!("encode TCP: {e}"))?;
    let mut frame = Vec::new();
    codec::encode_to_buf(&msg, &mut frame).map_err(|e| format!("encode TCP frame: {e}"))?;
    tx.send((
        id,
        SessionOutput::Raw(RawSessionOutput::new(
            frame,
            RawActivity::tcp_bytes(bytes),
            completion,
        )),
    ))
    .map_err(|_| "agent output disconnected".to_string())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn receive(rx: &mut mpsc::UnboundedReceiver<(u32, SessionOutput)>) -> Message {
        let (_, SessionOutput::Raw(mut output)) =
            tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap()
        else {
            panic!("expected raw TCP frame");
        };
        codec::try_decode_from_buf(&mut output.frame)
            .unwrap()
            .unwrap()
    }

    async fn connected() -> (
        TcpSession,
        TcpStream,
        mpsc::UnboundedReceiver<(u32, SessionOutput)>,
    ) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let session = TcpSession::open(
            7,
            TcpConnect {
                host: "127.0.0.1".into(),
                port: listener.local_addr().unwrap().port(),
            },
            &tx,
        );
        let (peer, _) = listener.accept().await.unwrap();
        assert_eq!(receive(&mut rx).await.t, MessageType::TcpConnected);
        (session, peer, rx)
    }

    #[tokio::test]
    async fn close_ack_follows_socket_release() {
        let (mut session, mut peer, mut rx) = connected().await;
        session.close();
        assert_eq!(receive(&mut rx).await.t, MessageType::TcpClosed);
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), peer.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        (&mut session.task).await.unwrap();
    }

    #[tokio::test]
    async fn byte_credit_bounds_output_and_close_bypasses_exhaustion() {
        let (session, mut peer, mut rx) = connected().await;
        peer.write_all(&vec![1; TCP_WINDOW_BYTES + 1])
            .await
            .unwrap();
        let mut bytes = 0;
        while bytes < TCP_WINDOW_BYTES {
            let message = receive(&mut rx).await;
            assert_eq!(message.t, MessageType::TcpData);
            let data: TcpData = message.payload().unwrap();
            assert!(data.data.len() <= TCP_MAX_DATA_BYTES);
            bytes += data.data.len();
        }
        assert_eq!(bytes, TCP_WINDOW_BYTES);
        assert_eq!(session.output_credit.load(Ordering::SeqCst), 0);
        assert!(rx.try_recv().is_err());
        session.credit(1).unwrap();
        let message = receive(&mut rx).await;
        assert_eq!(message.payload::<TcpData>().unwrap().data, vec![1]);
        session.close();
        assert_eq!(receive(&mut rx).await.t, MessageType::TcpClosed);
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn input_window_is_bytes_not_frames_and_rejects_excess() {
        let (mut session, _peer, mut rx) = connected().await;
        // No await: the writer cannot return credit while this task fills the window.
        for _ in 0..TCP_WINDOW_BYTES {
            session.write_data(vec![1]).unwrap();
        }
        assert_eq!(session.input_credit.load(Ordering::SeqCst), 0);
        assert!(session.write_data(vec![2]).is_err());
        assert_eq!(receive(&mut rx).await.t, MessageType::TcpFailed);
    }

    #[tokio::test]
    async fn malformed_data_and_credit_terminate() {
        for data in [Vec::new(), vec![0; TCP_MAX_DATA_BYTES + 1]] {
            let (mut session, _peer, mut rx) = connected().await;
            assert!(session.write_data(data).is_err());
            assert_eq!(receive(&mut rx).await.t, MessageType::TcpFailed);
        }
        for credit in [0, 1, u32::MAX] {
            let (session, _peer, mut rx) = connected().await;
            assert!(session.credit(credit).is_err());
            assert_eq!(receive(&mut rx).await.t, MessageType::TcpFailed);
        }
    }

    #[tokio::test]
    async fn stalled_socket_write_does_not_block_reads_or_cancellation() {
        const STALL_DEADLINE: Duration = Duration::from_millis(200);
        const MAX_SOCKET_BUFFER_BYTES: usize = 32 * 1024 * 1024;
        let (mut session, mut peer, mut rx) = connected().await;
        let mut sent = 0;
        // The real destination never reads. Drive until its kernel receive
        // window and the guest kernel send buffer stop accepting more bytes.
        loop {
            assert!(sent < MAX_SOCKET_BUFFER_BYTES, "socket never backpressured");
            session.write_data(vec![1; TCP_MAX_DATA_BYTES]).unwrap();
            sent += TCP_MAX_DATA_BYTES;
            match tokio::time::timeout(STALL_DEADLINE, rx.recv()).await {
                Err(_) => break,
                Ok(Some((_, SessionOutput::Raw(mut output)))) => {
                    let message = codec::try_decode_from_buf(&mut output.frame)
                        .unwrap()
                        .unwrap();
                    assert_eq!(message.t, MessageType::TcpCredit);
                    assert_eq!(
                        message.payload::<TcpCredit>().unwrap().bytes as usize,
                        TCP_MAX_DATA_BYTES
                    );
                }
                Ok(_) => panic!("expected TCP credit frame"),
            }
        }
        assert_eq!(
            session.input_credit.load(Ordering::SeqCst),
            TCP_WINDOW_BYTES - TCP_MAX_DATA_BYTES
        );
        peer.write_all(b"reverse").await.unwrap();
        let reverse = receive(&mut rx).await;
        assert_eq!(reverse.t, MessageType::TcpData);
        assert_eq!(reverse.payload::<TcpData>().unwrap().data, b"reverse");
        session.close();
        assert_eq!(receive(&mut rx).await.t, MessageType::TcpClosed);
        (&mut session.task).await.unwrap();
    }

    #[tokio::test]
    async fn destination_half_close_preserves_ordered_host_writes() {
        let (mut session, mut peer, mut rx) = connected().await;
        peer.shutdown().await.unwrap();
        assert_eq!(receive(&mut rx).await.t, MessageType::TcpEof);
        session.write_data(b"after-eof".to_vec()).unwrap();
        session.close_write().unwrap();
        let mut data = Vec::new();
        peer.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"after-eof");
        assert_eq!(
            receive(&mut rx).await.payload::<TcpCredit>().unwrap().bytes,
            9
        );
        assert_eq!(receive(&mut rx).await.t, MessageType::TcpClosed);
    }

    #[tokio::test]
    async fn dropping_owner_cancels_socket() {
        let (session, mut peer, mut rx) = connected().await;
        drop(session);
        assert_eq!(receive(&mut rx).await.t, MessageType::TcpClosed);
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn connect_failure_is_terminal() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let _session = TcpSession::open(
            7,
            TcpConnect {
                host: "127.0.0.1".into(),
                port: 0,
            },
            &tx,
        );
        assert_eq!(receive(&mut rx).await.t, MessageType::TcpFailed);
    }
}
