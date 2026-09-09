//! Real SSH and guest TCP tasks on loopback, without a VM or a protocol stub.

use super::*;
use microsandbox_agentd::session::SessionOutput;
use microsandbox_agentd::tcp::TcpSession;
use microsandbox_protocol::{codec, core::Ready, message::Message};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

enum InputPhase {
    Data,
    Eof,
}

#[test]
fn closed_tcp_worker_is_normal_but_live_budget_exhaustion_is_an_error() {
    let (mut channel, mut worker) = SshTcpChannel::new();
    let (input, receiver) = queue::channel(1);
    channel.input = input;
    worker.input = receiver;
    assert!(
        channel
            .data(&[1, 2])
            .unwrap_err()
            .to_string()
            .contains("byte budget")
    );
    worker.input.close();
    channel.data(&[3]).unwrap();
    channel.eof().unwrap();
}

struct InputGate {
    phase: InputPhase,
    entered: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

struct Forwarder {
    client: Arc<AgentClient>,
    channels: HashMap<ChannelId, SshTcpChannel>,
    gate: Option<InputGate>,
    finished: mpsc::Sender<oneshot::Receiver<()>>,
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        for channel in self.channels.values() {
            channel.close();
        }
    }
}

impl russh::server::Handler for Forwarder {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    fn manual_receive_window(&self, channel: ChannelId) -> bool {
        self.channels.contains_key(&channel)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _: &str,
        _: u32,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let id = channel.id();
        let writer = channel.make_writer();
        let (state, worker) = SshTcpChannel::new();
        self.channels.insert(id, state);
        let (done, done_rx) = oneshot::channel();
        self.finished.send(done_rx).await.unwrap();
        let client = Arc::clone(&self.client);
        let session = session.handle();
        let request = TcpConnect {
            host: host.into(),
            port: port.try_into()?,
        };
        tokio::spawn(async move {
            relay_tcp_to_ssh(id, request, client, reply, session, writer, worker).await;
            // Observers may stop watching a channel after a successful close.
            let _ = done.send(());
        });
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        if matches!(self.gate.as_ref().map(|g| &g.phase), Some(InputPhase::Data)) {
            let gate = self.gate.take().unwrap();
            gate.entered.send(()).unwrap();
            gate.release.await.unwrap();
        }
        self.channels.get_mut(&channel).unwrap().data(data)
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        if matches!(self.gate.as_ref().map(|g| &g.phase), Some(InputPhase::Eof)) {
            let gate = self.gate.take().unwrap();
            gate.entered.send(()).unwrap();
            gate.release.await.unwrap();
        }
        self.channels.get_mut(&channel).unwrap().eof()
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.remove(&channel) {
            state.close();
        }
        Ok(())
    }
}

#[derive(Default)]
struct Client {
    adjustments: usize,
    stop_after: Option<usize>,
    stalled: Option<oneshot::Sender<()>>,
}

impl russh::client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _: &russh::keys::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }

    fn adjust_window(&mut self, _: ChannelId, window: u32) -> u32 {
        self.adjustments += 1;
        if self.stop_after.is_some_and(|n| self.adjustments >= n) {
            1
        } else {
            window
        }
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        _: &[u8],
        session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        if self.stop_after.is_some_and(|n| self.adjustments >= n)
            && session.sender_window_size(channel) == 0
            && let Some(stalled) = self.stalled.take()
        {
            stalled.send(()).unwrap();
        }
        Ok(())
    }
}

struct Fixture {
    client: russh::client::Handle<Client>,
    destination: TcpListener,
    finished: mpsc::Receiver<oneshot::Receiver<()>>,
    server: tokio::task::JoinHandle<()>,
    agent: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn new(
        window: u32,
        client: Client,
        gate: Option<InputGate>,
        event_buffer_size: usize,
    ) -> Self {
        let agent_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let agent_address = agent_listener.local_addr().unwrap();
        let agent = tokio::spawn(async move {
            let (mut socket, _) = agent_listener.accept().await.unwrap();
            socket.write_all(&1u32.to_be_bytes()).await.unwrap();
            socket.write_all(&100u32.to_be_bytes()).await.unwrap();
            codec::write_message(
                &mut socket,
                &Message::with_payload(MessageType::Ready, 0, &Ready::default()).unwrap(),
            )
            .await
            .unwrap();
            let (mut reader, mut writer) = socket.into_split();
            let (tx, mut rx) = mpsc::unbounded_channel();
            let mut sockets = HashMap::<u32, TcpSession>::new();
            loop {
                tokio::select! {
                    incoming = codec::read_message(&mut reader) => {
                        let Ok(message) = incoming else { break };
                        match message.t {
                            MessageType::TcpConnect => { sockets.insert(message.id, TcpSession::open(message.id, message.payload().unwrap(), &tx)); }
                            MessageType::TcpData => { sockets.get_mut(&message.id).unwrap().write_data(message.payload::<TcpData>().unwrap().data).unwrap(); }
                            MessageType::TcpCredit => { sockets.get(&message.id).unwrap().credit(message.payload::<TcpCredit>().unwrap().bytes).unwrap(); }
                            MessageType::TcpEof => { sockets.get_mut(&message.id).unwrap().close_write().unwrap(); }
                            MessageType::TcpClose => { sockets.get(&message.id).unwrap().close(); }
                            other => panic!("unexpected message {other:?}"),
                        }
                    }
                    Some((_, output)) = rx.recv() => {
                        let SessionOutput::Raw(output) = output else { panic!("expected raw frame") };
                        writer.write_all(&output.frame).await.unwrap();
                    }
                }
            }
            for (_, session) in sockets {
                session.finish().await.unwrap();
            }
        });
        let agent_client = Arc::new(
            AgentClient::connect_stream_with_timeout(
                TcpStream::connect(agent_address).await.unwrap(),
                Duration::from_secs(2),
            )
            .await
            .unwrap(),
        );
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let config = Arc::new(russh::server::Config {
            keys: vec![
                PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap(),
            ],
            window_size: TCP_WINDOW_BYTES as u32,
            maximum_packet_size: TCP_MAX_DATA_BYTES as u32,
            event_buffer_size,
            ..Default::default()
        });
        let (finished, finished_rx) = mpsc::channel(4);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            russh::server::run_stream(
                config,
                socket,
                Forwarder {
                    client: agent_client,
                    channels: HashMap::new(),
                    gate,
                    finished,
                },
            )
            .await
            .unwrap()
            .await
            .unwrap();
        });
        let config = Arc::new(russh::client::Config {
            window_size: window,
            ..Default::default()
        });
        let mut client = russh::client::connect(config, address, client)
            .await
            .unwrap();
        assert!(client.authenticate_none("test").await.unwrap().success());
        Self {
            client,
            destination: TcpListener::bind(("127.0.0.1", 0)).await.unwrap(),
            finished: finished_rx,
            server,
            agent,
        }
    }

    async fn open(&mut self) -> (Channel<ClientMsg>, TcpStream, oneshot::Receiver<()>) {
        let port = self.destination.local_addr().unwrap().port() as u32;
        let channel = self
            .client
            .channel_open_direct_tcpip("127.0.0.1", port, "127.0.0.1", 0)
            .await
            .unwrap();
        let (peer, _) = self.destination.accept().await.unwrap();
        (channel, peer, self.finished.recv().await.unwrap())
    }

    async fn finish(self) {
        self.client
            .disconnect(russh::Disconnect::ByApplication, "test complete", "en")
            .await
            .unwrap();
        drop(self.client);
        self.server.await.unwrap();
        self.agent.await.unwrap();
    }
}

#[tokio::test]
async fn paused_ssh_output_keeps_input_and_other_channel_close_live() {
    tokio::time::timeout(Duration::from_secs(10), async {
        // A one-byte SSH window never auto-replenishes (target / 2 == 0).
        let mut fixture = Fixture::new(1, Client::default(), None, 10).await;
        let (mut first, mut peer, _) = fixture.open().await;
        peer.write_all(b"ab").await.unwrap();
        match first.wait().await.unwrap() {
            ChannelMsg::Data { data } => assert_eq!(data.as_ref(), b"a"),
            other => panic!("expected the one-byte SSH window to fill, got {other:?}"),
        }
        let receive = tokio::spawn(async move {
            let mut data = vec![0; TCP_WINDOW_BYTES * 2];
            peer.read_exact(&mut data).await.unwrap();
            assert!(data.iter().all(|b| *b == 7));
            peer
        });
        first
            .data(&vec![7; TCP_WINDOW_BYTES * 2][..])
            .await
            .unwrap();
        let mut peer = receive.await.unwrap();
        let (second, mut other, _) = fixture.open().await;
        second.close().await.unwrap();
        assert_eq!(other.read(&mut [0]).await.unwrap(), 0);
        first.close().await.unwrap();
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
        drop((first, second));
        fixture.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn repeated_ssh_replenishment_preserves_queued_reservations_and_controls() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (stalled, exhausted) = oneshot::channel();
        let client = Client {
            stop_after: Some(8),
            stalled: Some(stalled),
            ..Default::default()
        };
        // A single application queue slot leaves the writer reserving its next
        // chunk while the session processes earlier messages and replenishments.
        let mut fixture = Fixture::new(TCP_WINDOW_BYTES as u32, client, None, 1).await;
        let (first, mut peer, _) = fixture.open().await;
        let (mut reader, writer) = first.split();
        let received = tokio::spawn(async move {
            let mut bytes = 0;
            while let Some(message) = reader.wait().await {
                match message {
                    ChannelMsg::Data { data } => bytes += data.len(),
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
            bytes
        });
        let producer =
            tokio::spawn(async move { peer.write_all(&vec![1; TCP_WINDOW_BYTES * 128]).await });
        tokio::time::timeout(Duration::from_secs(3), exhausted)
            .await
            .expect("peer SSH window did not exhaust")
            .unwrap();
        let (second, mut other, _) = tokio::time::timeout(Duration::from_secs(3), fixture.open())
            .await
            .expect("second channel open blocked");
        second.close().await.unwrap();
        assert_eq!(other.read(&mut [0]).await.unwrap(), 0);
        writer.close().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(3), received)
                .await
                .expect("first SSH close blocked")
                .unwrap()
                > TCP_WINDOW_BYTES * 4
        );
        let error = producer.await.unwrap().unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
        ));
        drop((writer, second));
        fixture.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn reset_destination_racing_data_or_eof_does_not_disconnect_other_channels() {
    for phase in [InputPhase::Data, InputPhase::Eof] {
        tokio::time::timeout(Duration::from_secs(10), async {
            let data_phase = matches!(phase, InputPhase::Data);
            let (entered, processing) = oneshot::channel();
            let (release, released) = oneshot::channel();
            let gate = InputGate {
                phase,
                entered,
                release: released,
            };
            let mut fixture =
                Fixture::new(TCP_WINDOW_BYTES as u32, Client::default(), Some(gate), 10).await;
            let (first, peer, finished) = fixture.open().await;
            let (second, mut other, _) = fixture.open().await;
            if data_phase {
                first.data(&b"race"[..]).await.unwrap();
            } else {
                first.eof().await.unwrap();
            }
            processing.await.unwrap();
            let linger = libc::linger {
                l_onoff: 1,
                l_linger: 0,
            };
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        peer.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_LINGER,
                        (&linger as *const libc::linger).cast(),
                        std::mem::size_of_val(&linger) as libc::socklen_t,
                    )
                },
                0
            );
            drop(peer);
            // The worker has enqueued close and dropped its input receiver, but
            // the session is still in the old data/EOF callback.
            finished.await.unwrap();
            release.send(()).unwrap();
            second.data(&b"alive"[..]).await.unwrap();
            let mut bytes = [0; 5];
            other.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"alive");
            second.close().await.unwrap();
            assert_eq!(other.read(&mut [0]).await.unwrap(), 0);
            drop((first, second));
            fixture.finish().await;
        })
        .await
        .unwrap();
    }
}

type PendingOpen = (ChannelOpenHandle, russh::server::Handle, ChannelId);
type Opening = tokio::task::JoinHandle<Result<Channel<ClientMsg>, russh::Error>>;

struct OpenGate {
    pending: mpsc::Sender<PendingOpen>,
    remaining: usize,
    blocked: Option<oneshot::Sender<()>>,
    release: Option<oneshot::Receiver<()>>,
}

impl russh::server::Handler for OpenGate {
    type Error = russh::Error;

    async fn auth_none(&mut self, _: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _: &str,
        _: u32,
        _: &str,
        _: u32,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.pending
            .send((reply, session.handle(), channel.id()))
            .await
            .unwrap();
        self.remaining -= 1;
        if self.remaining == 0 {
            self.blocked.take().unwrap().send(()).unwrap();
            self.release.take().unwrap().await.unwrap();
        }
        Ok(())
    }
}

struct SaturatedOpens {
    client: Arc<russh::client::Handle<Client>>,
    pending: Vec<PendingOpen>,
    openings: Vec<Opening>,
    release: oneshot::Sender<()>,
    server: tokio::task::JoinHandle<Result<(), russh::Error>>,
}

impl SaturatedOpens {
    async fn new() -> Self {
        const OPENS: usize = 3;
        const QUEUE_SLOTS: usize = 10;
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let config = Arc::new(russh::server::Config {
            keys: vec![
                PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap(),
            ],
            event_buffer_size: QUEUE_SLOTS,
            ..Default::default()
        });
        let (pending, mut pending_rx) = mpsc::channel(OPENS);
        let (blocked, blocked_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            russh::server::run_stream(
                config,
                socket,
                OpenGate {
                    pending,
                    remaining: OPENS,
                    blocked: Some(blocked),
                    release: Some(release_rx),
                },
            )
            .await
            .unwrap()
            .await
        });
        let mut client =
            russh::client::connect(Arc::new(Default::default()), address, Client::default())
                .await
                .unwrap();
        assert!(client.authenticate_none("test").await.unwrap().success());
        let client = Arc::new(client);
        let mut openings = Vec::new();
        for _ in 0..OPENS {
            let client = Arc::clone(&client);
            openings.push(tokio::spawn(async move {
                client
                    .channel_open_direct_tcpip("127.0.0.1", 80, "127.0.0.1", 0)
                    .await
            }));
        }
        blocked_rx.await.unwrap();
        let mut pending = Vec::new();
        for _ in 0..OPENS {
            pending.push(pending_rx.recv().await.unwrap());
        }
        // The network callback is held, so all ten enqueues occupy distinct
        // application slots. No timing assumption is used to establish fullness.
        let (_, session, id) = &pending[0];
        for _ in 0..QUEUE_SLOTS {
            session.channel_success(*id).await.unwrap();
        }
        Self {
            client,
            pending,
            openings,
            release,
            server,
        }
    }
}

#[tokio::test]
async fn saturated_open_queue_preserves_cancelled_accept_and_delivers_all_rejections() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut fixture = SaturatedOpens::new().await;
        {
            let accepting = fixture.pending[0].0.respond(Ok(()));
            tokio::pin!(accepting);
            assert!(futures::poll!(&mut accepting).is_pending());
        } // Cancel without consuming the pending reply state.
        let rejections = fixture
            .pending
            .into_iter()
            .map(|(mut reply, session, _)| {
                tokio::spawn(async move { finish_ssh_open(&mut reply, false, &session).await })
            })
            .collect::<Vec<_>>();
        fixture.release.send(()).unwrap();
        for rejection in rejections {
            assert!(rejection.await.unwrap());
        }
        for opening in fixture.openings {
            assert!(matches!(
                opening.await.unwrap(),
                Err(russh::Error::ChannelOpenFailure(
                    ChannelOpenFailure::AdministrativelyProhibited
                ))
            ));
        }
        fixture
            .client
            .disconnect(russh::Disconnect::ByApplication, "test complete", "en")
            .await
            .unwrap();
        drop(fixture.client);
        fixture.server.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn saturated_open_reply_deadline_or_abandonment_terminates_transport() {
    for abandon in [false, true] {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut fixture = SaturatedOpens::new().await;
            if abandon {
                drop(fixture.pending.remove(0));
            } else {
                let replies = fixture
                    .pending
                    .drain(..)
                    .map(|(mut reply, session, _)| {
                        tokio::spawn(
                            async move { finish_ssh_open(&mut reply, false, &session).await },
                        )
                    })
                    .collect::<Vec<_>>();
                for reply in replies {
                    assert!(!reply.await.unwrap());
                }
            }
            assert!(matches!(
                fixture.server.await.unwrap(),
                Err(russh::Error::Disconnect)
            ));
            for opening in fixture.openings {
                assert!(opening.await.unwrap().is_err());
            }
            drop((fixture.client, fixture.pending, fixture.release));
        })
        .await
        .unwrap();
    }
}
