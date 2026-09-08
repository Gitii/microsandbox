//! Real SSH and guest TCP tasks on loopback, without a VM or a protocol stub.

use super::*;
use microsandbox_agentd::session::SessionOutput;
use microsandbox_agentd::tcp::TcpSession;
use microsandbox_protocol::{codec, core::Ready, message::Message};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

struct Forwarder {
    client: Arc<AgentClient>,
    channels: HashMap<ChannelId, (queue::Sender<SshTcpInput>, watch::Sender<bool>)>,
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        for (_, stop) in self.channels.values() {
            stop.send_replace(true);
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
        let (id, mut rx) = self
            .client
            .stream(
                MessageType::TcpConnect,
                &TcpConnect {
                    host: host.into(),
                    port: port.try_into()?,
                },
            )
            .await?;
        assert_eq!(rx.recv().await.unwrap().t, MessageType::TcpConnected);
        let channel_id = channel.id();
        let writer = channel.make_writer();
        let (input, input_rx) = queue::channel(queue::TRANSPORT_QUEUE_BYTES);
        let (stop, stop_rx) = watch::channel(false);
        self.channels.insert(channel_id, (input, stop));
        tokio::spawn(relay_tcp_to_ssh(
            channel_id,
            id,
            Arc::clone(&self.client),
            rx,
            session.handle(),
            writer,
            input_rx,
            stop_rx,
        ));
        reply.accept().await;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels[&channel]
            .0
            .try_send(SshTcpInput::Data(data.to_vec()), data.len())
            .map_err(|_| anyhow::anyhow!("input queue exhausted"))
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels[&channel]
            .0
            .try_send(SshTcpInput::Eof, 0)
            .map_err(|_| anyhow::anyhow!("input queue closed"))
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some((_, stop)) = self.channels.remove(&channel) {
            stop.send_replace(true);
        }
        Ok(())
    }
}

struct Client;

impl russh::client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _: &russh::keys::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[tokio::test]
async fn paused_ssh_output_keeps_input_and_other_channel_close_live() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let agent_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let agent_address = agent_listener.local_addr().unwrap();
        let agent = tokio::spawn(async move {
            let (mut socket, _) = agent_listener.accept().await.unwrap();
            socket.write_all(&1u32.to_be_bytes()).await.unwrap();
            socket.write_all(&100u32.to_be_bytes()).await.unwrap();
            codec::write_message(&mut socket, &Message::with_payload(MessageType::Ready, 0, &Ready::default()).unwrap()).await.unwrap();
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
            for (_, session) in sockets { session.finish().await.unwrap(); }
        });
        let agent_client = Arc::new(AgentClient::connect_stream_with_timeout(TcpStream::connect(agent_address).await.unwrap(), Duration::from_secs(2)).await.unwrap());
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let config = Arc::new(russh::server::Config {
            keys: vec![PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap()],
            window_size: TCP_WINDOW_BYTES as u32,
            maximum_packet_size: TCP_MAX_DATA_BYTES as u32,
            ..Default::default()
        });
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            russh::server::run_stream(config, socket, Forwarder { client: agent_client, channels: HashMap::new() }).await.unwrap().await.unwrap();
        });
        // A one-byte SSH window never auto-replenishes (target / 2 == 0).
        // This is a real stalled SSH receive window, not a mocked AsyncWrite.
        let config = Arc::new(russh::client::Config { window_size: 1, ..Default::default() });
        let mut client = russh::client::connect(config, address, Client).await.unwrap();
        assert!(client.authenticate_none("test").await.unwrap().success());
        let destination = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = destination.local_addr().unwrap().port() as u32;
        let first = client.channel_open_direct_tcpip("127.0.0.1", port, "127.0.0.1", 0).await.unwrap();
        let (mut peer, _) = destination.accept().await.unwrap();
        peer.write_all(b"ab").await.unwrap();
        // Input exceeds the initial TCP window and requires returned guest credit,
        // even though output cannot finish writing its two bytes to SSH.
        let receive = tokio::spawn(async move {
            let mut data = vec![0; TCP_WINDOW_BYTES * 2];
            peer.read_exact(&mut data).await.unwrap();
            assert!(data.iter().all(|b| *b == 7));
            peer
        });
        first.data(&vec![7; TCP_WINDOW_BYTES * 2][..]).await.unwrap();
        let mut peer = receive.await.unwrap();
        let second = client.channel_open_direct_tcpip("127.0.0.1", port, "127.0.0.1", 0).await.unwrap();
        let (mut other, _) = destination.accept().await.unwrap();
        second.close().await.unwrap();
        assert_eq!(other.read(&mut [0]).await.unwrap(), 0);
        first.close().await.unwrap();
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
        client.disconnect(russh::Disconnect::ByApplication, "test complete", "en").await.unwrap();
        drop(client);
        drop(first);
        drop(second);
        server.await.unwrap();
        agent.await.unwrap();
    }).await.unwrap();
}
