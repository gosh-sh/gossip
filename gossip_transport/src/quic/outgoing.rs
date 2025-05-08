use std::collections::HashMap;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::sync::Arc;

use anyhow::Context;
use async_channel::Receiver;
use chitchat::ChitchatMessage;
use chitchat::Serializable;
use ed25519_dalek::SigningKey;
use tracing::warn;
use tracing::{error, info};
use wtransport::Connection;
use wtransport::endpoint::endpoint_side::Client;

use crate::channel::{CHANNEL_CAPACITY, OutgoingMessage};

struct ClientConnectionPool {
    public_addr: SocketAddr,
    signing_key: SigningKey,
    endpoint: wtransport::Endpoint<Client>,
    connections: HashMap<SocketAddr, Arc<ActiveConnection>>,
}

struct ActiveConnection {
    task: tokio::task::JoinHandle<()>,
    message_tx: async_channel::Sender<ChitchatMessage>,
}

impl ClientConnectionPool {
    pub fn new(
        public_addr: SocketAddr,
        signing_key: SigningKey,
        endpoint: wtransport::Endpoint<Client>,
    ) -> Self {
        Self { public_addr, signing_key, endpoint, connections: HashMap::new() }
    }

    pub async fn get_or_create_connection(
        &mut self,
        to_addr: SocketAddr,
    ) -> anyhow::Result<Arc<ActiveConnection>> {
        if let Some(connection) = self.connections.get(&to_addr).cloned() {
            if !connection.task.is_finished() {
                return Ok(connection.clone());
            }
        }
        Ok(self.create_connection(to_addr).await?)
    }

    pub async fn create_connection(
        &mut self,
        to_addr: SocketAddr,
    ) -> anyhow::Result<Arc<ActiveConnection>> {
        warn!("create_connection to {to_addr}");
        let connection = self.endpoint.connect(format!("https://{to_addr}")).await?;
        let (message_tx, message_rx) = async_channel::bounded(CHANNEL_CAPACITY);
        let task = tokio::spawn(handle_connection_outgoing_messages(
            message_rx,
            connection,
            self.public_addr,
        ));
        let active_connection = Arc::new(ActiveConnection { message_tx, task });
        self.connections.insert(to_addr, active_connection.clone());
        Ok(active_connection)
    }

    pub fn open_connections(&self) -> usize {
        self.endpoint.open_connections()
    }
}

async fn handle_connection_outgoing_messages(
    messages_rx: Receiver<ChitchatMessage>,
    connection: Connection,
    public_addr: SocketAddr,
) {
    loop {
        if let Ok(message) = messages_rx.recv().await {
            if let Err(err) = handle_send(&connection, public_addr, &message).await {
                error!(%err, "failed to send message");
                break;
            }
        } else {
            break;
        }
    }
}

pub async fn run(
    _socket: UdpSocket,
    public_addr: SocketAddr,
    signing_key: SigningKey,
    outgoing_messages: Receiver<OutgoingMessage>,
) -> anyhow::Result<()> {
    let client_config =
        wtransport::ClientConfig::builder().with_bind_default().with_no_cert_validation().build();

    // let client_config = wtransport::ClientConfig::builder()
    //     // .with_bind_socket(socket)
    //     .with_bind_default()
    //     .with_no_cert_validation()
    //     // .keep_alive_interval(Some(Duration::from_secs(2)))
    //     // .max_idle_timeout(Some(Duration::from_secs(3)))?
    //     .build();

    tracing::info!("Starting gossip transport with config: {:?}", client_config);
    let client_endpoint = wtransport::Endpoint::client(client_config)
        .with_context(|| "failed to build quic client")?;

    tracing::info!("Public address: {}", public_addr);
    let mut connection_pool = ClientConnectionPool::new(public_addr, signing_key, client_endpoint);

    async fn inner(
        connection_pool: &mut ClientConnectionPool,
        to_addr: SocketAddr,
        message: ChitchatMessage,
    ) -> anyhow::Result<()> {
        let connection = connection_pool
            .get_or_create_connection(to_addr)
            .await
            .with_context(|| "failed to create connection")?;

        info!(open_connections = connection_pool.open_connections(), "open connections");

        match connection.message_tx.force_send(message) {
            Ok(None) => {}
            Ok(Some(_)) => {
                error!("message dropped");
            }
            Err(_err) => {
                anyhow::bail!("outgoing channel was closed");
            }
        }
        Ok(())
    }

    loop {
        let Ok(outgoing_message) = outgoing_messages.recv().await else {
            anyhow::bail!("outgoing_messages channel closed");
        };
        if outgoing_message.to_addr == public_addr {
            continue;
        }

        if let Err(err) =
            inner(&mut connection_pool, outgoing_message.to_addr, outgoing_message.message).await
        {
            tracing::warn!(%err, "client service failed");
        }
    }
}

#[must_use]
async fn handle_send(
    connection: &Connection,
    from_addr: SocketAddr,
    message: &ChitchatMessage,
) -> anyhow::Result<()> {
    let mut stream = connection.open_uni().await.context("failed to open uni stream")?.await?;
    stream.write_all(from_addr.serialize_to_vec().as_slice()).await.context("failed to write")?;
    stream.write_all(message.serialize_to_vec().as_slice()).await.context("failed to write")?;
    stream.finish().await.context("failed to finish")?;
    Ok(())
}
