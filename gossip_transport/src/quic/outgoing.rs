use std::collections::HashMap;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::time::Instant;

use anyhow::Context;
use async_channel::Receiver;
use chitchat::ChitchatMessage;
use chitchat::Serializable;
use ed25519_dalek::SigningKey;
use tracing::info;
use tracing::warn;
use wtransport::Connection;
use wtransport::endpoint::endpoint_side::Client;

use crate::channel::OutgoingMessage;

#[allow(unused)]
struct ClientConnectionPool {
    public_addr: SocketAddr,
    signing_key: SigningKey,
    endpoint: wtransport::Endpoint<Client>,
    connections: HashMap<SocketAddr, Connection>,
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
    ) -> anyhow::Result<Connection> {
        let connection = match self.connections.get(&to_addr) {
            Some(connection) => connection.clone(),
            None => self.create_connection(to_addr).await?,
        };
        Ok(connection)
    }

    pub async fn create_connection(&mut self, to_addr: SocketAddr) -> anyhow::Result<Connection> {
        warn!("create_connection to {to_addr}");
        // self.connections
        //     .entry(to_addr)
        //     .and_modify(|c| c.close(wtransport::VarInt::from_u32(0), "reconnect".as_bytes()));
        let connection = self.endpoint.connect(format!("https://{to_addr}")).await?;
        // self.connections.insert(to_addr, connection.clone());
        Ok(connection)
    }

    pub fn open_connections(&self) -> usize {
        self.endpoint.open_connections()
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
        let instant = Instant::now();
        // try use cached connection
        let connection = connection_pool
            .get_or_create_connection(to_addr)
            .await
            .with_context(|| "failed to create connection")?;
        // let connection = connection_pool.create_connection(to_addr).await?;
        let elapsed = instant.elapsed();
        info!(elapsed = ?elapsed, "create connection");

        info!(open_connections = connection_pool.open_connections(), "open connections");

        let instant = Instant::now();
        // handle_send(&connection, connection_pool.public_addr, &message).await?;
        if let Err(err) = handle_send(&connection, connection_pool.public_addr, &message)
            .await
            .with_context(|| "failed to send message")
        {
            // force reconnect
            tracing::warn!(%err, "failed to send message reconnect");
            let connection = connection_pool.create_connection(to_addr).await?;
            handle_send(&connection, connection_pool.public_addr, &message).await?;
        }
        let elapsed = instant.elapsed();
        info!(elapsed = ?elapsed, destination = ?to_addr, "message sent");
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
