use std::net::SocketAddr;
use std::sync::atomic;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use async_channel::Receiver;
use async_channel::Sender;
use async_trait::async_trait;
use chitchat::ChitchatMessage;
use chitchat::Serializable;
use chitchat::transport::Socket;
use chitchat::transport::Transport;
use tracing::debug;

pub const CHANNEL_CAPACITY: usize = 100;
pub const MESSAGE_SOFT_TTL: Duration = Duration::from_millis(100);
pub const SOFT_LEN_THRESHOLD: usize = CHANNEL_CAPACITY / 4;

pub struct IncomingMessage {
    pub received_at: Instant,
    pub from_addr: SocketAddr,
    pub message: ChitchatMessage,
}

pub struct OutgoingMessage {
    pub created_at: Instant,
    pub to_addr: SocketAddr,
    pub message: ChitchatMessage,
}

/// Universal channel transport fasade.
/// Allows using in tokio/multithread context.
#[derive(Debug)]
pub struct ChannelTransport {
    counter: atomic::AtomicU16,
    incoming_source: Receiver<IncomingMessage>,
    outgoing_source: Sender<OutgoingMessage>,
    health_report_channel_sender: tokio::sync::watch::Sender<Instant>,
}

impl ChannelTransport {
    pub fn new(
        incoming_source: Receiver<IncomingMessage>,
        outgoing_source: Sender<OutgoingMessage>,
        health_report_channel_sender: tokio::sync::watch::Sender<Instant>,
    ) -> Self {
        let counter = atomic::AtomicU16::new(0);
        Self { counter, incoming_source, outgoing_source, health_report_channel_sender }
    }
}

#[async_trait]
impl Transport for ChannelTransport {
    async fn open(&self, _listen_addr: SocketAddr) -> anyhow::Result<Box<dyn Socket>> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        let id = self.counter.load(Ordering::SeqCst);
        let incoming_channel = self.incoming_source.clone();
        let outgoing_channel = self.outgoing_source.clone();
        let health_report_channel_sender = self.health_report_channel_sender.clone();
        Ok(Box::new(ChannelSocket {
            id,
            incoming_channel,
            outgoing_channel,
            health_report_channel_sender,
        }))
    }
}

#[derive(Debug)]
struct ChannelSocket {
    id: u16,
    incoming_channel: Receiver<IncomingMessage>,
    outgoing_channel: Sender<OutgoingMessage>,
    health_report_channel_sender: tokio::sync::watch::Sender<Instant>,
}

#[async_trait]
impl Socket for ChannelSocket {
    async fn send(&mut self, to_addr: SocketAddr, message: ChitchatMessage) -> anyhow::Result<()> {
        debug!("send message to {to_addr}");
        self.outgoing_channel
            .send(OutgoingMessage { created_at: Instant::now(), to_addr, message })
            .await?;
        self.health_report_channel_sender.send(Instant::now())?;
        Ok(())
    }

    async fn recv(&mut self) -> anyhow::Result<(SocketAddr, ChitchatMessage)> {
        tracing::info!("chitchat call recv {}", self.id);

        let incoming_message = {
            loop {
                let incoming_message = self
                    .incoming_channel
                    .recv()
                    .await
                    .with_context(|| "Incoming channel is broken")?;

                // skip message by soft ttl if channel surpases upper bound
                if self.incoming_channel.len() >= SOFT_LEN_THRESHOLD
                    && incoming_message.received_at.elapsed() > MESSAGE_SOFT_TTL
                {
                    tracing::info!("skipping message by soft ttl");
                    continue;
                }
                break incoming_message;
            }
        };

        tracing::info!(
            "chitchat recv message from {} {}",
            incoming_message.from_addr,
            incoming_message.message.serialized_len()
        );

        self.health_report_channel_sender.send(Instant::now())?;
        Ok((incoming_message.from_addr, incoming_message.message))
    }
}
