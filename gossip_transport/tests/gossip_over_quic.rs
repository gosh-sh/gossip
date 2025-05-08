use chitchat::ChitchatConfig;
use chitchat::ChitchatId;
use chitchat::FailureDetectorConfig;
use chitchat::spawn_chitchat;
use chitchat::transport::{ChannelTransport, Transport, TransportExt};
use ed25519_dalek::SigningKey;
use once_cell::sync::OnceCell;
use rand::Rng;
use rand::distributions::Distribution;
use rand::rngs::OsRng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing_subscriber::EnvFilter;

static LOG_INIT: OnceCell<()> = OnceCell::new();

fn init_logs() {
    LOG_INIT.get_or_init(|| {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .with_test_writer()
            .init();
    });
}
#[derive(Clone)]
struct ConstDelay(f32);

impl chitchat::transport::DelayMillisDist for ConstDelay {}

impl Distribution<f32> for ConstDelay {
    fn sample<R: Rng + ?Sized>(&self, _rng: &mut R) -> f32 {
        self.0.clone()
    }
}

enum TransportFactory {
    Quick,
    Udp,
    InProcess(Arc<dyn Transport>),
}

impl TransportFactory {
    fn in_process(delay_sec: Option<f32>) -> Self {
        Self::InProcess(if let Some(delay_sec) = delay_sec {
            ChannelTransport::with_mtu(65_507).delay(ConstDelay(delay_sec)).into()
        } else {
            Arc::new(ChannelTransport::with_mtu(65_507))
        })
    }

    fn create_transport(&self, addr: SocketAddr, key: SigningKey) -> Arc<dyn Transport> {
        match self {
            Self::InProcess(transport) => transport.clone(),
            Self::Quick => {
                let (health_report_channel_sender, mut health_report_channel_receiver) =
                    tokio::sync::watch::channel(Instant::now());

                let _dummy_health_report_handler = tokio::spawn(async move {
                    while let Ok(health_report) = health_report_channel_receiver.changed().await {
                        tracing::debug!("Received health report: {:?}", health_report);
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                });
                let (_, incoming_rx, outgoing_tx) =
                    gossip_transport::quic::run(addr, addr, key).unwrap();
                Arc::new(gossip_transport::channel::ChannelTransport::new(
                    incoming_rx,
                    outgoing_tx,
                    health_report_channel_sender,
                ))
            }
            Self::Udp => Arc::new(chitchat::transport::UdpTransport),
        }
    }
}

#[tokio::test]
async fn test_gossip_over_quic() {
    test_gossip_over_transport(TransportFactory::Quick).await;
}

#[tokio::test]
async fn test_gossip_over_udp() {
    test_gossip_over_transport(TransportFactory::Udp).await;
}

#[tokio::test]
async fn test_gossip_over_inproc() {
    test_gossip_over_transport(TransportFactory::in_process(None)).await;
}

async fn test_gossip_over_transport(transport_factory: TransportFactory) {
    init_logs();
    tracing::trace!("test_gossip_over_quic");
    let host_count = 70;
    let seed_hosts = [0, 1, 2, 3, 4];
    // let seed_hosts = 0..host_count;

    let mut addrs = Vec::new();
    let mut keys = Vec::new();
    let mut csprng = OsRng;
    let mut seed_nodes = Vec::new();
    for host in 0..host_count {
        let addr = SocketAddr::from(([127, 0, 0, 1], 10_000 + host as u16));
        addrs.push(addr);
        keys.push(SigningKey::generate(&mut csprng));
        if seed_hosts.contains(&host) {
            seed_nodes.push(addr.to_string());
        }
    }
    let mut handles = Vec::new();
    for host in 0..host_count {
        let listen_addr = addrs[host];
        let chitchat_id = ChitchatId {
            node_id: format!("node_{host}"),
            generation_id: 0,
            gossip_advertise_addr: listen_addr,
        };
        let config = ChitchatConfig {
            chitchat_id,
            cluster_id: "default-cluster".to_string(),
            gossip_interval: Duration::from_millis(500),
            listen_addr,
            seed_nodes: seed_nodes.clone(),
            failure_detector_config: FailureDetectorConfig::default(),
            marked_for_deletion_grace_period: Duration::from_secs(10),
            catchup_callback: None,
            extra_liveness_predicate: None,
        };
        let transport = transport_factory.create_transport(listen_addr, keys[host].clone());
        let handle = spawn_chitchat(config, Vec::new(), transport.as_ref()).await.unwrap();
        handle
            .with_chitchat(|x| {
                for i in 0..10 {
                    x.self_node_state().set(format!("key{i}"), i.to_string().repeat(100));
                }
            })
            .await;
        handles.push(handle);
    }
    for sec in 0..60 {
        println!("\n=== {sec} ===\n");
        tokio::time::sleep(Duration::from_secs(1)).await;
        for handle in &handles {
            let chitchat = handle.chitchat();
            let chitchat = chitchat.lock().unwrap();
            let live = chitchat.live_nodes().collect::<Vec<_>>();
            let dead = chitchat.dead_nodes().collect::<Vec<_>>();
            if live.len() < host_count || dead.len() > 0 {
                println!("live: {:?}, dead: {}", live.len(), dead.len());
            }
        }
    }
}
