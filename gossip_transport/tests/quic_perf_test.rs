use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;

use chitchat::ChitchatConfig;
use chitchat::ChitchatHandle;
use chitchat::ChitchatId;
use chitchat::FailureDetectorConfig;
use chitchat::NodeState;
use chitchat::spawn_chitchat;
use chitchat::transport::Transport;
use gossip_transport::channel::ChannelTransport;
use gossip_transport::quic;
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;
use tracing::info;

async fn spawn_one(
    chitchat_id: u16,
    seed_nodes: Vec<String>,
    listen_addr: SocketAddr,
    transport: &dyn Transport,
) -> ChitchatHandle {
    let chitchat_id = ChitchatId {
        node_id: format!("node_{chitchat_id}"),
        generation_id: 0,
        gossip_advertise_addr: listen_addr,
    };
    let gossip_interval = Duration::from_millis(300);
    let config = ChitchatConfig {
        chitchat_id,
        cluster_id: "default-cluster".to_string(),
        gossip_interval,
        listen_addr,
        seed_nodes,
        failure_detector_config: FailureDetectorConfig {
            initial_interval: gossip_interval,
            ..Default::default()
        },
        marked_for_deletion_grace_period: Duration::from_secs(10_000),
        catchup_callback: None,
        extra_liveness_predicate: None,
    };
    spawn_chitchat(config, Vec::new(), transport).await.unwrap()
}

async fn spawn_nodes(
    num_nodes: u16,
    listen_addrs: Vec<SocketAddr>,
    transports: Vec<&dyn Transport>,
) -> Vec<ChitchatHandle> {
    let mut handles = Vec::new();
    for id in 0..num_nodes as usize {
        let handle = spawn_one(
            id as u16,
            vec![listen_addrs[0].to_string()],
            listen_addrs[id],
            transports[id],
        )
        .await;
        handles.push(handle);
    }
    handles
}

async fn wait_until<P: Fn(&BTreeMap<ChitchatId, NodeState>) -> bool>(
    handle: &ChitchatHandle,
    predicate: P,
) -> Duration {
    let start = Instant::now();
    let mut node_watcher = handle.chitchat().lock().await.live_nodes_watch_stream();
    while let Some(nodes) = node_watcher.next().await {
        if predicate(&nodes) {
            break;
        }
    }
    start.elapsed()
}

async fn delay_before_detection_sample(
    num_nodes: usize,
    listen_addrs: Vec<SocketAddr>,
    transports: Vec<&dyn Transport>,
) -> Duration {
    assert!(num_nodes > 2);
    let mut handles = spawn_nodes(num_nodes as u16, listen_addrs, transports).await;
    info!("spawn {num_nodes} nodes");
    let _delay = wait_until(&handles[1], |nodes| nodes.len() == num_nodes).await;
    info!("converged on {num_nodes} nodes");
    handles.pop();
    let time_to_death_detection =
        wait_until(&handles[1], |nodes| nodes.len() == num_nodes - 1).await;
    for handle in handles {
        handle.shutdown().await.unwrap();
    }
    info!(time_to_death_detection=?time_to_death_detection);
    time_to_death_detection
}

struct QuicTransport {
    bind_addr: SocketAddr,
    quic_handler: JoinHandle<anyhow::Result<()>>,
    transport: ChannelTransport,
}

async fn spawn_quic_transport(ip_addr: String, base_port: u16, n: usize) -> Vec<QuicTransport> {
    let mut transports = Vec::new();
    for i in 0..n {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let port = base_port + i as u16;
        let advertise_addr: SocketAddr = format!("{ip_addr}:{port}").parse().unwrap();
        let bind_addr: SocketAddr = format!("{ip_addr}:{port}").parse().unwrap();
        let (quic_handler, incoming_messages, outgoing_messages) =
            quic::run(bind_addr, advertise_addr, signing_key).unwrap();

        let transport =
            gossip_transport::channel::ChannelTransport::new(incoming_messages, outgoing_messages);

        transports.push(QuicTransport { bind_addr, quic_handler, transport });
    }
    transports
}

#[tokio::test]
async fn test_delay_before_dead_detection_10() {
    // let _ = tracing_subscriber::fmt::try_init();
    let count = 10;
    let base_port = 10000;
    let base_ip_addr = "127.0.0.1".to_string();
    let transports = spawn_quic_transport(base_ip_addr, base_port, count).await;

    let delay = delay_before_detection_sample(
        count,
        transports.iter().map(|t| t.bind_addr).collect(),
        transports.iter().map(|t| &t.transport as &dyn Transport).collect(),
    )
    .await;
    assert!(delay < Duration::from_secs(10), "Delay exceeded: {:?}", delay);

    for transport in transports {
        transport.quic_handler.abort();
        _ = transport.quic_handler.await;
    }
}

#[tokio::test]
async fn test_delay_before_dead_detection_40() {
    // let _ = tracing_subscriber::fmt::try_init();
    let count = 40;
    let base_port = 20000;
    let base_ip_addr = "127.0.0.1".to_string();
    let transports = spawn_quic_transport(base_ip_addr, base_port, count).await;

    let delay = delay_before_detection_sample(
        count,
        transports.iter().map(|t| t.bind_addr).collect(),
        transports.iter().map(|t| &t.transport as &dyn Transport).collect(),
    )
    .await;
    assert!(delay < Duration::from_secs(10), "Delay exceeded: {:?}", delay);

    for transport in transports {
        transport.quic_handler.abort();
        _ = transport.quic_handler.await;
    }
}
