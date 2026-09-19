use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use common::NodeTelemetry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterStatus {
    Stable,
    LocalIncident,
    DistributedStorm,
    Unknown,
}

struct NodeState {
    telemetry: NodeTelemetry,
    last_seen: Instant,
}

struct ClusterState {
    nodes: HashMap<u64, NodeState>,
    total_dropped_packets: u64,
}

pub struct BirdEyeView {
    state: Arc<RwLock<ClusterState>>,
    storm_threshold: f64,
    ttl: Duration,
}

impl BirdEyeView {
    pub fn new(storm_threshold: f64, ttl: Duration) -> Self {
        Self {
            state: Arc::new(RwLock::new(ClusterState {
                nodes: HashMap::new(),
                total_dropped_packets: 0,
            })),
            storm_threshold,
            ttl,
        }
    }

    pub async fn ingest(&self, telemetry: NodeTelemetry) {
        let mut state = self.state.write().await;
        
        let old_drops = state.nodes
            .get(&telemetry.node_id)
            .map_or(0, |n| n.telemetry.dropped_packets);
        
        state.total_dropped_packets = state.total_dropped_packets
            .saturating_sub(old_drops)
            .saturating_add(telemetry.dropped_packets);

        state.nodes.insert(telemetry.node_id, NodeState {
            telemetry,
            last_seen: Instant::now(),
        });
    }

    pub async fn global_cluster_health(&self) -> ClusterStatus {
        let mut state = self.state.write().await;
        self.prune_stale_nodes_locked(&mut state).await;

        let total_nodes = state.nodes.len();
        if total_nodes == 0 {
            return ClusterStatus::Unknown;
        }

        let attacked_nodes = state.nodes
            .values()
            .filter(|n| n.telemetry.under_attack != 0)
            .count();

        let attack_ratio = attacked_nodes as f64 / total_nodes as f64;

        if attack_ratio > self.storm_threshold {
            ClusterStatus::DistributedStorm
        } else if attack_ratio > 0.0 {
            ClusterStatus::LocalIncident
        } else {
            ClusterStatus::Stable
        }
    }

    pub async fn is_global_storm_detected(&self) -> bool {
        matches!(self.global_cluster_health().await, ClusterStatus::DistributedStorm)
    }

    pub async fn total_cluster_drops(&self) -> u64 {
        let mut state = self.state.write().await;
        self.prune_stale_nodes_locked(&mut state).await;
        state.total_dropped_packets
    }

    async fn prune_stale_nodes_locked(&self, state: &mut ClusterState) {
        let now = Instant::now();
        let ttl = self.ttl;
        
        state.nodes.retain(|_, node| {
            let is_alive = now.duration_since(node.last_seen) <= ttl;
            if !is_alive {
                state.total_dropped_packets = state.total_dropped_packets
                    .saturating_sub(node.telemetry.dropped_packets);
            }
            is_alive
        });
    }
}