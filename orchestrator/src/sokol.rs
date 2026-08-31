use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct FlowRate(pub f64);

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct EntropyValue(pub f64);

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct RelaxationSec(pub f64);

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct PhaseGradient(pub f64);

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FieldVector {
    pub q: FlowRate,
    pub h: EntropyValue,
    pub tau: RelaxationSec,
    pub phi: PhaseGradient,
}

#[derive(Clone, Debug)]
pub struct NodeTelemetry {
    pub node_id: u64,
    pub rx_packets: u64,
    pub dropped_packets: u64,
    pub anomaly_score: f64,
    pub under_attack: bool,
}

#[derive(Debug, PartialEq)]
pub enum ClusterStatus {
    Stable,
    LocalIncident,
    DistributedStorm,
    Unknown,
}

#[derive(Debug, PartialEq)]
pub enum EngineError {
    InvalidFloat,
    ZeroDeltaTime,
}

pub struct SokolEngine {
    epsilon: f64,
}

impl SokolEngine {
    pub fn new(epsilon: f64) -> Self {
        Self { epsilon }
    }

    pub fn detect_anomaly(&self, current: f64, prev: f64, dt: f64) -> Result<bool, EngineError> {
        if dt <= 0.0 || dt.is_nan() || dt.is_infinite() {
            return Err(EngineError::ZeroDeltaTime);
        }
        if current.is_nan() || prev.is_nan() || current.is_infinite() || prev.is_infinite() {
            return Err(EngineError::InvalidFloat);
        }
        
        let derivative = (current - prev) / dt;
        Ok(derivative.abs() > self.epsilon)
    }

    pub fn compute_flow_rate(delta_n: u64, delta_t: f64) -> FlowRate {
        if delta_t <= 0.0 || delta_t.is_nan() || delta_t.is_infinite() {
            return FlowRate(0.0);
        }
        FlowRate(delta_n as f64 / delta_t)
    }

    pub fn compute_shannon_entropy(probabilities: &[f64]) -> EntropyValue {
        let h = probabilities
            .iter()
            .filter(|&&p| p > 0.0 && !p.is_nan() && !p.is_infinite()) 
            .map(|&p| -p * p.log2())
            .sum();
        EntropyValue(h)
    }

    pub fn compute_relaxation_time(alpha: f64) -> RelaxationSec {
        if alpha <= 0.0 || alpha >= 1.0 || alpha.is_nan() {
            return RelaxationSec(0.0); 
        }
        RelaxationSec(-1.0 / alpha.ln())
    }
}

struct NodeState {
    telemetry: NodeTelemetry,
    last_seen: Instant,
}

struct ClusterState {
    nodes: HashMap<u64, NodeState>,
    total_dropped_packets: u64,
}

#[derive(Clone)]
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

    pub fn ingest_thought_block(&self, telemetry: NodeTelemetry) {
        let mut state = self.state.write().expect("RwLock poisoned");
        
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

    pub fn global_cluster_health(&self) -> ClusterStatus {
        let mut state = self.state.write().expect("RwLock poisoned");
        self.prune_stale_nodes_locked(&mut state);

        let total_nodes = state.nodes.len();
        if total_nodes == 0 {
            return ClusterStatus::Unknown;
        }

        let attacked_nodes = state.nodes
            .values()
            .filter(|n| n.telemetry.under_attack)
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

    pub fn total_cluster_drops(&self) -> u64 {
        let mut state = self.state.write().expect("RwLock poisoned");
        self.prune_stale_nodes_locked(&mut state);
        state.total_dropped_packets
    }

    fn prune_stale_nodes_locked(&self, state: &mut ClusterState) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sokol_temporal_spike() {
        let engine = SokolEngine::new(500.0);

        let normal_prev = 1000.0;
        let normal_curr = 1200.0;
        assert_eq!(engine.detect_anomaly(normal_curr, normal_prev, 1.0), Ok(false));

        let spike_prev = 1200.0;
        let spike_curr = 2500.0;
        assert_eq!(engine.detect_anomaly(spike_curr, spike_prev, 1.0), Ok(true));

        assert_eq!(engine.detect_anomaly(2500.0, 1200.0, 0.0), Err(EngineError::ZeroDeltaTime));
        assert_eq!(engine.detect_anomaly(2500.0, 1200.0, f64::INFINITY), Err(EngineError::ZeroDeltaTime));
        assert_eq!(engine.detect_anomaly(f64::NAN, 1200.0, 1.0), Err(EngineError::InvalidFloat));
    }

    #[test]
    fn test_chronoflux_math() {
        let flow = SokolEngine::compute_flow_rate(10000, 2.0);
        assert_eq!(flow, FlowRate(5000.0));

        let entropy = SokolEngine::compute_shannon_entropy(&[0.5, 0.5, f64::NAN]); 
        assert_eq!(entropy, EntropyValue(1.0));

        let tau = SokolEngine::compute_relaxation_time(0.5);
        assert!(tau.0 > 1.44 && tau.0 < 1.45); 
    }

    #[test]
    fn test_bird_eye_view() {
        let bird_eye = BirdEyeView::new(0.4, Duration::from_secs(300));
        
        assert_eq!(bird_eye.global_cluster_health(), ClusterStatus::Unknown);

        bird_eye.ingest_thought_block(NodeTelemetry {
            node_id: 1, rx_packets: 5000, dropped_packets: 0, anomaly_score: 0.1, under_attack: false,
        });
        bird_eye.ingest_thought_block(NodeTelemetry {
            node_id: 2, rx_packets: 5500, dropped_packets: 0, anomaly_score: 0.12, under_attack: false,
        });
        bird_eye.ingest_thought_block(NodeTelemetry {
            node_id: 3, rx_packets: 50000, dropped_packets: 20000, anomaly_score: 0.9, under_attack: true,
        });

        assert_eq!(bird_eye.global_cluster_health(), ClusterStatus::LocalIncident);
        assert_eq!(bird_eye.total_cluster_drops(), 20000);

        bird_eye.ingest_thought_block(NodeTelemetry {
            node_id: 4, rx_packets: 45000, dropped_packets: 15000, anomaly_score: 0.85, under_attack: true,
        });
        bird_eye.ingest_thought_block(NodeTelemetry {
            node_id: 5, rx_packets: 60000, dropped_packets: 30000, anomaly_score: 0.95, under_attack: true,
        });

        assert_eq!(bird_eye.global_cluster_health(), ClusterStatus::DistributedStorm);
        assert_eq!(bird_eye.total_cluster_drops(), 65000);
    }
}