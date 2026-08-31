#![allow(dead_code)]

mod sokol;

use aya::maps::lpm_trie::Key;
use aya::maps::sock::SockMap;
use aya::maps::{LpmTrie, MapData, PerCpuArray};
use aya::programs::{SchedClassifier, TcAttachType, Xdp, tc};
use aya::{include_bytes_aligned, Bpf, Pod};
use clap::Parser;
use sokol::SokolEngine;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

#[link(name = "sntl_db", kind = "static")]
extern "C" {
    fn sntl_db_init(path_ptr: *const u8, path_len: usize) -> bool;
    fn sntl_db_append_request(data_ptr: *const u8, data_len: usize) -> u64;
    fn sntl_db_version() -> u32;
}

pub struct SentinelDb {
    tx: mpsc::UnboundedSender<String>,
}

impl SentinelDb {
    pub fn init(path: &str) -> Result<Self, &'static str> {
        let success = unsafe { sntl_db_init(path.as_ptr(), path.len()) };
        if !success {
            return Err("Failed to initialize Zig DB Engine");
        }
        log::info!("Zig DB Engine initialized successfully (v{})", Self::version());

        let (tx, mut rx) = mpsc::unbounded_channel::<String>();

        
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                while let Some(payload) = rx.recv().await {
                    unsafe {
                        sntl_db_append_request(payload.as_ptr(), payload.len());
                    }
                }
            });
        });

        Ok(Self { tx })
    }

    pub fn append(&self, data: String) {
        let _ = self.tx.send(data);
    }

    pub fn version() -> u32 {
        unsafe { sntl_db_version() }
    }
}

#[repr(transparent)]
#[derive(Copy, Clone)]
struct BpfPacketStats(common::PacketStats);

unsafe impl Pod for BpfPacketStats {}

#[derive(Parser, Debug)]
#[command(author, version, about = "Sokol-Core Sovereign Orchestrator - Production Node")]
struct Args {
    #[arg(short, long, default_value = "eth0")]
    interface: String,

    #[arg(long, value_name = "IP")]
    block: Vec<String>,

    #[arg(long, value_name = "PORT")]
    trap_port: Vec<u16>,

    #[arg(long, default_value = "/var/lib/sokol/sntl_events.sntl")]
    db_path: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    log::info!("Initializing Sokol-Core Production Daemon on interface: {}", args.interface);

    let sntl_db = Arc::new(SentinelDb::init(&args.db_path).map_err(|e| {
        anyhow::anyhow!("Failed to initialize sntl_db: {}", e)
    })?);

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/bpfel-unknown-none/debug/ebpf_probe"
    )))?;

    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/bpfel-unknown-none/release/ebpf_probe"
    )))?;

    
    let prog_mut = bpf
        .program_mut("sentinel_vfr_filter")
        .ok_or_else(|| anyhow::anyhow!("Critical: Program sentinel_vfr_filter not found in ELF"))?;
    let program: &mut Xdp = prog_mut.try_into()?;
    program.load()?;
    let _link = program.attach(&args.interface, Default::default())?;
    log::info!("XDP program successfully locked and attached to interface: {}", args.interface);

    
    let tc_prog_mut = bpf
        .program_mut("sentinel_vfr_tc")
        .ok_or_else(|| anyhow::anyhow!("Critical: Program sentinel_vfr_tc not found in ELF"))?;
    let tc_program: &mut SchedClassifier = tc_prog_mut.try_into()?;
    let _qdisc = tc::qdisc_add_clsact(&args.interface)?;
    tc_program.load()?;
    let _tc_link = tc_program.attach(&args.interface, TcAttachType::Ingress)?;
    log::info!("TC stateful VFR program successfully locked and attached to ingress of {}", args.interface);

    let stats_map_data = bpf.take_map("STATS").ok_or_else(|| anyhow::anyhow!("STATS missing"))?;
    let stats_map: PerCpuArray<MapData, BpfPacketStats> = PerCpuArray::try_from(stats_map_data)?;

    let blocklist_map_data = bpf.take_map("BLOCKLIST_V4").ok_or_else(|| anyhow::anyhow!("BLOCKLIST_V4 missing"))?;
    let blocklist_map = Arc::new(tokio::sync::Mutex::new(LpmTrie::<MapData, [u8; 4], u32>::try_from(blocklist_map_data)?));

    let socket_map_data = bpf.take_map("SOCKET_MAP").ok_or_else(|| anyhow::anyhow!("SOCKET_MAP missing"))?;
    let socket_map = Arc::new(tokio::sync::Mutex::new(SockMap::<MapData>::try_from(socket_map_data)?));

    for ip_str in &args.block {
        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
            let key = Key::new(32, ip.octets());
            blocklist_map.lock().await.insert(&key, 1u32, 0)?;
            sntl_db.append(format!("STATIC_BLOCK|IP:{}|Action:XDP_DROP", ip));
        }
    }

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Ipv4Addr>(100);

    for (idx, &port) in args.trap_port.iter().enumerate() {
        let tx_trap = cmd_tx.clone();
        let db_trap = sntl_db.clone();
        let sock_map_clone = socket_map.clone();
        let bind_addr = format!("0.0.0.0:{}", port);
        let map_index = idx as u32;

        tokio::spawn(async move {
            if let Ok(listener) = tokio::net::TcpListener::bind(&bind_addr).await {
                log::info!("[TRAP] Decoy TCP trap listening on port {}", port);
                while let Ok((stream, peer)) = listener.accept().await {
                    let ip = peer.ip();
                    let v4_ip = match ip {
                        std::net::IpAddr::V4(v4) => v4,
                        _ => continue,
                    };

                    log::warn!("[TRAP HIT] Unauthorized connection on port {} from {}", port, ip);

                    let mut map = sock_map_clone.lock().await;
                    if let Err(e) = map.set(map_index, &stream, 0) {
                        log::error!("[SOCKMAP ERROR] Failed to insert socket into map: {}", e);
                    }

                    let _ = tx_trap.send(v4_ip).await;
                    db_trap.append(format!("TRAP_HIT|Port:{}|IP:{}|Action:SockMapRedirect", port, ip));
                }
            }
        });
    }

    let map_clone = blocklist_map.clone();
    let db_clone = sntl_db.clone();
    tokio::spawn(async move {
        while let Some(ip_to_block) = cmd_rx.recv().await {
            let key = Key::new(32, ip_to_block.octets());
            if map_clone.lock().await.insert(&key, 1u32, 0).is_ok() {
                log::info!("Dynamic runtime block enforced for IP: {}", ip_to_block);
                db_clone.append(format!("DYNAMIC_BLOCK|IP:{}|Enforced", ip_to_block));
            }
        }
    });

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        log::warn!("Shutdown signal received. Teardown initiated...");
        r.store(false, Ordering::SeqCst);
    })?;

    let sokol_engine = SokolEngine::new(500.0);
    let mut prev_packets = 0;
    let mut prev_bytes = 0;

    while running.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let mut total_rx_packets = 0u64;
        let mut total_rx_bytes = 0u64;
        let mut total_dropped = 0u64;

        if let Ok(values) = stats_map.get(&0u32, 0) {
            total_rx_packets = values.iter().map(|v| v.0.rx_packets).sum();
            total_rx_bytes = values.iter().map(|v| v.0.rx_bytes).sum();
            total_dropped = values.iter().map(|v| v.0.dropped_packets).sum();
        }

        let pps = total_rx_packets.saturating_sub(prev_packets);
        let bps = total_rx_bytes.saturating_sub(prev_bytes);

        if let Ok(true) = sokol_engine.detect_anomaly(total_rx_packets as f64, prev_packets as f64, 1.0) {
            log::warn!("SOKOL ALERT: Packet storm detected! PPS: {}", pps);
            sntl_db.append(format!("STORM_ALERT|PPS:{}|Dropped:{}", pps, total_dropped));
        }

        prev_packets = total_rx_packets;
        prev_bytes = total_rx_bytes;

        log::info!("METRICS | PPS: {} | BPS: {} | Total RX: {} | Dropped: {}", pps, bps, total_rx_packets, total_dropped);
    }

    Ok(())
}