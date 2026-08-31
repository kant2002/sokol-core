use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

const DB_FILE: &str = "sokol_audit.sntl";
const MAGIC: u32 = 0x534E544C;
const PAGE_SIZE: usize = 4096;
const HEADER_SIZE: usize = 64;

#[derive(Debug, Clone)]
struct AuditEvent {
    page_id: u64,
    ip: String,
    tier: String,
    payload_len: String,
    #[allow(dead_code)]
    raw: String,
}

fn parse_db() -> io::Result<Vec<AuditEvent>> {
    let path = Path::new(DB_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();
    let mut events = Vec::new();
    let mut buffer = vec![0u8; PAGE_SIZE];

    let mut current_pos = 0;
    while current_pos < file_size {
        file.seek(SeekFrom::Start(current_pos))?;
        let n = file.read(&mut buffer)?;
        if n < PAGE_SIZE {
            break;
        }

        let magic = u32::from_le_bytes(buffer[0..4].try_into().unwrap());
        if magic != MAGIC {
            current_pos += PAGE_SIZE as u64;
            continue;
        }

        let page_id = u64::from_le_bytes(buffer[16..24].try_into().unwrap());
        let data_len = u32::from_le_bytes(buffer[40..44].try_into().unwrap());

        let payload_end = HEADER_SIZE + data_len as usize;
        if payload_end <= PAGE_SIZE {
            let payload_bytes = &buffer[HEADER_SIZE..payload_end];
            if let Ok(log_str) = String::from_utf8(payload_bytes.to_vec()) {
                let mut ip = "Unknown".to_string();
                let mut tier = "UNKNOWN".to_string();
                let mut payload_len = "0".to_string();

                for part in log_str.split('|') {
                    if let Some(val) = part.strip_prefix("IP=") {
                        ip = val.to_string();
                    } else if let Some(val) = part.strip_prefix("TIER=") {
                        tier = val.to_string();
                    } else if let Some(val) = part.strip_prefix("LEN=") {
                        payload_len = val.to_string();
                    }
                }

                events.push(AuditEvent {
                    page_id,
                    ip,
                    tier,
                    payload_len,
                    raw: log_str,
                });
            }
        }

        current_pos += PAGE_SIZE as u64;
    }

    Ok(events)
}

fn get_ebpf_active_blocks() -> Vec<String> {
    let output = Command::new("sudo")
        .args(["bpftool", "map", "dump", "name", "BLOCKLIST_V4"])
        .output();

    let mut banned_ips = Vec::new();
    if let Ok(out) = output {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                if line.contains("key:") {
                    let parts: Vec<&str> = line.split("key:").collect();
                    if parts.len() > 1 {
                        let hex_bytes: Vec<u8> = parts[1]
                            .split_whitespace()
                            .filter_map(|s| u8::from_str_radix(s, 16).ok())
                            .collect();
                        if hex_bytes.len() >= 4 {
                            let ip = format!("{}.{}.{}.{}", hex_bytes[0], hex_bytes[1], hex_bytes[2], hex_bytes[3]);
                            banned_ips.push(ip);
                        }
                    }
                }
            }
        }
    }
    banned_ips
}

fn main() -> io::Result<()> {
    loop {
        print!("\x1B[2J\x1B[1;1H");
        io::stdout().flush()?;

        println!("==================================================================");
        println!("       SOKOL-CORE: RUST NATIVE SECURITY & EBPF TELEMETRY         ");
        println!("==================================================================");

        let events = parse_db().unwrap_or_default();
        let total_attacks = events.len();

        let mut unique_ips = HashMap::new();
        let mut tiers_counter = HashMap::new();

        for ev in &events {
            *unique_ips.entry(ev.ip.clone()).or_insert(0) += 1;
            *tiers_counter.entry(ev.tier.clone()).or_insert(0) += 1;
        }

        let ebpf_blocks = get_ebpf_active_blocks();

        println!("[*] Total Intercepted Attacks (sntl_db) : {}", total_attacks);
        println!("[*] Unique Attacker IPs Logged         : {}", unique_ips.len());
        println!("[*] Active eBPF XDP Kernel Drops (IPs) : {}", ebpf_blocks.len());

        println!("\n--- Active eBPF Kernel Blocklist (BLOCKLIST_V4) ---");
        if ebpf_blocks.is_empty() {
            println!("    (No active IP blocks in kernel XDP map yet)");
        } else {
            for ip in &ebpf_blocks {
                println!("    [XDP_DROP] Blocked IP -> {}", ip);
            }
        }

        println!("\n--- Trident Tier Distribution ---");
        for (tier, count) in &tiers_counter {
            println!("    {:<25} : {}", tier, count);
        }

        println!("\n--- Recent Audit Events (sntl_db) ---");
        println!("{:<6} | {:<15} | {:<25} | {:<10}", "PAGE", "IP ADDRESS", "TRIDENT TIER", "LEN (B)");
        println!("{}", "-".repeat(65));

        let start = if total_attacks > 8 { total_attacks - 8 } else { 0 };
        for ev in &events[start..] {
            let tier_truncated: String = ev.tier.chars().take(23).collect();
            println!("{:<6} | {:<15} | {:<25} | {:<10}", 
                ev.page_id, 
                ev.ip, 
                tier_truncated, 
                ev.payload_len
            );
        }

        println!("\n[Press Ctrl+C to exit]");
        thread::sleep(Duration::from_secs(2));
    }
}