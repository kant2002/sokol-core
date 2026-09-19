use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

const DB_FILE: &str = "/var/lib/sokol/sntl_events.sntl";
const MAGIC: u32 = 0x534E544C;
const PAGE_SIZE: usize = 4096;
const HEADER_SIZE: usize = 64;

#[derive(Debug, Clone)]
struct AuditEvent {
    page_id: u64,
    ip: String,
    tier: String,
    payload_len: String,
    payload_snippet: String,
    #[allow(dead_code)]
    raw: String,
}

fn read_new_events(
    file: &mut Option<File>,
    current_pos: &mut u64,
    events: &mut Vec<AuditEvent>,
) -> io::Result<()> {
    let path = Path::new(DB_FILE);
    if !path.exists() {
        *current_pos = 0;
        events.clear();
        *file = None;
        return Ok(());
    }

    if file.is_none() {
        *file = Some(File::open(path)?);
    }

    let f = file.as_mut().unwrap();
    let metadata = f.metadata()?;
    let file_size = metadata.len();

    if file_size < *current_pos {
        *current_pos = 0;
        events.clear();
    }

    if *current_pos >= file_size {
        return Ok(());
    }

    f.seek(SeekFrom::Start(*current_pos))?;
    let mut buffer = [0u8; PAGE_SIZE];

    while *current_pos + (PAGE_SIZE as u64) <= file_size {
        let n = f.read(&mut buffer)?;
        if n < PAGE_SIZE {
            break;
        }

        *current_pos += PAGE_SIZE as u64;

        let magic = u32::from_le_bytes(buffer[0..4].try_into().unwrap_or([0; 4]));
        if magic != MAGIC {
            continue;
        }

        let page_id = u64::from_le_bytes(buffer[16..24].try_into().unwrap_or([0; 8]));
        let data_len = u32::from_le_bytes(buffer[40..44].try_into().unwrap_or([0; 4]));

        let payload_end = HEADER_SIZE + data_len as usize;
        if payload_end <= PAGE_SIZE {
            let payload_bytes = &buffer[HEADER_SIZE..payload_end];

            let log_str = String::from_utf8_lossy(payload_bytes)
                .replace('\0', "")
                .trim()
                .to_string();

            let mut ip = "Unknown".to_string();
            let mut tier = "Event".to_string();
            let mut payload_len = data_len.to_string();
            let mut payload_snippet = String::new();

            let parts: Vec<&str> = log_str.split('|').collect();
            if let Some(first) = parts.first() {
                tier = first.trim().to_string();
            }

            for part in &parts {
                let part = part.trim();
                if let Some(val) = part.strip_prefix("IP=") {
                    ip = val.to_string();
                } else if let Some(val) = part.strip_prefix("IP:") {
                    ip = val.to_string();
                } else if let Some(val) = part.strip_prefix("TIER=") {
                    tier = val.to_string();
                } else if let Some(val) = part.strip_prefix("LEN=") {
                    payload_len = val.to_string();
                } else if let Some(val) = part.strip_prefix("DATA=") {
                    payload_snippet = val.to_string();
                }
            }

            if ip == "Unknown" {
                if let Some(found_ip) = log_str
                    .split(|c: char| c.is_whitespace() || c == '|' || c == '=' || c == ',' || c == '"' || c == '\'')
                    .map(|token| token.trim_matches(|c: char| !c.is_ascii_digit() && c != '.'))
                    .find_map(|candidate| candidate.parse::<Ipv4Addr>().ok())
                {
                    ip = found_ip.to_string();
                }
            }

            if payload_snippet.is_empty() {
                payload_snippet = log_str.chars().take(30).collect();
            }

            events.push(AuditEvent {
                page_id,
                ip,
                tier,
                payload_len,
                payload_snippet,
                raw: log_str,
            });
        }
    }

    Ok(())
}

fn get_ebpf_active_blocks() -> Vec<String> {
    let output = Command::new("bpftool")
        .args(["map", "dump", "name", "BLOCKLIST_V4"])
        .output()
        .or_else(|_| Command::new("sudo").args(["bpftool", "map", "dump", "name", "BLOCKLIST_V4"]).output());

    let mut banned_ips = Vec::new();
    if let Ok(out) = output {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                if let Some(idx) = line.find("key:") {
                    let key_str = &line[idx + 4..];
                    let hex_bytes: Vec<u8> = key_str
                        .split_whitespace()
                        .filter_map(|s| u8::from_str_radix(s, 16).ok())
                        .collect();

                    if hex_bytes.len() >= 8 {
                        let ip = format!("{}.{}.{}.{}", hex_bytes[4], hex_bytes[5], hex_bytes[6], hex_bytes[7]);
                        banned_ips.push(ip);
                    }
                }
            }
        }
    }
    banned_ips
}

fn main() -> io::Result<()> {
    let mut db_file: Option<File> = None;
    let mut db_pos: u64 = 0;
    let mut events: Vec<AuditEvent> = Vec::new();

    loop {
        let _ = read_new_events(&mut db_file, &mut db_pos, &mut events);

        let total_attacks = events.len();
        let mut unique_ips = HashMap::new();
        let mut tiers_counter = HashMap::new();

        for ev in &events {
            *unique_ips.entry(ev.ip.clone()).or_insert(0) += 1;
            *tiers_counter.entry(ev.tier.clone()).or_insert(0) += 1;
        }

        let ebpf_blocks = get_ebpf_active_blocks();

        print!("\x1B[H\x1B[2J");
        io::stdout().flush()?;

        println!("==================================================================");
        println!("       SOKOL-CORE: RUST NATIVE SECURITY & EBPF TELEMETRY         ");
        println!("==================================================================");

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

        println!("\n--- Live Captured Attack Payloads (sntl_db) ---");
        println!("{:<6} | {:<15} | {:<18} | {:<6} | {:<20}", "PAGE", "IP ADDRESS", "TIER", "LEN", "PAYLOAD SNIPPET");
        println!("{}", "-".repeat(78));

        let start = events.len().saturating_sub(8);

        for ev in &events[start..] {
            println!(
                "{:<6} | {:<15} | {:<18.18} | {:<6} | {:<20.20}", 
                ev.page_id, 
                ev.ip, 
                ev.tier, 
                ev.payload_len,
                ev.payload_snippet
            );
        }

        println!("\n[Press Ctrl+C to exit]");
        thread::sleep(Duration::from_secs(2));
    }
}