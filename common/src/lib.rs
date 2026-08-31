#![no_std]

pub mod drop_reason {
    pub const STATIC_BLOCK: u16 = 1;
    pub const FAST_PATH_HIT: u16 = 2;
    pub const SLOW_PATH_LPM_HIT: u16 = 3;
    pub const VFR_ANOMALY: u16 = 4;
    pub const MALFORMED_HEADER: u16 = 5;
    pub const TRAP_INTERCEPTED: u16 = 6;
    pub const SOCK_REDIRECTED: u16 = 7;
    pub const MANUAL_BLOCK: u16 = 8;
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketStats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub dropped_packets: u64,
    pub vfr_anomalies: u64,
    pub fast_path_hits: u64,
    pub slow_path_hits: u64,
    pub redirected_packets: u64,
}

impl PacketStats {
    pub const ZERO: Self = Self {
        rx_packets: 0,
        rx_bytes: 0,
        dropped_packets: 0,
        vfr_anomalies: 0,
        fast_path_hits: 0,
        slow_path_hits: 0,
        redirected_packets: 0,
    };
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DropEvent {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub pkt_len: u32,
    pub reason: u16,
    pub protocol: u8,
    pub ip_version: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LpmKeyV4 {
    pub prefixlen: u32,
    pub data: [u8; 4],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LpmKeyV6 {
    pub prefixlen: u32,
    pub data: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpcBlockCommand {
    pub src_ip: [u8; 16],
    pub duration_secs: u32, 
    pub reason: u16,
    pub ip_version: u8,     
    pub _pad: u8,           
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForensicHeader {
    pub page_id: u32,
    pub timestamp_epoch: u64,
    pub src_ip: [u8; 16],
    pub payload_len: u16,
    pub reason: u16,
    pub _pad: u32,
}