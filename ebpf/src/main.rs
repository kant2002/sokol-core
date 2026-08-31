#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{lpm_trie::Key, LpmTrie, PerCpuArray, RingBuf},
    programs::XdpContext,
};
use common::{drop_reason, DropEvent, PacketStats};

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const TRAP_PORT: u16 = 44333;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EthHdr {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct IpHdr {
    pub version_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TcpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub doff_reserved: u8,
    pub flags: u8,
    pub window: u16,
    pub check: u16,
    pub urg_ptr: u16,
}

#[map]
static BLOCKLIST_V4: LpmTrie<[u8; 4], u32> = LpmTrie::with_max_entries(65536, 0);

#[map]
static STATS: PerCpuArray<PacketStats> = PerCpuArray::with_max_entries(1, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[inline(always)]
fn emit_drop_event(src_ip: [u8; 16], dst_ip: [u8; 16], pkt_len: u32, reason: u16, protocol: u8, ip_version: u8) {
    if let Some(mut entry) = EVENTS.reserve::<DropEvent>(0) {
        entry.write(DropEvent {
            src_ip,
            dst_ip,
            pkt_len,
            reason,
            protocol,
            ip_version,
        });
        entry.submit(0);
    }
}

#[xdp]
pub fn sentinel_vfr_filter(ctx: XdpContext) -> u32 {
    match try_sentinel_vfr_filter(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_sentinel_vfr_filter(ctx: &XdpContext) -> Result<u32, ()> {
    let eth_ptr = ptr_at::<EthHdr>(ctx, 0)?;
    let raw_eth_type = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth_ptr).ether_type)) };
    let eth_type = u16::from_be(raw_eth_type);
    let ip_offset = core::mem::size_of::<EthHdr>();
    let packet_len = (ctx.data_end() - ctx.data()) as u64;

    if eth_type != ETH_P_IP {
        record_rx(packet_len);
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_ptr = ptr_at::<IpHdr>(ctx, ip_offset)?;
    let version_ihl = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_ptr).version_ihl)) };
    let version = version_ihl >> 4;
    let ihl_bytes = ((version_ihl & 0x0F) * 4) as usize;
    let protocol = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_ptr).protocol)) };

    let src_addr_be = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_ptr).src_addr)) };
    let dst_addr_be = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_ptr).dst_addr)) };

    let mut src_ip_16 = [0u8; 16];
    let mut dst_ip_16 = [0u8; 16];
    src_ip_16[..4].copy_from_slice(&src_addr_be.to_ne_bytes());
    dst_ip_16[..4].copy_from_slice(&dst_addr_be.to_ne_bytes());

    if version != 4 || ihl_bytes < 20 || ctx.data() + ip_offset + ihl_bytes > ctx.data_end() {
        record_drop(packet_len, drop_reason::MALFORMED_HEADER);
        emit_drop_event(src_ip_16, dst_ip_16, packet_len as u32, drop_reason::MALFORMED_HEADER, protocol, 4);
        return Ok(xdp_action::XDP_DROP);
    }

    let key = Key::new(32, src_addr_be.to_ne_bytes());
    if BLOCKLIST_V4.get(&key).is_some() {
        record_drop(packet_len, drop_reason::SLOW_PATH_LPM_HIT);
        emit_drop_event(src_ip_16, dst_ip_16, packet_len as u32, drop_reason::SLOW_PATH_LPM_HIT, protocol, 4);
        return Ok(xdp_action::XDP_DROP);
    }

    if protocol == IPPROTO_TCP {
        let tcp_offset = ip_offset + ihl_bytes;
        if let Ok(tcp_ptr) = ptr_at::<TcpHdr>(ctx, tcp_offset) {
            let dst_port = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp_ptr).dst_port)) };
            let port = u16::from_be(dst_port);
            
            if port == 80 || port == 443 {
                record_rx(packet_len);
                return Ok(xdp_action::XDP_PASS);
            }

            
            if port == TRAP_PORT {
                emit_drop_event(
                    src_ip_16,
                    dst_ip_16,
                    packet_len as u32,
                    drop_reason::TRAP_INTERCEPTED,
                    protocol,
                    4,
                );
                record_rx(packet_len);
                return Ok(xdp_action::XDP_PASS);
            }
        }
    }

    record_rx(packet_len);
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn record_rx(packet_len: u64) {
    if let Some(stats_ptr) = STATS.get_ptr_mut(0) {
        unsafe {
            (*stats_ptr).rx_packets += 1;
            (*stats_ptr).rx_bytes += packet_len;
        }
    }
}

#[inline(always)]
fn record_drop(packet_len: u64, reason: u16) {
    if let Some(stats_ptr) = STATS.get_ptr_mut(0) {
        unsafe {
            (*stats_ptr).rx_packets += 1;
            (*stats_ptr).rx_bytes += packet_len;
            (*stats_ptr).dropped_packets += 1;
            if reason == drop_reason::SLOW_PATH_LPM_HIT || reason == drop_reason::STATIC_BLOCK {
                (*stats_ptr).slow_path_hits += 1;
            }
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}