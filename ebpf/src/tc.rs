#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::LruHashMap,
    programs::XdpContext,
};
use core::mem;

const ETH_P_IP: u16 = 0x0800;
const IP_MF: u16 = 0x2000;
const IP_OFFSET_MASK: u16 = 0x1FFF;
const MAX_FRAGS_PER_WINDOW: u32 = 64;
const WINDOW_NS: u64 = 5_000_000_000;

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

#[repr(C, align(4))]
#[derive(Clone, Copy)]
pub struct FragKey {
    pub src_addr: u32,
}

unsafe impl aya_ebpf::Pod for FragKey {}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct FragValue {
    pub first_seen_ns: u64,
    pub pkt_count: u32,
    pub _pad: u32,
}

unsafe impl aya_ebpf::Pod for FragValue {}

#[map]
static FRAG_RATE_MAP: LruHashMap<FragKey, FragValue> = LruHashMap::with_max_entries(16384, 0);

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data() as usize;
    let end = ctx.data_end() as usize;
    let len = mem::size_of::<T>();

    if start.checked_add(offset).and_then(|v| v.checked_add(len)).is_some() {
        if start + offset + len <= end {
            return Ok((start + offset) as *const T);
        }
    }
    Err(())
}

#[xdp]
pub fn sentinel_frag_filter(ctx: XdpContext) -> u32 {
    match try_sentinel_frag_filter(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_sentinel_frag_filter(ctx: &XdpContext) -> Result<u32, ()> {
    let eth_ptr = ptr_at::<EthHdr>(ctx, 0)?;
    let raw_eth_type = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth_ptr).ether_type)) };
    if u16::from_be(raw_eth_type) != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_offset = mem::size_of::<EthHdr>();
    let ip_ptr = match ptr_at::<IpHdr>(ctx, ip_offset) {
        Ok(ptr) => ptr,
        Err(_) => return Ok(xdp_action::XDP_DROP),
    };

    let version_ihl = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_ptr).version_ihl)) };
    let version = version_ihl >> 4;
    let ihl_bytes = ((version_ihl & 0x0F) * 4) as usize;

    if version != 4 || ihl_bytes < 20 || (ctx.data() as usize) + ip_offset + ihl_bytes > (ctx.data_end() as usize) {
        return Ok(xdp_action::XDP_DROP);
    }

    let frag_off_raw = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_ptr).frag_off)) };
    let frag_off = u16::from_be(frag_off_raw);

    if (frag_off & (IP_MF | IP_OFFSET_MASK)) != 0 {
        let src_addr = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_ptr).src_addr)) };
        let current_time = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

        let key = FragKey { src_addr };

        if let Some(val_ptr) = FRAG_RATE_MAP.get_ptr_mut(&key) {
            unsafe {
                let val = &mut *val_ptr;

                if current_time.saturating_sub(val.first_seen_ns) > WINDOW_NS {
                    val.first_seen_ns = current_time;
                    val.pkt_count = 1;
                } else {
                    val.pkt_count = val.pkt_count.saturating_add(1);
                    if val.pkt_count > MAX_FRAGS_PER_WINDOW {
                        return Ok(xdp_action::XDP_DROP);
                    }
                }
            }
        } else {
            let val = FragValue {
                first_seen_ns: current_time,
                pkt_count: 1,
                _pad: 0,
            };
            let _ = FRAG_RATE_MAP.insert(&key, &val, 0);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}