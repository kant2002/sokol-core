#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tc},
    maps::LruHashMap,
    programs::TcContext,
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
};

const ETH_P_IP: u16 = 0x0800;

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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FragKey {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub id: u16,
}

unsafe impl aya_ebpf::Pod for FragKey {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FragValue {
    pub pkt_count: u32,
    pub first_seen_ns: u64,
}

unsafe impl aya_ebpf::Pod for FragValue {}

#[map]
static FRAG_TABLE: LruHashMap<FragKey, FragValue> = LruHashMap::with_max_entries(16384, 0);

#[inline(always)]
fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[tc]
pub fn sentinel_vfr_tc(ctx: TcContext) -> i32 {
    match try_sentinel_vfr_tc(&ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

#[inline(always)]
fn try_sentinel_vfr_tc(ctx: &TcContext) -> Result<i32, ()> {
    let eth_ptr = ptr_at::<EthHdr>(ctx, 0)?;
    let raw_eth_type = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth_ptr).ether_type)) };
    let eth_type = u16::from_be(raw_eth_type);

    if eth_type != ETH_P_IP {
        return Ok(TC_ACT_OK);
    }

    let ip_offset = core::mem::size_of::<EthHdr>();
    let ip_ptr = ptr_at::<IpHdr>(ctx, ip_offset)?;

    let frag_off_raw = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_ptr).frag_off)) };
    let frag_off = u16::from_be(frag_off_raw);

    const IP_MF: u16 = 0x2000;
    const IP_OFFSET: u16 = 0x1FFF;

    if (frag_off & IP_MF) != 0 || (frag_off & IP_OFFSET) != 0 {
        let src_addr = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_ptr).src_addr)) };
        let dst_addr = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_ptr).dst_addr)) };
        let id = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_ptr).id)) };
        let current_time = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

        let key = FragKey { src_addr, dst_addr, id };

        if let Some(val_ptr) = FRAG_TABLE.get_ptr_mut(&key) {
            unsafe {
    
                if current_time - (*val_ptr).first_seen_ns > 5_000_000_000 {
                    (*val_ptr).pkt_count = 1;
                    (*val_ptr).first_seen_ns = current_time;
                } else {
                    (*val_ptr).pkt_count += 1;
                    if (*val_ptr).pkt_count > 64 {
                        return Ok(TC_ACT_SHOT);
                    }
                }
            }
        } else {
            let _ = FRAG_TABLE.insert(
                &key,
                &FragValue {
                    pkt_count: 1,
                    first_seen_ns: current_time,
                },
                0,
            );
        }
    }

    Ok(TC_ACT_OK)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}