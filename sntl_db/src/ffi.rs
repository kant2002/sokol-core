use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum AttackType {
    SynFlood = 1,
    UdpAmplification = 2,
    InvalidExtHdr = 3,
    BgpBlackholed = 4,
}

extern "C" {
    fn sntl_db_init(path_ptr: *const u8, path_len: usize) -> u8;
    fn sntl_db_close();
    fn sntl_db_sync() -> u8;
    fn sntl_db_append_request(data_ptr: *const u8, data_len: usize) -> u64;
    
    
    fn sntl_db_flag_high_value_target(target_ptr: *const u8, target_len: usize) -> u8;
    
    fn sntl_db_flag_high_value_target_v6(
        src_ip_ptr: *const u8,
        dst_ip_ptr: *const u8,
        packets_dropped: u32,
        attack_type: u8,
    ) -> u8;
    
    fn sntl_db_get_total_pages() -> u64;
    fn sntl_db_read_page(
        page_id: u64,
        out_ptr: *mut u8,
        max_len: usize,
        out_written: *mut usize,
    ) -> u8;
    fn sntl_db_version() -> u32;
}

pub struct SntlDb;

unsafe impl Send for SntlDb {}
unsafe impl Sync for SntlDb {}

impl SntlDb {
    pub fn init(path: &Path) -> io::Result<Self> {
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Database path cannot be empty",
            ));
        }

        let res = unsafe { sntl_db_init(bytes.as_ptr(), bytes.len()) };
        if res == 1 {
            Ok(SntlDb)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to initialize sntl_db engine",
            ))
        }
    }

    #[inline]
    pub fn log_ipv6_anomaly(
        &self,
        src_ip: &Ipv6Addr,
        dst_ip: &Ipv6Addr,
        packets_dropped: u32,
        attack_type: AttackType,
    ) -> bool {
        let src_octets = src_ip.octets();
        let dst_octets = dst_ip.octets();
        
        let res = unsafe { 
            sntl_db_flag_high_value_target_v6(
                src_octets.as_ptr(),
                dst_octets.as_ptr(),
                packets_dropped,
                attack_type as u8,
            ) 
        };
        res == 1
    }

    #[inline]
    pub fn sync(&self) -> io::Result<()> {
        let res = unsafe { sntl_db_sync() };
        if res == 1 {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Io,
                "Failed to flush database pages to disk",
            ))
        }
    }

    
}

impl Drop for SntlDb {
    fn drop(&mut self) {
        let _ = self.sync();
        unsafe { sntl_db_close() };
    }
}