use std::ffi::CString;
use std::path::Path;
use std::io;

extern "C" {
    fn sntl_db_init(path_ptr: *const u8, path_len: usize) -> bool;
    fn sntl_db_close();
    fn sntl_db_append_request(data_ptr: *const u8, data_len: usize) -> u64;
    fn sntl_db_version() -> u32;
    fn sntl_db_flag_high_value_target(target_ptr: *const u8, target_len: usize) -> bool;
}

pub struct SntlDb;

impl SntlDb {
    pub fn init(path: &Path) -> io::Result<()> {
        let path_str = path.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Invalid database path")
        })?;
        
        let c_str = CString::new(path_str)?;
        let success = unsafe {
            sntl_db_init(c_str.as_ptr() as *const u8, c_str.as_bytes().len())
        };

        if success {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "Failed to initialize the sntl_db engine"))
        }
    }

    pub fn append(data: &[u8]) -> io::Result<u64> {
        let page_id = unsafe {
            sntl_db_append_request(data.as_ptr(), data.len())
        };

        if page_id == u64::MAX {
            Err(io::Error::new(io::ErrorKind::Other, "Failed to append packet to sntl_db"))
        } else {
            Ok(page_id)
        }
    }

    pub fn flag_high_value_target(target: &str) -> bool {
        unsafe {
            sntl_db_flag_high_value_target(target.as_ptr(), target.len())
        }
    }

    pub fn close() {
        unsafe {
            sntl_db_close();
        }
    }

    pub fn version() -> u32 {
        unsafe { sntl_db_version() }
    }
}