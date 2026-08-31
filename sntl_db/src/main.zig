const std = @import("std");

pub const PAGE_SIZE: usize = 4096;
pub const MAGIC: u32 = 0x534E544C;
pub const HEADER_SIZE: usize = 64;

export fn __zig_probe_stack() callconv(.c) void {}

pub const PageType = enum(u8) {
    meta = 0,
    data = 1,
    index = 2,
    journal = 3,
};

pub const PageHeader = extern struct {
    magic: u32,
    version: u16,
    page_type: u8,
    flags: u8,
    checksum: u32,
    reserved_align: u32,
    page_id: u64,
    prev_page: u64,
    next_page: u64,
    data_len: u32,
    reserved: [20]u8,
};

pub const AppendLog = struct {
    fd: i32,
    current_page_id: u64,

    pub fn init(path: []const u8) !AppendLog {
        var buf: [512]u8 = undefined;
        if (path.len >= buf.len) return error.NameTooLong;
        @memcpy(buf[0..path.len], path);
        buf[path.len] = 0;
        const zpath: [*:0]const u8 = @ptrCast(&buf);

        const flags: std.os.linux.O = @bitCast(@as(u32, 2 | 64));
        const res = std.os.linux.open(zpath, flags, 0o644);
        const fd = @as(i32, @intCast(res));
        if (fd < 0) return error.OpenFailed;

        const size_res = std.os.linux.lseek(fd, 0, 2);
        if (@as(isize, @bitCast(size_res)) < 0) {
            _ = std.os.linux.close(fd);
            return error.SeekFailed;
        }
        var size = @as(u64, @intCast(size_res));

        const remainder = size % PAGE_SIZE;
        if (remainder != 0) {
            size = size - remainder;
            const trunc_res = std.os.linux.ftruncate(fd, @intCast(size));
            if (@as(isize, @bitCast(trunc_res)) < 0) {
                _ = std.os.linux.close(fd);
                return error.TruncateFailed;
            }
        }

        const valid_pages = size / PAGE_SIZE;
        _ = std.os.linux.lseek(fd, 0, 2);

        return AppendLog{
            .fd = fd,
            .current_page_id = valid_pages,
        };
    }

    pub fn deinit(self: *AppendLog) void {
        _ = std.os.linux.close(self.fd);
    }

    pub fn append(self: *AppendLog, data: []const u8) !u64 {
        if (data.len > PAGE_SIZE - HEADER_SIZE) {
            return error.DataTooLargeForPage;
        }

        var page_buffer: [PAGE_SIZE]u8 = undefined;
        @memset(&page_buffer, 0);

        const header = PageHeader{
            .magic = MAGIC,
            .version = 1,
            .page_type = @intFromEnum(PageType.data),
            .flags = 0,
            .checksum = 0,
            .reserved_align = 0,
            .page_id = self.current_page_id,
            .prev_page = if (self.current_page_id > 0) self.current_page_id - 1 else 0,
            .next_page = 0,
            .data_len = @intCast(data.len),
            .reserved = std.mem.zeroes([20]u8),
        };

        const header_bytes = std.mem.asBytes(&header);
        @memcpy(page_buffer[0..header_bytes.len], header_bytes);
        @memcpy(page_buffer[header_bytes.len..][0..data.len], data);

        const checksum = std.hash.Crc32.hash(&page_buffer);
        const checksum_offset = @offsetOf(PageHeader, "checksum");
        std.mem.writeInt(u32, page_buffer[checksum_offset .. checksum_offset + 4][0..4], checksum, .little);

        _ = std.os.linux.lseek(self.fd, 0, 2);
        const written = std.os.linux.write(self.fd, &page_buffer, PAGE_SIZE);
        if (@as(isize, @bitCast(written)) < 0 or written != PAGE_SIZE) {
            return error.WriteFailed;
        }
        _ = std.os.linux.fsync(self.fd);

        const written_id = self.current_page_id;
        self.current_page_id += 1;
        return written_id;
    }
};

pub const Mutex = struct {
    locked: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn lock(self: *Mutex) void {
        while (self.locked.swap(true, .acquire)) {
            std.atomic.spinLoopHint();
        }
    }

    pub fn unlock(self: *Mutex) void {
        self.locked.store(false, .release);
    }
};

var global_mutex = Mutex{};
var global_log: ?AppendLog = null;

pub export fn sntl_db_init(path_ptr: [*]const u8, path_len: usize) callconv(.c) bool {
    global_mutex.lock();
    defer global_mutex.unlock();

    if (global_log != null) return true;
    if (path_len == 0) return false;

    const path = path_ptr[0..path_len];
    global_log = AppendLog.init(path) catch return false;
    return true;
}

pub export fn sntl_db_close() callconv(.c) void {
    global_mutex.lock();
    defer global_mutex.unlock();

    if (global_log) |*log| {
        log.deinit();
    }
    global_log = null;
}

pub export fn sntl_db_append_request(data_ptr: [*]const u8, data_len: usize) callconv(.c) u64 {
    global_mutex.lock();
    defer global_mutex.unlock();

    if (global_log) |*log| {
        if (data_len == 0) return std.math.maxInt(u64);
        const data = data_ptr[0..data_len];
        return log.append(data) catch return std.math.maxInt(u64);
    }
    return std.math.maxInt(u64);
}

pub export fn sntl_db_flag_high_value_target(ptr: [*]const u8, len: usize) callconv(.c) bool {
    global_mutex.lock();
    defer global_mutex.unlock();

    if (global_log == null) return false;
    if (len == 0) return false;

    const target = ptr[0..len];
    _ = target;

    return true;
}

pub export fn sntl_db_version() callconv(.c) u32 {
    return 1;
}

test "sntl_db integrity test" {
    const test_file = "test_sntl_unique.db";
    var unlink_buf: [256]u8 = undefined;
    @memcpy(unlink_buf[0..test_file.len], test_file);
    unlink_buf[test_file.len] = 0;
    _ = std.os.linux.unlink(@ptrCast(&unlink_buf));

    var log = try AppendLog.init(test_file);
    defer {
        log.deinit();
        _ = std.os.linux.unlink(@ptrCast(&unlink_buf));
    }

    const id = try log.append("test_payload");
    try std.testing.expectEqual(@as(u64, 0), id);
}
