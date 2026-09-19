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
    checksum: u64,
    page_id: u64,
    prev_page: u64,
    next_page: u64,
    data_len: u32,
    reserved: [20]u8,
};

comptime {
    std.debug.assert(@sizeOf(PageHeader) == HEADER_SIZE);
}

pub const Ipv6AnomalyRecord = extern struct {
    timestamp_ns: u64,
    src_ip: [16]u8,
    dst_ip: [16]u8,
    packets_dropped: u32,
    attack_type: u8,
    reserved: [3]u8,
};

comptime {
    std.debug.assert(@sizeOf(Ipv6AnomalyRecord) == 48);
}

pub const AppendLog = struct {
    fd: i32,
    current_page_id: u64,

    pub fn init(path: []const u8) !AppendLog {
        if (path.len >= 512) return error.NameTooLong;

        var buf: [512:0]u8 = undefined;
        @memcpy(buf[0..path.len], path);
        buf[path.len] = 0;

        const O_RDWR: u32 = 2;
        const O_CREAT: u32 = 64;
        const O_APPEND: u32 = 1024;
        const flags: std.os.linux.O = @bitCast(O_RDWR | O_CREAT | O_APPEND);

        const open_res = std.os.linux.open(&buf, flags, 0o644);
        const fd = @as(i32, @intCast(open_res));
        if (fd < 0) return error.OpenFailed;

        const size_res = std.os.linux.lseek(fd, 0, std.os.linux.SEEK.END);
        if (@as(isize, @bitCast(size_res)) < 0) {
            _ = std.os.linux.close(fd);
            return error.SeekFailed;
        }
        var size = @as(u64, @intCast(size_res));

        const remainder = size % PAGE_SIZE;
        if (remainder != 0) {
            size -= remainder;
            const trunc_res = std.os.linux.ftruncate(fd, @intCast(size));
            if (@as(isize, @bitCast(trunc_res)) < 0) {
                _ = std.os.linux.close(fd);
                return error.TruncateFailed;
            }
        }

        return AppendLog{
            .fd = fd,
            .current_page_id = size / PAGE_SIZE,
        };
    }

    pub fn deinit(self: *AppendLog) void {
        if (self.fd >= 0) {
            _ = std.os.linux.close(self.fd);
            self.fd = -1;
        }
    }

    pub fn append(self: *AppendLog, data: []const u8) !u64 {
        if (data.len > PAGE_SIZE - HEADER_SIZE) return error.DataTooLargeForPage;

        var page_buffer: [PAGE_SIZE]u8 = undefined;
        @memset(&page_buffer, 0);

        const checksum = std.hash.XxHash64.hash(0, data);

        const header = PageHeader{
            .magic = MAGIC,
            .version = 1,
            .page_type = @intFromEnum(PageType.data),
            .flags = 0,
            .checksum = checksum,
            .page_id = self.current_page_id,
            .prev_page = if (self.current_page_id > 0) self.current_page_id - 1 else 0,
            .next_page = 0,
            .data_len = @intCast(data.len),
            .reserved = std.mem.zeroes([20]u8),
        };

        const header_bytes = std.mem.asBytes(&header);
        @memcpy(page_buffer[0..header_bytes.len], header_bytes);
        @memcpy(page_buffer[header_bytes.len..][0..data.len], data);

        const EINTR: isize = -4;
        var written_bytes: usize = 0;

        while (written_bytes < PAGE_SIZE) {
            const ptr = page_buffer[written_bytes..].ptr;
            const res = std.os.linux.write(self.fd, ptr, PAGE_SIZE - written_bytes);
            const err_code = @as(isize, @bitCast(res));
            if (err_code == EINTR) continue;
            if (err_code < 0) return error.WriteFailed;
            written_bytes += @as(usize, @intCast(res));
        }

        const written_id = self.current_page_id;
        self.current_page_id += 1;
        return written_id;
    }

    pub fn sync(self: *AppendLog) !void {
        const EINTR: isize = -4;
        while (true) {
            const sync_res = std.os.linux.fdatasync(self.fd);
            const err_code = @as(isize, @bitCast(sync_res));
            if (err_code == EINTR) continue;
            if (err_code < 0) return error.SyncFailed;
            break;
        }
    }

    pub fn readPage(self: *AppendLog, page_id: u64, out_data: []u8) !usize {
        if (page_id >= self.current_page_id) return error.PageNotFound;

        const offset = page_id * PAGE_SIZE;
        var page_buffer: [PAGE_SIZE]u8 = undefined;

        const EINTR: isize = -4;
        var read_bytes: usize = 0;

        while (read_bytes < PAGE_SIZE) {
            const ptr = page_buffer[read_bytes..].ptr;
            const read_res = std.os.linux.pread(self.fd, ptr, PAGE_SIZE - read_bytes, @intCast(offset + read_bytes));
            const err_code = @as(isize, @bitCast(read_res));
            if (err_code == EINTR) continue;
            if (err_code <= 0) return error.ReadFailed;
            read_bytes += @as(usize, @intCast(read_res));
        }

        const header = @as(*const PageHeader, @ptrCast(@alignCast(&page_buffer[0])));
        if (header.magic != MAGIC) return error.CorruptedMagic;
        if (header.data_len > PAGE_SIZE - HEADER_SIZE) return error.InvalidDataLen;

        const payload = page_buffer[HEADER_SIZE .. HEADER_SIZE + header.data_len];
        const computed_checksum = std.hash.XxHash64.hash(0, payload);
        if (computed_checksum != header.checksum) return error.ChecksumMismatch;

        if (out_data.len < payload.len) return error.BufferTooSmall;
        @memcpy(out_data[0..payload.len], payload);

        return payload.len;
    }
};

pub const AtomicMutex = struct {
    state: std.atomic.Value(u32),

    pub fn init() AtomicMutex {
        return .{ .state = std.atomic.Value(u32).init(0) };
    }

    pub fn lock(self: *AtomicMutex) void {
        while (self.state.swap(1, .acquire) != 0) {
            while (self.state.load(.monotonic) != 0) {
                std.atomic.spinLoopHint();
            }
        }
    }

    pub fn unlock(self: *AtomicMutex) void {
        self.state.store(0, .release);
    }
};

var global_mutex = AtomicMutex.init();
var global_log: ?AppendLog = null;
var global_timestamp_counter = std.atomic.Value(u64).init(1_700_000_000_000_000_000);

pub export fn sntl_db_init(path_ptr: [*]const u8, path_len: usize) callconv(.c) u8 {
    global_mutex.lock();
    defer global_mutex.unlock();

    if (global_log != null) return 1;
    if (path_len == 0) return 0;

    const path = path_ptr[0..path_len];
    global_log = AppendLog.init(path) catch return 0;
    return 1;
}

pub export fn sntl_db_close() callconv(.c) void {
    global_mutex.lock();
    defer global_mutex.unlock();

    if (global_log) |*log| {
        log.sync() catch {};
        log.deinit();
    }
    global_log = null;
}

pub export fn sntl_db_sync() callconv(.c) u8 {
    global_mutex.lock();
    defer global_mutex.unlock();

    if (global_log) |*log| {
        log.sync() catch return 0;
        return 1;
    }
    return 0;
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

pub export fn sntl_db_flag_high_value_target_v6(
    src_ip_ptr: [*]const u8,
    dst_ip_ptr: [*]const u8,
    packets_dropped: u32,
    attack_type: u8,
) callconv(.c) u8 {
    global_mutex.lock();
    defer global_mutex.unlock();

    if (global_log) |*log| {
        var record: Ipv6AnomalyRecord = undefined;

        record.timestamp_ns = global_timestamp_counter.fetchAdd(1000, .monotonic);

        @memcpy(&record.src_ip, src_ip_ptr[0..16]);
        @memcpy(&record.dst_ip, dst_ip_ptr[0..16]);
        record.packets_dropped = packets_dropped;
        record.attack_type = attack_type;
        record.reserved = [_]u8{0} ** 3;

        const record_bytes = std.mem.asBytes(&record);
        _ = log.append(record_bytes) catch return 0;
        return 1;
    }
    return 0;
}

pub export fn sntl_db_get_total_pages() callconv(.c) u64 {
    global_mutex.lock();
    defer global_mutex.unlock();

    if (global_log) |log| {
        return log.current_page_id;
    }
    return 0;
}

pub export fn sntl_db_read_page(page_id: u64, out_ptr: [*]u8, max_len: usize, out_written: *usize) callconv(.c) u8 {
    global_mutex.lock();
    defer global_mutex.unlock();

    if (global_log) |*log| {
        const out_slice = out_ptr[0..max_len];
        const bytes_written = log.readPage(page_id, out_slice) catch return 0;
        out_written.* = bytes_written;
        return 1;
    }
    return 0;
}

pub export fn sntl_db_version() callconv(.c) u32 {
    return 3;
}
