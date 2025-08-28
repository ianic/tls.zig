const std = @import("std");
const tls = @import("tls");
const assert = std.debug.assert;
const Io = std.Io;
const linux = std.os.linux;
const posix = std.posix;
const net = std.net;
const errno = std.posix.errno;

const Stream = @This();
handle: posix.fd_t,

pub fn close(s: Stream) void {
    posix.close(s.handle);
}

pub fn enableKtls(s: Stream) !void {
    const res = linux.setsockopt(s.handle, linux.IPPROTO.TCP, linux.TCP.ULP, "tls", 3);
    switch (errno(res)) {
        .SUCCESS => {},
        .NOENT => return error.KernelTlsModuleNotLoaded,
        .NOTCONN => return error.SocketNotConnected,
        .OPNOTSUPP, .NOPROTOOPT => return error.OperationNotSupported,
        .BADF => unreachable,
        .NOTSOCK => unreachable,
        .INVAL => unreachable,
        .FAULT => unreachable,
        .BUSY => unreachable, // AlreadyEnabled,
        else => |err| return posix.unexpectedErrno(err),
    }
}

pub const Reader = struct {
    handle: posix.fd_t,
    interface: Io.Reader,
    err: ?anyerror = null,

    pub fn init(s: Stream, buffer: []u8) Reader {
        return .{
            .handle = s.handle,
            .interface = .{
                .vtable = &.{
                    .stream = stream,
                },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const self: *Reader = @fieldParentPtr("interface", r);
        const n = posix.read(self.handle, limit.slice(w.unusedCapacitySlice())) catch |err| {
            self.err = err;
            if (err == error.EndOfStream) return error.EndOfStream;
            return error.ReadFailed;
        };
        if (n == 0) return error.EndOfStream;
        w.advance(n);
        return n;
    }
};

pub const Writer = struct {
    handle: posix.fd_t,
    interface: Io.Writer,
    err: ?anyerror = null,

    pub fn init(s: Stream, buffer: []u8) Writer {
        return .{
            .handle = s.handle,
            .interface = .{
                .vtable = &.{
                    .drain = drain,
                },
                .buffer = buffer,
                .end = 0,
            },
        };
    }

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const self: *Writer = @fieldParentPtr("interface", w);
        // w.buffer is consumed first
        try self.writeAll(w.buffered());

        if (data.len == 0) return 0;
        // Followed by each slice of `data` in order
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |bytes| {
            try self.writeAll(bytes);
            n += bytes.len;
        }

        // Last element of `data` is repeated as necessary so that it is
        // written `splat` number of times, which may be zero.
        const pattern = data[data.len - 1];
        for (0..splat) |_| {
            try self.writeAll(pattern);
            n += pattern.len;
        }

        // Number of bytes consumed from `data` is returned, excluding bytes
        // from w.buffer.
        return n;
    }

    fn writeAll(self: Writer, bytes: []const u8) Io.Writer.Error!void {
        var index: usize = 0;
        while (index < bytes.len) {
            index += posix.write(self.handle, bytes[index..]) catch |err| {
                self.err = err;
                return error.WriteFailed;
            };
        }
    }
};
