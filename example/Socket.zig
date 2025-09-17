/// Kernel tls supported socket. Skips tls control messages. Server sends new
/// session ticket which will break ktls connection if it is not read by
/// recvmsg. For the control messages control part of the msghdr is used.
const std = @import("std");
const tls = @import("tls");
const assert = std.debug.assert;
const Io = std.Io;
const linux = std.os.linux;
const posix = std.posix;
const mem = std.mem;

const Socket = @This();

fd: posix.fd_t,

pub fn close(s: Socket) void {
    posix.close(s.fd);
}

pub fn reader(s: Socket, buffer: []u8) Reader {
    return .init(s, buffer);
}

pub fn writer(s: Socket, buffer: []u8) Writer {
    return .init(s, buffer);
}

pub const Reader = struct {
    fd: posix.fd_t,
    interface: Io.Reader,
    err: ?anyerror = null,

    pub fn init(s: Socket, buffer: []u8) Reader {
        return .{
            .fd = s.fd,
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

    const cmsghdr = extern struct {
        len: u32,
        _: [4]u8,
        level: i32,
        typ: i32,
        record_type: u8,
    };

    fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const self: *Reader = @fieldParentPtr("interface", r);
        const buf = limit.slice(w.unusedCapacitySlice());

        while (true) {
            var iov: [1]posix.iovec = .{
                posix.iovec{
                    .base = buf.ptr,
                    .len = buf.len,
                },
            };
            var cmsg = mem.zeroes(cmsghdr);

            var msg: linux.msghdr = .{
                .name = null,
                .control = &cmsg,
                .controllen = @sizeOf(cmsghdr),
                .namelen = 0,
                .flags = 0,
                .iov = &iov,
                .iovlen = 1,
            };

            const n = recvmsg(self.fd, &msg, 0) catch |err| {
                self.err = err;
                return error.ReadFailed;
            };
            if (n == 0) return error.EndOfStream;

            // tls control message
            if (cmsg.len > 0 and cmsg.level == linux.SOL.TLS and cmsg.typ == 2) {
                if (cmsg.record_type == 22) {
                    // there is handshake content message in the buf
                    // std.debug.print(" {x}\n", .{buf[0..n]});
                    // TODO: handle new session ticket message
                    continue;
                }
            }
            w.advance(n);
            return n;
        }
    }
};

fn recvmsg(fd: posix.fd_t, msg: *linux.msghdr, flags: u32) !usize {
    while (true) {
        const rc = linux.recvmsg(fd, msg, flags);
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .INVAL => unreachable,
            .BADMSG => return error.BadMessage,
            .FAULT => unreachable,
            .SRCH => return error.ProcessNotFound,
            .AGAIN => return error.WouldBlock,
            .CANCELED => return error.Canceled,
            .BADF => return error.NotOpenForReading, // Can be a race condition.
            .IO => return error.InputOutput,
            .ISDIR => return error.IsDir,
            .NOBUFS => return error.SystemResources,
            .NOMEM => return error.SystemResources,
            .NOTCONN => return error.SocketNotConnected,
            .CONNRESET => return error.ConnectionResetByPeer,
            .TIMEDOUT => return error.ConnectionTimedOut,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

pub const Writer = struct {
    fd: posix.fd_t,
    interface: Io.Writer,
    err: ?anyerror = null,

    pub fn init(s: Socket, buffer: []u8) Writer {
        return .{
            .fd = s.fd,
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
        w.end = 0;

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

    fn writeAll(self: *Writer, bytes: []const u8) Io.Writer.Error!void {
        var index: usize = 0;
        while (index < bytes.len) {
            index += posix.write(self.fd, bytes[index..]) catch |err| {
                self.err = err;
                return error.WriteFailed;
            };
        }
    }
};

pub const cipher_suites = [_]tls.config.CipherSuite{
    // tls 1.3 recommended
    .AES_128_GCM_SHA256,
    .AES_256_GCM_SHA384,
    .CHACHA20_POLY1305_SHA256,
    // tls 1.2 recommended
    .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    // tls 1.2 secure
    .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
};

// Move cipher key to the kernel
pub fn upgrade(s: Socket, conn: tls.Connection) !void {
    var k = tls.Ktls.init(conn.cipher);
    try posix.setsockopt(s.fd, linux.IPPROTO.TCP, linux.TCP.ULP, "tls");
    try posix.setsockopt(s.fd, linux.SOL.TLS, tls.Ktls.TX, k.txBytes());
    try posix.setsockopt(s.fd, linux.SOL.TLS, tls.Ktls.RX, k.rxBytes());
}
