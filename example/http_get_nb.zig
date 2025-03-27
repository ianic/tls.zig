const std = @import("std");
const tls = @import("tls");
const cmn = @import("common.zig");

pub fn main() !void {
    var dbga: std.heap.DebugAllocator(.{}) = .init;
    const allocator = dbga.allocator();
    defer _ = dbga.deinit();

    // Read domain name argument
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len == 1) return;
    const domain = args[1];

    // Open tcp connection
    var tcp = try std.net.tcpConnectToHost(allocator, domain, 443);
    defer tcp.close();

    // Prepare buffers
    var recv_buf: [tls.max_ciphertext_record_len]u8 = undefined;
    var send_buf: [tls.max_ciphertext_record_len]u8 = undefined;
    var recv_pos: usize = 0;

    // Do the handshake, cipher is handshake result.
    const cipher = brk: {
        var ca_bundle = try tls.config.CertBundle.fromSystem(allocator);
        defer ca_bundle.deinit(allocator);
        const config: tls.config.Client = .{
            .host = domain,
            .root_ca = ca_bundle,
            .cipher_suites = tls.config.cipher_suites.secure,
            .key_log_callback = tls.config.key_log.callback,
        };
        var handshake = tls.nonblock.Client.init(config);

        while (true) { // run handshake until done
            const res = try handshake.run(recv_buf[0..recv_pos], &send_buf);
            if (res.send.len > 0)
                try tcp.writeAll(res.send);
            recv_pos = shiftUnused(&recv_buf, res.unused_recv);
            if (handshake.done()) break;
            recv_pos += try tcp.read(recv_buf[recv_pos..]);
        }
        break :brk handshake.cipher().?;
    };

    // Init connection with cipher
    var conn = tls.nonblock.Connection.init(cipher);
    { // Make http get request
        var cleartext_buf: [4096]u8 = undefined;
        const cleartext = try std.fmt.bufPrint(&cleartext_buf, "GET / HTTP/1.1\r\nHost: {s}\r\n\r\n", .{domain});
        const res = try conn.encrypt(cleartext, &send_buf);
        try tcp.writeAll(res.ciphertext);
    }

    std.debug.print("|        ciphertext        |    cleartext    |\n", .{});
    std.debug.print("|   read |    len |   used | unused |   used |\n", .{});
    while (true) { // Read and decrypt response
        const n = try tcp.read(recv_buf[recv_pos..]);
        if (n == 0) break;
        recv_pos += n;

        const res = try conn.decrypt(recv_buf[0..recv_pos], &send_buf);
        //std.debug.print("{s}", .{res.cleartext});
        std.debug.print("|{:>7} |{:>7} |{:>7} |{:>7} |{:>7} |\n", .{ n, recv_pos, res.ciphertext_pos, res.unused_ciphertext.len, res.cleartext.len });

        if (pageEnd(res.cleartext)) break;
        if (res.closed) break;
        recv_pos = shiftUnused(&recv_buf, res.unused_ciphertext);
    }
}

fn pageEnd(bytes: []const u8) bool {
    return (std.ascii.endsWithIgnoreCase(
        std.mem.trimRight(u8, bytes, "\r\n"),
        "</html>",
    ) or std.ascii.endsWithIgnoreCase(bytes, "\r\n0\r\n\r\n") or
        std.ascii.endsWithIgnoreCase(bytes, "0\r\n\r\n"));
}

/// Shift unused part of the buffer to the beginning.
/// Returns write position for the next write into buffer.
/// Unused part is at the end of the buffer.
fn shiftUnused(buf: []u8, unused: []const u8) usize {
    if (unused.len == 0) return 0;
    if (unused.ptr == buf.ptr) return unused.len;
    std.mem.copyForwards(u8, buf, unused);
    return unused.len;
}
