const std = @import("std");
const tls = @import("tls");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const linux = std.os.linux;
const posix = std.posix;
const net = std.net;
const errno = std.posix.errno;

const Socket = @import("Socket.zig");

// Check if module is loaded:
//$ lsmod | grep tls
// Load module:
//$ sudo modprobe tls
// Enable module at boot:
//$ echo tls | sudo tee /etc/modules-load.d/gnutls.conf

pub fn main() !void {
    var dbga = std.heap.DebugAllocator(.{}){};
    defer _ = dbga.deinit();
    const gpa = dbga.allocator();

    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);
    const url = if (args.len > 1) args[1] else "https://www.cloudflare.com";
    const uri = try std.Uri.parse(url);
    const host = uri.host.?.percent_encoded;

    // Load system root certificates
    var root_ca = try tls.config.cert.fromSystem(gpa);
    defer root_ca.deinit(gpa);

    for (Socket.cipher_suites) |cipher_tag| {
        try get(gpa, .{
            .host = host,
            .root_ca = root_ca,
            .cipher_suites = &[_]tls.config.CipherSuite{cipher_tag},
            .key_log_callback = tls.config.key_log.callback,
        });
    }
}

const port = 443;

fn get(gpa: Allocator, cfg: tls.config.Client) !void {
    var session_resumption: tls.config.Client.SessionResumption = .init(gpa);
    defer session_resumption.deinit();
    var diagnostic: tls.config.Client.Diagnostic = .{};

    // Establish tcp connection
    const net_stream = try net.tcpConnectToHost(gpa, cfg.host, port);
    const tcp = Socket{ .fd = net_stream.handle };
    defer tcp.close();

    var tcp_reader_buf: [tls.input_buffer_len]u8 = undefined;
    var tcp_writer_buf: [tls.output_buffer_len]u8 = undefined;
    var tcp_reader = tcp.reader(&tcp_reader_buf);
    var tcp_writer = tcp.writer(&tcp_writer_buf);
    const input: *Io.Reader = &tcp_reader.interface;
    const output: *Io.Writer = &tcp_writer.interface;

    var ccfg = cfg;
    ccfg.diagnostic = &diagnostic;
    ccfg.session_resumption = &session_resumption;
    // Upgrade tcp connection to tls
    var conn = try tls.client(input, output, ccfg);

    { // Move encryption keys to the kernel
        try tcp.upgrade(conn);
    }
    { // Send http GET request
        try output.print("GET / HTTP/1.1\r\nHost: {s}\r\n\r\n", .{cfg.host});
        try output.flush();
    }
    { // Parse http respose
        try readHttpResponse(gpa, input);
    }
    std.debug.print("diagnostic: {}\nsession resumption tickets: {}\n", .{
        diagnostic,
        session_resumption.tickets.items.len,
    });
    try conn.close();
}

fn readHttpResponse(gpa: Allocator, rdr: *Io.Reader) !void {
    // Find headers length
    const header_length = while (true) {
        try rdr.fillMore();
        var hp: std.http.HeadParser = .{};
        const n = hp.feed(rdr.buffered());
        if (hp.state == .finished) break n;
    };

    // Iterate headers and find content length
    var content_length: usize = 0;
    var chunked: bool = false;
    var header_iter: std.http.HeaderIterator = .init(try rdr.take(header_length));
    while (header_iter.next()) |h| {
        if (std.ascii.eqlIgnoreCase("content-length", h.name)) {
            content_length = try std.fmt.parseInt(usize, h.value, 10);
        }
        if (std.ascii.eqlIgnoreCase("transfer-encoding", h.name)) {
            if (std.ascii.eqlIgnoreCase("chunked", h.value)) {
                chunked = true;
            }
        }
        //std.debug.print("{s} => {s}\n", .{ h.name, h.value });
    }

    std.debug.print(
        "header length: {}, content length: {}, chunked: {}\n",
        .{ header_length, content_length, chunked },
    );

    if (chunked) {
        var body_bytes: usize = 0;
        var chunks_count: usize = 0;

        while (true) {
            var cp: std.http.ChunkParser = .init;
            if (rdr.bufferedLen() > 0) {
                const b = try rdr.peekByte();
                if (b == '\r' or b == '\n')
                    cp.state = .data_suffix;
            }
            const n = cp.feed(rdr.buffered());
            if (cp.state == .invalid) return error.InvalidChunk;
            if (n < rdr.bufferedLen()) {
                assert(cp.state == .data);
                _ = try rdr.take(n);
                if (cp.chunk_len == 0) break; // last chunk
                body_bytes += cp.chunk_len;
                chunks_count += 1;
                const chunk_body = try rdr.readAlloc(gpa, cp.chunk_len);
                defer gpa.free(chunk_body);

                // show length of the each chunk
                // if (cp.chunk_len >= 7)
                //     std.debug.print("chunk {d:>6} bytes  ... {s}\n", .{ cp.chunk_len, chunk_body[chunk_body.len - 7 ..] });
                if (rdr.bufferedLen() != 0)
                    continue;
            }
            try rdr.fillMore();
        }
        std.debug.print("chunked in {} chunks {} bytes\n", .{ chunks_count, body_bytes });
    } else if (content_length > 0) {
        const body = try rdr.readAlloc(gpa, content_length);
        std.debug.print("{s}", .{body});
        defer gpa.free(body);
    } else {
        while (true) {
            const data = rdr.buffered();
            std.debug.print("{s}", .{data});
            rdr.toss(data.len);
            try rdr.fillMore();
        }
    }
}
