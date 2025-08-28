const std = @import("std");
const tls = @import("tls");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const linux = std.os.linux;
const posix = std.posix;
const net = std.net;
const errno = std.posix.errno;

const Stream = @import("Stream.zig");

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
    const url = if (args.len > 1) args[1] else "https://www.lutrija.hr";
    const uri = try std.Uri.parse(url);
    const host = uri.host.?.percent_encoded;
    const port = 443;

    // Load system root certificates
    var root_ca = try tls.config.cert.fromSystem(gpa);
    defer root_ca.deinit(gpa);
    var session_resumption: tls.config.Client.SessionResumption = .init(gpa);
    defer session_resumption.deinit();
    var diagnostic: tls.config.Client.Diagnostic = .{};

    // Establish tcp connection
    var tcp = try net.tcpConnectToHost(gpa, host, port);
    defer tcp.close();
    {
        const s = Stream{ .handle = tcp.handle };
        try s.enableKtls();
    }

    var tcp_reader_buf: [tls.input_buffer_len]u8 = undefined;
    var tcp_writer_buf: [tls.output_buffer_len]u8 = undefined;
    var tcp_reader = tcp.reader(&tcp_reader_buf);
    var tcp_writer = tcp.writer(&tcp_writer_buf);
    const input: *Io.Reader = tcp_reader.interface();
    const output: *Io.Writer = &tcp_writer.interface;

    // Upgrade tcp connection to tls
    var conn = try tls.client(input, output, .{
        .host = host,
        .root_ca = root_ca,
        .diagnostic = &diagnostic,
        .session_resumption = &session_resumption,
        .key_log_callback = tls.config.key_log.callback,
    });

    //try input.fillMore();
    //std.debug.print("input buffered len: {}\n", .{input.bufferedLen()});
    //_ = try input.discardRemaining();
    {
        std.debug.print("diagnostic: {}\n", .{diagnostic});
        assert(conn.cipher == .AES_128_GCM_SHA256);
        const cipher = conn.cipher.AES_128_GCM_SHA256;
        const info_tx: tls12_crypto_info_aes_gcm_128 = .{
            .salt = cipher.encrypt_iv[0..4].*,
            .iv = cipher.encrypt_iv[4..].*,
            .key = cipher.encrypt_key,
            .rec_seq = cipher.encrypt_seq,
        };
        var rc = linux.setsockopt(tcp.handle, linux.SOL.TLS, TLS_TX, &std.mem.toBytes(info_tx), @sizeOf(tls12_crypto_info_aes_gcm_128));
        std.debug.print("tx rc = {}\n", .{std.posix.errno(rc)});

        const info_rx: tls12_crypto_info_aes_gcm_128 = .{
            .salt = cipher.decrypt_iv[0..4].*,
            .iv = cipher.decrypt_iv[4..].*,
            .key = cipher.decrypt_key,
            .rec_seq = cipher.decrypt_seq,
        };
        rc = linux.setsockopt(tcp.handle, linux.SOL.TLS, TLS_RX, &std.mem.toBytes(info_rx), @sizeOf(tls12_crypto_info_aes_gcm_128));
        std.debug.print("rx rc = {}\n", .{std.posix.errno(rc)});
    }
    { // Send http GET request
        var buf: [64]u8 = undefined;
        const req = try std.fmt.bufPrint(&buf, "GET / HTTP/1.1\r\nHost: {s}\r\n\r\n", .{host});
        //try conn.writeAll(req);
        try tcp.writeAll(req);
    }
    { // Parse http respose
        // Buffer must be big enough for http headers
        //var http_reader_buf: [4096]u8 = undefined;
        //var http_reader = conn.reader(&http_reader_buf);
        //try readHttpResponse(gpa, &http_reader.interface);

        try readHttpResponse(gpa, input);
    }
    std.debug.print("session resumption tickets: {}\n", .{session_resumption.tickets.items.len});
    try conn.close();
}

const TLS_TX = 1;
const TLS_RX = 2;

const tls_crypto_info = extern struct {
    version: u16 = 0x0304,
    cipher_type: u16 = 51,
};

const tls12_crypto_info_aes_gcm_128 = extern struct {
    const TLS_CIPHER_AES_GCM_128_IV_SIZE = 8;
    const TLS_CIPHER_AES_GCM_128_KEY_SIZE = 16;
    const TLS_CIPHER_AES_GCM_128_SALT_SIZE = 4;
    const TLS_CIPHER_AES_GCM_128_TAG_SIZE = 16;
    const TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE = 8;

    info: tls_crypto_info = .{ .version = 0x0304, .cipher_type = 51 },
    iv: [TLS_CIPHER_AES_GCM_128_IV_SIZE]u8,
    key: [TLS_CIPHER_AES_GCM_128_KEY_SIZE]u8,
    salt: [TLS_CIPHER_AES_GCM_128_SALT_SIZE]u8,
    rec_seq: u64,
};

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

                if (cp.chunk_len >= 7)
                    std.debug.print("chunk {d:>6} bytes  ... {s}\n", .{ cp.chunk_len, chunk_body[chunk_body.len - 7 ..] });
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
