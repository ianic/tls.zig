const std = @import("std");
const tls = @import("tls");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

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
    var diagnostic: tls.config.Client.Diagnostic = .{};

    // Establish tcp connection
    var tcp = try std.net.tcpConnectToHost(gpa, host, port);
    defer tcp.close();

    var tcp_reader_buf: [tls.input_buffer_len]u8 = undefined;
    var tcp_writer_buf: [tls.output_buffer_len]u8 = undefined;
    var tcp_reader = tcp.reader(&tcp_reader_buf);
    var tcp_writer = tcp.writer(&tcp_writer_buf);

    // Upgrade tcp connection to tls
    var conn = try tls.client(tcp_reader.interface(), &tcp_writer.interface, .{
        .host = host,
        .root_ca = root_ca,
        .diagnostic = &diagnostic,
    });

    // conn.output.buffer = conn.output.buffer[0..62];
    // std.debug.print("conn output buffer: {}\n", .{conn.output.buffer.len});

    { // Send http GET request
        var buf: [64]u8 = undefined;
        const req = try std.fmt.bufPrint(&buf, "GET / HTTP/1.1\r\nHost: {s}\r\n\r\n", .{host});
        try conn.writeAll(req);
    }

    try readHttpResponse(gpa, &conn);

    try conn.close();
}

fn readHttpResponse(gpa: Allocator, conn: *tls.Connection) !void {

    // Buffer must be big enough for http headers
    var http_reader_buf: [4096]u8 = undefined;
    var http_reader = conn.reader(&http_reader_buf);
    var rdr = &http_reader.interface;

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
