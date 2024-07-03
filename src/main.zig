pub const CipherSuite = @import("cipher.zig").CipherSuite;
pub const PrivateKey = @import("PrivateKey.zig");
pub const Connection = @import("connection.zig").Connection;
pub const ClientOptions = @import("handshake.zig").Options;
pub const ServerOptions = @import("handshake_server.zig").Options;

const record = @import("record.zig");

pub fn client(stream: anytype, opt: ClientOptions) !Connection(@TypeOf(stream)) {
    const Stream = @TypeOf(stream);
    var conn: Connection(Stream) = .{
        .stream = stream,
        .rec_rdr = record.reader(stream),
    };

    const Handshake = @import("handshake.zig").Handshake(Stream);
    var h = try Handshake.init(&conn.write_buf, &conn.rec_rdr);
    conn.cipher = try h.handshake(conn.stream, opt);
    if (h.tls_version == .tls_1_2) {
        conn.cipher_client_seq = 1;
        conn.cipher_server_seq = 1;
    }

    return conn;
}

pub fn server(stream: anytype, opt: ServerOptions) !Connection(@TypeOf(stream)) {
    const Stream = @TypeOf(stream);
    var conn: Connection(Stream) = .{
        .stream = stream,
        .rec_rdr = record.reader(stream),
    };

    const Handshake = @import("handshake_server.zig").Handshake(Stream);
    var h = try Handshake.init(&conn.write_buf, &conn.rec_rdr);
    conn.cipher = try h.handshake(conn.stream, opt);

    return conn;
}

test {
    _ = @import("handshake_common.zig");
    _ = @import("handshake_server.zig");
    _ = @import("handshake.zig");
    _ = @import("cipher.zig");
    _ = @import("PrivateKey.zig");
}
