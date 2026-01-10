const std = @import("std");
const tls = @import("tls");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    const url = "https://ziglang.org";
    const uri = try std.Uri.parse(url);
    const host = uri.host.?.percent_encoded;
    const port = 443;

    // Establish tcp
    const host_name = try std.Io.net.HostName.init(host);
    var tcp = try host_name.connect(io, port, .{ .mode = .stream });
    defer tcp.close(io);

    // Load system root certificates
    var root_ca = try tls.config.cert.fromSystem(gpa, io);
    defer root_ca.deinit(gpa);

    // Upgrade tcp connection to tls
    var input_buf: [tls.input_buffer_len]u8 = undefined;
    var output_buf: [tls.output_buffer_len]u8 = undefined;
    var reader = tcp.reader(io, &input_buf);
    var writer = tcp.writer(io, &output_buf);
    var conn = try tls.client(&reader.interface, &writer.interface, .{
        .host = host,
        .root_ca = root_ca,
        .now = try std.Io.Clock.real.now(io),
    });

    // Send http GET request
    var buf: [64]u8 = undefined;
    const req = try std.fmt.bufPrint(&buf, "GET / HTTP/1.0\r\nHost: {s}\r\n\r\n", .{host});
    try conn.writeAll(req);

    // Print response
    while (try conn.next()) |data| {
        std.debug.print("{s}", .{data});
    }
    try conn.close();
}
