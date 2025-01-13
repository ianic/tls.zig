const std = @import("std");
const tls = @import("tls");
const Certificate = std.crypto.Certificate;
const cmn = @import("common.zig");

const host = "localhost";
const port = 9443;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const dir = try std.fs.cwd().openDir("example/cert", .{});
    var root_ca = try tls.config.CertBundle.fromFile(allocator, dir, "minica.pem");
    defer root_ca.deinit(allocator);

    const opt = try parseArgs(allocator);

    const verbose = opt.cycles == 1;
    for (0..opt.cycles) |_| {
        if (opt.std_lib) {
            try stdLib(allocator, root_ca, verbose);
        } else {
            try thisLib(allocator, root_ca, verbose);
        }
    }
}

fn thisLib(allocator: std.mem.Allocator, root_ca: tls.config.CertBundle, verbose: bool) !void {
    // Make tcp connection
    var tcp = try std.net.tcpConnectToHost(allocator, host, port);
    defer tcp.close();

    // Upgrade tcp connection to tls
    var diagnostic: tls.config.Client.Diagnostic = .{};
    var conn = try tls.client(tcp, .{
        .host = host,
        .root_ca = root_ca,
        .diagnostic = &diagnostic,
        .named_groups = &.{ .x25519, .secp256r1, .x25519_kyber768d00 }, // use same set as in std lib
        .key_log_callback = tls.config.key_log.callback,
    });

    // Show response
    var n: usize = 0;
    while (try conn.next()) |data| {
        n += data.len;
        if (verbose) std.debug.print("{s}", .{data});
    }
    try conn.close();
    if (verbose) {
        std.debug.print("{} bytes read\n", .{n});
        cmn.showDiagnostic(&diagnostic, host);
    }
}

fn stdLib(allocator: std.mem.Allocator, root_ca: tls.config.CertBundle, verbose: bool) !void {
    var tcp = try std.net.tcpConnectToHost(allocator, host, port);
    defer tcp.close();

    var cli = try std.crypto.tls.Client.init(tcp, .{ .ca = .{ .bundle = root_ca.bundle }, .host = .{ .explicit = host } });

    var buf: [16 * 1024]u8 = undefined;
    while (true) {
        const n = try cli.read(tcp, &buf);
        if (verbose) std.debug.print("{s}", .{buf[0..n]});
        //if (n < buf.len) break;
        if (n == 0) break;
    }
    _ = try cli.writeEnd(tcp, "", true);
}

const Options = struct {
    std_lib: bool = false,
    cycles: usize = 1,
};

fn parseArgs(allocator: std.mem.Allocator) !Options {
    var args_iter = try std.process.argsWithAllocator(allocator);
    defer args_iter.deinit();

    var opt: Options = .{};
    while (args_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--std")) {
            opt.std_lib = true;
        }
        if (std.mem.eql(u8, arg, "--cycles")) {
            if (args_iter.next()) |sub_arg| {
                opt.cycles = try std.fmt.parseInt(usize, sub_arg, 10);
            }
        }
    }
    return opt;
}
