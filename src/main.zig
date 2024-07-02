pub const Options = @import("handshake.zig").Options;
pub const CipherSuite = @import("cipher.zig").CipherSuite;
pub const PrivateKey = @import("PrivateKey.zig");

pub const Client = @import("client.zig").Client;
pub const client = @import("client.zig").client;

pub const Server = @import("server.zig").Server;
pub const server = @import("server.zig").server;

test {
    _ = @import("handshake.zig");
    _ = @import("cipher.zig");
    _ = @import("PrivateKey.zig");
    _ = @import("client.zig");
}
