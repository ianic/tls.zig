const std = @import("std");
const crypto = std.crypto;
const tls = crypto.tls;
const hkdfExpandLabel = tls.hkdfExpandLabel;
const Sha1 = crypto.hash.Sha1;
const Sha256 = crypto.hash.sha2.Sha256;
const Sha384 = crypto.hash.sha2.Sha384;

const handsakeHeader = @import("handshake.zig").handshakeHeader;
const CipherSuite = @import("cipher.zig").CipherSuite;
const HashTag = CipherSuite.Hash;

// Transcript holds transcript hash for both sha256 and sha384. Until the server
// hello is parsed we don't know which hash will be used so we update both hashes.
// Handshake process will set selected field once cipher suite is known.
//
// Most of the functions are inlined because they are returning pointers.
//
pub const Transcript = struct {
    sha256: TT(.sha256) = .{ .hash = Sha256.init(.{}) },
    sha384: TT(.sha384) = .{ .hash = Sha384.init(.{}) },
    selected: HashTag = .sha256,

    // Transcript Type from hash tag
    fn TT(h: HashTag) type {
        return switch (h) {
            .sha256 => TranscriptT(Sha256),
            .sha384 => TranscriptT(Sha384),
        };
    }

    pub fn update(t: *Transcript, buf: []const u8) void {
        t.sha256.hash.update(buf);
        t.sha384.hash.update(buf);
    }

    // tls 1.2 specific functions

    pub inline fn masterSecret(
        t: *Transcript,
        pre_master_secret: []const u8,
        client_random: [32]u8,
        server_random: [32]u8,
    ) []const u8 {
        return switch (t.selected) {
            inline .sha256, .sha384 => |h| brk: {
                break :brk &TT(h).masterSecret(pre_master_secret, client_random, server_random);
            },
        };
    }

    pub inline fn keyMaterial(
        t: *Transcript,
        master_secret: []const u8,
        client_random: [32]u8,
        server_random: [32]u8,
    ) []const u8 {
        return switch (t.selected) {
            inline .sha256, .sha384 => |h| &TT(h).keyExpansion(master_secret, client_random, server_random),
        };
    }

    pub fn Hkdf(ht: HashTag) type {
        return switch (ht) {
            inline .sha256, .sha384 => |h| TT(h).Hkdf,
        };
    }

    pub fn clientFinishedTls12(t: *Transcript, master_secret: []const u8) [16]u8 {
        return switch (t.selected) {
            inline .sha256, .sha384 => |h| @field(t, @tagName(h)).clientFinishedTls12(master_secret),
        };
    }

    pub fn serverFinishedTls12(t: *Transcript, master_secret: []const u8) [16]u8 {
        return switch (t.selected) {
            inline .sha256, .sha384 => |h| @field(t, @tagName(h)).serverFinishedTls12(master_secret),
        };
    }

    // tls 1.3 specific functions

    pub inline fn verifyBytesTls13(t: *Transcript) []const u8 {
        return switch (t.selected) {
            inline .sha256, .sha384 => |h| &@field(t, @tagName(h)).verifyBytesTls13(),
        };
    }

    pub inline fn clientVerifyBytesTls13(t: *Transcript) []const u8 {
        return switch (t.selected) {
            inline .sha256, .sha384 => |h| &@field(t, @tagName(h)).clientVerifyBytesTls13(),
        };
    }

    pub inline fn serverFinishedTls13(t: *Transcript) []const u8 {
        return switch (t.selected) {
            inline .sha256, .sha384 => |h| &@field(t, @tagName(h)).serverFinishedTls13(),
        };
    }

    pub inline fn clientFinishedTls13(t: *Transcript) []const u8 {
        return switch (t.selected) {
            inline .sha256, .sha384 => |h| &@field(t, @tagName(h)).clientFinishedTls13(),
        };
    }

    pub const Secret = struct {
        client: []const u8,
        server: []const u8,
    };

    pub inline fn handshakeSecret(t: *Transcript, shared_key: []const u8) Secret {
        return switch (t.selected) {
            inline .sha256, .sha384 => |h| @field(t, @tagName(h)).handshakeSecret(shared_key),
        };
    }

    pub inline fn applicationSecret(t: *Transcript) Secret {
        return switch (t.selected) {
            inline .sha256, .sha384 => |h| @field(t, @tagName(h)).applicationSecret(),
        };
    }

    pub inline fn hash(t: *Transcript, comptime Hash: type) Hash {
        return switch (Hash) {
            Sha256 => t.sha256.hash,
            Sha384 => t.sha384.hash,
            else => @compileError("unimplemented"),
        };
    }
};

fn TranscriptT(comptime HashType: type) type {
    return struct {
        const Hash = HashType;
        const Hmac = crypto.auth.hmac.Hmac(Hash);
        const Hkdf = crypto.kdf.hkdf.Hkdf(Hmac);
        const mac_length = Hmac.mac_length;

        hash: Hash,
        handshake_secret: [Hmac.mac_length]u8 = undefined,
        server_finished_key: [Hmac.key_length]u8 = undefined,
        client_finished_key: [Hmac.key_length]u8 = undefined,

        const Self = @This();

        fn init(transcript: Hash) Self {
            return .{ .transcript = transcript };
        }

        fn verifyBytesTls13(c: *Self) [64 + 34 + Hash.digest_length]u8 {
            return ([1]u8{0x20} ** 64) ++
                "TLS 1.3, server CertificateVerify\x00".* ++
                c.hash.peek();
        }

        // ref: https://www.rfc-editor.org/rfc/rfc8446#section-4.4.3
        fn clientVerifyBytesTls13(c: Self) [64 + 34 + Hash.digest_length]u8 {
            return ([1]u8{0x20} ** 64) ++
                "TLS 1.3, client CertificateVerify\x00".* ++
                c.hash.peek();
        }

        fn masterSecret(
            pre_master_secret: []const u8,
            client_random: [32]u8,
            server_random: [32]u8,
        ) [mac_length * 2]u8 {
            const seed = "master secret" ++ client_random ++ server_random;

            var a1: [mac_length]u8 = undefined;
            var a2: [mac_length]u8 = undefined;
            Hmac.create(&a1, seed, pre_master_secret);
            Hmac.create(&a2, &a1, pre_master_secret);

            var p1: [mac_length]u8 = undefined;
            var p2: [mac_length]u8 = undefined;
            Hmac.create(&p1, a1 ++ seed, pre_master_secret);
            Hmac.create(&p2, a2 ++ seed, pre_master_secret);

            return p1 ++ p2;
        }

        fn keyExpansion(
            master_secret: []const u8,
            client_random: [32]u8,
            server_random: [32]u8,
        ) [mac_length * 4]u8 {
            const seed = "key expansion" ++ server_random ++ client_random;

            const a0 = seed;
            var a1: [mac_length]u8 = undefined;
            var a2: [mac_length]u8 = undefined;
            var a3: [mac_length]u8 = undefined;
            var a4: [mac_length]u8 = undefined;
            Hmac.create(&a1, a0, master_secret);
            Hmac.create(&a2, &a1, master_secret);
            Hmac.create(&a3, &a2, master_secret);
            Hmac.create(&a4, &a3, master_secret);

            var key_material: [mac_length * 4]u8 = undefined;
            Hmac.create(key_material[0..mac_length], a1 ++ seed, master_secret);
            Hmac.create(key_material[mac_length .. mac_length * 2], a2 ++ seed, master_secret);
            Hmac.create(key_material[mac_length * 2 .. mac_length * 3], a3 ++ seed, master_secret);
            Hmac.create(key_material[mac_length * 3 ..], a4 ++ seed, master_secret);
            return key_material;
        }

        fn clientFinishedTls12(self: *Self, master_secret: []const u8) [16]u8 {
            const seed = "client finished" ++ self.hash.peek();
            var a1: [mac_length]u8 = undefined;
            var p1: [mac_length]u8 = undefined;
            Hmac.create(&a1, seed, master_secret);
            Hmac.create(&p1, a1 ++ seed, master_secret);
            return handsakeHeader(.finished, 12) ++ p1[0..12].*;
        }

        fn serverFinishedTls12(self: *Self, master_secret: []const u8) [16]u8 {
            const seed = "server finished" ++ self.hash.peek();
            var a1: [mac_length]u8 = undefined;
            var p1: [mac_length]u8 = undefined;
            Hmac.create(&a1, seed, master_secret);
            Hmac.create(&p1, a1 ++ seed, master_secret);
            return handsakeHeader(.finished, 12) ++ p1[0..12].*;
        }

        // tls 1.3

        inline fn handshakeSecret(self: *Self, shared_key: []const u8) Transcript.Secret {
            const hello_hash = self.hash.peek();

            const zeroes = [1]u8{0} ** Hash.digest_length;
            const early_secret = Hkdf.extract(&[1]u8{0}, &zeroes);
            const empty_hash = tls.emptyHash(Hash);
            const hs_derived_secret = hkdfExpandLabel(Hkdf, early_secret, "derived", &empty_hash, Hash.digest_length);

            self.handshake_secret = Hkdf.extract(&hs_derived_secret, shared_key);
            const client_secret = hkdfExpandLabel(Hkdf, self.handshake_secret, "c hs traffic", &hello_hash, Hash.digest_length);
            const server_secret = hkdfExpandLabel(Hkdf, self.handshake_secret, "s hs traffic", &hello_hash, Hash.digest_length);

            self.server_finished_key = hkdfExpandLabel(Hkdf, server_secret, "finished", "", Hmac.key_length);
            self.client_finished_key = hkdfExpandLabel(Hkdf, client_secret, "finished", "", Hmac.key_length);

            return .{ .client = &client_secret, .server = &server_secret };
        }

        inline fn applicationSecret(self: *Self) Transcript.Secret {
            const handshake_hash = self.hash.peek();

            const empty_hash = tls.emptyHash(Hash);
            const zeroes = [1]u8{0} ** Hash.digest_length;
            const ap_derived_secret = hkdfExpandLabel(Hkdf, self.handshake_secret, "derived", &empty_hash, Hash.digest_length);
            const master_secret = Hkdf.extract(&ap_derived_secret, &zeroes);

            const client_secret = hkdfExpandLabel(Hkdf, master_secret, "c ap traffic", &handshake_hash, Hash.digest_length);
            const server_secret = hkdfExpandLabel(Hkdf, master_secret, "s ap traffic", &handshake_hash, Hash.digest_length);

            return .{ .client = &client_secret, .server = &server_secret };
        }

        fn serverFinishedTls13(self: *Self) [mac_length]u8 {
            var msg: [mac_length]u8 = undefined;
            Hmac.create(&msg, &self.hash.peek(), &self.server_finished_key);
            return msg;
        }

        // client finished message with header
        fn clientFinishedTls13(self: *Self) [4 + mac_length]u8 {
            var msg: [4 + mac_length]u8 = undefined;
            msg[0..4].* = handsakeHeader(.finished, mac_length);
            Hmac.create(msg[4..], &self.hash.peek(), &self.client_finished_key);
            return msg;
        }
    };
}
