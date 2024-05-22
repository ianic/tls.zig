const std = @import("std");
const crypto = std.crypto;
const tls12 = @import("tls12.zig");
const Aes128Cbc = @import("cbc.zig").Aes128Cbc;
const tls = std.crypto.tls;
const hkdfExpandLabel = tls.hkdfExpandLabel;

const Sha256 = crypto.hash.sha2.Sha256;
const Sha384 = crypto.hash.sha2.Sha384;

pub const Transcript = struct {
    const Transcript256 = TranscriptT(Sha256);
    const Transcript384 = TranscriptT(Sha384);

    sha256: Transcript256 = .{ .transcript = Sha256.init(.{}) },
    sha384: Transcript384 = .{ .transcript = Sha384.init(.{}) },

    pub fn update(t: *Transcript, buf: []const u8) void {
        t.sha256.transcript.update(buf);
        t.sha384.transcript.update(buf);
    }

    pub fn masterSecret(
        comptime len: usize,
        cs: tls12.CipherSuite,
        pre_master_secret: []const u8,
        client_random: [32]u8,
        server_random: [32]u8,
    ) [len]u8 {
        return switch (cs.hash()) {
            .sha256 => Transcript256.masterSecret(pre_master_secret, client_random, server_random)[0..len].*,
            .sha384 => Transcript384.masterSecret(pre_master_secret, client_random, server_random)[0..len].*,
        };
    }

    pub fn keyMaterial(
        comptime len: usize,
        cs: tls12.CipherSuite,
        master_secret: []const u8,
        client_random: [32]u8,
        server_random: [32]u8,
    ) [len]u8 {
        return switch (cs.hash()) {
            .sha256 => Transcript256.keyExpansion(master_secret, client_random, server_random)[0..len].*,
            .sha384 => Transcript384.keyExpansion(master_secret, client_random, server_random)[0..len].*,
        };
    }

    pub fn clientFinished(self: *Transcript, cs: tls12.CipherSuite, master_secret: []const u8) [16]u8 {
        return switch (cs.hash()) {
            .sha256 => self.sha256.clientFinished(master_secret),
            .sha384 => self.sha384.clientFinished(master_secret),
        };
    }

    pub fn serverFinished(self: *Transcript, cs: tls12.CipherSuite, master_secret: []const u8) [16]u8 {
        return switch (cs.hash()) {
            .sha256 => self.sha256.serverFinished(master_secret),
            .sha384 => self.sha384.serverFinished(master_secret),
        };
    }

    pub inline fn verifyBytes13(self: *Transcript, cs: tls12.CipherSuite) []const u8 {
        return switch (cs.hash()) {
            .sha256 => &self.sha256.verifyBytes13(),
            .sha384 => &self.sha384.verifyBytes13(),
        };
    }

    pub inline fn serverFinished13(self: *Transcript, cs: tls12.CipherSuite) []const u8 {
        return switch (cs.hash()) {
            .sha256 => &self.sha256.serverFinished13(),
            .sha384 => &self.sha384.serverFinished13(),
        };
    }
};

pub fn TranscriptT(comptime HashType: type) type {
    return struct {
        const Hash = HashType;
        const Hmac = crypto.auth.hmac.Hmac(Hash);
        const Hkdf = crypto.kdf.hkdf.Hkdf(Hmac);
        const mac_length = Hmac.mac_length;

        transcript: Hash,
        handshake_secret: [Hmac.mac_length]u8 = undefined,
        server_finished_key: [Hmac.key_length]u8 = undefined,
        client_finished_key: [Hmac.key_length]u8 = undefined,

        const Self = @This();

        fn init(transcript: Hash) Self {
            return .{ .transcript = transcript };
        }

        pub fn verifyBytes13(c: *Self) [64 + 34 + Hash.digest_length]u8 {
            return ([1]u8{0x20} ** 64) ++
                "TLS 1.3, server CertificateVerify\x00".* ++
                c.transcript.peek();
        }

        pub fn masterSecret(
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

        pub fn keyExpansion(
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

        pub fn clientFinished(self: *Self, master_secret: []const u8) [16]u8 {
            const seed = "client finished" ++ self.transcript.peek();
            var a1: [mac_length]u8 = undefined;
            var p1: [mac_length]u8 = undefined;
            Hmac.create(&a1, seed, master_secret);
            Hmac.create(&p1, a1 ++ seed, master_secret);
            return tls12.handshake_finished_header ++ p1[0..12].*;
        }

        pub fn serverFinished(self: *Self, master_secret: []const u8) [16]u8 {
            const seed = "server finished" ++ self.transcript.peek();
            var a1: [mac_length]u8 = undefined;
            var p1: [mac_length]u8 = undefined;
            Hmac.create(&a1, seed, master_secret);
            Hmac.create(&p1, a1 ++ seed, master_secret);
            return tls12.handshake_finished_header ++ p1[0..12].*;
        }

        // tls 1.3

        pub fn handshakeSecret(self: *Self, shared_key: []const u8) struct { client: [Hash.digest_length]u8, server: [Hash.digest_length]u8 } {
            const hello_hash = self.transcript.peek();

            const zeroes = [1]u8{0} ** Hash.digest_length;
            const early_secret = Hkdf.extract(&[1]u8{0}, &zeroes);
            const empty_hash = tls.emptyHash(Hash);
            const hs_derived_secret = hkdfExpandLabel(Hkdf, early_secret, "derived", &empty_hash, Hash.digest_length);

            self.handshake_secret = Hkdf.extract(&hs_derived_secret, shared_key);
            const client_secret = hkdfExpandLabel(Hkdf, self.handshake_secret, "c hs traffic", &hello_hash, Hash.digest_length);
            const server_secret = hkdfExpandLabel(Hkdf, self.handshake_secret, "s hs traffic", &hello_hash, Hash.digest_length);

            self.server_finished_key = hkdfExpandLabel(Hkdf, server_secret, "finished", "", Hmac.key_length);
            self.client_finished_key = hkdfExpandLabel(Hkdf, client_secret, "finished", "", Hmac.key_length);

            return .{ .client = client_secret, .server = server_secret };
        }

        pub fn applicationSecret(self: *Self) struct { client: [Hash.digest_length]u8, server: [Hash.digest_length]u8 } {
            const handshake_hash = self.transcript.peek();

            const empty_hash = tls.emptyHash(Hash);
            const zeroes = [1]u8{0} ** Hash.digest_length;
            const ap_derived_secret = hkdfExpandLabel(Hkdf, self.handshake_secret, "derived", &empty_hash, Hash.digest_length);
            const master_secret = Hkdf.extract(&ap_derived_secret, &zeroes);

            const client_secret = hkdfExpandLabel(Hkdf, master_secret, "c ap traffic", &handshake_hash, Hash.digest_length);
            const server_secret = hkdfExpandLabel(Hkdf, master_secret, "s ap traffic", &handshake_hash, Hash.digest_length);

            return .{ .client = client_secret, .server = server_secret };
        }

        pub fn serverFinished13(self: *Self) [mac_length]u8 {
            var msg: [mac_length]u8 = undefined;
            Hmac.create(&msg, &self.transcript.peek(), &self.server_finished_key);
            return msg;
        }

        pub fn clientFinished13(self: *Self) [mac_length]u8 {
            var msg: [mac_length]u8 = undefined;
            Hmac.create(&msg, &self.transcript.peek(), &self.client_finished_key);
            return msg;
        }
    };
}

pub const AppCipher = union(tls12.CipherSuite.Cipher) {
    aes_128_cbc_sha: CipherCbcT(Aes128Cbc, crypto.hash.Sha1),
    aes_128_cbc_sha256: CipherCbcT(Aes128Cbc, crypto.hash.sha2.Sha256),
    aes_128_gcm: CipherAeadT(crypto.aead.aes_gcm.Aes128Gcm),
    aes_256_gcm: CipherAeadT(crypto.aead.aes_gcm.Aes256Gcm),

    // tls13
    aes_256_gcm_sha384: CipherAead13T(crypto.aead.aes_gcm.Aes256Gcm),

    pub fn init(tag: tls12.CipherSuite, key_material: []const u8, rnd: std.Random) !AppCipher {
        return switch (try tag.cipher()) {
            .aes_128_cbc_sha => .{ .aes_128_cbc_sha = CipherCbcT(Aes128Cbc, crypto.hash.Sha1).init(key_material, rnd) },
            .aes_128_cbc_sha256 => .{ .aes_128_cbc_sha256 = CipherCbcT(Aes128Cbc, crypto.hash.sha2.Sha256).init(key_material, rnd) },
            .aes_128_gcm => .{ .aes_128_gcm = CipherAeadT(crypto.aead.aes_gcm.Aes128Gcm).init(key_material, rnd) },
            .aes_256_gcm => .{ .aes_256_gcm = CipherAeadT(crypto.aead.aes_gcm.Aes256Gcm).init(key_material, rnd) },
            else => return error.TlsIllegalParameter,
        };
    }

    pub fn initHandshake(tag: tls12.CipherSuite, shared_key: []const u8, transcript: *Transcript) !AppCipher {
        return switch (tag) {
            .TLS_AES_256_GCM_SHA384 => {
                const Hkdf = @TypeOf(transcript.sha384).Hkdf;
                const AEAD = CipherAead13T(crypto.aead.aes_gcm.Aes256Gcm);
                const hs_secret = transcript.sha384.handshakeSecret(shared_key);

                return .{ .aes_256_gcm_sha384 = AEAD{
                    .client_key = hkdfExpandLabel(Hkdf, hs_secret.client, "key", "", AEAD.key_len),
                    .server_key = hkdfExpandLabel(Hkdf, hs_secret.server, "key", "", AEAD.key_len),
                    .client_iv = hkdfExpandLabel(Hkdf, hs_secret.client, "iv", "", AEAD.nonce_len),
                    .server_iv = hkdfExpandLabel(Hkdf, hs_secret.server, "iv", "", AEAD.nonce_len),
                    .rnd = crypto.random,
                } };
            },
            else => return error.TlsIllegalParameter,
        };
    }

    pub fn initApp(tag: tls12.CipherSuite, transcript: *Transcript) !AppCipher {
        return switch (tag) {
            .TLS_AES_256_GCM_SHA384 => {
                const Hkdf = @TypeOf(transcript.sha384).Hkdf;
                const AEAD = CipherAead13T(crypto.aead.aes_gcm.Aes256Gcm);
                const ap_secret = transcript.sha384.applicationSecret();

                return .{ .aes_256_gcm_sha384 = AEAD{
                    .client_key = hkdfExpandLabel(Hkdf, ap_secret.client, "key", "", AEAD.key_len),
                    .server_key = hkdfExpandLabel(Hkdf, ap_secret.server, "key", "", AEAD.key_len),
                    .client_iv = hkdfExpandLabel(Hkdf, ap_secret.client, "iv", "", AEAD.nonce_len),
                    .server_iv = hkdfExpandLabel(Hkdf, ap_secret.server, "iv", "", AEAD.nonce_len),
                    .rnd = crypto.random,
                } };
            },
            else => return error.TlsIllegalParameter,
        };
    }

    const Self = @This();

    pub fn overhead(self: Self) usize {
        return switch (self) {
            .aes_128_cbc_sha => 16 + 20 + 16, // iv (16 bytes), mac (20 bytes), padding (1-16 bytes)
            .aes_128_cbc_sha256 => 16 + 32 + 16, // iv (16 bytes), mac (32 bytes), padding (1-16 bytes)
            .aes_128_gcm => 8 + 16, // explicit_iv (8 bytes) + auth_tag_len (16 bytes)
            .aes_256_gcm => 8 + 16, // explicit_iv (8 bytes) + auth_tag_len (16 bytes)
            else => 8, // TODO
        };
    }

    pub const max_overhead = 16 + 32 + 16;

    pub fn minEncryptBufferLen(self: Self, cleartext_len: usize) usize {
        return self.overhead() + cleartext_len;
    }
};

fn CipherAeadT(comptime AeadType: type) type {
    return struct {
        const key_len = AeadType.key_length;
        const auth_tag_len = AeadType.tag_length;
        const nonce_len = AeadType.nonce_length;
        const iv_len = AeadType.nonce_length - tls12.explicit_iv_len;

        client_key: [key_len]u8,
        server_key: [key_len]u8,
        client_iv: [iv_len]u8,
        server_iv: [iv_len]u8,
        rnd: std.Random,

        const Cipher = @This();

        fn init(key_material: []const u8, rnd: std.Random) Cipher {
            return .{
                .rnd = rnd,
                .client_key = key_material[0..key_len].*,
                .server_key = key_material[key_len..][0..key_len].*,
                .client_iv = key_material[2 * key_len ..][0..iv_len].*,
                .server_iv = key_material[2 * key_len + iv_len ..][0..iv_len].*,
            };
        }

        /// Encrypt cleartext into provided buffer `buf`.
        /// After this buf contains payload in format:
        ///   explicit iv | ciphertext | auth tag
        pub fn encrypt(
            cipher: Cipher,
            buf: []u8,
            sequence: u64,
            content_type: tls.ContentType,
            cleartext: []const u8,
        ) []const u8 {
            const header = buf[0..tls.record_header_len];
            var explicit_iv: [tls12.explicit_iv_len]u8 = undefined;
            cipher.rnd.bytes(&explicit_iv);
            buf[header.len..][0..explicit_iv.len].* = explicit_iv;

            const iv = cipher.client_iv ++ explicit_iv;
            const ciphertext = buf[header.len + explicit_iv.len ..][0..cleartext.len];
            const auth_tag = buf[header.len + explicit_iv.len + ciphertext.len ..][0..auth_tag_len];
            const ad = additionalData(sequence, content_type, cleartext.len);
            AeadType.encrypt(ciphertext, auth_tag, cleartext, &ad, iv, cipher.client_key);

            header.* = tls12.recordHeader(content_type, explicit_iv.len + ciphertext.len + auth_tag.len);
            return buf[0 .. header.len + explicit_iv.len + ciphertext.len + auth_tag.len];
        }

        pub fn decrypt(
            cipher: Cipher,
            buf: []u8,
            sequence: u64,
            header: []const u8,
            payload: []const u8,
        ) !struct { tls.ContentType, []u8 } {
            const overhead = tls12.explicit_iv_len + auth_tag_len;
            if (payload.len < overhead) return error.TlsDecryptError;

            const iv = cipher.server_iv ++ payload[0..tls12.explicit_iv_len].*;
            const cleartext_len = payload.len - overhead;
            const ciphertext = payload[tls12.explicit_iv_len..][0..cleartext_len];
            const auth_tag = payload[tls12.explicit_iv_len + cleartext_len ..][0..auth_tag_len];
            const cleartext = buf[0..cleartext_len];
            const content_type: tls.ContentType = @enumFromInt(header[0]);
            const ad = additionalData(sequence, content_type, cleartext_len);

            try AeadType.decrypt(cleartext, ciphertext, auth_tag.*, &ad, iv, cipher.server_key);
            return .{ content_type, cleartext };
        }
    };
}

fn CipherAead13T(comptime AeadType: type) type {
    return struct {
        const key_len = AeadType.key_length;
        const auth_tag_len = AeadType.tag_length;
        const nonce_len = AeadType.nonce_length;

        client_key: [key_len]u8,
        server_key: [key_len]u8,
        client_iv: [nonce_len]u8,
        server_iv: [nonce_len]u8,
        rnd: std.Random,

        const Cipher = @This();

        pub fn encrypt(
            cipher: Cipher,
            buf: []u8,
            sequence: u64,
            content_type: tls.ContentType,
            cleartext: []const u8,
        ) []const u8 {
            // xor iv and sequence
            var iv = cipher.client_iv;
            const operand = std.mem.readInt(u64, iv[nonce_len - 8 ..], .big);
            std.mem.writeInt(u64, iv[nonce_len - 8 ..], operand ^ sequence, .big);

            const header = buf[0..tls.record_header_len];
            @memcpy(buf[header.len..][0..cleartext.len], cleartext);
            buf[header.len + cleartext.len] = @intFromEnum(content_type);
            const ciphertext = buf[header.len..][0 .. cleartext.len + 1];
            const auth_tag = buf[header.len + ciphertext.len ..][0..auth_tag_len];
            const encrypted_len = ciphertext.len + auth_tag_len;
            header.* = tls12.recordHeader(.application_data, encrypted_len);

            AeadType.encrypt(ciphertext, auth_tag, ciphertext, header, iv, cipher.client_key);
            return buf[0 .. header.len + encrypted_len];
        }

        pub fn decrypt(
            cipher: Cipher,
            buf: []u8,
            sequence: u64,
            header: []const u8,
            payload: []const u8,
        ) !struct { tls.ContentType, []u8 } {
            const overhead = auth_tag_len;
            if (payload.len < overhead) return error.TlsDecryptError;

            // xor iv and sequence
            var iv = cipher.server_iv;
            const operand = std.mem.readInt(u64, iv[nonce_len - 8 ..], .big);
            std.mem.writeInt(u64, iv[nonce_len - 8 ..], operand ^ sequence, .big);

            const cleartext_len = payload.len - overhead;
            const ciphertext = payload[0..cleartext_len];
            const auth_tag = payload[cleartext_len..][0..auth_tag_len];

            const cleartext = buf[0..cleartext_len];
            try AeadType.decrypt(cleartext, ciphertext, auth_tag.*, header, iv, cipher.server_key);
            return .{
                @enumFromInt(cleartext[cleartext_len - 1]),
                cleartext[0 .. cleartext.len - 1],
            };
        }
    };
}

fn CipherCbcT(comptime CbcType: type, comptime HashType: type) type {
    const mac_length = HashType.digest_length; // 20 bytes for sha1
    const key_length = CbcType.key_length; // 16 bytes for CBCAed128
    const iv_length = CbcType.nonce_length; // 16 bytes for CBCAed128

    return struct {
        pub const CBC = CbcType;
        pub const Hmac = crypto.auth.hmac.Hmac(HashType);

        client_secret: [mac_length]u8,
        server_secret: [mac_length]u8,
        client_key: [key_length]u8,
        server_key: [key_length]u8,
        rnd: std.Random,

        const Cipher = @This();

        fn init(key_material: []const u8, rnd: std.Random) Cipher {
            return .{
                .rnd = rnd,
                .client_secret = key_material[0..mac_length].*,
                .server_secret = key_material[mac_length..][0..mac_length].*,
                .client_key = key_material[2 * mac_length ..][0..key_length].*,
                .server_key = key_material[2 * mac_length + key_length ..][0..key_length].*,
            };
        }

        pub fn encrypt(
            cipher: Cipher,
            buf: []u8,
            sequence: u64,
            content_type: tls.ContentType,
            cleartext: []const u8,
        ) []const u8 {
            const ad = additionalData(sequence, content_type, cleartext.len);
            const cleartext_idx = tls.record_header_len + iv_length;

            // unused | ad | cleartext | mac
            //        | --mac input--  | --mac output--
            const mac_input_buf = buf[cleartext_idx - ad.len ..][0 .. ad.len + cleartext.len + mac_length];
            @memcpy(mac_input_buf[0..ad.len], &ad);
            @memcpy(mac_input_buf[ad.len..][0..cleartext.len], cleartext);
            const mac_output_buf = mac_input_buf[ad.len + cleartext.len ..][0..mac_length];

            Hmac.create(mac_output_buf, mac_input_buf[0 .. ad.len + cleartext.len], &cipher.client_secret);

            // unused | ad | cleartext | mac | padding
            const unpadded_len = cleartext.len + mac_length;
            const padded_len = CBC.paddedLength(unpadded_len);
            const payload_buf = buf[cleartext_idx..][0..padded_len];
            const padding_byte: u8 = @intCast(padded_len - unpadded_len - 1);
            @memset(payload_buf[unpadded_len..padded_len], padding_byte);

            // iv | cleartext | mac | padding
            // iv | -------   payload -------
            const iv = buf[cleartext_idx - iv_length .. cleartext_idx];
            cipher.rnd.bytes(iv);

            CBC.init(cipher.client_key).encrypt(payload_buf, payload_buf, iv[0..iv_length].*);
            buf[0..tls.record_header_len].* = tls12.recordHeader(content_type, iv_length + payload_buf.len);
            //return buf[cleartext_idx - iv_length .. cleartext_idx + payload_buf.len];
            return buf[0 .. cleartext_idx + payload_buf.len];
        }

        pub fn decrypt(
            cipher: Cipher,
            buf: []u8,
            sequence: u64,
            header: []const u8,
            payload: []const u8,
        ) !struct { tls.ContentType, []u8 } {
            const content_type: tls.ContentType = @enumFromInt(header[0]);
            if (payload.len < iv_length + mac_length + 1) return error.TlsDecryptError;
            var ad = additionalData(sequence, content_type, payload.len);

            // --------- payload ------------
            // iv | -------   crypted -------
            // iv | cleartext | mac | padding
            const iv = payload[0..iv_length];
            const crypted = payload[iv_length..];
            // ---------- buf ---------------
            // ad | ------ decrypted --------
            // ad | cleartext | mac | padding
            const decrypted = buf[ad.len..][0..crypted.len];
            // decrypt crypted -> decrypted
            try CBC.init(cipher.server_key).decrypt(decrypted, crypted, iv[0..iv_length].*);

            // get padding len from last padding byte
            const padding_len = decrypted[decrypted.len - 1] + 1;
            if (decrypted.len < mac_length + padding_len) return error.TlsDecryptError;

            // split decrypted into cleartext and mac
            const cleartext_len = decrypted.len - mac_length - padding_len;
            const cleartext = decrypted[0..cleartext_len];
            const mac = decrypted[cleartext_len..][0..mac_length];

            // write len to the ad
            std.mem.writeInt(u16, ad[ad.len - 2 ..][0..2], @intCast(cleartext_len), .big);
            @memcpy(buf[0..ad.len], &ad);
            // calculate expected mac
            var expected_mac: [mac_length]u8 = undefined;
            Hmac.create(&expected_mac, buf[0 .. ad.len + cleartext_len], &cipher.server_secret);
            if (!std.mem.eql(u8, &expected_mac, mac))
                return error.TlsBadRecordMac;

            return .{ content_type, cleartext };
        }
    };
}

pub const additional_data_len = tls.record_header_len + @sizeOf(u64);

fn additionalData(sequence: u64, content_type: tls.ContentType, payload_len: usize) [additional_data_len]u8 {
    const header = tls12.recordHeader(content_type, payload_len);
    var sequence_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &sequence_buf, sequence, .big);
    return sequence_buf ++ header;
}
