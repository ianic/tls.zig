pub const client_hello =
    hexToBytes("16030100f8010000f40303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000813021303130100ff010000a30000001800160000136578616d706c652e756c666865696d2e6e6574000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d00020101003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254");

pub const server_hello =
    hexToBytes("160303007a") ++ // record header
    hexToBytes("020000760303") ++ // handshake header, server version
    hexToBytes("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f") ++ // server_random
    hexToBytes("20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff") ++ // session id
    hexToBytes("130200") ++ // cipher suite, compression method
    hexToBytes("002e002b00020304") ++ // extensions, supported version
    hexToBytes("00330024001d00209fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615"); // extension key share

pub const server_random =
    hexToBytes("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
pub const server_pub_key =
    hexToBytes("9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615");
pub const client_private_key =
    hexToBytes("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
pub const client_public_key =
    hexToBytes("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254");

pub const shared_key = hexToBytes("df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624");
pub const server_handshake_key = hexToBytes("9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f");
pub const server_handshake_iv = hexToBytes("9563bc8b590f671f488d2da3");
pub const client_handshake_key = hexToBytes("1135b4826a9a70257e5a391ad93093dfd7c4214812f493b3e3daae1eb2b1ac69");
pub const client_handshake_iv = hexToBytes("4256d2e0e88babdd05eb2f27");

pub const server_encrypted_extensions_wrapped =
    hexToBytes("17030300176be02f9da7c2dc9ddef56f2468b90adfa25101ab0344ae");
pub const server_encrypted_extensions =
    hexToBytes("08000002000016");

fn hexToBytes(comptime input: []const u8) [input.len / 2]u8 {
    var out: [input.len / 2]u8 = undefined;
    var in_i: usize = 0;
    while (in_i < input.len) : (in_i += 2) {
        const hi = charToDigit(input[in_i]);
        const lo = charToDigit(input[in_i + 1]);
        out[in_i / 2] = (hi << 4) | lo;
    }
    return out;
}

fn charToDigit(c: u8) u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'A'...'F' => c - 'A' + 10,
        'a'...'f' => c - 'a' + 10,
        else => unreachable,
    };
}
