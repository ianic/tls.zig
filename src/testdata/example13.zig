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

pub const server_application_key = hexToBytes("01f78623f17e3edcc09e944027ba3218d57c8e0db93cd3ac419309274700ac27");
pub const server_application_iv = hexToBytes("196a750b0c5049c0cc51a541");
pub const client_application_key = hexToBytes("de2f4c7672723a692319873e5c227606691a32d1c59d8b9f51dbb9352e9ca9cc");
pub const client_application_iv = hexToBytes("bb007956f474b25de902432f");

pub const server_encrypted_extensions_wrapped =
    hexToBytes("17030300176be02f9da7c2dc9ddef56f2468b90adfa25101ab0344ae");
pub const server_encrypted_extensions =
    hexToBytes("080000020000");

pub const server_certificate_wrapped =
    hexToBytes("1703030343baf00a9be50f3f2307e726edcbdacbe4b18616449d46c6207af6e9953ee5d2411ba65d31feaf4f78764f2d693987186cc01329c187a5e4608e8d27b318e98dd94769f7739ce6768392caca8dcc597d77ec0d1272233785f6e69d6f43effa8e7905edfdc4037eee5933e990a7972f206913a31e8d04931366d3d8bcd6a4a4d647dd4bd80b0ff863ce3554833d744cf0e0b9c07cae726dd23f9953df1f1ce3aceb3b7230871e92310cfb2b098486f43538f8e82d8404e5c6c25f66a62ebe3c5f26232640e20a769175ef83483cd81e6cb16e78dfad4c1b714b04b45f6ac8d1065ad18c13451c9055c47da300f93536ea56f531986d6492775393c4ccb095467092a0ec0b43ed7a0687cb470ce350917b0ac30c6e5c24725a78c45f9f5f29b6626867f6f79ce054273547b36df030bd24af10d632dba54fc4e890bd0586928c0206ca2e28e44e227a2d5063195935df38da8936092eef01e84cad2e49d62e470a6c7745f625ec39e4fc23329c79d1172876807c36d736ba42bb69b004ff55f93850dc33c1f98abb92858324c76ff1eb085db3c1fc50f74ec04442e622973ea70743418794c388140bb492d6294a0540e5a59cfae60ba0f14899fca71333315ea083a68e1d7c1e4cdc2f56bcd6119681a4adbc1bbf42afd806c3cbd42a076f545dee4e118d0b396754be2b042a685dd4727e89c0386a94d3cd6ecb9820e9d49afeed66c47e6fc243eabebbcb0b02453877f5ac5dbfbdf8db1052a3c994b224cd9aaaf56b026bb9efa2e01302b36401ab6494e7018d6e5b573bd38bcef023b1fc92946bbca0209ca5fa926b4970b1009103645cb1fcfe552311ff730558984370038fd2cce2a91fc74d6f3e3ea9f843eed356f6f82d35d03bc24b81b58ceb1a43ec9437e6f1e50eb6f555e321fd67c8332eb1b832aa8d795a27d479c6e27d5a61034683891903f66421d094e1b00a9a138d861e6f78a20ad3e1580054d2e305253c713a02fe1e28deee7336246f6ae34331806b46b47b833c39b9d31cd300c2a6ed831399776d07f570eaf0059a2c68a5f3ae16b617404af7b7231a4d942758fc020b3f23ee8c15e36044cfd67cd640993b16207597fbf385ea7a4d99e8d456ff83d41f7b8b4f069b028a2a63a919a70e3a10e3084158faa5bafa30186c6b2f238eb530c73e");
pub const server_certificate =
    hexToBytes("0b00032e0000032a0003253082032130820209a0030201020208155a92adc2048f90300d06092a864886f70d01010b05003022310b300906035504061302555331133011060355040a130a4578616d706c65204341301e170d3138313030353031333831375a170d3139313030353031333831375a302b310b3009060355040613025553311c301a060355040313136578616d706c652e756c666865696d2e6e657430820122300d06092a864886f70d01010105000382010f003082010a0282010100c4803606bae7476b089404eca7b691043ff792bc19eefb7d74d7a80d001e7b4b3a4ae60fe8c071fc73e7024c0dbcf4bdd11d396bba70464a13e94af83df3e10959547bc955fb412da3765211e1f3dc776caa53376eca3aecbec3aab73b31d56cb6529c8098bcc9e02818e20bf7f8a03afd1704509ece79bd9f39f1ea69ec47972e830fb5ca95de95a1e60422d5eebe527954a1e7bf8a86f6466d0d9f16951a4cf7a04692595c1352f2549e5afb4ebfd77a37950144e4c026874c653e407d7d23074401f484ffd08f7a1fa05210d1f4f0d5ce79702932e2cabe701fdfad6b4bb71101f44bad666a11130fe2ee829e4d029dc91cdd6716dbb9061886edc1ba94210203010001a3523050300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030206082b06010505070301301f0603551d23041830168014894fde5bcc69e252cf3ea300dfb197b81de1c146300d06092a864886f70d01010b05000382010100591645a69a2e3779e4f6dd271aba1c0bfd6cd75599b5e7c36e533eff3659084324c9e7a504079d39e0d42987ffe3ebdd09c1cf1d914455870b571dd19bdf1d24f8bb9a11fe80fd592ba0398cde11e2651e618ce598fa96e5372eef3d248afde17463ebbfabb8e4d1ab502a54ec0064e92f7819660d3f27cf209e667fce5ae2e4ac99c7c93818f8b2510722dfed97f32e3e9349d4c66c9ea6396d744462a06b42c6d5ba688eac3a017bddfc8e2cfcad27cb69d3ccdca280414465d3ae348ce0f34ab2fb9c618371312b191041641c237f11a5d65c844f0404849938712b959ed685bc5c5dd645ed19909473402926dcb40e3469a15941e8e2cca84bb6084636a00000");

pub const server_certificate_verify_wrapped = hexToBytes("170303011973719fce07ec2f6d3bba0292a0d40b2770c06a271799a53314f6f77fc95c5fe7b9a4329fd9548c670ebeea2f2d5c351dd9356ef2dcd52eb137bd3a676522f8cd0fb7560789ad7b0e3caba2e37e6b4199c6793b3346ed46cf740a9fa1fec414dc715c415c60e575703ce6a34b70b5191aa6a61a18faff216c687ad8d17e12a7e99915a611bfc1a2befc15e6e94d784642e682fd17382a348c301056b940c9847200408bec56c81ea3d7217ab8e85a88715395899c90587f72e8ddd74b26d8edc1c7c837d9f2ebbc260962219038b05654a63a0b12999b4a8306a3ddcc0e17c53ba8f9c80363f7841354d291b4ace0c0f330c0fcd5aa9deef969ae8ab2d98da88ebb6ea80a3a11f00ea296a3232367ff075e1c66dd9cbedc4713");
pub const server_finished_wrapped = hexToBytes("17030300451061de27e51c2c9f342911806f282b710c10632ca5006755880dbf7006002d0e84fed9adf27a43b5192303e4df5c285d58e3c76224078440c0742374744aecf28cf3182fd0");

pub const handshake_hash = hexToBytes("fa6800169a6baac19159524fa7b9721b41be3c9db6f3f93fa5ff7e3db3ece204d2b456c51046e40ec5312c55a86126f5");

pub const client_finished_verify_data = hexToBytes("bff56a671b6c659d0a7c5dd18428f58bdd38b184a3ce342d9fde95cbd5056f7da7918ee320eab7a93abd8f1c02454d27");

pub const client_finished_wrapped = hexToBytes("17030300459ff9b063175177322a46dd9896f3c3bb820ab51743ebc25fdadd53454b73deb54cc7248d411a18bccf657a960824e9a19364837c350a69a88d4bf635c85eb874aebc9dfde8");

pub const client_ping_wrapped = hexToBytes("1703030015828139cb7b73aaabf5b82fbf9a2961bcde10038a32");
pub const server_flight =
    hexToBytes("140303000101") ++
    server_encrypted_extensions_wrapped ++
    server_certificate_wrapped ++
    server_certificate_verify_wrapped ++
    server_finished_wrapped;

fn hexToBytes(comptime input: []const u8) [input.len / 2]u8 {
    @setEvalBranchQuota(1000 * 10);
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
