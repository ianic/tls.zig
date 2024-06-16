const std = @import("std");

fn hex2Bytes(comptime input: []const u8) [input.len / 3]u8 {
    @setEvalBranchQuota(1000 * 10);
    var out: [input.len / 3]u8 = undefined;
    var in_i: usize = 0;
    while (in_i < input.len) : (in_i += 3) {
        const hi = charToDigit(input[in_i]);
        const lo = charToDigit(input[in_i + 1]);
        out[in_i / 3] = (hi << 4) | lo;
    }
    return out;
}

pub fn hexStr2(comptime input: []const u8) [input.len / 2]u8 {
    return hexStr(input, 2);
}

pub fn hexStr3(comptime input: []const u8) [input.len / 3]u8 {
    return hexStr(input, 3);
}

fn hexStr(comptime input: []const u8, comptime byte_len: u8) [input.len / byte_len]u8 {
    @setEvalBranchQuota(1000 * 10);
    var out: [input.len / byte_len]u8 = undefined;
    var in_i: usize = 0;
    while (in_i < input.len) : (in_i += byte_len) {
        const hi = charToDigit(input[in_i]);
        const lo = charToDigit(input[in_i + 1]);
        out[in_i / byte_len] = (hi << 4) | lo;
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

pub fn bufPrint(var_name: []const u8, buf: []const u8) void {
    // std.debug.print("\nconst {s} = [_]u8{{\n", .{var_name});
    // for (buf, 1..) |b, i| {
    //     std.debug.print("0x{x:0>2}, ", .{b});
    //     if (i % 16 == 0)
    //         std.debug.print("\n", .{});
    // }
    // std.debug.print("}};\n", .{});

    std.debug.print("const {s} = \"", .{var_name});
    const charset = "0123456789abcdef";
    for (buf) |b| {
        const x = charset[b >> 4];
        const y = charset[b & 15];
        std.debug.print("{c}{c} ", .{ x, y });
    }
    std.debug.print("\"\n", .{});
}


const random_instance = std.Random{ .ptr = undefined, .fillFn = randomFillFn };
var random_seed: u8 = 0;

pub fn randomFillFn(_: *anyopaque, buf: []u8) void {
    for (buf) |*v| {
        v.* =  random_seed;
        random_seed +%= 1;
    }
}

pub fn random(seed: u8) std.Random {
    random_seed =  seed;
    return random_instance;
}

pub const Stream = struct {
    output: std.io.FixedBufferStream([]u8) = undefined,
    input: std.io.FixedBufferStream([]const u8) = undefined,

    pub fn init(input: []const u8, output: []u8) Stream {
        return .{
            .input = std.io.fixedBufferStream(input),
            .output = std.io.fixedBufferStream(output),
        };
    }

    pub fn write(self: *Stream, buf: []const u8) !usize {
        return try self.output.writer().write(buf);
    }

    pub fn read(self: *Stream, buffer: []u8) !usize {
        return self.input.read(buffer);
    }
};
