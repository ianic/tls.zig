const std = @import("std");
const tls = @import("tls");
const Certificate = std.crypto.Certificate;

pub fn showStats(stats: *tls.Stats, domain: []const u8) void {
    std.debug.print(
        "\n{s}\n\t tls version: {s}\n\t cipher: {s}\n\t named group: {s}\n\t signature scheme: {s}\n",
        .{
            domain,
            if (@intFromEnum(stats.tls_version) == 0) "none" else @tagName(stats.tls_version),
            if (@intFromEnum(stats.cipher_suite_tag) == 0) "none" else @tagName(stats.cipher_suite_tag),
            if (@intFromEnum(stats.named_group) == 0) "none" else @tagName(stats.named_group),
            if (@intFromEnum(stats.signature_scheme) == 0) "none" else @tagName(stats.signature_scheme),
        },
    );
}

pub fn initCaBundle(gpa: std.mem.Allocator) !Certificate.Bundle {
    var ca_bundle: Certificate.Bundle = .{};
    try ca_bundle.rescan(gpa);
    return ca_bundle;
}

pub fn topSites(gpa: std.mem.Allocator) !std.json.Parsed([]Site) {
    const data = @embedFile("top-sites.json");
    return std.json.parseFromSlice([]Site, gpa, data, .{ .allocate = .alloc_always });
}

pub const Site = struct {
    rank: usize,
    rootDomain: []const u8,
    linkingRootDomains: usize,
    domainAuthority: usize,
};

pub const Counter = struct {
    const Result = enum {
        success,
        fail,
        skip,
        err,
    };

    mu: std.Thread.Mutex = .{},

    success: usize = 0,
    fail: usize = 0,
    skip: usize = 0,
    err: usize = 0,

    pub fn add(self: *@This(), res: Result) void {
        self.mu.lock();
        defer self.mu.unlock();

        switch (res) {
            .success => self.success += 1,
            .fail => self.fail += 1,
            .skip => self.skip += 1,
            .err => self.err += 1,
        }
    }

    pub fn total(self: @This()) usize {
        return self.success + self.fail + self.skip + self.err;
    }

    pub fn show(self: @This()) void {
        std.debug.print(
            "stats:\n\t total: {}\n\t success: {}\n\t fail: {}\n\terror: {}\n\t skip: {}\n",
            .{ self.total(), self.success, self.fail, self.err, self.skip },
        );
    }
};
