const std = @import("std");
const tls = @import("tls");
const Certificate = std.crypto.Certificate;

pub fn showDiagnostic(stats: *tls.ClientOptions.Diagnostic, domain: []const u8) void {
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
    if (@intFromEnum(stats.client_signature_scheme) != 0) {
        std.debug.print("\t client signature scheme: {s}\n", .{@tagName(stats.client_signature_scheme)});
    }
}

pub fn initCaBundle(allocator: std.mem.Allocator) !Certificate.Bundle {
    var ca_bundle: Certificate.Bundle = .{};
    try ca_bundle.rescan(allocator);
    return ca_bundle;
}

pub fn topSites(allocator: std.mem.Allocator) !std.json.Parsed([]Site) {
    const data = @embedFile("top-sites.json");
    return std.json.parseFromSlice([]Site, allocator, data, .{ .allocate = .alloc_always });
}

pub const Site = struct {
    rank: usize,
    rootDomain: []const u8,
    linkingRootDomains: usize,
    domainAuthority: usize,
};

pub fn skipDomain(domain: []const u8) bool {
    for (domainsToSkip) |d| {
        if (std.mem.eql(u8, d, domain)) return true;
    }
    return false;
}

pub const domainsToSkip = [_][]const u8{
    "dw.com", // timeout after long time, fine on www.dw.com
    "alicdn.com",
    "usnews.com",
    "canada.ca", // SSL certificate problem: unable to get local issuer certificate
};

pub const domainsWithErrors = [_][]const u8{
    // certificate subject name no match
    "list-manage.com",
    // certificate expired or unable to get issuer
    "windows.net",
    "youronlinechoices.com",
    "canada.ca",
    // should disable keyber
    "godaddy.com",
    "secureserver.net",
};

pub fn inList(domain: []const u8, list: []const []const u8) bool {
    for (list) |d| {
        if (std.mem.eql(u8, d, domain)) return true;
    }
    return false;
}

pub const noKeyber = [_][]const u8{
    "secureserver.net",
    "godaddy.com",
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
            "stats:\n\t total: {}\n\t success: {}\n\t fail: {}\n\t error: {}\n\t skip: {}\n",
            .{ self.total(), self.success, self.fail, self.err, self.skip },
        );
    }
};

pub fn get(
    allocator: std.mem.Allocator,
    domain: []const u8,
    port: ?u16,
    show_handshake_stat: bool,
    show_response: bool,
    opt_: tls.ClientOptions,
) !void {
    var opt = opt_;

    // Add https:// prefix if needed
    const url = brk: {
        const scheme = "https://";
        if (domain.len >= scheme.len and std.mem.eql(u8, domain[0..scheme.len], scheme))
            break :brk domain;

        var url_buf: [128]u8 = undefined;
        break :brk try std.fmt.bufPrint(&url_buf, "https://{s}", .{domain});
    };
    const uri = try std.Uri.parse(url);
    const host = uri.host.?.percent_encoded;

    // Establish tcp connection
    var tcp = try std.net.tcpConnectToHost(allocator, host, if (port) |p| p else 443);
    defer tcp.close();
    // Set socket timeout
    const read_timeout: std.posix.timeval = .{ .tv_sec = 10, .tv_usec = 0 };
    try std.posix.setsockopt(tcp.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.toBytes(read_timeout)[0..]);

    // Prepare and show handshake stats
    if (show_handshake_stat and opt.diagnostic == null) {
        var diagnostic: tls.ClientOptions.Diagnostic = .{};
        opt.diagnostic = &diagnostic;
    }
    defer if (show_handshake_stat) showDiagnostic(opt.diagnostic.?, domain);

    // Upgrade tcp connection to tls
    opt.host = host;
    var cli = try tls.client(tcp, opt);

    // Send http GET request
    var buf: [64]u8 = undefined;
    const req = try std.fmt.bufPrint(&buf, "GET / HTTP/1.0\r\nHost: {s}\r\n\r\n", .{host});
    try cli.writeAll(req);

    // Read and print http response
    var n: usize = 0;
    defer if (show_response) std.debug.print("{} bytes read\n", .{n});
    while (try cli.next()) |data| {
        n += data.len;
        if (show_response) std.debug.print("{s}", .{data});
        if (std.mem.endsWith(u8, data, "</html>\n")) break;
    }

    try cli.close();
}

fn hasPrefix(str: []const u8, prefixes: []const []const u8) bool {
    for (prefixes) |prefix|
        if (str.len >= prefix.len and std.mem.eql(u8, str[0..prefix.len], prefix))
            return true;

    return false;
}

pub const tls12domains = [_][]const u8{
    "change.org",
    "linkedin.com",
    "uol.com.br",
    "esa.int",
    "fastcompany.com",
    "unicef.org",
    "deloitte.com",
    "cisco.com",
    "admin.ch",
    "usda.gov",
    "blackberry.com",
    "excite.co.jp",
    "dictionary.com",
    "leparisien.fr",
    "interia.pl",
    "etsy.com",
    "tes.com",
    "oecd.org",
    "umich.edu",
    "news.com.au",
    "goo.ne.jp",
    "newscientist.com",
    "si.edu",
    "alibaba.com",
    "psu.edu",
    "sciencemag.org",
    "mysql.com",
    "warnerbros.com",
    "zdf.de",
    "jhu.edu",
    "imageshack.com",
    "lg.com",
    "sueddeutsche.de",
    "justice.gov",
    "ted.com",
    "pbs.org",
    "vice.com",
    "playstation.com",
    "seesaa.net",
    "zippyshare.com",
    "sapo.pt",
    "kakao.com",
    "cointernet.com.co",
    "www.privacyshield.gov",
    "harvard.edu",
    "outlook.com",
    "instructables.com",
    "linktr.ee",
    "nbcnews.com",
    "alexa.com",
    "sakura.ne.jp",
    "cornell.edu",
    "latimes.com",
    "prezi.com",
    "cambridge.org",
    "huawei.com",
    "oracle.com",
    "theatlantic.com",
    "qq.com",
    "insider.com",
    "unsplash.com",
    "detik.com",
    "samsung.com",
    "britannica.com",
    "quora.com",
    "liveinternet.ru",
    "thetimes.co.uk",
    "weibo.com",
    "oup.com",
    "hp.com",
    "unesco.org",
    "newyorker.com",
    "calameo.com",
    "gizmodo.com",
    "psychologytoday.com",
    "trustpilot.com",
    "stanford.edu",
    "wired.com",
    "mit.edu",
    "ca.gov",
    "php.net",
    "imageshack.us",
    "reuters.com",
    "nginx.org",
    "cbsnews.com",
    "hatena.ne.jp",
    "mirror.co.uk",
    "un.org",
    "forbes.com",
    "namecheap.com",
    "cdc.gov",
    "mediafire.com",
    "webmd.com",
    "correios.com.br",
    "businessinsider.com",
    "independent.co.uk",
    "4shared.com",
    "planalto.gov.br",
    "wiley.com",
    "nytimes.com",
    "aliexpress.com",
    "mail.ru",
    "nih.gov",
    "jimdofree.com",
};

pub const tls13stdFails = [_][]const u8{
    // fragmented message
    "whatsapp.com",
    "wa.me",
    "facebook.com",
    "instagram.com",
    "m.me",
    "fb.com",
    "fb.me",

    // certificate not part of the chain
    "www.wix.com",
    "terra.com.br",

    // certificate longer than handshake buffer
    "googleblog.com",
    "feedburner.com",
    "g.page",
    "googleusercontent.com",
    "marriott.com",

    // other
    "dailymotion.com", // rsa_pkcs1_sha384 required in client hello signature algorithms extension
    "home.pl", // secp384r1 named group required in client hello supported groups extension

    // certificate problems
    "windows.net", // certificate host mismatch
    "list-manage.com", // certificate host mismatch
    "youronlinechoices.com", // certificate issuer not found

    // keyber, no response on client hello then timeout
    "godaddy.com",
    "secureserver.net",
};
