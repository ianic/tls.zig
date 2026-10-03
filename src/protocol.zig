pub const Version = enum(u16) {
    tls_1_2 = 0x0303,
    tls_1_3 = 0x0304,
    _,
};

pub const ContentType = enum(u8) {
    invalid = 0,
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    _,
};

pub const Handshake = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
    key_update = 24,
    message_hash = 254,
    _,
};

pub const Curve = enum(u8) {
    named_curve = 0x03,
    _,
};

pub const KeyExchangeModes = enum(u8) {
    psk_ke = 0,
    psk_dhe_ke = 1,
};

pub const Extension = enum(u16) {
    /// RFC 6066
    server_name = 0,
    /// RFC 6066
    max_fragment_length = 1,
    /// RFC 6066
    status_request = 5,
    /// RFC 8422, 7919
    supported_groups = 10,
    /// RFC 8446
    signature_algorithms = 13,
    /// RFC 5764
    use_srtp = 14,
    /// RFC 6520
    heartbeat = 15,
    /// RFC 7301
    application_layer_protocol_negotiation = 16,
    /// RFC 6962
    signed_certificate_timestamp = 18,
    /// RFC 7250
    client_certificate_type = 19,
    /// RFC 7250
    server_certificate_type = 20,
    /// RFC 7685
    padding = 21,
    /// RFC 8446
    pre_shared_key = 41,
    /// RFC 8446
    early_data = 42,
    /// RFC 8446
    supported_versions = 43,
    /// RFC 8446
    cookie = 44,
    /// RFC 8446
    psk_key_exchange_modes = 45,
    /// RFC 8446
    certificate_authorities = 47,
    /// RFC 8446
    oid_filters = 48,
    /// RFC 8446
    post_handshake_auth = 49,
    /// RFC 8446
    signature_algorithms_cert = 50,
    /// RFC 8446
    key_share = 51,

    _,
};

/// The fatal alert to send for a locally detected failure, or null when
/// there is nothing to tell the peer about. See `Alert.forLocalError`.
pub fn alertForLocalError(err: anyerror) ?[2]u8 {
    const alert = Alert.forLocalError(err) orelse return null;
    return [2]u8{ @intFromEnum(Alert.Level.fatal), @intFromEnum(alert) };
}

pub const Alert = enum(u8) {
    pub const Level = enum(u8) {
        warning = 1,
        fatal = 2,
        _,
    };

    pub const Error = error{
        TlsAlertUnexpectedMessage,
        TlsAlertBadRecordMac,
        TlsAlertRecordOverflow,
        TlsAlertHandshakeFailure,
        TlsAlertBadCertificate,
        TlsAlertUnsupportedCertificate,
        TlsAlertCertificateRevoked,
        TlsAlertCertificateExpired,
        TlsAlertCertificateUnknown,
        TlsAlertIllegalParameter,
        TlsAlertUnknownCa,
        TlsAlertAccessDenied,
        TlsAlertDecodeError,
        TlsAlertDecryptError,
        TlsAlertProtocolVersion,
        TlsAlertInsufficientSecurity,
        TlsAlertInternalError,
        TlsAlertInappropriateFallback,
        TlsAlertMissingExtension,
        TlsAlertUnsupportedExtension,
        TlsAlertUnrecognizedName,
        TlsAlertBadCertificateStatusResponse,
        TlsAlertUnknownPskIdentity,
        TlsAlertCertificateRequired,
        TlsAlertNoApplicationProtocol,
        TlsAlertUnknown,
    };

    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    record_overflow = 22,
    handshake_failure = 40,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    inappropriate_fallback = 86,
    user_canceled = 90,
    missing_extension = 109,
    unsupported_extension = 110,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    unknown_psk_identity = 115,
    certificate_required = 116,
    no_application_protocol = 120,
    _,

    pub fn toError(alert: Alert) Error!void {
        return switch (alert) {
            .close_notify => {}, // not an error
            .unexpected_message => error.TlsAlertUnexpectedMessage,
            .bad_record_mac => error.TlsAlertBadRecordMac,
            .record_overflow => error.TlsAlertRecordOverflow,
            .handshake_failure => error.TlsAlertHandshakeFailure,
            .bad_certificate => error.TlsAlertBadCertificate,
            .unsupported_certificate => error.TlsAlertUnsupportedCertificate,
            .certificate_revoked => error.TlsAlertCertificateRevoked,
            .certificate_expired => error.TlsAlertCertificateExpired,
            .certificate_unknown => error.TlsAlertCertificateUnknown,
            .illegal_parameter => error.TlsAlertIllegalParameter,
            .unknown_ca => error.TlsAlertUnknownCa,
            .access_denied => error.TlsAlertAccessDenied,
            .decode_error => error.TlsAlertDecodeError,
            .decrypt_error => error.TlsAlertDecryptError,
            .protocol_version => error.TlsAlertProtocolVersion,
            .insufficient_security => error.TlsAlertInsufficientSecurity,
            .internal_error => error.TlsAlertInternalError,
            .inappropriate_fallback => error.TlsAlertInappropriateFallback,
            .user_canceled => {}, // not an error
            .missing_extension => error.TlsAlertMissingExtension,
            .unsupported_extension => error.TlsAlertUnsupportedExtension,
            .unrecognized_name => error.TlsAlertUnrecognizedName,
            .bad_certificate_status_response => error.TlsAlertBadCertificateStatusResponse,
            .unknown_psk_identity => error.TlsAlertUnknownPskIdentity,
            .certificate_required => error.TlsAlertCertificateRequired,
            .no_application_protocol => error.TlsAlertNoApplicationProtocol,
            _ => error.TlsAlertUnknown,
        };
    }

    /// True for the errors produced by `toError`, i.e. an alert the peer sent
    /// us. Derived from `Error` rather than from the error name, so it cannot
    /// drift as that set changes.
    pub fn isFromPeer(err: anyerror) bool {
        inline for (@typeInfo(Error).error_set.?) |e| {
            if (err == @field(anyerror, e.name)) return true;
        }
        return false;
    }

    /// The alert describing a failure we detected locally, or null when the
    /// peer should not be sent one: it already told us about its own failure,
    /// or the transport is gone and there is nothing to send on.
    pub fn forLocalError(err: anyerror) ?Alert {
        if (isFromPeer(err)) return null;
        return switch (err) {
            // Transport or resource failures. Not protocol violations, and
            // in most cases there is no longer a connection to send on.
            error.ReadFailed,
            error.WriteFailed,
            error.EndOfStream,
            error.TlsConnectionTruncated,
            error.TlsConnectionFailed,
            error.Canceled,
            error.OutOfMemory,
            => null,

            error.TlsUnexpectedMessage => .unexpected_message,
            error.TlsBadRecordMac => .bad_record_mac,
            error.TlsRecordOverflow => .record_overflow,
            error.TlsHandshakeFailure => .handshake_failure,
            error.TlsBadCertificate => .bad_certificate,
            error.TlsUnsupportedCertificate => .unsupported_certificate,
            error.TlsCertificateRevoked => .certificate_revoked,
            error.TlsCertificateExpired => .certificate_expired,
            error.TlsCertificateUnknown => .certificate_unknown,
            error.TlsIllegalParameter,
            error.IdentityElement,
            error.InvalidEncoding,
            error.TlsNoSupportedCiphers,
            error.TlsBadSignatureScheme,
            error.TlsUnknownSignatureScheme,
            => .illegal_parameter,
            error.TlsUnknownCa => .unknown_ca,
            error.TlsAccessDenied => .access_denied,
            error.TlsDecodeError => .decode_error,
            error.TlsDecryptError, error.TlsDecryptFailure => .decrypt_error,
            error.TlsProtocolVersion, error.TlsBadVersion => .protocol_version,
            // The peer offered nothing we can complete the handshake with.
            error.TlsServerHelloRetryRequest => .handshake_failure,
            // Our own limitation rather than anything the peer did wrong.
            error.TlsUnsupportedFragmentedHandshakeMessage => .internal_error,
            error.TlsInsufficientSecurity => .insufficient_security,
            error.TlsInternalError => .internal_error,
            error.TlsInappropriateFallback => .inappropriate_fallback,
            error.TlsMissingExtension => .missing_extension,
            error.TlsUnsupportedExtension => .unsupported_extension,
            error.TlsUnrecognizedName => .unrecognized_name,
            error.TlsBadCertificateStatusResponse => .bad_certificate_status_response,
            error.TlsUnknownPskIdentity => .unknown_psk_identity,
            error.TlsCertificateRequired => .certificate_required,
            error.TlsNoApplicationProtocol => .no_application_protocol,
            else => .internal_error,
        };
    }

    pub const Parsed = struct {
        level: Level,
        description: Alert,
    };

    /// Callers deliberately decide on `description` alone. TLS 1.3 makes
    /// severity implicit in the alert type and says `level` "can safely be
    /// ignored" (RFC 8446 6), and treating a TLS 1.2 warning-level alert as
    /// fatal is the safe reading. `level` is kept for diagnostics.
    pub fn parse(buf: [2]u8) Parsed {
        return .{
            .level = @enumFromInt(buf[0]),
            .description = @enumFromInt(buf[1]),
        };
    }

    pub fn format(alert: Alert) [2]u8 {
        return [2]u8{
            @intFromEnum(if (alert == .close_notify) Alert.Level.warning else Alert.Level.fatal),
            @intFromEnum(alert),
        };
    }

    pub fn closeNotify() [2]u8 {
        return [2]u8{
            @intFromEnum(Alert.Level.warning),
            @intFromEnum(Alert.close_notify),
        };
    }
};

pub const SignatureScheme = enum(u16) {
    // RSASSA-PKCS1-v1_5 algorithms
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,

    // ECDSA algorithms
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,

    // RSASSA-PSS algorithms with public key OID rsaEncryption
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,

    // EdDSA algorithms
    ed25519 = 0x0807,
    ed448 = 0x0808,

    // RSASSA-PSS algorithms with public key OID RSASSA-PSS
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,

    // Legacy algorithms
    rsa_pkcs1_sha1 = 0x0201,
    ecdsa_sha1 = 0x0203,

    _,
};

pub const NamedGroup = enum(u16) {
    // Elliptic Curve Groups (ECDHE)
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
    x25519 = 0x001D,
    x448 = 0x001E,

    // Finite Field Groups (DHE)
    ffdhe2048 = 0x0100,
    ffdhe3072 = 0x0101,
    ffdhe4096 = 0x0102,
    ffdhe6144 = 0x0103,
    ffdhe8192 = 0x0104,

    // Hybrid post-quantum key agreements
    x25519_kyber512d00 = 0xFE30,
    x25519_kyber768d00 = 0x6399,
    x25519_ml_kem768 = 0x11EC,

    _,
};

pub const KeyUpdateRequest = enum(u8) {
    update_not_requested = 0,
    update_requested = 1,
    _,
};

pub const Side = enum {
    client,
    server,
};

const testing = @import("std").testing;

test "Alert.parse keeps the level" {
    const parsed = Alert.parse(.{
        @intFromEnum(Alert.Level.warning),
        @intFromEnum(Alert.close_notify),
    });
    try testing.expectEqual(Alert.Level.warning, parsed.level);
    try testing.expectEqual(Alert.close_notify, parsed.description);
}

test "Alert.isFromPeer covers exactly the alerts we can receive" {
    inline for (@typeInfo(Alert.Error).error_set.?) |e| {
        const err = @field(anyerror, e.name);
        try testing.expect(Alert.isFromPeer(err));
        // An alert the peer sent is its failure to report, not ours.
        try testing.expectEqual(@as(?Alert, null), Alert.forLocalError(err));
    }
    try testing.expect(!Alert.isFromPeer(error.TlsDecodeError));
}

test "Alert.forLocalError sends nothing for transport failures" {
    for ([_]anyerror{
        error.ReadFailed,
        error.WriteFailed,
        error.EndOfStream,
        error.TlsConnectionTruncated,
        error.TlsConnectionFailed,
        error.Canceled,
        error.OutOfMemory,
    }) |err| {
        try testing.expectEqual(@as(?Alert, null), Alert.forLocalError(err));
    }
}

test "Alert.forLocalError maps local failures to a matching alert" {
    const cases = [_]struct { err: anyerror, alert: Alert }{
        .{ .err = error.TlsBadVersion, .alert = .protocol_version },
        .{ .err = error.TlsProtocolVersion, .alert = .protocol_version },
        .{ .err = error.TlsDecryptFailure, .alert = .decrypt_error },
        .{ .err = error.TlsDecryptError, .alert = .decrypt_error },
        .{ .err = error.TlsBadSignatureScheme, .alert = .illegal_parameter },
        .{ .err = error.TlsUnknownSignatureScheme, .alert = .illegal_parameter },
        .{ .err = error.TlsServerHelloRetryRequest, .alert = .handshake_failure },
        .{ .err = error.TlsUnsupportedFragmentedHandshakeMessage, .alert = .internal_error },
        .{ .err = error.TlsBadRecordMac, .alert = .bad_record_mac },
        .{ .err = error.TlsNoApplicationProtocol, .alert = .no_application_protocol },
    };
    for (cases) |c| {
        try testing.expectEqual(@as(?Alert, c.alert), Alert.forLocalError(c.err));
    }
    // Anything we did not classify is still reported, as internal_error.
    try testing.expectEqual(@as(?Alert, .internal_error), Alert.forLocalError(error.Unexpected));
}

test "alertForLocalError builds a fatal record body, or none" {
    try testing.expectEqualSlices(u8, &.{
        @intFromEnum(Alert.Level.fatal),
        @intFromEnum(Alert.protocol_version),
    }, &(alertForLocalError(error.TlsBadVersion).?));
    try testing.expectEqual(@as(?[2]u8, null), alertForLocalError(error.TlsAlertHandshakeFailure));
}
