-- fero.tls: TLS and SSLv2 hellos built and read by hand, for scripts that
-- ask a server what it offers (cipher suites, compression, ALPN, NPN, the
-- protocol versions) without finishing a handshake.
-- Written for FeroProbe from scratch, from RFC 5246 (TLS 1.2, sections
-- 6.2, 7.4.1 to 7.4.3 and 7.4.5), RFC 8446 (TLS 1.3, sections 4.1 and
-- 4.2), RFC 6101 (SSLv3), RFC 4492 and 8422 (elliptic curves), RFC 7301
-- (ALPN), draft-agl-tls-nextprotoneg-04 (NPN), RFC 3749 (compression),
-- the IANA TLS parameter registries and the SSL 2.0 draft (Hickman,
-- 1995); GPL-3.0-or-later.
local fero = ...
local tls = fero.tls

-- The mark every hello carries, so the target's logs and IDS can tell
-- them apart (IDS rules 9100019 and 9100020): after the four time bytes
-- of a TLS ClientHello's random, and as the whole challenge of an SSLv2
-- CLIENT-HELLO.
tls.MARK = "FeroProbeTLSScan"

-- The protocol versions, oldest first, as nmap names them.
tls.PROTOCOLS = { "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3" }
tls.VERSIONS = {
  SSLv3 = 0x0300, ["TLSv1.0"] = 0x0301, ["TLSv1.1"] = 0x0302,
  ["TLSv1.2"] = 0x0303, ["TLSv1.3"] = 0x0304,
}
local VERSION_NAME = {}
for name, v in pairs(tls.VERSIONS) do VERSION_NAME[v] = name end

-- The name of a protocol version number (0x0303 is "TLSv1.2"), or nil.
function tls.version_name(v) return VERSION_NAME[v] end

-- The cipher suites of the IANA registry, by code: all but the
-- signalling values and the national and password suites (ECCPWD, SM4,
-- GOST R 34.12-2015), which no ClientHello here offers. TLS 1.3 suites are named as nmap names them, with "AKE_WITH"
-- (IANA: TLS_AES_128_GCM_SHA256), so each name reads KEX_WITH_CIPHER.
tls.CIPHERS = {
  { 0x0000, "TLS_NULL_WITH_NULL_NULL" },
  { 0x0001, "TLS_RSA_WITH_NULL_MD5" },
  { 0x0002, "TLS_RSA_WITH_NULL_SHA" },
  { 0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5" },
  { 0x0004, "TLS_RSA_WITH_RC4_128_MD5" },
  { 0x0005, "TLS_RSA_WITH_RC4_128_SHA" },
  { 0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5" },
  { 0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA" },
  { 0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA" },
  { 0x0009, "TLS_RSA_WITH_DES_CBC_SHA" },
  { 0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA" },
  { 0x000b, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA" },
  { 0x000c, "TLS_DH_DSS_WITH_DES_CBC_SHA" },
  { 0x000d, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA" },
  { 0x000e, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA" },
  { 0x000f, "TLS_DH_RSA_WITH_DES_CBC_SHA" },
  { 0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA" },
  { 0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA" },
  { 0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA" },
  { 0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA" },
  { 0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA" },
  { 0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA" },
  { 0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA" },
  { 0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5" },
  { 0x0018, "TLS_DH_anon_WITH_RC4_128_MD5" },
  { 0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA" },
  { 0x001a, "TLS_DH_anon_WITH_DES_CBC_SHA" },
  { 0x001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA" },
  { 0x001e, "TLS_KRB5_WITH_DES_CBC_SHA_or_SSL_FORTEZZA_KEA_WITH_RC4_128_SHA" },
  { 0x001f, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA" },
  { 0x0020, "TLS_KRB5_WITH_RC4_128_SHA" },
  { 0x0021, "TLS_KRB5_WITH_IDEA_CBC_SHA" },
  { 0x0022, "TLS_KRB5_WITH_DES_CBC_MD5" },
  { 0x0023, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5" },
  { 0x0024, "TLS_KRB5_WITH_RC4_128_MD5" },
  { 0x0025, "TLS_KRB5_WITH_IDEA_CBC_MD5" },
  { 0x0026, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA" },
  { 0x0027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA" },
  { 0x0028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA" },
  { 0x0029, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5" },
  { 0x002a, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5" },
  { 0x002b, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5" },
  { 0x002c, "TLS_PSK_WITH_NULL_SHA" },
  { 0x002d, "TLS_DHE_PSK_WITH_NULL_SHA" },
  { 0x002e, "TLS_RSA_PSK_WITH_NULL_SHA" },
  { 0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA" },
  { 0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA" },
  { 0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA" },
  { 0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA" },
  { 0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" },
  { 0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA" },
  { 0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA" },
  { 0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA" },
  { 0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA" },
  { 0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" },
  { 0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" },
  { 0x003a, "TLS_DH_anon_WITH_AES_256_CBC_SHA" },
  { 0x003b, "TLS_RSA_WITH_NULL_SHA256" },
  { 0x003c, "TLS_RSA_WITH_AES_128_CBC_SHA256" },
  { 0x003d, "TLS_RSA_WITH_AES_256_CBC_SHA256" },
  { 0x003e, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256" },
  { 0x003f, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256" },
  { 0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256" },
  { 0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA" },
  { 0x0042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA" },
  { 0x0043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA" },
  { 0x0044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA" },
  { 0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" },
  { 0x0046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA" },
  { 0x0060, "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5" },
  { 0x0061, "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5" },
  { 0x0062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA" },
  { 0x0063, "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA" },
  { 0x0064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA" },
  { 0x0065, "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA" },
  { 0x0066, "TLS_DHE_DSS_WITH_RC4_128_SHA" },
  { 0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256" },
  { 0x0068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256" },
  { 0x0069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256" },
  { 0x006a, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256" },
  { 0x006b, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256" },
  { 0x006c, "TLS_DH_anon_WITH_AES_128_CBC_SHA256" },
  { 0x006d, "TLS_DH_anon_WITH_AES_256_CBC_SHA256" },
  { 0x0072, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_RMD" },
  { 0x0073, "TLS_DHE_DSS_WITH_AES_128_CBC_RMD" },
  { 0x0074, "TLS_DHE_DSS_WITH_AES_256_CBC_RMD" },
  { 0x0077, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_RMD" },
  { 0x0078, "TLS_DHE_RSA_WITH_AES_128_CBC_RMD" },
  { 0x0079, "TLS_DHE_RSA_WITH_AES_256_CBC_RMD" },
  { 0x007c, "TLS_RSA_WITH_3DES_EDE_CBC_RMD" },
  { 0x007d, "TLS_RSA_WITH_AES_128_CBC_RMD" },
  { 0x007e, "TLS_RSA_WITH_AES_256_CBC_RMD" },
  { 0x0080, "TLS_GOSTR341094_WITH_28147_CNT_IMIT" },
  { 0x0081, "TLS_GOSTR341001_WITH_28147_CNT_IMIT" },
  { 0x0082, "TLS_GOSTR341094_WITH_NULL_GOSTR3411" },
  { 0x0083, "TLS_GOSTR341001_WITH_NULL_GOSTR3411" },
  { 0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA" },
  { 0x0085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA" },
  { 0x0086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA" },
  { 0x0087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA" },
  { 0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" },
  { 0x0089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA" },
  { 0x008a, "TLS_PSK_WITH_RC4_128_SHA" },
  { 0x008b, "TLS_PSK_WITH_3DES_EDE_CBC_SHA" },
  { 0x008c, "TLS_PSK_WITH_AES_128_CBC_SHA" },
  { 0x008d, "TLS_PSK_WITH_AES_256_CBC_SHA" },
  { 0x008e, "TLS_DHE_PSK_WITH_RC4_128_SHA" },
  { 0x008f, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA" },
  { 0x0090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA" },
  { 0x0091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA" },
  { 0x0092, "TLS_RSA_PSK_WITH_RC4_128_SHA" },
  { 0x0093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA" },
  { 0x0094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA" },
  { 0x0095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA" },
  { 0x0096, "TLS_RSA_WITH_SEED_CBC_SHA" },
  { 0x0097, "TLS_DH_DSS_WITH_SEED_CBC_SHA" },
  { 0x0098, "TLS_DH_RSA_WITH_SEED_CBC_SHA" },
  { 0x0099, "TLS_DHE_DSS_WITH_SEED_CBC_SHA" },
  { 0x009a, "TLS_DHE_RSA_WITH_SEED_CBC_SHA" },
  { 0x009b, "TLS_DH_anon_WITH_SEED_CBC_SHA" },
  { 0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256" },
  { 0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384" },
  { 0x009e, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" },
  { 0x009f, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" },
  { 0x00a0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256" },
  { 0x00a1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384" },
  { 0x00a2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256" },
  { 0x00a3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384" },
  { 0x00a4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256" },
  { 0x00a5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384" },
  { 0x00a6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256" },
  { 0x00a7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384" },
  { 0x00a8, "TLS_PSK_WITH_AES_128_GCM_SHA256" },
  { 0x00a9, "TLS_PSK_WITH_AES_256_GCM_SHA384" },
  { 0x00aa, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256" },
  { 0x00ab, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384" },
  { 0x00ac, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256" },
  { 0x00ad, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384" },
  { 0x00ae, "TLS_PSK_WITH_AES_128_CBC_SHA256" },
  { 0x00af, "TLS_PSK_WITH_AES_256_CBC_SHA384" },
  { 0x00b0, "TLS_PSK_WITH_NULL_SHA256" },
  { 0x00b1, "TLS_PSK_WITH_NULL_SHA384" },
  { 0x00b2, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256" },
  { 0x00b3, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384" },
  { 0x00b4, "TLS_DHE_PSK_WITH_NULL_SHA256" },
  { 0x00b5, "TLS_DHE_PSK_WITH_NULL_SHA384" },
  { 0x00b6, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256" },
  { 0x00b7, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384" },
  { 0x00b8, "TLS_RSA_PSK_WITH_NULL_SHA256" },
  { 0x00b9, "TLS_RSA_PSK_WITH_NULL_SHA384" },
  { 0x00ba, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
  { 0x00bb, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
  { 0x00bc, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
  { 0x00bd, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
  { 0x00be, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
  { 0x00bf, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256" },
  { 0x00c0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
  { 0x00c1, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
  { 0x00c2, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
  { 0x00c3, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
  { 0x00c4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
  { 0x00c5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256" },
  { 0x1301, "TLS_AKE_WITH_AES_128_GCM_SHA256" },
  { 0x1302, "TLS_AKE_WITH_AES_256_GCM_SHA384" },
  { 0x1303, "TLS_AKE_WITH_CHACHA20_POLY1305_SHA256" },
  { 0x1304, "TLS_AKE_WITH_AES_128_CCM_SHA256" },
  { 0x1305, "TLS_AKE_WITH_AES_128_CCM_8_SHA256" },
  { 0xc001, "TLS_ECDH_ECDSA_WITH_NULL_SHA" },
  { 0xc002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA" },
  { 0xc003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA" },
  { 0xc004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA" },
  { 0xc005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA" },
  { 0xc006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA" },
  { 0xc007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA" },
  { 0xc008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA" },
  { 0xc009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" },
  { 0xc00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" },
  { 0xc00b, "TLS_ECDH_RSA_WITH_NULL_SHA" },
  { 0xc00c, "TLS_ECDH_RSA_WITH_RC4_128_SHA" },
  { 0xc00d, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA" },
  { 0xc00e, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA" },
  { 0xc00f, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA" },
  { 0xc010, "TLS_ECDHE_RSA_WITH_NULL_SHA" },
  { 0xc011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA" },
  { 0xc012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" },
  { 0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" },
  { 0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" },
  { 0xc015, "TLS_ECDH_anon_WITH_NULL_SHA" },
  { 0xc016, "TLS_ECDH_anon_WITH_RC4_128_SHA" },
  { 0xc017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA" },
  { 0xc018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA" },
  { 0xc019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA" },
  { 0xc01a, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA" },
  { 0xc01b, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA" },
  { 0xc01c, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA" },
  { 0xc01d, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA" },
  { 0xc01e, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA" },
  { 0xc01f, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA" },
  { 0xc020, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA" },
  { 0xc021, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA" },
  { 0xc022, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA" },
  { 0xc023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" },
  { 0xc024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384" },
  { 0xc025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256" },
  { 0xc026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384" },
  { 0xc027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" },
  { 0xc028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" },
  { 0xc029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256" },
  { 0xc02a, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384" },
  { 0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" },
  { 0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" },
  { 0xc02d, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256" },
  { 0xc02e, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384" },
  { 0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" },
  { 0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" },
  { 0xc031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256" },
  { 0xc032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384" },
  { 0xc033, "TLS_ECDHE_PSK_WITH_RC4_128_SHA" },
  { 0xc034, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA" },
  { 0xc035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA" },
  { 0xc036, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA" },
  { 0xc037, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256" },
  { 0xc038, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384" },
  { 0xc039, "TLS_ECDHE_PSK_WITH_NULL_SHA" },
  { 0xc03a, "TLS_ECDHE_PSK_WITH_NULL_SHA256" },
  { 0xc03b, "TLS_ECDHE_PSK_WITH_NULL_SHA384" },
  { 0xc03c, "TLS_RSA_WITH_ARIA_128_CBC_SHA256" },
  { 0xc03d, "TLS_RSA_WITH_ARIA_256_CBC_SHA384" },
  { 0xc03e, "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256" },
  { 0xc03f, "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384" },
  { 0xc040, "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256" },
  { 0xc041, "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384" },
  { 0xc042, "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256" },
  { 0xc043, "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384" },
  { 0xc044, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256" },
  { 0xc045, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384" },
  { 0xc046, "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256" },
  { 0xc047, "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384" },
  { 0xc048, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256" },
  { 0xc049, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384" },
  { 0xc04a, "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256" },
  { 0xc04b, "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384" },
  { 0xc04c, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256" },
  { 0xc04d, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384" },
  { 0xc04e, "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256" },
  { 0xc04f, "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384" },
  { 0xc050, "TLS_RSA_WITH_ARIA_128_GCM_SHA256" },
  { 0xc051, "TLS_RSA_WITH_ARIA_256_GCM_SHA384" },
  { 0xc052, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256" },
  { 0xc053, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384" },
  { 0xc054, "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256" },
  { 0xc055, "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384" },
  { 0xc056, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256" },
  { 0xc057, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384" },
  { 0xc058, "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256" },
  { 0xc059, "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384" },
  { 0xc05a, "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256" },
  { 0xc05b, "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384" },
  { 0xc05c, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256" },
  { 0xc05d, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384" },
  { 0xc05e, "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256" },
  { 0xc05f, "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384" },
  { 0xc060, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256" },
  { 0xc061, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384" },
  { 0xc062, "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256" },
  { 0xc063, "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384" },
  { 0xc064, "TLS_PSK_WITH_ARIA_128_CBC_SHA256" },
  { 0xc065, "TLS_PSK_WITH_ARIA_256_CBC_SHA384" },
  { 0xc066, "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256" },
  { 0xc067, "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384" },
  { 0xc068, "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256" },
  { 0xc069, "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384" },
  { 0xc06a, "TLS_PSK_WITH_ARIA_128_GCM_SHA256" },
  { 0xc06b, "TLS_PSK_WITH_ARIA_256_GCM_SHA384" },
  { 0xc06c, "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256" },
  { 0xc06d, "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384" },
  { 0xc06e, "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256" },
  { 0xc06f, "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384" },
  { 0xc070, "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256" },
  { 0xc071, "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384" },
  { 0xc072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256" },
  { 0xc073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384" },
  { 0xc074, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256" },
  { 0xc075, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384" },
  { 0xc076, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
  { 0xc077, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384" },
  { 0xc078, "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
  { 0xc079, "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384" },
  { 0xc07a, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
  { 0xc07b, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
  { 0xc07c, "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
  { 0xc07d, "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
  { 0xc07e, "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
  { 0xc07f, "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
  { 0xc080, "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256" },
  { 0xc081, "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384" },
  { 0xc082, "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256" },
  { 0xc083, "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384" },
  { 0xc084, "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256" },
  { 0xc085, "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384" },
  { 0xc086, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256" },
  { 0xc087, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384" },
  { 0xc088, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256" },
  { 0xc089, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384" },
  { 0xc08a, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
  { 0xc08b, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
  { 0xc08c, "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
  { 0xc08d, "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
  { 0xc08e, "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256" },
  { 0xc08f, "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384" },
  { 0xc090, "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256" },
  { 0xc091, "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384" },
  { 0xc092, "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256" },
  { 0xc093, "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384" },
  { 0xc094, "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
  { 0xc095, "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
  { 0xc096, "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
  { 0xc097, "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
  { 0xc098, "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
  { 0xc099, "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
  { 0xc09a, "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
  { 0xc09b, "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
  { 0xc09c, "TLS_RSA_WITH_AES_128_CCM" },
  { 0xc09d, "TLS_RSA_WITH_AES_256_CCM" },
  { 0xc09e, "TLS_DHE_RSA_WITH_AES_128_CCM" },
  { 0xc09f, "TLS_DHE_RSA_WITH_AES_256_CCM" },
  { 0xc0a0, "TLS_RSA_WITH_AES_128_CCM_8" },
  { 0xc0a1, "TLS_RSA_WITH_AES_256_CCM_8" },
  { 0xc0a2, "TLS_DHE_RSA_WITH_AES_128_CCM_8" },
  { 0xc0a3, "TLS_DHE_RSA_WITH_AES_256_CCM_8" },
  { 0xc0a4, "TLS_PSK_WITH_AES_128_CCM" },
  { 0xc0a5, "TLS_PSK_WITH_AES_256_CCM" },
  { 0xc0a6, "TLS_DHE_PSK_WITH_AES_128_CCM" },
  { 0xc0a7, "TLS_DHE_PSK_WITH_AES_256_CCM" },
  { 0xc0a8, "TLS_PSK_WITH_AES_128_CCM_8" },
  { 0xc0a9, "TLS_PSK_WITH_AES_256_CCM_8" },
  { 0xc0aa, "TLS_PSK_DHE_WITH_AES_128_CCM_8" },
  { 0xc0ab, "TLS_PSK_DHE_WITH_AES_256_CCM_8" },
  { 0xc0ac, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM" },
  { 0xc0ad, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM" },
  { 0xc0ae, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8" },
  { 0xc0af, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8" },
  { 0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
  { 0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" },
  { 0xccaa, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
  { 0xccab, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256" },
  { 0xccac, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256" },
  { 0xccad, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256" },
  { 0xccae, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256" },
  { 0xd001, "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256" },
  { 0xd002, "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384" },
  { 0xd003, "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256" },
  { 0xd005, "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256" },
}

local CODE, NAME = {}, {}
for _, c in ipairs(tls.CIPHERS) do
  CODE[c[2]] = c[1]
  NAME[c[1]] = c[2]
end

-- The code of a cipher suite name, or nil.
function tls.cipher_code(name) return CODE[name] end

-- The name of a cipher suite code, or "unknown 0x...." for one not in
-- the registry.
function tls.cipher_name(code)
  return NAME[code] or string.format("unknown 0x%04x", code)
end

-- What a cipher suite's name says about it: `kex` (the part before
-- "_WITH_": "RSA", "ECDHE_RSA", "DH_anon", "AKE"...), `cipher` ("AES",
-- "3DES", "RC4", "CHACHA20", "NULL"...), `size` (key bits, 0 for NULL),
-- `mode` ("CBC", "GCM", "CCM", "stream", "AEAD"), `block` (block size in
-- bits for a block cipher), `hash` ("SHA", "SHA256", "MD5"...; nil for
-- CCM), `export`, `anon`, `forward_secrecy`, `tls13` (a TLS 1.3 suite)
-- and `tls12` (TLS 1.2 or later only). nil for a name it cannot read.
function tls.cipher_info(name)
  local kex, rest = name:match("^TLS_(.-)_WITH_(.+)$")
  if not kex then return nil end
  -- RFC 6655 spells two DHE-PSK suites PSK_DHE; they are DHE_PSK.
  if kex == "PSK_DHE" then kex = "DHE_PSK" end
  local info = { kex = kex, tls13 = kex == "AKE" }
  info.export = kex:find("EXPORT", 1, true) ~= nil
  info.anon = kex:find("anon", 1, true) ~= nil
  info.forward_secrecy = kex == "AKE" or kex:match("^DHE") ~= nil
    or kex:match("^ECDHE") ~= nil
  -- The hash is the last word, unless the suite is CCM.
  local body, hash = rest:match("^(.-)_(SHA%d*)$")
  if not body then body, hash = rest:match("^(.-)_(MD5)$") end
  if not body then body, hash = rest:match("^(.-)_(IMIT)$") end
  if not body then body, hash = rest:match("^(.-)_(GOSTR3411)$") end
  if not body then body = rest end
  info.hash = hash
  local function set(cipher, size, mode, block)
    info.cipher, info.size, info.mode, info.block = cipher, size, mode, block
  end
  if body == "NULL" then
    set("NULL", 0, "none")
  elseif body:match("^RC4_") then
    set("RC4", tonumber(body:match("^RC4_(%d+)")), "stream")
  elseif body:match("^RC2_CBC_") then
    set("RC2", tonumber(body:match("(%d+)$")), "CBC", 64)
  elseif body == "IDEA_CBC" then
    set("IDEA", 128, "CBC", 64)
  elseif body == "SEED_CBC" then
    set("SEED", 128, "CBC", 128)
  elseif body == "3DES_EDE_CBC" then
    set("3DES", 112, "CBC", 64)
  elseif body == "DES40_CBC" or body == "DES_CBC_40" then
    set("DES", 40, "CBC", 64)
  elseif body == "DES_CBC" then
    set("DES", 56, "CBC", 64)
  elseif body:match("^CHACHA20_POLY1305") then
    set("CHACHA20", 256, "AEAD")
  elseif body:match("^28147_CNT") then
    set("GOST28147", 256, "CNT", 64)
  else
    local alg, size, mode = body:match("^(%u+)_(%d+)_(%u+)")
    if not alg then return nil end
    set(alg, tonumber(size), mode, 128)
  end
  -- AEAD suites need TLS 1.2; so do the SHA-256/384 MAC suites, except
  -- the PSK ones of RFC 5487 and 5489, which TLS 1.0 and 1.1 may use.
  info.tls12 = info.tls13 or info.mode == "GCM" or info.mode == "CCM"
    or info.mode == "AEAD"
    or ((hash == "SHA256" or hash == "SHA384") and not kex:find("PSK", 1, true))
  return info
end

-- The named groups (elliptic curves and finite-field groups) by code,
-- with nmap's names for the curves.
tls.GROUPS = {
  [1] = "sect163k1", [2] = "sect163r1", [3] = "sect163r2", [4] = "sect193r1",
  [5] = "sect193r2", [6] = "sect233k1", [7] = "sect233r1", [8] = "sect239k1",
  [9] = "sect283k1", [10] = "sect283r1", [11] = "sect409k1", [12] = "sect409r1",
  [13] = "sect571k1", [14] = "sect571r1", [15] = "secp160k1", [16] = "secp160r1",
  [17] = "secp160r2", [18] = "secp192k1", [19] = "secp192r1", [20] = "secp224k1",
  [21] = "secp224r1", [22] = "secp256k1", [23] = "secp256r1", [24] = "secp384r1",
  [25] = "secp521r1", [26] = "brainpoolP256r1", [27] = "brainpoolP384r1",
  [28] = "brainpoolP512r1", [29] = "ecdh_x25519", [30] = "ecdh_x448",
  [31] = "brainpoolP256r1tls13", [32] = "brainpoolP384r1tls13",
  [33] = "brainpoolP512r1tls13",
  [0x0100] = "ffdhe2048", [0x0101] = "ffdhe3072", [0x0102] = "ffdhe4096",
  [0x0103] = "ffdhe6144", [0x0104] = "ffdhe8192",
  [0x0200] = "MLKEM512", [0x0201] = "MLKEM768", [0x0202] = "MLKEM1024",
  [0x11eb] = "SecP256r1MLKEM768", [0x11ec] = "X25519MLKEM768",
  [0x11ed] = "SecP384r1MLKEM1024",
}

-- The name of a group code, or "unknown group 0x....".
function tls.group_name(code)
  return tls.GROUPS[code] or string.format("unknown group 0x%04x", code)
end

-- The groups a ClientHello offers, in this order: the common curves
-- first, then every other one. TLS 1.3 hellos put x25519 first, the one
-- they send a key share for; older ones secp256r1, as nmap's do, so a
-- server that follows the client's order reports the same curve.
local OFFER_GROUPS_13 = {
  29, 23, 24, 25, 30, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104,
  26, 27, 28, 22, 21, 20, 19, 18, 17, 16, 15,
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
}
local OFFER_GROUPS = { 23, 24, 25, 29 }
for i = 5, #OFFER_GROUPS_13 do OFFER_GROUPS[i] = OFFER_GROUPS_13[i] end

-- The signature algorithms a TLS 1.2 or 1.3 ClientHello offers (RFC 8446
-- 4.2.3), the old SHA-1, MD5 and SHA-224 ones included so that old
-- servers answer too.
local SIGNATURES = {
  0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807, 0x0808,
  0x0809, 0x080a, 0x080b, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301,
  0x0302, 0x0402, 0x0502, 0x0602, 0x0203, 0x0201, 0x0202, 0x0101,
}

-- The key strength of a group or curve as RSA bits (NIST SP 800-57's
-- table), for grading a key exchange; nil for an unknown group.
function tls.group_strength(name)
  local ff = name:match("^ffdhe(%d+)$")
  if ff then return tonumber(ff) end
  if name:find("MLKEM1024", 1, true) then return 15360 end
  if name:find("MLKEM768", 1, true) then return 7680 end
  if name:find("MLKEM512", 1, true) then return 3072 end
  local bits
  if name == "ecdh_x25519" then bits = 256
  elseif name == "ecdh_x448" then bits = 448
  else bits = tonumber(name:match("^%a+(%d+)")) end
  return bits and tls.ec_strength(bits)
end

-- An elliptic-curve key size as RSA bits (NIST SP 800-57).
function tls.ec_strength(bits)
  if bits >= 512 then return 15360
  elseif bits >= 384 then return 7680
  elseif bits >= 256 then return 3072
  elseif bits >= 224 then return 2048
  elseif bits >= 160 then return 1024
  else return 512 end
end

local function u16_list(list)
  local t = {}
  for i, v in ipairs(list) do t[i] = string.pack(">I2", v) end
  return table.concat(t)
end

local function ext(kind, data)
  return string.pack(">I2s2", kind, data)
end

-- A TLS record of content type `kind` (22 handshake, 21 alert...).
function tls.record(kind, version, body)
  return string.pack(">BI2s2", kind, version, body)
end

-- Whether `name` may go in the server_name extension: a host name, not
-- an address (RFC 6066 3).
local function sni_ok(name)
  return type(name) == "string" and name ~= "" and #name < 256
    and not name:match("^[%d.]+$") and not name:find(":", 1, true)
end

-- The ciphers a ClientHello gets: codes, or names from tls.CIPHERS.
local function cipher_codes(list)
  local out = {}
  for _, c in ipairs(list) do
    if type(c) == "string" then c = CODE[c] end
    if c then out[#out + 1] = c end
  end
  return out
end

-- A ClientHello in one record. `opts`:
--   version       the protocol version asked for (default 0x0303, TLS 1.2;
--                 0x0304 sends 0x0303 and the supported_versions
--                 extension, with a random x25519 key share)
--   ciphers       cipher suites, as codes or names (default the TLS 1.3
--                 ones for TLS 1.3, else all the others)
--   compressors   compression methods (default { 0 }, NULL)
--   server_name   the name for SNI (left out for an address)
--   alpn          a list of protocol names for ALPN
--   npn           true to ask for NPN
--   groups        the named groups offered (default all known)
--   extensions    more extensions, as { type, data } pairs
-- SSLv3 hellos carry no extensions.
function tls.client_hello(opts)
  opts = opts or {}
  local version = opts.version or 0x0303
  local tls13 = version >= 0x0304
  local ciphers = cipher_codes(opts.ciphers or {})
  if not opts.ciphers then
    for _, c in ipairs(tls.CIPHERS) do
      local is13 = c[1] >= 0x1301 and c[1] <= 0x13ff
      if tls13 == is13 then ciphers[#ciphers + 1] = c[1] end
    end
  end
  local exts = {}
  local groups = opts.groups or (tls13 and OFFER_GROUPS_13 or OFFER_GROUPS)
  if version > 0x0300 then
    if sni_ok(opts.server_name) then
      exts[#exts + 1] = ext(0x0000, string.pack(">s2", "\0" .. string.pack(">s2", opts.server_name)))
    end
    exts[#exts + 1] = ext(0x000a, string.pack(">s2", u16_list(groups)))
    exts[#exts + 1] = ext(0x000b, "\1\0")
    if version >= 0x0303 then
      exts[#exts + 1] = ext(0x000d, string.pack(">s2", u16_list(SIGNATURES)))
    end
    if opts.alpn then
      local names = {}
      for i, n in ipairs(opts.alpn) do names[i] = string.pack(">s1", n) end
      exts[#exts + 1] = ext(0x0010, string.pack(">s2", table.concat(names)))
    end
    if opts.npn then exts[#exts + 1] = ext(0x3374, "") end
    if tls13 then
      exts[#exts + 1] = ext(0x002b, string.pack(">s1", u16_list({ version })))
      exts[#exts + 1] = ext(0x002d, "\1\1")
      -- A key share only for a group offered: x25519 when it is, else
      -- none, and the server asks again for the group it wants.
      local share = ""
      for _, g in ipairs(groups) do
        if g == 29 then share = string.pack(">I2s2", 29, fero.crypto.random_bytes(32)) end
      end
      exts[#exts + 1] = ext(0x0033, string.pack(">s2", share))
    else
      exts[#exts + 1] = ext(0xff01, "\0")
    end
    for _, e in ipairs(opts.extensions or {}) do
      exts[#exts + 1] = ext(e[1], e[2])
    end
  end
  local random = string.pack(">I4", os.time()) .. tls.MARK .. fero.crypto.random_bytes(12)
  local session = tls13 and fero.crypto.random_bytes(32) or ""
  local body = string.pack(">I2", tls13 and 0x0303 or version) .. random
    .. string.pack(">s1", session)
    .. string.pack(">s2", u16_list(ciphers))
    .. string.pack(">s1", string.char(table.unpack(opts.compressors or { 0 })))
  if #exts > 0 then body = body .. string.pack(">s2", table.concat(exts)) end
  local hs = "\1" .. string.pack(">I3", #body) .. body
  -- The record carries TLS 1.0 for TLS 1.0 and later (RFC 8446 5.1),
  -- SSL 3.0 for an SSLv3 hello.
  return tls.record(22, version == 0x0300 and 0x0300 or 0x0301, hs)
end

-- The random of a TLS 1.3 HelloRetryRequest (RFC 8446 4.1.3).
local HRR_RANDOM = string.char(
  0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02,
  0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
  0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c)

-- A ServerHello's body read: `version` (the one chosen, from
-- supported_versions for TLS 1.3), `random`, `session_id`, `cipher`
-- (code), `compressor`, `extensions` (data by type), `hrr` (a TLS 1.3
-- HelloRetryRequest), `group` (the TLS 1.3 key share's group code), `alpn`
-- (the protocol chosen) and `npn` (the protocols listed); or nil.
function tls.parse_server_hello(b)
  local ok, version, random, session, cipher, comp, pos = pcall(string.unpack, ">I2c32s1I2B", b)
  if not ok then return nil end
  local sh = {
    version = version, random = random, session_id = session,
    cipher = cipher, compressor = comp, extensions = {},
    hrr = random == HRR_RANDOM,
  }
  if pos <= #b then
    local ok2, all = pcall(string.unpack, ">s2", b, pos)
    if not ok2 then return nil end
    local p = 1
    while p + 3 <= #all do
      local ok3, kind, data, nextp = pcall(string.unpack, ">I2s2", all, p)
      if not ok3 then return nil end
      sh.extensions[kind] = data
      p = nextp
    end
  end
  local e = sh.extensions
  if e[0x002b] and #e[0x002b] == 2 then sh.version = string.unpack(">I2", e[0x002b]) end
  if e[0x0033] and #e[0x0033] >= 2 then sh.group = string.unpack(">I2", e[0x0033]) end
  if e[0x0010] then
    -- Exactly one non-empty name, filling the extension (RFC 7301 3.1).
    local okp, list, after = pcall(string.unpack, ">s2", e[0x0010])
    if okp and after == #e[0x0010] + 1 and #list > 0 then
      local okn, name, nafter = pcall(string.unpack, ">s1", list)
      if okn and #name > 0 and nafter == #list + 1 then sh.alpn = name end
    end
  end
  if e[0x3374] then
    -- Only a list read to its end; a cut one is not reported.
    local list, p, whole = {}, 1, true
    while p <= #e[0x3374] do
      local okn, name, nextp = pcall(string.unpack, ">s1", e[0x3374], p)
      if not okn then
        whole = false
        break
      end
      list[#list + 1] = name
      p = nextp
    end
    if whole then sh.npn = list end
  end
  return sh
end

-- The alert descriptions by code (RFC 8446 6, RFC 5246 7.2).
tls.ALERTS = {
  [0] = "close_notify", [10] = "unexpected_message", [20] = "bad_record_mac",
  [21] = "decryption_failed", [22] = "record_overflow",
  [30] = "decompression_failure", [40] = "handshake_failure",
  [41] = "no_certificate", [42] = "bad_certificate",
  [43] = "unsupported_certificate", [44] = "certificate_revoked",
  [45] = "certificate_expired", [46] = "certificate_unknown",
  [47] = "illegal_parameter", [48] = "unknown_ca", [49] = "access_denied",
  [50] = "decode_error", [51] = "decrypt_error", [60] = "export_restriction",
  [70] = "protocol_version", [71] = "insufficient_security",
  [80] = "internal_error", [86] = "inappropriate_fallback",
  [90] = "user_canceled", [100] = "no_renegotiation",
  [109] = "missing_extension", [110] = "unsupported_extension",
  [112] = "unrecognized_name", [116] = "certificate_required",
  [120] = "no_application_protocol",
}

-- The certificates of a Certificate message (TLS 1.2 and older), DER
-- each, the server's own first.
local function parse_certificates(b)
  local ok, all = pcall(string.unpack, ">s3", b)
  if not ok then return {} end
  local out, p = {}, 1
  while p <= #all and #out < 10 do
    local okc, der, nextp = pcall(string.unpack, ">s3", all, p)
    if not okc then break end
    out[#out + 1] = der
    p = nextp
  end
  return out
end

-- How many bytes of a server's answer are read at most.
local MAX_ANSWER = 256 * 1024

-- Read a server's answer to a ClientHello from `sock`: its records until
-- ServerHelloDone, an alert, or (with `opts.hello_only`, and always for a
-- TLS 1.3 ServerHello) the ServerHello. All of it within `opts.timeout`
-- milliseconds (default 5000, on fero.clock_ms),
-- however slowly the server sends. Returns a table with what came:
-- `server_hello` (tls.parse_server_hello), `certificates` (DER, server's
-- first), `server_key_exchange` (the message body), `done`, `alert`
-- (`level`, `code`, `name`), `record_version`; or nil and a message when
-- nothing TLS-like came.
function tls.read_answer(sock, opts)
  opts = opts or {}
  local timeout = tonumber(opts.timeout) or 5000
  local deadline = fero.clock_ms() + timeout
  local buf, total = "", 0
  local function need(n)
    while #buf < n do
      local left = deadline - fero.clock_ms()
      if left <= 0 then return false, "TIMEOUT" end
      sock:set_timeout(left)
      local ok, data = sock:receive()
      if not ok then return false, data end
      total = total + #data
      if total > MAX_ANSWER then return false, "answer too long" end
      buf = buf .. data
    end
    return true
  end
  local answer = {}
  local hs = ""
  local function got_something()
    if answer.server_hello or answer.alert then return answer end
    return nil, answer.error or "no answer"
  end
  for _ = 1, 400 do
    local ok, err = need(5)
    if not ok then
      answer.error = err
      return got_something()
    end
    local kind, version, len = string.unpack(">BI2I2", buf)
    if kind < 20 or kind > 24 or version >> 8 ~= 3 or len > 18432 then
      answer.error = "not TLS"
      return got_something()
    end
    answer.record_version = answer.record_version or version
    ok, err = need(5 + len)
    if not ok then
      answer.error = err
      return got_something()
    end
    local body = buf:sub(6, 5 + len)
    buf = buf:sub(6 + len)
    if kind == 21 then
      if #body >= 2 then
        local level, code = string.unpack("BB", body)
        answer.alert = { level = level, code = code, name = tls.ALERTS[code] or tostring(code) }
      end
      return got_something()
    elseif kind == 22 then
      hs = hs .. body
      -- Each whole handshake message in turn.
      while #hs >= 4 do
        local typ, hlen = string.unpack(">BI3", hs)
        if #hs < 4 + hlen then break end
        local msg = hs:sub(5, 4 + hlen)
        hs = hs:sub(5 + hlen)
        if typ == 2 then
          answer.server_hello = tls.parse_server_hello(msg)
          if not answer.server_hello then
            answer.error = "bad ServerHello"
            return nil, answer.error
          end
          if opts.hello_only or answer.server_hello.version >= 0x0304 then
            return answer
          end
        elseif typ == 11 then
          answer.certificates = parse_certificates(msg)
        elseif typ == 12 then
          answer.server_key_exchange = msg
        elseif typ == 14 then
          answer.done = true
          return answer
        end
      end
    elseif answer.server_hello then
      -- ChangeCipherSpec or encrypted data: nothing more to read in clear.
      return answer
    end
  end
  return got_something()
end

-- A connected socket on `port`, ready for a hello: plain TCP, or after
-- the protocol's request to switch to TLS (fero.starttls) when
-- `opts.starttls` names a protocol. nil and a message on failure.
function tls.connect(host, port, opts)
  opts = opts or {}
  local timeout = tonumber(opts.timeout) or 5000
  if opts.starttls then
    return fero.starttls.connect(host, port, {
      protocol = opts.starttls, timeout = timeout, plain = true,
    })
  end
  local sock = fero.socket.new()
  sock:set_timeout(timeout)
  local ok, err = sock:connect(host, port, "tcp")
  if not ok then return nil, err end
  return sock
end

-- Connect, send the ClientHello `opts` describes (see tls.client_hello;
-- `server_name` defaults to the host's name) and read the answer (see
-- tls.read_answer, which takes `opts.timeout` and `opts.hello_only`).
-- `opts.starttls` names a protocol to switch with first. Returns the
-- answer, or nil and a message.
function tls.hello(host, port, opts)
  opts = opts or {}
  local hello_opts = {}
  for k, v in pairs(opts) do hello_opts[k] = v end
  if hello_opts.server_name == nil then
    hello_opts.server_name = host.targetname or host.name
  end
  local sock, err = tls.connect(host, port, opts)
  if not sock then return nil, err end
  local ok, serr = sock:send(tls.client_hello(hello_opts))
  if not ok then
    sock:close()
    return nil, serr
  end
  local answer, aerr = tls.read_answer(sock, opts)
  sock:close()
  return answer, aerr
end

-- What a ServerKeyExchange says about the key exchange of the suite
-- `info` (tls.cipher_info): { type = "dh", bits = N } for finite-field
-- Diffie-Hellman, { type = "ec", group = name, bits = N } for an
-- elliptic curve, { type = "rsa", bits = N } for an export RSA key; nil
-- when it cannot be read.
function tls.parse_server_key_exchange(msg, info)
  if not msg or not info then return nil end
  local p = 1
  local kex = info.kex
  local ok
  if kex:find("PSK", 1, true) then
    -- The PSK identity hint comes first (RFC 4279 2, RFC 5489 2).
    local _
    ok, _, p = pcall(string.unpack, ">s2", msg)
    if not ok then return nil end
  end
  local function bits_of(n)
    n = n:gsub("^%z+", "")
    if #n == 0 then return 0 end
    local top, b = n:byte(1), 0
    while top > 0 do b = b + 1; top = top >> 1 end
    return (#n - 1) * 8 + b
  end
  if kex:match("^ECDH") then
    local okc, curve_type, named = pcall(string.unpack, ">BI2", msg, p)
    if not okc then return nil end
    if curve_type == 3 then
      local name = tls.group_name(named)
      return { type = "ec", group = name, code = named }
    end
    return { type = "ec", group = "explicit" }
  elseif kex:match("^DH") then
    local okd, prime = pcall(string.unpack, ">s2", msg, p)
    if not okd then return nil end
    return { type = "dh", bits = bits_of(prime) }
  elseif kex:match("^RSA") then
    local okr, modulus = pcall(string.unpack, ">s2", msg, p)
    if not okr then return nil end
    return { type = "rsa", bits = bits_of(modulus) }
  end
  return nil
end

-- ---- SSLv2 ----

-- The SSLv2 cipher kinds (SSL 2.0 draft, appendix C), as nmap names
-- them.
tls.SSLV2_CIPHERS = {
  { 0x010080, "SSL2_RC4_128_WITH_MD5" },
  { 0x020080, "SSL2_RC4_128_EXPORT40_WITH_MD5" },
  { 0x030080, "SSL2_RC2_128_CBC_WITH_MD5" },
  { 0x040080, "SSL2_RC2_128_CBC_EXPORT40_WITH_MD5" },
  { 0x050080, "SSL2_IDEA_128_CBC_WITH_MD5" },
  { 0x060040, "SSL2_DES_64_CBC_WITH_MD5" },
  { 0x0700c0, "SSL2_DES_192_EDE3_CBC_WITH_MD5" },
  { 0x080080, "SSL2_RC4_64_WITH_MD5" },
}
local SSLV2_NAME = {}
for _, c in ipairs(tls.SSLV2_CIPHERS) do SSLV2_NAME[c[1]] = c[2] end

-- An SSLv2 CLIENT-HELLO offering every SSLv2 cipher kind, no session,
-- with tls.MARK as its 16-byte challenge.
function tls.sslv2_client_hello()
  local specs = {}
  for i, c in ipairs(tls.SSLV2_CIPHERS) do specs[i] = string.pack(">I3", c[1]) end
  specs = table.concat(specs)
  local body = string.pack(">BI2I2I2I2", 1, 0x0002, #specs, 0, #tls.MARK)
    .. specs .. tls.MARK
  return string.pack(">I2", 0x8000 | #body) .. body
end

-- Read an SSLv2 SERVER-HELLO from `sock` within `timeout` ms. Returns
-- { version, certificate (DER or nil), ciphers (names, unknown kinds as
-- "unknown 0x......") }; or nil and a message.
function tls.sslv2_read_server_hello(sock, timeout)
  timeout = tonumber(timeout) or 5000
  local deadline = fero.clock_ms() + timeout
  local buf = ""
  local function need(n)
    while #buf < n do
      local left = deadline - fero.clock_ms()
      if left <= 0 then return false, "TIMEOUT" end
      sock:set_timeout(left)
      local ok, data = sock:receive()
      if not ok then return false, data end
      buf = buf .. data
      if #buf > 40000 then return false, "answer too long" end
    end
    return true
  end
  local ok, err = need(2)
  if not ok then return nil, err end
  local b1, b2 = buf:byte(1, 2)
  local len, head
  if b1 & 0x80 ~= 0 then
    len, head = ((b1 & 0x7f) << 8) | b2, 2
  else
    -- A three-byte header (with padding) only after the first byte's top
    -- two bits are 0 and 0; a TLS record (0x15 or 0x16) is not SSLv2.
    if b1 == 0x15 or b1 == 0x16 then return nil, "not SSLv2" end
    len, head = ((b1 & 0x3f) << 8) | b2, 3
  end
  ok, err = need(head + len)
  if not ok then return nil, err end
  -- The third header byte counts the padding at the record's end, which
  -- is not part of the message.
  local pad = head == 3 and buf:byte(3) or 0
  if pad > len then return nil, "bad SERVER-HELLO" end
  local msg = buf:sub(head + 1, head + len - pad)
  local okp, typ, _, _, version, cert_len, specs_len, id_len, pos =
    pcall(string.unpack, ">BBBI2I2I2I2", msg)
  if not okp or typ ~= 4 then return nil, "not a SERVER-HELLO" end
  -- The message must hold its certificate, cipher specs and connection
  -- ID.
  if specs_len % 3 ~= 0 or id_len == 0
    or pos + cert_len + specs_len + id_len - 1 > #msg then
    return nil, "bad SERVER-HELLO"
  end
  local cert = cert_len > 0 and msg:sub(pos, pos + cert_len - 1) or nil
  local specs = msg:sub(pos + cert_len, pos + cert_len + specs_len - 1)
  local ciphers = {}
  for i = 1, #specs, 3 do
    local kind = string.unpack(">I3", specs, i)
    ciphers[#ciphers + 1] = SSLV2_NAME[kind] or string.format("unknown 0x%06x", kind)
  end
  return { version = version, certificate = cert, ciphers = ciphers }
end

fero.tls = tls
