//! What the built-in scripts' hostrules and portrules key on, in words,
//! for `--explain`.
//!
//! Only FeroProbe's own scripts are described: their rules are written
//! with `fero.portrule.match`, `fero.portrule.http`, `fero.portrule.ssl`
//! or `fero.smb.port`, so the ports and service names they want are known
//! before the scan. A script from a file (an nmap script above all) has a
//! rule that is its own Lua code, which says nothing about its targets
//! until it runs; FeroProbe does not guess at it.

/// The HTTP ports and services of `fero.portrule.http` (engine.rs).
const HTTP: &str = "TCP 80, 443, 591, 631, 3000, 5000, 7080, 8000, 8008, 8080, 8081, 8088, \
                    8180, 8443, 8888, 9000, 9443, or a TCP port named http, https, http-alt, \
                    https-alt, http-proxy, http-mgmt, ssl/http or ipp";

/// The TLS ports and services of `fero.portrule.ssl` (engine.rs).
const SSL: &str = "a TCP port -sV found speaking TLS, TCP 443, 465, 636, 989, 990, 992, 993, \
                   995, 4443, 5061, 6697, 8443, 9443, or a TCP port named https, https-alt, \
                   ssl, ssl/http, imaps, pop3s, smtps, submissions, ldaps, ftps, ftps-data, \
                   ircs, sip-tls or telnets";

/// [`SSL`], plus the ports that can switch to TLS (`fero.starttls`).
const SSL_STARTTLS: &str = "a TCP port -sV found speaking TLS, TCP 443, 465, 636, 989, 990, \
                            992, 993, 995, 4443, 5061, 6697, 8443, 9443, or a TCP port named \
                            https, https-alt, ssl, ssl/http, imaps, pop3s, smtps, \
                            submissions, ldaps, ftps, ftps-data, ircs, sip-tls or telnets; \
                            also a TCP port that can switch to TLS with STARTTLS: 21, \
                            25, 110, 119, 143, 389, 587, 5222, 5269, 5432, or one named ftp, \
                            smtp, submission, lmtp, imap, pop3, nntp, ldap, postgresql, xmpp, \
                            xmpp-client or xmpp-server";

/// `fero.smb.port`: the first of TCP 445 and 139 the scan found open.
const SMB: &str = "TCP 445, else TCP 139 (or the smbport script argument), when the scan \
                   found it open";

/// What the hostrule or portrule of the built-in script `id` keys on,
/// or `None` for a script that is not built in. Ports are wanted in the
/// states `open` or `open|filtered` unless the text says otherwise.
pub fn rule_keys(id: &str) -> Option<&'static str> {
    Some(match id {
        "banner" => "every open TCP port",
        "clock-skew" => "a host other scripts noted a clock for; it sends nothing itself",
        "dns-nsid" => "TCP or UDP 53, or a port named domain",
        "ftp-anon" | "ftp-syst" => "TCP 21, or a TCP port named ftp",
        "http-auth" | "http-cookie-flags" | "http-cors" | "http-date" | "http-favicon"
        | "http-generator" | "http-git" | "http-headers" | "http-methods" | "http-ntlm-info"
        | "http-robots.txt" | "http-server-header" | "http-title" | "http-webdav-scan" => HTTP,
        "imap-capabilities" | "imap-ntlm-info" => {
            "TCP 143 or 993, or a TCP port named imap or imaps"
        }
        "ms-sql-ntlm-info" => "TCP 1433, or a TCP port named ms-sql-s",
        "mysql-info" => "TCP 3306, or a TCP port named mysql",
        "nbstat" => {
            "UDP 137 (or the nbstat.port script argument), only when the scan probes it (-sU)"
        }
        "nntp-ntlm-info" => "TCP 119, 433 or 563, or a TCP port named nntp or snews",
        "ntp-info" => "UDP 123, or a UDP port named ntp",
        "pop3-capabilities" | "pop3-ntlm-info" => {
            "TCP 110 or 995, or a TCP port named pop3 or pop3s"
        }
        "rdp-ntlm-info" => "TCP 3389, or a TCP port named ms-wbt-server",
        "rpcinfo" => "TCP or UDP 111, or a port named rpcbind or sunrpc",
        "smb-os-discovery" | "smb-protocols" | "smb-security-mode" | "smb2-capabilities"
        | "smb2-security-mode" | "smb2-time" => SMB,
        "smtp-commands" => {
            "TCP 25, 465 or 587, or a TCP port named smtp, smtps, submission or submissions"
        }
        "smtp-ntlm-info" => "TCP 25, 465 or 587, or a TCP port named smtp, smtps or submission",
        "snmp-info" | "snmp-interfaces" | "snmp-sysdescr" => "UDP 161, or a UDP port named snmp",
        "ssh-hostkey" | "ssh2-enum-algos" | "sshv1" => "TCP 22, or a TCP port named ssh",
        "ssl-cert" | "ssl-enum-ciphers" => SSL_STARTTLS,
        "ssl-date" | "sslv2" | "tls-alpn" | "tls-nextprotoneg" => SSL,
        "telnet-ntlm-info" => "TCP 23, or a TCP port named telnet",
        "vnc-info" => "TCP 5900-5910, or a TCP port named vnc",
        "x11-access" => "TCP 6000-6009, or a TCP port named X11 or x11",
        _ => return None,
    })
}

/// The protocols a built-in script's sockets use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Needs {
    /// It connects nowhere.
    Nothing,
    Tcp,
    Udp,
    /// Either serves: it uses whichever the port it runs on speaks.
    TcpOrUdp,
}

/// What the built-in script `id` connects over, or `None` for a script
/// that is not built in (its sockets are its own code).
pub fn rule_needs(id: &str) -> Option<Needs> {
    rule_keys(id)?;
    Some(match id {
        "clock-skew" => Needs::Nothing,
        "dns-nsid" | "rpcinfo" => Needs::TcpOrUdp,
        "nbstat" | "ntp-info" | "snmp-info" | "snmp-interfaces" | "snmp-sysdescr" => Needs::Udp,
        _ => Needs::Tcp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every built-in script is described, and the ports a
    /// `fero.portrule.match({ ... })` rule lists all appear in the text,
    /// so the description cannot fall behind the rule unnoticed.
    #[test]
    fn every_built_in_script_is_described() {
        for (id, src) in super::super::BUILT_IN {
            let keys = rule_keys(id).unwrap_or_else(|| panic!("{id} has no rule_keys entry"));
            for line in src.lines() {
                let Some(rest) = line.trim().strip_prefix("portrule = fero.portrule.match({")
                else {
                    continue;
                };
                let list = rest.split('}').next().unwrap_or_default();
                for port in list.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                    assert!(
                        keys.contains(port),
                        "{id}: rule_keys does not name port {port}: {keys}"
                    );
                }
            }
            if src.contains("portrule = fero.portrule.http") {
                assert_eq!(keys, HTTP, "{id}");
            }
            if src.contains("portrule = fero.portrule.ssl") {
                assert_eq!(keys, SSL, "{id}");
            }
            if src.contains("fero.smb.port(host) ~= nil") {
                assert_eq!(keys, SMB, "{id}");
            }
        }
        assert_eq!(rule_keys("nsecompat-ftp-brute"), None);
    }

    /// What a script connects over agrees with what its rule keys on.
    #[test]
    fn needs_match_the_rule_keys() {
        for (id, _) in super::super::BUILT_IN {
            let keys = rule_keys(id).unwrap();
            let (tcp, udp) = (keys.contains("TCP"), keys.contains("UDP"));
            let want = match (tcp, udp) {
                _ if *id == "clock-skew" => Needs::Nothing,
                (true, true) => Needs::TcpOrUdp,
                (false, true) => Needs::Udp,
                _ => Needs::Tcp,
            };
            assert_eq!(rule_needs(id), Some(want), "{id}: {keys}");
        }
        assert_eq!(rule_needs("nsecompat-ftp-brute"), None);
    }
}
