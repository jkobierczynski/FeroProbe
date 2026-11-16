//! FTP bounce scan (nmap's `-b`): an FTP server that accepts `PORT`
//! commands naming a third host is asked to open a data connection to each
//! target port in turn. Whether the `LIST` that follows can open it tells
//! whether the port is open.
//!
//! Only the FTP server (the relay) talks to the targets, so the scan shows
//! what the targets look like from the relay's network. Few servers still
//! allow it (RFC 2577 asks them not to), and the command-line layer treats
//! it like the evasion options: public targets need
//! `--allow-public-evasion`.
//!
//! The protocol steps and their reading follow nmap's `bounce_scan`
//! (nmap_ftp.cc): a reply starting with 1 or 2 to `LIST` means open, 425 or
//! anything else closed, silence filtered. IPv4 only, since `PORT` carries
//! an IPv4 address.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::model::{HostResult, PortResult, PortState, Protocol, ScanConfig, reason};
use crate::target::Target;

/// nmap's default login for the relay.
pub const DEFAULT_USER: &str = "anonymous";
pub const DEFAULT_PASS: &str = "-wwwuser@";

/// How often a lost control connection is opened again (nmap's
/// `FTP_RETRIES`).
const RECONNECTS: u32 = 2;

/// The reason for a port state an FTP relay reported.
pub const REASON: &str = "ftp-bounce";

/// An FTP relay from `-b [user[:pass]@]server[:port]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpRelay {
    pub user: String,
    pub pass: String,
    pub server: String,
    pub port: u16,
}

impl FtpRelay {
    /// Parse nmap's `-b` argument: `user:pass@server:port`, where every
    /// part but the server is optional (`anonymous`, `-wwwuser@`, 21).
    /// The last `@` ends the login, so a password may contain `@`.
    pub fn parse(arg: &str) -> Result<Self, String> {
        let (login, host) = match arg.rfind('@') {
            Some(i) => (Some(&arg[..i]), &arg[i + 1..]),
            None => (None, arg),
        };
        let (user, pass) = match login {
            Some(l) => match l.split_once(':') {
                Some((u, p)) => (u.to_string(), p.to_string()),
                None => (l.to_string(), DEFAULT_PASS.to_string()),
            },
            None => (DEFAULT_USER.to_string(), DEFAULT_PASS.to_string()),
        };
        let (server, port) = match host.rsplit_once(':') {
            // An IPv6 address has colons of its own; bounce scans are IPv4.
            Some((s, p)) if !s.contains(':') => (
                s.to_string(),
                p.parse::<u16>()
                    .ok()
                    .filter(|&p| p > 0)
                    .ok_or_else(|| format!("-b: '{p}' is not a port number"))?,
            ),
            _ => (host.to_string(), 21),
        };
        if server.is_empty() {
            return Err(
                "-b needs an FTP server: [user[:pass]@]server[:port], e.g. ftp.example.com"
                    .to_string(),
            );
        }
        Ok(Self {
            user,
            pass,
            server,
            port,
        })
    }
}

/// The `PORT` command that points the relay's data connection at
/// `target:port`.
pub fn port_command(target: Ipv4Addr, port: u16) -> String {
    let o = target.octets();
    format!(
        "PORT {},{},{},{},{},{}",
        o[0],
        o[1],
        o[2],
        o[3],
        port >> 8,
        port & 0xff
    )
}

/// One FTP reply: its code and its last line.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Reply {
    code: u16,
    text: String,
}

impl Reply {
    fn class(&self) -> u16 {
        self.code / 100
    }
}

/// A logged-in control connection to the relay.
struct Control {
    addr: SocketAddr,
    read: BufReader<OwnedReadHalf>,
    write: OwnedWriteHalf,
    /// A reply may still be on its way (one timed out, or `ABOR` was
    /// sent), so the next reply read might answer an older command: the
    /// connection must not be used for another port.
    out_of_step: bool,
}

impl Control {
    /// Read one reply, multi-line ones whole (RFC 959: `123-` lines up to
    /// `123 `). `Ok(None)` when nothing came within `wait`; an error of
    /// kind `UnexpectedEof` when the relay closed the connection.
    async fn reply(&mut self, wait: Duration) -> io::Result<Option<Reply>> {
        let read = async {
            let mut first: Option<String> = None;
            loop {
                let mut line = String::new();
                if self.read.read_line(&mut line).await? == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the FTP relay closed the connection",
                    ));
                }
                let line = line.trim_end().to_string();
                let code = line.get(..3).and_then(|c| c.parse::<u16>().ok());
                let Some(code) = code else { continue };
                let start = first.get_or_insert_with(|| line[..3].to_string());
                // The last line repeats the code followed by a space.
                if line[..3] == **start && line.as_bytes().get(3) != Some(&b'-') {
                    crate::packet_trace::log("RCVD", || format!("FTP {} {line}", self.addr));
                    return Ok(Reply { code, text: line });
                }
            }
        };
        match tokio::time::timeout(wait, read).await {
            Ok(r) => r.map(Some),
            Err(_) => {
                self.out_of_step = true;
                Ok(None)
            }
        }
    }

    async fn send(&mut self, cmd: &str) -> io::Result<()> {
        let shown = if cmd.starts_with("PASS ") {
            "PASS ****"
        } else {
            cmd
        };
        crate::packet_trace::log("SENT", || format!("FTP {} {shown}", self.addr));
        self.write.write_all(format!("{cmd}\r\n").as_bytes()).await
    }

    /// Connect and log in, as nmap's `ftp_anon_connect`.
    async fn login(addr: SocketAddr, relay: &FtpRelay) -> io::Result<Self> {
        let stream = tokio::time::timeout(Duration::from_secs(15), crate::netif::connect_tcp(addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the FTP relay did not answer"))?
            .map_err(|e| {
                io::Error::new(e.kind(), format!("the FTP relay won't talk to us: {e}"))
            })?;
        crate::packet_trace::conn(addr, "Connected");
        let (r, w) = stream.into_split();
        let mut c = Control {
            addr,
            read: BufReader::new(r),
            write: w,
            out_of_step: false,
        };
        match c.reply(Duration::from_secs(7)).await? {
            Some(r) if r.class() == 2 => {}
            Some(r) => {
                return Err(io::Error::other(format!(
                    "the FTP relay refused us: {}",
                    r.text
                )));
            }
            None => return Err(io::Error::other("the FTP relay sent no greeting")),
        }
        c.send(&format!("USER {}", relay.user)).await?;
        let r = c
            .reply(Duration::from_secs(12))
            .await?
            .ok_or_else(|| io::Error::other("the FTP relay did not answer USER"))?;
        if r.class() == 5 {
            return Err(io::Error::other(format!(
                "the FTP relay doesn't like the username \"{}\": {}",
                relay.user, r.text
            )));
        }
        if r.code == 230 {
            return Ok(c);
        }
        c.send(&format!("PASS {}", relay.pass)).await?;
        match c.reply(Duration::from_secs(12)).await? {
            Some(r) if r.class() == 2 => Ok(c),
            Some(r) => Err(io::Error::other(format!(
                "the FTP relay refused the login {}: {}",
                relay.user, r.text
            ))),
            None => Err(io::Error::other("the FTP relay did not answer PASS")),
        }
    }
}

/// What one `PORT` + `LIST` round said about a port.
enum Verdict {
    State(PortState, &'static str),
    /// The relay refused `PORT` for this port.
    Refused,
}

/// Ask the relay about one port.
async fn probe(c: &mut Control, target: Ipv4Addr, port: u16) -> io::Result<Verdict> {
    c.send(&port_command(target, port)).await?;
    let Some(r) = c.reply(Duration::from_secs(15)).await? else {
        // No answer to PORT: a LIST now would read it late as its own.
        return Ok(Verdict::State(PortState::Filtered, reason::NO_RESPONSE));
    };
    if r.class() == 5 {
        return Ok(Verdict::Refused);
    }
    c.send("LIST").await?;
    let mut r = match c.reply(Duration::from_secs(12)).await {
        Ok(Some(r)) => r,
        Ok(None) => return Ok(Verdict::State(PortState::Filtered, reason::NO_RESPONSE)),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(e),
        Err(e) => return Err(e),
    };
    if r.code == 500 {
        // A reply out of step with our commands: take the next one.
        if let Some(next) = c.reply(Duration::from_secs(10)).await? {
            r = next;
        }
    }
    if r.class() == 1 {
        // The data connection opened (150/125): wait for the transfer to
        // end. If it never does, the relay is stuck: abort, filtered.
        match c.reply(Duration::from_secs(10)).await? {
            Some(next) => r = next,
            None => {
                c.send("ABOR").await?;
                let _ = c.reply(Duration::from_secs(10)).await;
                // ABOR may draw one reply or two (426 then 226).
                c.out_of_step = true;
                return Ok(Verdict::State(PortState::Filtered, reason::NO_RESPONSE));
            }
        }
        // 150 then 226: the port took the connection.
        if r.class() == 2 || r.class() == 1 {
            return Ok(Verdict::State(PortState::Open, REASON));
        }
        // 150 then 426: the connection broke; nmap changes its mind.
        return Ok(Verdict::State(PortState::Closed, REASON));
    }
    Ok(if r.class() == 2 {
        Verdict::State(PortState::Open, REASON)
    } else {
        // 425 "Can't open data connection", and the rest.
        Verdict::State(PortState::Closed, REASON)
    })
}

/// Scan `ports` on every target through the FTP relay at `relay_addr`, one
/// port at a time over one control connection, as nmap does. A target that
/// is not IPv4 gets no ports.
pub async fn bounce_scan(
    relay_addr: SocketAddr,
    relay: &FtpRelay,
    targets: &[Target],
    ports: &[u16],
    cfg: &ScanConfig,
) -> io::Result<Vec<HostResult>> {
    let mut hosts: Vec<HostResult> = targets
        .iter()
        .map(|t| HostResult::new(t.addr, t.hostname.clone()))
        .collect();
    if ports.is_empty() || targets.is_empty() {
        return Ok(hosts);
    }
    let mut control = Control::login(relay_addr, relay).await?;
    let mut reconnects = RECONNECTS;
    // Once a port below 1024 went through, refusals are not about
    // privileged ports (nmap's `privok`).
    let mut privileged_ok = false;
    let mut skip_privileged = false;
    for (h, t) in targets.iter().enumerate() {
        let IpAddr::V4(target) = t.addr else { continue };
        let mut i = 0;
        while i < ports.len() {
            if cfg.expired() {
                return Err(ScanConfig::timed_out());
            }
            let port = ports[i];
            if skip_privileged && port < 1024 {
                i += 1;
                continue;
            }
            // A reply still due on this connection would be read as the
            // answer about the next port: start a fresh one instead.
            if control.out_of_step {
                let _ = control.send("QUIT").await;
                control = Control::login(relay_addr, relay).await?;
            }
            crate::timing::pace(cfg.scan_delay).await;
            let verdict = match probe(&mut control, target, port).await {
                Ok(v) => v,
                Err(e) if reconnects > 0 => {
                    // The relay hung up: log in again and retry the port.
                    reconnects -= 1;
                    eprintln!("Warning: the FTP relay hung up ({e}); reconnecting");
                    control = Control::login(relay_addr, relay).await?;
                    continue;
                }
                Err(e) => {
                    return Err(io::Error::new(
                        e.kind(),
                        format!("lost the FTP relay and out of retries: {e}"),
                    ));
                }
            };
            match verdict {
                Verdict::Refused if !privileged_ok && port < 1024 => {
                    eprintln!(
                        "Warning: your FTP bounce server doesn't allow privileged ports, \
                         skipping them."
                    );
                    skip_privileged = true;
                    if ports.iter().all(|&p| p < 1024) {
                        return Err(io::Error::other(
                            "the FTP relay refuses privileged ports, and no unprivileged ports \
                             were asked for",
                        ));
                    }
                }
                Verdict::Refused if !privileged_ok => {
                    return Err(io::Error::other(
                        "the FTP relay won't let us name other hosts in PORT commands, so it \
                         cannot be used for a bounce scan",
                    ));
                }
                Verdict::Refused => hosts[h].ports.push(PortResult {
                    port,
                    protocol: Protocol::Tcp,
                    state: PortState::Filtered,
                    reason: REASON,
                    rtt_ms: None,
                    service: None,
                }),
                Verdict::State(state, why) => {
                    if port < 1024 {
                        privileged_ok = true;
                    }
                    hosts[h].ports.push(PortResult {
                        port,
                        protocol: Protocol::Tcp,
                        state,
                        reason: why,
                        rtt_ms: None,
                        service: None,
                    });
                }
            }
            crate::progress::tick(1);
            i += 1;
        }
    }
    let _ = control.send("QUIT").await;
    for host in &mut hosts {
        host.sort_ports();
    }
    Ok(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_argument_like_nmap() {
        assert_eq!(
            FtpRelay::parse("ftp.example.com").unwrap(),
            FtpRelay {
                user: "anonymous".into(),
                pass: "-wwwuser@".into(),
                server: "ftp.example.com".into(),
                port: 21
            }
        );
        let r = FtpRelay::parse("bob:s3cr@t@10.0.0.5:2121").unwrap();
        assert_eq!(
            (r.user.as_str(), r.pass.as_str(), r.server.as_str(), r.port),
            ("bob", "s3cr@t", "10.0.0.5", 2121)
        );
        let r = FtpRelay::parse("alice@10.0.0.5").unwrap();
        assert_eq!((r.user.as_str(), r.pass.as_str()), ("alice", "-wwwuser@"));
        assert!(FtpRelay::parse("10.0.0.5:ftp").is_err());
        assert!(FtpRelay::parse("bob@").is_err());
    }

    #[test]
    fn port_command_splits_the_port() {
        assert_eq!(
            port_command(Ipv4Addr::new(192, 0, 2, 7), 8080),
            "PORT 192,0,2,7,31,144"
        );
    }

    /// A fake relay: answers like an FTP server that can reach port 80 but
    /// not port 81, and refuses port 82.
    async fn fake_relay() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (r, mut w) = stream.into_split();
            let mut lines = BufReader::new(r).lines();
            w.write_all(b"220-Welcome\r\n220 ready\r\n").await.unwrap();
            let mut port = 0;
            while let Ok(Some(line)) = lines.next_line().await {
                let reply: &[u8] = if line.starts_with("USER") {
                    b"331 password please\r\n"
                } else if line.starts_with("PASS") {
                    b"230 logged in\r\n"
                } else if let Some(arg) = line.strip_prefix("PORT ") {
                    let n: Vec<u16> = arg.split(',').map(|x| x.parse().unwrap()).collect();
                    port = (n[4] << 8) | n[5];
                    if port == 82 {
                        b"500 Illegal PORT command\r\n"
                    } else {
                        b"200 PORT command successful\r\n"
                    }
                } else if line == "LIST" {
                    if port == 80 {
                        b"150 Opening data connection\r\n226 Transfer complete\r\n"
                    } else {
                        b"425 Can't build data connection\r\n"
                    }
                } else if line == "QUIT" {
                    b"221 bye\r\n"
                } else {
                    b"502 not implemented\r\n"
                };
                w.write_all(reply).await.unwrap();
            }
        });
        addr
    }

    #[tokio::test]
    async fn reads_open_closed_and_refused() {
        let addr = fake_relay().await;
        let relay = FtpRelay::parse(&format!("127.0.0.1:{}", addr.port())).unwrap();
        let targets = vec![Target {
            addr: "192.0.2.7".parse().unwrap(),
            hostname: None,
        }];
        let hosts = bounce_scan(
            addr,
            &relay,
            &targets,
            &[80, 81, 82],
            &ScanConfig::default(),
        )
        .await
        .unwrap();
        let states: Vec<(u16, PortState)> =
            hosts[0].ports.iter().map(|p| (p.port, p.state)).collect();
        assert_eq!(
            states,
            vec![
                (80, PortState::Open),
                (81, PortState::Closed),
                (82, PortState::Filtered)
            ]
        );
    }
}
