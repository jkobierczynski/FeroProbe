//! `fero.socket`: TCP and UDP sockets for scripts, held to the script's
//! scope by the engine rather than by trust in the script. A script that
//! runs against a host may connect to that host only, and only to the
//! ports of the protocol the scan probed on it; a script that runs before
//! or after the scan (prerule, postrule) may connect nowhere.
//!
//! The calls answer like nmap's sockets: `status, value`, where a failed
//! call gives `false` and a message such as `"TIMEOUT"` or `"EOF"`.
//!
//! A TCP socket can speak TLS: connected with `"ssl"` as the protocol, or
//! upgraded in place with `reconnect_ssl()` after a STARTTLS exchange.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use mlua::{Lua, MultiValue, UserData, UserDataMethods, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use super::trace::{Dir, Ends};
use crate::model::Protocol;

/// Where a script's sockets may go.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    /// The host the script runs against; `None` before and after the scan.
    pub addr: Option<IpAddr>,
    /// Names that stand for that host: the target as given and its
    /// reverse DNS name.
    pub names: Vec<String>,
    /// The ports the scan probed on it.
    pub tcp: BTreeSet<u16>,
    pub udp: BTreeSet<u16>,
    /// The script, for messages.
    pub script: String,
}

impl Scope {
    /// The address to connect to, or why the script may not.
    pub(crate) fn check(
        &self,
        host: &str,
        port: u16,
        proto: Protocol,
    ) -> Result<SocketAddr, String> {
        let Some(addr) = self.addr else {
            return Err(format!(
                "{host}:{port} is outside this script's scope: scripts that run before or \
                 after the scan have no network access"
            ));
        };
        let same = host.parse::<IpAddr>().is_ok_and(|a| a == addr)
            || self.names.iter().any(|n| n.eq_ignore_ascii_case(host));
        if !same {
            return Err(format!(
                "{host} is outside this script's scope: it may only connect to {addr}, the \
                 host it runs against"
            ));
        }
        let probed = match proto {
            Protocol::Tcp => &self.tcp,
            Protocol::Udp => &self.udp,
            _ => return Err(format!("scripts cannot open {proto} sockets")),
        };
        if !probed.contains(&port) {
            return Err(format!(
                "{proto} port {port} is outside this script's scope: it may only connect to \
                 the {proto} ports the scan probed on {addr}"
            ));
        }
        Ok(crate::target::socket_addr(addr, port))
    }
}

/// The default wait of a socket call, as nmap's.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Sockets one script run may have open at once.
const MAX_SOCKETS: usize = 32;
/// The most data one receive call may gather.
const MAX_RECEIVE: usize = 16 * 1024 * 1024;

enum Conn {
    Closed,
    Tcp(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
    Udp(tokio::net::UdpSocket),
}

struct State {
    conn: Conn,
    /// Data read past what the last call returned.
    buf: Vec<u8>,
    timeout: Duration,
    /// Holds one of the run's [`MAX_SOCKETS`] while connected.
    slot: Option<Slot>,
    /// The name to send as TLS SNI, from the last `connect`.
    sni: Option<String>,
    /// The connection's ends, for `--script-trace`.
    ends: Option<Ends>,
}

/// One open socket counted against a run's limit.
pub(crate) struct Slot(Arc<AtomicUsize>);

impl Slot {
    /// One of the run's sockets, or why there is none left.
    pub(crate) fn take(open: &Arc<AtomicUsize>) -> Result<Slot, String> {
        if open.fetch_add(1, Ordering::Relaxed) >= MAX_SOCKETS {
            open.fetch_sub(1, Ordering::Relaxed);
            return Err(format!("too many open sockets (at most {MAX_SOCKETS})"));
        }
        Ok(Slot(open.clone()))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A script's socket.
pub(crate) struct ScriptSocket {
    scope: Arc<Scope>,
    open: Arc<AtomicUsize>,
    state: Arc<Mutex<State>>,
}

impl ScriptSocket {
    pub(crate) fn new(scope: Arc<Scope>, open: Arc<AtomicUsize>) -> Self {
        ScriptSocket {
            scope,
            open,
            state: Arc::new(Mutex::new(State {
                conn: Conn::Closed,
                buf: Vec::new(),
                timeout: DEFAULT_TIMEOUT,
                slot: None,
                sni: None,
                ends: None,
            })),
        }
    }
}

fn fail(lua: &Lua, msg: impl AsRef<str>) -> mlua::Result<MultiValue> {
    Ok(MultiValue::from_vec(vec![
        Value::Boolean(false),
        Value::String(lua.create_string(msg.as_ref())?),
    ]))
}

fn ok_with(lua: &Lua, data: &[u8]) -> mlua::Result<MultiValue> {
    Ok(MultiValue::from_vec(vec![
        Value::Boolean(true),
        Value::String(lua.create_string(data)?),
    ]))
}

fn ok(_lua: &Lua) -> mlua::Result<MultiValue> {
    Ok(MultiValue::from_vec(vec![Value::Boolean(true)]))
}

/// A host argument: an address or name, or a host table with `ip`.
/// Returns the host to connect to and the name to send as TLS SNI, if
/// any: a name given as text, or the host table's `targetname` (else its
/// reverse DNS `name`). An address is never sent as SNI.
pub(crate) fn host_arg(v: &Value) -> mlua::Result<(String, Option<String>)> {
    let named = |n: &str| (!n.is_empty() && n.parse::<IpAddr>().is_err()).then(|| n.to_string());
    match v {
        Value::String(s) => {
            let h = s.to_str()?.to_string();
            let sni = named(&h);
            Ok((h, sni))
        }
        Value::Table(t) => {
            let ip = t.get::<String>("ip")?;
            let target: Option<String> = t.get("targetname")?;
            let rdns: Option<String> = t.get("name")?;
            let sni = target
                .as_deref()
                .and_then(named)
                .or_else(|| rdns.as_deref().and_then(named));
            Ok((ip, sni))
        }
        _ => Err(mlua::Error::runtime(
            "host must be an address or a host table",
        )),
    }
}

/// A TLS handshake over `tcp`, sending `sni` when given, within
/// `timeout`. Certificates are not checked. `http` offers ALPN
/// `http/1.1`.
pub(crate) async fn tls_handshake(
    tcp: TcpStream,
    sni: Option<&str>,
    timeout: Duration,
    http: bool,
) -> Result<TlsStream<TcpStream>, String> {
    use rustls::pki_types::ServerName;
    let name = match sni.and_then(|h| ServerName::try_from(h.to_string()).ok()) {
        Some(n) => n,
        None => {
            let ip = tcp.peer_addr().map_err(|e| e.to_string())?.ip();
            ServerName::IpAddress(ip.into())
        }
    };
    match tokio::time::timeout(
        timeout,
        crate::service::tls::connector(http).connect(name, tcp),
    )
    .await
    {
        Err(_) => Err("TIMEOUT".to_string()),
        Ok(Err(e)) => Err(format!("TLS handshake failed: {e}")),
        Ok(Ok(s)) => Ok(s),
    }
}

/// A read error as nmap names it: a connection closed without a TLS
/// close_notify is just the end.
fn read_error(e: std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        "EOF".to_string()
    } else {
        e.to_string()
    }
}

/// A port argument: a number, or a port table with `number` (and maybe
/// `protocol`).
pub(crate) fn port_arg(v: &Value) -> mlua::Result<(u16, Option<String>)> {
    let n = match v {
        Value::Integer(n) => *n,
        Value::Number(n) if n.fract() == 0.0 => *n as i64,
        Value::String(s) => s
            .to_str()?
            .parse()
            .map_err(|_| mlua::Error::runtime("bad port number"))?,
        Value::Table(t) => {
            let n: i64 = t.get("number")?;
            let proto: Option<String> = t.get("protocol")?;
            return u16::try_from(n)
                .map(|p| (p, proto))
                .map_err(|_| mlua::Error::runtime("bad port number"));
        }
        _ => {
            return Err(mlua::Error::runtime(
                "port must be a number or a port table",
            ));
        }
    };
    u16::try_from(n)
        .map(|p| (p, None))
        .map_err(|_| mlua::Error::runtime("bad port number"))
}

/// What a receive call waits for.
#[derive(Clone, Copy)]
enum Want {
    Any,
    Bytes(usize),
    Lines(usize),
}

impl Want {
    fn met(self, buf: &[u8]) -> bool {
        match self {
            Want::Any => !buf.is_empty(),
            Want::Bytes(n) => buf.len() >= n.max(1),
            Want::Lines(n) => buf.iter().filter(|&&b| b == b'\n').count() >= n.max(1),
        }
    }
}

async fn receive(lua: Lua, state: Arc<Mutex<State>>, want: Want) -> mlua::Result<MultiValue> {
    let mut st = state.lock().await;
    let st = &mut *st;
    if want.met(&st.buf) {
        let data = std::mem::take(&mut st.buf);
        return ok_with(&lua, &data);
    }
    let timeout = st.timeout;
    let read = async {
        let mut chunk = vec![0u8; 65536];
        loop {
            let n = match &mut st.conn {
                Conn::Closed => return Err("socket is not connected".to_string()),
                Conn::Tcp(s) => s.read(&mut chunk).await.map_err(read_error)?,
                Conn::Tls(s) => s.read(&mut chunk).await.map_err(read_error)?,
                Conn::Udp(s) => s.recv(&mut chunk).await.map_err(|e| e.to_string())?,
            };
            if n == 0 && matches!(st.conn, Conn::Tcp(_) | Conn::Tls(_)) {
                return Err("EOF".to_string());
            }
            if let Some(e) = &st.ends {
                e.data(Dir::In, &chunk[..n]);
            }
            st.buf.extend_from_slice(&chunk[..n]);
            if st.buf.len() > MAX_RECEIVE {
                return Err("too much data".to_string());
            }
            if want.met(&st.buf) {
                return Ok(());
            }
        }
    };
    let outcome = match tokio::time::timeout(timeout, read).await {
        Ok(r) => r,
        Err(_) => Err("TIMEOUT".to_string()),
    };
    if let (Err(e), Some(ends)) = (&outcome, &st.ends) {
        ends.event(Dir::In, e);
    }
    match outcome {
        Ok(()) => {
            let data = std::mem::take(&mut st.buf);
            ok_with(&lua, &data)
        }
        // What came before the end or the timeout is still returned when
        // the call asked for more than it got, as nmap does.
        Err(e) if !st.buf.is_empty() && e != "too much data" => {
            let data = std::mem::take(&mut st.buf);
            ok_with(&lua, &data)
        }
        // Too much data: the connection is dropped with what it sent, so
        // retrying cannot pile up more than the limit.
        Err(e) if e == "too much data" => {
            st.conn = Conn::Closed;
            st.buf = Vec::new();
            st.slot = None;
            st.ends = None;
            fail(&lua, e)
        }
        Err(e) => fail(&lua, e),
    }
}

impl UserData for ScriptSocket {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_async_method(
            "connect",
            |lua, this, (host, port, proto): (Value, Value, Option<String>)| {
                let scope = this.scope.clone();
                let open = this.open.clone();
                let state = this.state.clone();
                async move {
                    let (host, sni) = host_arg(&host)?;
                    let (port, table_proto) = port_arg(&port)?;
                    let mut ssl = false;
                    let proto = match proto.or(table_proto).as_deref().unwrap_or("tcp") {
                        "tcp" => Protocol::Tcp,
                        "ssl" => {
                            ssl = true;
                            Protocol::Tcp
                        }
                        "udp" => Protocol::Udp,
                        other => return fail(&lua, format!("unsupported protocol {other}")),
                    };
                    let addr = match scope.check(&host, port, proto) {
                        Ok(a) => a,
                        Err(why) => {
                            eprintln!(
                                "Warning: script {}: connection refused: {why}",
                                scope.script
                            );
                            return fail(&lua, why);
                        }
                    };
                    let mut st = state.lock().await;
                    st.conn = Conn::Closed;
                    st.buf.clear();
                    st.slot = None;
                    st.ends = None;
                    let slot = match Slot::take(&open) {
                        Ok(s) => s,
                        Err(e) => return fail(&lua, e),
                    };
                    let timeout = st.timeout;
                    // A failed connect is traced with the reason.
                    let failed = |ends: Ends, why: String| {
                        ends.event(Dir::Out, &why);
                        fail(&lua, why)
                    };
                    let (conn, ends) = match proto {
                        Protocol::Tcp => {
                            let unknown = Ends::tcp(None, addr);
                            match tokio::time::timeout(timeout, crate::netif::connect_tcp(addr))
                                .await
                            {
                                Err(_) => return failed(unknown, "TIMEOUT".into()),
                                Ok(Err(e)) => return failed(unknown, e.to_string()),
                                Ok(Ok(s)) => {
                                    let ends = Ends::tcp(s.local_addr().ok(), addr);
                                    ends.event(Dir::Out, "CONNECT");
                                    if ssl {
                                        match tls_handshake(s, sni.as_deref(), timeout, false).await
                                        {
                                            Ok(t) => (Conn::Tls(Box::new(t)), ends),
                                            Err(e) => return failed(ends, e),
                                        }
                                    } else {
                                        (Conn::Tcp(s), ends)
                                    }
                                }
                            }
                        }
                        _ => {
                            let udp = (|| {
                                let sock = crate::netif::udp_socket(addr.is_ipv6())?;
                                sock.bind(&crate::netif::any_addr(addr.ip(), 0).into())?;
                                let std: std::net::UdpSocket = sock.into();
                                let s = tokio::net::UdpSocket::from_std(std)?;
                                Ok::<_, std::io::Error>(s)
                            })();
                            let unknown = Ends::udp(None, addr);
                            match udp {
                                Ok(s) => match s.connect(addr).await {
                                    Ok(()) => {
                                        let ends = Ends::udp(s.local_addr().ok(), addr);
                                        ends.event(Dir::Out, "CONNECT");
                                        (Conn::Udp(s), ends)
                                    }
                                    Err(e) => return failed(unknown, e.to_string()),
                                },
                                Err(e) => return failed(unknown, e.to_string()),
                            }
                        }
                    };
                    st.conn = conn;
                    st.slot = Some(slot);
                    st.sni = sni;
                    st.ends = Some(ends);
                    ok(&lua)
                }
            },
        );
        methods.add_async_method("send", |lua, this, data: mlua::LuaString| {
            let state = this.state.clone();
            async move {
                let data = data.as_bytes().to_vec();
                let mut st = state.lock().await;
                let timeout = st.timeout;
                let sent = async {
                    match &mut st.conn {
                        Conn::Closed => Err("socket is not connected".to_string()),
                        Conn::Tcp(s) => s.write_all(&data).await.map_err(|e| e.to_string()),
                        Conn::Tls(s) => async {
                            s.write_all(&data).await?;
                            s.flush().await
                        }
                        .await
                        .map_err(|e| e.to_string()),
                        Conn::Udp(s) => s.send(&data).await.map(|_| ()).map_err(|e| e.to_string()),
                    }
                };
                let outcome = match tokio::time::timeout(timeout, sent).await {
                    Err(_) => Err("TIMEOUT".to_string()),
                    Ok(r) => r,
                };
                if let Some(ends) = &st.ends {
                    match &outcome {
                        Ok(()) => ends.data(Dir::Out, &data),
                        Err(e) => ends.event(Dir::Out, e),
                    }
                }
                match outcome {
                    Err(e) => fail(&lua, e),
                    Ok(()) => ok(&lua),
                }
            }
        });
        methods.add_async_method("receive", |lua, this, ()| {
            receive(lua, this.state.clone(), Want::Any)
        });
        methods.add_async_method("receive_bytes", |lua, this, n: usize| {
            receive(lua, this.state.clone(), Want::Bytes(n))
        });
        methods.add_async_method("receive_lines", |lua, this, n: usize| {
            receive(lua, this.state.clone(), Want::Lines(n))
        });
        methods.add_method("set_timeout", |_, this, ms: u64| {
            if let Ok(mut st) = this.state.try_lock() {
                st.timeout = Duration::from_millis(ms);
            }
            Ok(())
        });
        // Upgrade a connected TCP socket to TLS in place, as after a
        // STARTTLS exchange. The name sent as SNI is the one `connect` got.
        methods.add_async_method("reconnect_ssl", |lua, this, ()| {
            let state = this.state.clone();
            async move {
                let mut st = state.lock().await;
                let tcp = match std::mem::replace(&mut st.conn, Conn::Closed) {
                    Conn::Tcp(t) => t,
                    other => {
                        let why = match other {
                            Conn::Tls(_) => "socket already speaks TLS",
                            Conn::Udp(_) => "TLS over UDP is not supported",
                            _ => "socket is not connected",
                        };
                        st.conn = other;
                        return fail(&lua, why);
                    }
                };
                st.buf.clear();
                let sni = st.sni.clone();
                match tls_handshake(tcp, sni.as_deref(), st.timeout, false).await {
                    Ok(t) => {
                        st.conn = Conn::Tls(Box::new(t));
                        ok(&lua)
                    }
                    Err(e) => {
                        if let Some(ends) = st.ends.take() {
                            ends.event(Dir::Out, &e);
                        }
                        st.slot = None;
                        fail(&lua, e)
                    }
                }
            }
        });
        methods.add_async_method("get_ssl_certificate", |lua, this, ()| {
            let state = this.state.clone();
            async move {
                let st = state.lock().await;
                let Conn::Tls(t) = &st.conn else {
                    return fail(&lua, "not an SSL socket");
                };
                let Some(der) = t.get_ref().1.peer_certificates().and_then(|c| c.first()) else {
                    return fail(&lua, "no certificate");
                };
                match super::tls::cert_table(&lua, der)? {
                    Some(t) => Ok(MultiValue::from_vec(vec![Value::Table(t)])),
                    None => fail(&lua, "certificate does not parse"),
                }
            }
        });
        methods.add_async_method("get_tls_info", |lua, this, ()| {
            let state = this.state.clone();
            async move {
                let st = state.lock().await;
                let Conn::Tls(t) = &st.conn else {
                    return fail(&lua, "not an SSL socket");
                };
                let info = super::tls::info_table(&lua, t.get_ref().1)?;
                Ok(MultiValue::from_vec(vec![Value::Table(info)]))
            }
        });
        // status, local address, local port, remote address, remote port.
        methods.add_async_method("get_info", |lua, this, ()| {
            let state = this.state.clone();
            async move {
                let st = state.lock().await;
                let addrs = match &st.conn {
                    Conn::Closed => return fail(&lua, "socket is not connected"),
                    Conn::Tcp(s) => (s.local_addr(), s.peer_addr()),
                    Conn::Tls(s) => (s.get_ref().0.local_addr(), s.get_ref().0.peer_addr()),
                    Conn::Udp(s) => (s.local_addr(), s.peer_addr()),
                };
                let (Ok(l), Ok(r)) = addrs else {
                    return fail(&lua, "socket is not connected");
                };
                Ok(MultiValue::from_vec(vec![
                    Value::Boolean(true),
                    Value::String(lua.create_string(l.ip().to_string())?),
                    Value::Integer(l.port().into()),
                    Value::String(lua.create_string(r.ip().to_string())?),
                    Value::Integer(r.port().into()),
                ]))
            }
        });
        methods.add_async_method("close", |lua, this, ()| {
            let state = this.state.clone();
            async move {
                let mut st = state.lock().await;
                if !matches!(st.conn, Conn::Closed)
                    && let Some(ends) = st.ends.take()
                {
                    ends.event(Dir::Out, "CLOSE");
                }
                st.conn = Conn::Closed;
                st.buf.clear();
                st.slot = None;
                ok(&lua)
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> Scope {
        Scope {
            addr: Some("192.0.2.7".parse().unwrap()),
            names: vec!["box.example".into()],
            tcp: [22, 80].into(),
            udp: [53].into(),
            script: "t".into(),
        }
    }

    #[test]
    fn only_the_host_and_its_probed_ports() {
        let s = scope();
        assert!(s.check("192.0.2.7", 22, Protocol::Tcp).is_ok());
        assert!(s.check("BOX.example", 80, Protocol::Tcp).is_ok());
        assert!(s.check("192.0.2.7", 53, Protocol::Udp).is_ok());
        assert!(s.check("192.0.2.8", 22, Protocol::Tcp).is_err());
        assert!(s.check("other.example", 22, Protocol::Tcp).is_err());
        assert!(s.check("192.0.2.7", 443, Protocol::Tcp).is_err());
        assert!(s.check("192.0.2.7", 22, Protocol::Udp).is_err());
        assert!(s.check("192.0.2.7", 22, Protocol::Sctp).is_err());
        let none = Scope::default();
        assert!(none.check("192.0.2.7", 22, Protocol::Tcp).is_err());
    }
}
