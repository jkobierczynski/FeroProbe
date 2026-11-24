//! `fero.http`: an HTTP/1.1 client for scripts, written for FeroProbe.
//!
//! Every request goes through the script's scope, like its sockets: the
//! host it runs against, the TCP ports the scan probed there. Redirects
//! are followed only while they stay inside that scope. Each request
//! names FeroProbe in its `User-Agent`, the script engine's documented
//! signature (see `docs/responsible-use.md`), unless the script or
//! `--script-args http.useragent` sets another, as in nmap.
//!
//! Like nmap's HTTP library, a request goes over TLS or plain TCP as the
//! port suggests (the service `-sV` found, else the port number), and
//! tries the other when the first gets no HTTP answer.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use mlua::{Lua, MultiValue, Table, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::socket::{Scope, Slot, host_arg, port_arg, tls_handshake};
use super::trace::{Dir, Ends, Traced};
use crate::model::Protocol;

/// The `User-Agent` script requests send: FeroProbe's script engine
/// signature. Detection rules in `rules/` match on it.
pub const USER_AGENT: &str = "Mozilla/5.0 (compatible; FeroProbe Scripting Engine; https://github.com/jkobierczynski/FeroProbe)";

/// How long one request may take, by default (connect, send and the whole
/// answer), as nmap's.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// The largest body kept by default, as nmap's `http.max-body-size`.
pub const DEFAULT_MAX_BODY: usize = 2 * 1024 * 1024;
/// The largest body a script may ask for.
const MAX_BODY_LIMIT: usize = 16 * 1024 * 1024;
/// The most bytes of status line and headers read.
const MAX_HEAD: usize = 1024 * 1024;
/// Redirects followed by default.
const DEFAULT_REDIRECTS: u32 = 3;
/// Ports that suggest TLS when nothing else does.
const TLS_PORTS: &[u16] = &[443, 4443, 8443, 9443, 10443];

/// A request, after its options are read.
struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    timeout: Duration,
    ssl: Option<bool>,
    redirects: u32,
    max_body: usize,
    truncated_ok: bool,
}

/// A parsed answer.
#[derive(Debug, Default)]
struct Response {
    version: String,
    status: u16,
    status_line: String,
    /// (name as sent, value), in order.
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    truncated: bool,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Headers that carry credentials.
fn is_credential(name: &str) -> bool {
    ["Authorization", "Proxy-Authorization", "Cookie"]
        .iter()
        .any(|c| name.eq_ignore_ascii_case(c))
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Whether `s` can go in a request line or header value: no control
/// characters (no CR or LF, so nothing can be smuggled in).
fn clean_value(s: &str) -> bool {
    s.bytes().all(|b| b == b'\t' || (b >= 0x20 && b != 0x7f))
}

fn clean_target(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b > 0x20 && b != 0x7f)
}

fn nil_err(lua: &Lua, msg: impl AsRef<str>) -> mlua::Result<MultiValue> {
    Ok(MultiValue::from_vec(vec![
        Value::Nil,
        Value::String(lua.create_string(msg.as_ref())?),
    ]))
}

fn opt<T: mlua::FromLua>(opts: Option<&Table>, key: &str) -> mlua::Result<Option<T>> {
    match opts {
        Some(t) => t.get::<Option<T>>(key),
        None => Ok(None),
    }
}

fn read_request(method: String, path: String, opts: Option<&Table>) -> Result<Request, String> {
    let lua_err = |e: mlua::Error| e.to_string();
    if !is_token(&method) {
        return Err(format!("bad HTTP method {method:?}"));
    }
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path
    };
    if !clean_target(&path) {
        return Err("bad request path: it may not hold spaces or control characters".into());
    }
    let mut headers: Vec<(String, String)> = Vec::new();
    if let Some(h) = opt::<Table>(opts, "header").map_err(lua_err)? {
        let mut pairs: Vec<(String, String)> = Vec::new();
        for pair in h.pairs::<String, String>() {
            let (k, v) = pair.map_err(lua_err)?;
            if !is_token(&k) || !clean_value(&v) {
                return Err(format!("bad header {k:?}"));
            }
            pairs.push((k, v));
        }
        pairs.sort();
        headers.extend(pairs);
    }
    let has = |hs: &[(String, String)], n: &str| hs.iter().any(|(k, _)| k.eq_ignore_ascii_case(n));
    if !has(&headers, "User-Agent") {
        let ua = opt::<String>(opts, "user_agent")
            .map_err(lua_err)?
            .unwrap_or_else(|| USER_AGENT.to_string());
        if !clean_value(&ua) {
            return Err("bad User-Agent".into());
        }
        headers.push(("User-Agent".into(), ua));
    }
    if let Some(auth) = opt::<Table>(opts, "auth").map_err(lua_err)? {
        let user: String = auth.get("username").map_err(lua_err)?;
        let pass: String = auth
            .get::<Option<String>>("password")
            .map_err(lua_err)?
            .unwrap_or_default();
        if !has(&headers, "Authorization") {
            headers.push((
                "Authorization".into(),
                format!(
                    "Basic {}",
                    super::base64::encode(format!("{user}:{pass}").as_bytes())
                ),
            ));
        }
    }
    match opt::<Value>(opts, "cookies").map_err(lua_err)? {
        Some(Value::String(s)) => {
            headers.push(("Cookie".into(), s.to_str().map_err(lua_err)?.to_string()))
        }
        Some(Value::Table(t)) => {
            let mut parts = Vec::new();
            for pair in t.pairs::<String, String>() {
                let (k, v) = pair.map_err(lua_err)?;
                parts.push(format!("{k}={v}"));
            }
            parts.sort();
            if !parts.is_empty() {
                headers.push(("Cookie".into(), parts.join("; ")));
            }
        }
        _ => {}
    }
    if headers.iter().any(|(_, v)| !clean_value(v)) {
        return Err("bad header value".into());
    }
    let body = match opt::<mlua::LuaString>(opts, "content").map_err(lua_err)? {
        Some(b) => Some(b.as_bytes().to_vec()),
        None if method == "POST" || method == "PUT" => Some(Vec::new()),
        None => None,
    };
    let timeout = opt::<u64>(opts, "timeout")
        .map_err(lua_err)?
        .map_or(DEFAULT_TIMEOUT, Duration::from_millis);
    let ssl = opt::<bool>(opts, "ssl").map_err(lua_err)?;
    let redirects = match opt::<Value>(opts, "redirect_ok").map_err(lua_err)? {
        Some(Value::Boolean(false)) => 0,
        Some(Value::Integer(n)) => u32::try_from(n.max(0)).unwrap_or(0).min(20),
        _ => DEFAULT_REDIRECTS,
    };
    let max_body = opt::<i64>(opts, "max_body_size")
        .map_err(lua_err)?
        .map_or(DEFAULT_MAX_BODY, |n| usize::try_from(n.max(0)).unwrap_or(0))
        .min(MAX_BODY_LIMIT);
    let truncated_ok = opt::<bool>(opts, "truncated_ok")
        .map_err(lua_err)?
        .unwrap_or(false);
    Ok(Request {
        method,
        path,
        headers,
        body,
        timeout,
        ssl,
        redirects,
        max_body,
        truncated_ok,
    })
}

/// Whether the port suggests TLS: the tunnel or service `-sV` found, else
/// the port number.
fn tls_hint(port: &Value, number: u16) -> bool {
    if let Value::Table(t) = port {
        let service: Option<String> = t.get("service").ok().flatten();
        let tunnel: Option<String> = t
            .get::<Option<Table>>("version")
            .ok()
            .flatten()
            .and_then(|v| v.get("service_tunnel").ok().flatten());
        if tunnel.as_deref() == Some("ssl") {
            return true;
        }
        if let Some(s) = service.as_deref() {
            if matches!(s, "https" | "https-alt" | "ssl" | "ssl/http") {
                return true;
            }
            if matches!(s, "http" | "http-alt" | "http-proxy") && !TLS_PORTS.contains(&number) {
                return false;
            }
        }
    }
    TLS_PORTS.contains(&number)
}

/// The Host header's value: the name, or the address (IPv6 in brackets),
/// with the port unless it is the scheme's own.
fn host_header(name: &str, port: u16, ssl: bool) -> String {
    let host = match name.parse::<IpAddr>() {
        Ok(IpAddr::V6(a)) => format!("[{a}]"),
        _ => name.to_string(),
    };
    if port == if ssl { 443 } else { 80 } {
        host
    } else {
        format!("{host}:{port}")
    }
}

fn request_bytes(req: &Request, host: &str, port: u16, ssl: bool) -> Vec<u8> {
    let mut out = format!("{} {} HTTP/1.1\r\n", req.method, req.path);
    if !req
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("Host"))
    {
        out.push_str(&format!("Host: {}\r\n", host_header(host, port, ssl)));
    }
    for (k, v) in &req.headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    if !req
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("Connection"))
    {
        out.push_str("Connection: close\r\n");
    }
    if let Some(b) = &req.body
        && !req
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
    {
        out.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    if let Some(b) = &req.body {
        bytes.extend_from_slice(b);
    }
    bytes
}

/// Reads with a buffer of what came before.
struct Reader<S> {
    io: S,
    buf: Vec<u8>,
    eof: bool,
}

impl<S: AsyncRead + Unpin> Reader<S> {
    async fn fill(&mut self) -> std::io::Result<bool> {
        if self.eof {
            return Ok(false);
        }
        let mut chunk = [0u8; 16384];
        match self.io.read(&mut chunk).await {
            Ok(0) => {
                self.eof = true;
                Ok(false)
            }
            Ok(n) => {
                self.buf.extend_from_slice(&chunk[..n]);
                Ok(true)
            }
            // A TLS peer that closes without close_notify has still ended.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                self.eof = true;
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// One line (without its end), at most `max` bytes.
    async fn line(&mut self, max: usize) -> Result<Vec<u8>, String> {
        loop {
            if let Some(i) = self.buf.iter().position(|&b| b == b'\n') {
                let mut line: Vec<u8> = self.buf.drain(..=i).collect();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(line);
            }
            if self.buf.len() > max {
                return Err("line too long".into());
            }
            if !self.fill().await.map_err(|e| e.to_string())? {
                return Err("EOF".into());
            }
        }
    }

    /// Up to `n` bytes into `out`; false at the end of the stream.
    async fn take(&mut self, mut n: usize, out: &mut Vec<u8>) -> Result<bool, String> {
        while n > 0 {
            if self.buf.is_empty() && !self.fill().await.map_err(|e| e.to_string())? {
                return Ok(false);
            }
            let k = n.min(self.buf.len());
            out.extend(self.buf.drain(..k));
            n -= k;
        }
        Ok(true)
    }
}

/// Read one answer: the head, then the body as its headers say.
async fn read_response<S: AsyncRead + Unpin>(
    r: &mut Reader<S>,
    head_only: bool,
    max_body: usize,
) -> Result<Response, String> {
    let mut used = 0;
    let mut resp;
    loop {
        let line = r.line(MAX_HEAD).await?;
        used += line.len();
        let text = String::from_utf8_lossy(&line).into_owned();
        let mut parts = text.splitn(3, ' ');
        let version = parts.next().unwrap_or("");
        let Some(v) = version.strip_prefix("HTTP/") else {
            return Err("not an HTTP response".into());
        };
        let status: u16 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or("not an HTTP response")?;
        resp = Response {
            version: v.to_string(),
            status,
            status_line: text.clone(),
            ..Response::default()
        };
        loop {
            let line = r.line(MAX_HEAD).await?;
            used += line.len() + 2;
            if used > MAX_HEAD {
                return Err("response headers too large".into());
            }
            if line.is_empty() {
                break;
            }
            let line = String::from_utf8_lossy(&line).into_owned();
            // A folded line continues the previous header (obsolete, but
            // still sent by some devices).
            if line.starts_with([' ', '\t']) {
                if let Some(last) = resp.headers.last_mut() {
                    last.1.push(' ');
                    last.1.push_str(line.trim());
                }
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                resp.headers
                    .push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        // An interim answer (100 Continue and the like) is followed by the
        // real one.
        if !(100..200).contains(&status) || status == 101 {
            break;
        }
    }
    if head_only || (100..200).contains(&resp.status) || resp.status == 204 || resp.status == 304 {
        return Ok(resp);
    }
    let chunked = resp
        .header("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let mut body = Vec::new();
    if chunked {
        loop {
            let line = r.line(4096).await?;
            let size = String::from_utf8_lossy(&line);
            let size = size.split(';').next().unwrap_or("").trim();
            let Ok(n) = usize::from_str_radix(size, 16) else {
                return Err("bad chunk size".into());
            };
            if n == 0 {
                // Trailers, up to the empty line; an early end is fine.
                while let Ok(l) = r.line(MAX_HEAD).await {
                    if l.is_empty() {
                        break;
                    }
                }
                break;
            }
            let room = max_body.saturating_sub(body.len());
            if n > room {
                r.take(room, &mut body).await?;
                resp.truncated = true;
                break;
            }
            if !r.take(n, &mut body).await? {
                break;
            }
            let _ = r.line(16).await;
        }
    } else if let Some(len) = resp.header("content-length") {
        let n: usize = len.trim().parse().map_err(|_| "bad Content-Length")?;
        if n > max_body {
            r.take(max_body, &mut body).await?;
            resp.truncated = true;
        } else {
            r.take(n, &mut body).await?;
        }
    } else {
        // To the end of the connection.
        loop {
            if body.len() + r.buf.len() > max_body {
                let room = max_body - body.len();
                body.extend(r.buf.drain(..room));
                resp.truncated = true;
                break;
            }
            body.append(&mut r.buf);
            if !r.fill().await.map_err(|e| e.to_string())? {
                body.append(&mut r.buf);
                break;
            }
        }
    }
    resp.body = body;
    Ok(resp)
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    request: &[u8],
    head_only: bool,
    max_body: usize,
) -> Result<Response, String> {
    let mut r = Reader {
        io,
        buf: Vec::new(),
        eof: false,
    };
    r.io.write_all(request).await.map_err(|e| e.to_string())?;
    r.io.flush().await.map_err(|e| e.to_string())?;
    read_response(&mut r, head_only, max_body).await
}

/// One request to `addr` over TLS or not. `Err` when nothing usable came
/// back.
async fn attempt(
    addr: std::net::SocketAddr,
    sni: Option<&str>,
    ssl: bool,
    req: &Request,
    bytes: &[u8],
    local: &std::sync::Mutex<Option<std::net::SocketAddr>>,
) -> Result<Response, String> {
    let tcp = match crate::netif::connect_tcp(addr).await {
        Ok(t) => t,
        Err(e) => {
            Ends::tcp(None, addr).event(Dir::Out, &e.to_string());
            return Err(e.to_string());
        }
    };
    let ends = Ends::tcp(tcp.local_addr().ok(), addr);
    // Kept outside this future, for the trace when a timeout cancels it.
    if let Ok(mut l) = local.lock() {
        *l = ends.local;
    }
    ends.event(Dir::Out, "CONNECT");
    let head_only = req.method == "HEAD";
    if ssl {
        let tls = match tls_handshake(tcp, sni, req.timeout, true).await {
            Ok(t) => t,
            Err(e) => {
                ends.event(Dir::Out, &e);
                return Err(e);
            }
        };
        let io = Traced { inner: tls, ends };
        exchange(io, bytes, head_only, req.max_body).await
    } else {
        let io = Traced { inner: tcp, ends };
        exchange(io, bytes, head_only, req.max_body).await
    }
}

/// Where a redirect points: (host, port, ssl, path), resolved against the
/// current request.
fn resolve_location(
    loc: &str,
    host: &str,
    port: u16,
    ssl: bool,
    path: &str,
) -> Option<(String, u16, bool, String)> {
    let lower = loc.to_ascii_lowercase();
    let (rest, ssl2) = if lower.starts_with("https://") {
        (&loc[8..], true)
    } else if lower.starts_with("http://") {
        (&loc[7..], false)
    } else if let Some(r) = loc.strip_prefix("//") {
        (r, ssl)
    } else if loc.starts_with('/') {
        return Some((host.to_string(), port, ssl, loc.to_string()));
    } else if !loc.contains("://") && !loc.is_empty() {
        let dir = path.rsplit_once('/').map_or("", |(d, _)| d);
        return Some((host.to_string(), port, ssl, format!("{dir}/{loc}")));
    } else {
        return None;
    };
    let (authority, p) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let p = if p.starts_with('/') {
        p.to_string()
    } else {
        format!("/{p}")
    };
    let authority = authority.rsplit('@').next()?;
    let (h, port2) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(n) => n.parse().ok()?,
            None => {
                if ssl2 {
                    443
                } else {
                    80
                }
            }
        };
        (h.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, n)) => (h.to_string(), n.parse().ok()?),
            None => (authority.to_string(), if ssl2 { 443 } else { 80 }),
        }
    };
    let p = p.split('#').next().unwrap_or("/").to_string();
    Some((h, port2, ssl2, p))
}

/// `fero.http.request(method, host, port, path [, options])`: the answer
/// as a table, or nil and a message.
pub(crate) async fn request(
    lua: Lua,
    scope: Arc<Scope>,
    open: Arc<AtomicUsize>,
    (method, host, port, path, opts): (String, Value, Value, String, Option<Table>),
) -> mlua::Result<MultiValue> {
    let mut req = match read_request(method, path, opts.as_ref()) {
        Ok(r) => r,
        Err(e) => return nil_err(&lua, e),
    };
    let (mut host_s, sni) = host_arg(&host)?;
    let (mut port_n, _) = port_arg(&port)?;
    // The name the request goes to: the name given, else the address.
    let mut name = sni.clone().unwrap_or_else(|| host_s.clone());
    let mut ssl_choice = req.ssl;
    let mut first_ssl = ssl_choice.unwrap_or_else(|| tls_hint(&port, port_n));
    let mut followed: Vec<String> = Vec::new();
    let mut redirects_left = req.redirects;
    let started = tokio::time::Instant::now();
    loop {
        let addr = match scope.check(&host_s, port_n, Protocol::Tcp) {
            Ok(a) => a,
            Err(r) => {
                // A redirect out of scope is not followed, silently; see
                // below. Only the request the script made is counted.
                let why = if followed.is_empty() {
                    scope.refuse(r)
                } else {
                    r.message
                };
                return nil_err(&lua, why);
            }
        };
        let sni_now = (name.parse::<IpAddr>().is_err()).then_some(name.as_str());
        // Credentials never fall back from TLS to plain text: a request
        // that carries them and started over TLS stays there.
        let credentials = req.headers.iter().any(|(k, _)| is_credential(k));
        let modes: Vec<bool> = match ssl_choice {
            Some(s) => vec![s],
            None if first_ssl && credentials => vec![true],
            None => vec![first_ssl, !first_ssl],
        };
        let mut last_err = String::new();
        let mut got = None;
        let tries = modes.len();
        for (i, ssl) in modes.into_iter().enumerate() {
            let _slot = match Slot::take(&open) {
                Ok(s) => s,
                Err(e) => return nil_err(&lua, e),
            };
            let left = req.timeout.saturating_sub(started.elapsed());
            if left.is_zero() {
                last_err = "TIMEOUT".into();
                break;
            }
            // A first try that hangs leaves half the time to the other.
            let budget = if i + 1 < tries { left / 2 } else { left };
            let bytes = request_bytes(&req, &name, port_n, ssl);
            let local = std::sync::Mutex::new(None);
            let tried = attempt(addr, sni_now, ssl, &req, &bytes, &local);
            match tokio::time::timeout(budget, tried).await {
                Err(_) => {
                    // The attempt was cancelled: its stream traced only
                    // CLOSE (or nothing, during the connect).
                    let local = local.lock().ok().and_then(|l| *l);
                    Ends::tcp(local, addr).event(Dir::In, "TIMEOUT");
                    last_err = "TIMEOUT".into();
                }
                Ok(Err(e)) => last_err = e,
                Ok(Ok(r)) => {
                    got = Some((r, ssl));
                    break;
                }
            }
        }
        let Some((resp, ssl)) = got else {
            return nil_err(&lua, last_err);
        };
        if resp.truncated && !req.truncated_ok {
            return nil_err(
                &lua,
                format!("body exceeds the maximum size of {} bytes", req.max_body),
            );
        }
        // A redirect is followed only within scope, and silently not
        // otherwise: the script asked for the first request, not for this.
        if matches!(resp.status, 301 | 302 | 303 | 307 | 308)
            && redirects_left > 0
            && let Some(loc) = resp.header("location")
            && let Some((h, p, s, path)) = resolve_location(loc, &name, port_n, ssl, &req.path)
            && clean_target(&path)
            && scope
                .check(h.trim_end_matches('.'), p, Protocol::Tcp)
                .is_ok()
        {
            let target = h.trim_end_matches('.').to_string();
            redirects_left -= 1;
            // Credentials go no further than where the script sent them:
            // not down from TLS to plain text, not to another port.
            if (ssl && !s) || p != port_n {
                req.headers.retain(|(k, _)| !is_credential(k));
            }
            let scheme = if s { "https" } else { "http" };
            followed.push(format!("{scheme}://{}{}", host_header(&target, p, s), path));
            host_s = target.clone();
            name = target;
            port_n = p;
            ssl_choice = Some(s);
            first_ssl = s;
            req.path = path;
            if resp.status == 303
                || (resp.status != 307 && resp.status != 308 && req.method == "POST")
            {
                req.method = "GET".into();
                req.body = None;
            }
            continue;
        }
        let t = response_table(&lua, &resp, ssl, &followed)?;
        return Ok(MultiValue::from_vec(vec![Value::Table(t)]));
    }
}

fn response_table(lua: &Lua, r: &Response, ssl: bool, followed: &[String]) -> mlua::Result<Table> {
    let t = lua.create_table()?;
    t.raw_set("status", r.status)?;
    t.raw_set("status-line", r.status_line.as_str())?;
    t.raw_set("version", r.version.as_str())?;
    let header = lua.create_table()?;
    let raw = lua.create_table()?;
    let cookies = lua.create_table()?;
    for (i, (k, v)) in r.headers.iter().enumerate() {
        raw.raw_set(i + 1, format!("{k}: {v}"))?;
        let key = k.to_ascii_lowercase();
        let joined = match header.raw_get::<Option<String>>(key.as_str())? {
            Some(old) => format!("{old}, {v}"),
            None => v.clone(),
        };
        header.raw_set(key.as_str(), joined)?;
        if key == "set-cookie" {
            cookies.raw_set(cookies.raw_len() + 1, cookie_table(lua, v)?)?;
        }
    }
    t.raw_set("header", header)?;
    t.raw_set("rawheader", raw)?;
    t.raw_set("cookies", cookies)?;
    t.raw_set("body", lua.create_string(&r.body)?)?;
    t.raw_set("ssl", ssl)?;
    t.raw_set("truncated", r.truncated)?;
    let loc = lua.create_table()?;
    for (i, u) in followed.iter().enumerate() {
        loc.raw_set(i + 1, u.as_str())?;
    }
    t.raw_set("location", loc)?;
    Ok(t)
}

/// A Set-Cookie value as `name`, `value` and its attributes, named in
/// lower case (`path`, `domain`, `expires`, `max-age`, ...); flags such as
/// `secure` and `httponly` are `true`.
fn cookie_table(lua: &Lua, v: &str) -> mlua::Result<Table> {
    let t = lua.create_table()?;
    let mut parts = v.split(';');
    let first = parts.next().unwrap_or("");
    let (n, val) = first.split_once('=').unwrap_or((first, ""));
    t.raw_set("name", n.trim())?;
    t.raw_set("value", val.trim())?;
    for p in parts {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        match p.split_once('=') {
            Some((k, v)) => {
                let k = k.trim().to_ascii_lowercase();
                if k != "name" && k != "value" {
                    t.raw_set(k, v.trim())?;
                }
            }
            None => t.raw_set(p.to_ascii_lowercase(), true)?,
        }
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locations() {
        let r = |l| resolve_location(l, "box.test", 8080, false, "/a/b");
        assert_eq!(r("/x"), Some(("box.test".into(), 8080, false, "/x".into())));
        assert_eq!(
            r("c"),
            Some(("box.test".into(), 8080, false, "/a/c".into()))
        );
        assert_eq!(
            r("https://box.test/login?x=1#top"),
            Some(("box.test".into(), 443, true, "/login?x=1".into()))
        );
        assert_eq!(
            r("http://[::1]:81"),
            Some(("::1".into(), 81, false, "/".into()))
        );
        assert_eq!(
            r("//other.test:9/p"),
            Some(("other.test".into(), 9, false, "/p".into()))
        );
        assert_eq!(r("ftp://x/"), None);
    }

    #[test]
    fn requests() {
        let lua = Lua::new();
        let opts = lua.create_table().unwrap();
        let h = lua.create_table().unwrap();
        h.set("X-Test", "1").unwrap();
        opts.set("header", h).unwrap();
        opts.set("content", "a=b").unwrap();
        let req = read_request("POST".into(), "/form".into(), Some(&opts)).unwrap();
        let text = String::from_utf8(request_bytes(&req, "::1", 8080, false)).unwrap();
        assert_eq!(
            text,
            format!(
                "POST /form HTTP/1.1\r\nHost: [::1]:8080\r\nX-Test: 1\r\nUser-Agent: {USER_AGENT}\r\n\
                 Connection: close\r\nContent-Length: 3\r\n\r\na=b"
            )
        );
        assert!(read_request("GE T".into(), "/".into(), None).is_err());
        assert!(read_request("GET".into(), "/a b".into(), None).is_err());
        assert!(read_request("GET".into(), "/\r\nX: y".into(), None).is_err());
        let bad = lua.create_table().unwrap();
        let h = lua.create_table().unwrap();
        h.set("X", "a\r\nInjected: 1").unwrap();
        bad.set("header", h).unwrap();
        assert!(read_request("GET".into(), "/".into(), Some(&bad)).is_err());
        assert_eq!(host_header("example.test", 443, true), "example.test");
        assert_eq!(host_header("example.test", 443, false), "example.test:443");
    }
}
