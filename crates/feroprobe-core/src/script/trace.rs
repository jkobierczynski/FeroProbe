//! `--script-trace`: one line for each thing a script's connection does
//! (connect, data sent, data received, close, failures), in the layout of
//! nmap's script trace:
//!
//! ```text
//! LUA: TCP 192.0.2.1:40312 > 192.0.2.7:80 | CONNECT
//! LUA: TCP 192.0.2.1:40312 > 192.0.2.7:80 | GET / HTTP/1.1\r\n...
//! LUA: TCP 192.0.2.1:40312 < 192.0.2.7:80 | HTTP/1.1 200 OK\r\n...
//! ```
//!
//! `>` is towards the target, `<` from it. Data that is mostly printable
//! is shown as text, with the other bytes escaped, on one line; data with
//! more than 5% unprintable bytes is shown as a hex dump, as nmap decides.
//! TLS connections show the data inside the TLS, as nmap's do.
//! `--packet-trace` turns this trace on too, as in nmap. Lines go to
//! standard output, with the packet trace.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

static ENABLED: AtomicBool = AtomicBool::new(false);

/// Turn the script trace on for the rest of the process.
pub fn enable() {
    ENABLED.store(true, Ordering::Relaxed);
}

/// Whether script connections are traced: `--script-trace`, or a packet
/// trace that is on.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed) || crate::packet_trace::enabled()
}

/// The direction of a trace line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dir {
    /// Towards the target.
    Out,
    /// From the target.
    In,
}

/// One connection's ends, for its trace lines.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ends {
    /// `"TCP"` or `"UDP"`.
    pub proto: &'static str,
    /// The local end; `None` before it is known (a failed connect).
    pub local: Option<SocketAddr>,
    pub remote: SocketAddr,
}

impl Ends {
    pub(crate) fn tcp(local: Option<SocketAddr>, remote: SocketAddr) -> Self {
        Ends {
            proto: "TCP",
            local,
            remote,
        }
    }

    pub(crate) fn udp(local: Option<SocketAddr>, remote: SocketAddr) -> Self {
        Ends {
            proto: "UDP",
            local,
            remote,
        }
    }

    /// A trace line about the connection: `CONNECT`, `CLOSE`, `TIMEOUT`...
    pub(crate) fn event(&self, dir: Dir, what: &str) {
        if enabled() {
            println!("{}", self.line(dir, what));
        }
    }

    /// The trace of data sent or received.
    pub(crate) fn data(&self, dir: Dir, data: &[u8]) {
        if enabled() && !data.is_empty() {
            println!("{}", self.line(dir, &show(data)));
        }
    }

    fn line(&self, dir: Dir, what: &str) -> String {
        let local = self
            .local
            .unwrap_or_else(|| crate::netif::any_addr(self.remote.ip(), 0));
        let arrow = match dir {
            Dir::Out => '>',
            Dir::In => '<',
        };
        format!(
            "LUA: {} {} {arrow} {} | {what}",
            self.proto,
            addr(local),
            addr(self.remote)
        )
    }
}

/// An address as nmap's trace writes it: `ip:port`, IPv6 without
/// brackets.
fn addr(a: SocketAddr) -> String {
    format!("{}:{}", a.ip(), a.port())
}

/// A byte that shows as itself in the text form.
fn printable(b: u8) -> bool {
    b.is_ascii_graphic() || b == b' ' || b == b'\r' || b == b'\n' || b == b'\t'
}

/// Data as the trace shows it: text when at most 5% of it is unprintable,
/// else a hex dump.
pub(crate) fn show(data: &[u8]) -> String {
    let unprintable = data.iter().filter(|&&b| !printable(b)).count();
    if unprintable * 20 <= data.len() {
        text(data)
    } else {
        hex_dump(data)
    }
}

/// Text on one line: line ends and tabs as `\r`, `\n`, `\t`, other
/// unprintable bytes and the backslash escaped.
fn text(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len());
    for &b in data {
        match b {
            b'\r' => out.push_str("\\r"),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            b'\\' => out.push_str("\\\\"),
            b if b.is_ascii_graphic() || b == b' ' => out.push(b as char),
            b => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out
}

/// A hex dump: sixteen bytes a line, offset, bytes, then the printable
/// ones (others as `.`). The first line follows the `|`.
fn hex_dump(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, row) in data.chunks(16).enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&format!("{:08x}: ", i * 16));
        for j in 0..16 {
            match row.get(j) {
                Some(b) => out.push_str(&format!("{b:02x} ")),
                None => out.push_str("   "),
            }
            if j == 7 {
                out.push(' ');
            }
        }
        out.push(' ');
        for &b in row {
            out.push(if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            });
        }
    }
    out
}

/// A stream whose reads and writes are traced: the HTTP library's
/// connections, which do not go through `fero.socket`.
pub(crate) struct Traced<S> {
    pub inner: S,
    pub ends: Ends,
}

impl<S: AsyncRead + Unpin> AsyncRead for Traced<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            let got = &buf.filled()[before..];
            if got.is_empty() {
                self.ends.event(Dir::In, "EOF");
            } else {
                self.ends.data(Dir::In, got);
            }
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Traced<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            self.ends.data(Dir::Out, &buf[..*n]);
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S> Drop for Traced<S> {
    fn drop(&mut self) {
        self.ends.event(Dir::Out, "CLOSE");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_or_hex_at_five_percent() {
        assert_eq!(
            show(b"GET / HTTP/1.1\r\n\r\n"),
            "GET / HTTP/1.1\\r\\n\\r\\n"
        );
        // 1 unprintable byte in 20: still text.
        let mut d = b"abcdefghijklmnopqrs".to_vec();
        d.push(0);
        assert_eq!(show(&d), "abcdefghijklmnopqrs\\x00");
        // 1 in 19: a hex dump.
        d.remove(0);
        assert!(show(&d).starts_with("00000000: 62 63 "));
        assert_eq!(show(b"a\\b"), "a\\\\b");
    }

    #[test]
    fn hex_dump_layout() {
        let d: Vec<u8> = (0u8..18).collect();
        let s = hex_dump(&d);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "00000000: 00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................"
        );
        assert!(lines[1].starts_with("00000010: 10 11 "));
        assert!(lines[1].ends_with(" .."));
    }

    #[test]
    fn line_layout() {
        let e = Ends::tcp(
            Some("192.0.2.1:40312".parse().unwrap()),
            "192.0.2.7:80".parse().unwrap(),
        );
        assert_eq!(
            e.line(Dir::Out, "CONNECT"),
            "LUA: TCP 192.0.2.1:40312 > 192.0.2.7:80 | CONNECT"
        );
        let e = Ends::udp(None, "[2001:db8::7]:123".parse().unwrap());
        assert_eq!(
            e.line(Dir::In, "TIMEOUT"),
            "LUA: UDP :::0 < 2001:db8::7:123 | TIMEOUT"
        );
    }
}
