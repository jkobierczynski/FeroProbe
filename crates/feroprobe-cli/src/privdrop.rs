//! Giving up root after start-up.
//!
//! Raw scans need root, so FeroProbe usually runs under `sudo`. Only the
//! raw sockets need it, though: banner parsing, TLS, regular expressions,
//! reading `-iL` and `--service-rules` files and writing reports do not.
//! So when root runs FeroProbe under `sudo`, it reads its settings files
//! (root's own among them) and then becomes the user who ran `sudo`
//! (`SUDO_UID`, `SUDO_GID` and that user's groups), before any other file
//! is opened and before any thread is started.
//!
//! On Linux it keeps three capabilities, which is all a scan needs:
//! `CAP_NET_RAW` (raw and packet sockets, binding to an interface),
//! `CAP_NET_ADMIN` (binding to an interface on older kernels) and
//! `CAP_NET_BIND_SERVICE` (`-g` with a port below 1024). Raw sockets are
//! still opened when each scan phase needs them, as before. Elsewhere raw
//! scans are not supported, so root is given up entirely.
//!
//! nmap keeps root for the whole run, which is why it is a known way to
//! escalate from a restricted sudoers entry. `--keep-root` keeps the old
//! behaviour for a run that must write to or read from root-only places.

use anyhow::Result;
#[cfg(unix)]
use anyhow::{Context, bail};

/// What [`drop_to_invoking_user`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
// Off Unix only `NotRoot` is ever made.
#[cfg_attr(not(unix), allow(dead_code))]
pub enum Outcome {
    /// Not running as root: nothing to give up.
    NotRoot,
    /// Root, but not under `sudo` (no usable `SUDO_UID`): there is no
    /// other user to become.
    NotUnderSudo,
    /// Root under `sudo`, kept because of `--keep-root`.
    Kept,
    /// Now running as `uid`/`gid`, with the named capabilities.
    Dropped {
        uid: u32,
        gid: u32,
        caps: Vec<&'static str>,
    },
}

impl Outcome {
    /// A line for `-v`, or `None` when there is nothing worth saying.
    pub fn describe(&self) -> Option<String> {
        match self {
            Outcome::NotRoot => None,
            Outcome::NotUnderSudo => {
                Some("Running as root without sudo: root is kept for the whole run".to_string())
            }
            Outcome::Kept => Some("--keep-root: root is kept for the whole run".to_string()),
            Outcome::Dropped { uid, gid, caps } if caps.is_empty() => Some(format!(
                "Gave up root: running as uid {uid}, gid {gid} (the user who ran sudo)"
            )),
            Outcome::Dropped { uid, gid, caps } => Some(format!(
                "Gave up root: running as uid {uid}, gid {gid} (the user who ran sudo), \
                 keeping only {}",
                caps.join(", ")
            )),
        }
    }
}

/// `SUDO_UID` and `SUDO_GID`, when both are set to numbers and the user
/// is not root.
#[cfg(unix)]
pub fn sudo_ids() -> Option<(u32, u32)> {
    let get = |k: &str| std::env::var(k).ok()?.trim().parse::<u32>().ok();
    let uid = get("SUDO_UID")?;
    let gid = get("SUDO_GID")?;
    (uid != 0).then_some((uid, gid))
}

/// Become the user who ran `sudo`, unless `keep` (`--keep-root`) or this
/// is not root under sudo. Must run before any thread is started: the
/// capability calls on Linux apply to the calling thread only.
#[cfg(unix)]
pub fn drop_to_invoking_user(keep: bool) -> Result<Outcome> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(Outcome::NotRoot);
    }
    let Some((uid, gid)) = sudo_ids() else {
        return Ok(Outcome::NotUnderSudo);
    };
    if keep {
        return Ok(Outcome::Kept);
    }
    #[cfg(target_os = "linux")]
    {
        let threads = std::fs::read_dir("/proc/self/task")
            .map(|d| d.count())
            .unwrap_or(1);
        if threads > 1 {
            bail!("internal error: giving up root after {threads} threads were started");
        }
    }
    #[cfg(target_os = "linux")]
    let wanted = caps::wanted()?;
    #[cfg(target_os = "linux")]
    // SAFETY: plain prctl call. Keeps the permitted capabilities across
    // the setuid below; cleared again once they are trimmed.
    if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error()).context("giving up root (PR_SET_KEEPCAPS)");
    }
    set_groups(gid)?;
    // SAFETY: plain setgid/setuid calls; as root they set the real,
    // effective and saved ids.
    if unsafe { libc::setgid(gid as libc::gid_t) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("giving up root: setgid({gid})"));
    }
    // SAFETY: as above.
    if unsafe { libc::setuid(uid as libc::uid_t) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("giving up root: setuid({uid})"));
    }
    #[cfg(target_os = "linux")]
    {
        caps::set(wanted.mask)?;
        // SAFETY: plain prctl call.
        unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) };
    }
    // There must be no way back.
    // SAFETY: plain setuid call; it must fail.
    if unsafe { libc::setuid(0) } == 0 {
        bail!("giving up root failed: setuid(0) still works");
    }
    Ok(Outcome::Dropped {
        uid,
        gid,
        #[cfg(target_os = "linux")]
        caps: wanted.names,
        #[cfg(not(target_os = "linux"))]
        caps: Vec::new(),
    })
}

#[cfg(not(unix))]
pub fn drop_to_invoking_user(_keep: bool) -> Result<Outcome> {
    Ok(Outcome::NotRoot)
}

/// The invoking user's supplementary groups (from `SUDO_USER`), so files
/// they can write through a group stay writable; just `gid` when the name
/// is missing.
#[cfg(unix)]
fn set_groups(gid: u32) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let user = std::env::var_os("SUDO_USER")
        .filter(|u| !u.is_empty())
        .and_then(|u| std::ffi::CString::new(u.as_bytes()).ok());
    let rc = match &user {
        // SAFETY: name is a valid C string; initgroups reads it only.
        Some(name) => unsafe { libc::initgroups(name.as_ptr(), gid as _) },
        None => {
            let g = gid as libc::gid_t;
            // SAFETY: one valid gid_t.
            unsafe { libc::setgroups(1, &g) }
        }
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("giving up root: setting the invoking user's groups");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod caps {
    use anyhow::{Context, Result};

    const VERSION_3: u32 = 0x2008_0522;
    pub const NET_BIND_SERVICE: u32 = 10;
    pub const NET_ADMIN: u32 = 12;
    pub const NET_RAW: u32 = 13;

    #[repr(C)]
    struct Header {
        version: u32,
        pid: libc::c_int,
    }

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    /// The capabilities to keep: the network ones root actually has.
    pub struct Wanted {
        pub mask: u32,
        pub names: Vec<&'static str>,
    }

    pub fn wanted() -> Result<Wanted> {
        let mut header = Header {
            version: VERSION_3,
            pid: 0,
        };
        let mut data = [Data::default(); 2];
        // SAFETY: header and two data structs, as capget(2) wants for v3.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_capget,
                &mut header as *mut Header,
                data.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("giving up root (capget)");
        }
        let mut mask = 0;
        let mut names = Vec::new();
        for (cap, name) in [
            (NET_RAW, "CAP_NET_RAW"),
            (NET_ADMIN, "CAP_NET_ADMIN"),
            (NET_BIND_SERVICE, "CAP_NET_BIND_SERVICE"),
        ] {
            if data[0].permitted & (1 << cap) != 0 {
                mask |= 1 << cap;
                names.push(name);
            }
        }
        Ok(Wanted { mask, names })
    }

    /// Make `mask` the whole permitted and effective set; nothing
    /// inheritable, so a program FeroProbe started would get none.
    pub fn set(mask: u32) -> Result<()> {
        let mut header = Header {
            version: VERSION_3,
            pid: 0,
        };
        let data = [
            Data {
                effective: mask,
                permitted: mask,
                inheritable: 0,
            },
            Data::default(),
        ];
        // SAFETY: header and two data structs, as capset(2) wants for v3.
        let rc =
            unsafe { libc::syscall(libc::SYS_capset, &mut header as *mut Header, data.as_ptr()) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("giving up root (capset)");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe() {
        assert_eq!(Outcome::NotRoot.describe(), None);
        let d = Outcome::Dropped {
            uid: 1000,
            gid: 1000,
            caps: vec!["CAP_NET_RAW"],
        }
        .describe()
        .unwrap();
        assert!(
            d.contains("uid 1000") && d.contains("keeping only CAP_NET_RAW"),
            "{d}"
        );
    }
}
