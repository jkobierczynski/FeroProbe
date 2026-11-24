//! Files for the NSE compatibility layer (roadmap 7.6): `nmap.fetchfile`
//! and the read-only `io` module. Scripts never write files. They read
//! only:
//!
//! - files in the data directories ([`data_roots`]): FeroProbe's own data
//!   directory (the parent of the scripts directory), then `$NMAPDIR` and
//!   the places an installed nmap keeps its data, so word lists and data
//!   files the user already has are found as nmap finds them; and
//! - a file the user named themselves in `--script-args` (the value
//!   exactly as given, such as `userdb=users.txt`).
//!
//! FeroProbe ships none of nmap's data files.

use std::path::{Component, Path, PathBuf};

use super::args::{ArgTable, ArgValue};

/// Largest file a script may read.
pub(crate) const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Where `nmap.fetchfile` looks, in order, found once per run.
pub(crate) fn data_roots() -> &'static [PathBuf] {
    static ROOTS: std::sync::OnceLock<Vec<PathBuf>> = std::sync::OnceLock::new();
    ROOTS.get_or_init(find_roots)
}

/// The data directories that exist.
fn find_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(dir) = super::db::user_dir()
        && let Some(parent) = dir.parent()
    {
        roots.push(parent.to_path_buf());
    }
    if let Some(d) = std::env::var_os("NMAPDIR").filter(|d| !d.is_empty()) {
        roots.push(PathBuf::from(d));
    }
    for d in [
        "/usr/local/share/nmap",
        "/usr/share/nmap",
        "/opt/homebrew/share/nmap",
        "/opt/local/share/nmap",
    ] {
        roots.push(PathBuf::from(d));
    }
    roots.retain(|r| r.is_dir());
    roots
}

/// A relative name made only of normal parts: no root, no `..`.
fn plain_relative(name: &str) -> bool {
    let p = Path::new(name);
    !name.is_empty()
        && !name.contains('\0')
        && p.components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
}

/// `nmap.fetchfile(name)`: the full path of `name` under the first data
/// directory that has it as a readable regular file, as nmap's search.
/// Absolute names and names with `..` are not searched.
pub(crate) fn fetch(roots: &[PathBuf], name: &str) -> Option<String> {
    if !plain_relative(name) {
        return None;
    }
    roots.iter().find_map(|root| {
        let p = root.join(name);
        let ok =
            std::fs::metadata(&p).is_ok_and(|m| m.is_file()) && std::fs::File::open(&p).is_ok();
        // The file must really be inside the root (a symbolic link may
        // point anywhere).
        (ok && inside(roots, &p)).then(|| p.to_string_lossy().into_owned())
    })
}

/// `p`, with links resolved, is inside one of `roots`.
fn inside(roots: &[PathBuf], p: &Path) -> bool {
    let Ok(real) = std::fs::canonicalize(p) else {
        return false;
    };
    roots
        .iter()
        .filter_map(|r| std::fs::canonicalize(r).ok())
        .any(|r| real.starts_with(r))
}

/// Every string value in the script arguments, nested tables included.
pub(crate) fn arg_paths(args: &ArgTable) -> Vec<String> {
    fn walk(t: &ArgTable, out: &mut Vec<String>) {
        for v in t.list.iter().chain(t.named.iter().map(|(_, v)| v)) {
            match v {
                ArgValue::Str(s) if !s.is_empty() => out.push(s.clone()),
                ArgValue::Str(_) => {}
                ArgValue::Table(t) => walk(t, out),
            }
        }
    }
    let mut out = Vec::new();
    walk(args, &mut out);
    out
}

/// Why a file cannot be read, in the form of a C library message.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReadError {
    /// Not one of the files scripts may read.
    NotAllowed,
    NotFound,
    TooLarge,
    Other(String),
}

impl ReadError {
    /// The message and number `io.open` returns.
    pub(crate) fn describe(&self, path: &str) -> (String, i32) {
        match self {
            ReadError::NotAllowed => (
                format!(
                    "{path}: FeroProbe scripts read only files named in --script-args or found by nmap.fetchfile"
                ),
                13,
            ),
            ReadError::NotFound => (format!("{path}: No such file or directory"), 2),
            ReadError::TooLarge => (
                format!("{path}: larger than {MAX_FILE_BYTES} bytes, the most a script may read"),
                27,
            ),
            ReadError::Other(e) => (format!("{path}: {e}"), 5),
        }
    }
}

/// Read `path` whole, if a script may read it: it is one of `named` (the
/// script arguments' values, exactly as given) or lies inside one of
/// `roots`.
pub(crate) fn read(roots: &[PathBuf], named: &[String], path: &str) -> Result<Vec<u8>, ReadError> {
    if path.is_empty() || path.contains('\0') {
        return Err(ReadError::NotFound);
    }
    let p = Path::new(path);
    let allowed = named.iter().any(|n| n == path) || (p.is_absolute() && inside(roots, p));
    if !allowed {
        return Err(ReadError::NotAllowed);
    }
    let meta = match std::fs::metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(ReadError::NotFound),
        Err(e) => return Err(ReadError::Other(e.to_string())),
    };
    if !meta.is_file() {
        return Err(ReadError::Other(
            "Is a directory or not a regular file".into(),
        ));
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(ReadError::TooLarge);
    }
    use std::io::Read;
    let f = std::fs::File::open(p).map_err(|e| ReadError::Other(e.to_string()))?;
    let mut buf = Vec::new();
    // The size may change between the check and the read.
    f.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| ReadError::Other(e.to_string()))?;
    if buf.len() as u64 > MAX_FILE_BYTES {
        return Err(ReadError::TooLarge);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("feroprobe-files-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn fetch_finds_files_only_inside_the_roots() {
        let a = tmp("a");
        let b = tmp("b");
        std::fs::create_dir_all(b.join("nselib/data")).unwrap();
        std::fs::write(b.join("nselib/data/passwords.lst"), "secret\n").unwrap();
        std::fs::write(a.join("only-a"), "x").unwrap();
        let roots = vec![a.clone(), b.clone()];
        let got = fetch(&roots, "nselib/data/passwords.lst").unwrap();
        assert_eq!(Path::new(&got), b.join("nselib/data/passwords.lst"));
        assert!(fetch(&roots, "only-a").is_some());
        assert_eq!(fetch(&roots, "nselib/data"), None, "a directory");
        assert_eq!(fetch(&roots, "../b/nselib/data/passwords.lst"), None);
        assert_eq!(fetch(&roots, "/etc/passwd"), None);
        assert_eq!(fetch(&roots, "missing"), None);
        // A link out of the root is not followed.
        #[cfg(unix)]
        {
            let outside = tmp("outside");
            std::fs::write(outside.join("secret"), "x").unwrap();
            std::os::unix::fs::symlink(outside.join("secret"), a.join("link")).unwrap();
            assert_eq!(fetch(&roots, "link"), None);
            assert_eq!(
                read(&roots, &[], a.join("link").to_str().unwrap()),
                Err(ReadError::NotAllowed)
            );
        }

        assert_eq!(read(&roots, &[], &got).unwrap(), b"secret\n");
        let elsewhere = tmp("named");
        let named = elsewhere.join("users.txt");
        std::fs::write(&named, "root\nadmin\n").unwrap();
        let named = named.to_string_lossy().into_owned();
        assert_eq!(read(&roots, &[], &named), Err(ReadError::NotAllowed));
        assert_eq!(
            read(&roots, std::slice::from_ref(&named), &named).unwrap(),
            b"root\nadmin\n"
        );
        assert_eq!(
            read(
                &roots,
                &[b.to_string_lossy().into_owned()],
                b.to_str().unwrap()
            ),
            Err(ReadError::Other(
                "Is a directory or not a regular file".into()
            ))
        );
        let gone = a.join("gone").to_string_lossy().into_owned();
        assert_eq!(
            read(&roots, std::slice::from_ref(&gone), &gone),
            Err(ReadError::NotFound)
        );
        // Outside the named files, a missing file is not told apart from
        // one the script may not read.
        assert_eq!(read(&roots, &[], &gone), Err(ReadError::NotAllowed));
    }

    #[test]
    fn arg_paths_walks_tables() {
        let t = super::super::args::parse("userdb=u.txt,x={a,b={c}},flag").unwrap();
        let got = arg_paths(&t);
        for want in ["u.txt", "a", "c", "flag"] {
            assert!(got.iter().any(|g| g == want), "{want} in {got:?}");
        }
    }
}
