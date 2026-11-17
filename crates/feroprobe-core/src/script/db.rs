//! The installed scripts: Lua files the user put in their scripts
//! directory, and `script.db`, the index of their categories that
//! `--script-updatedb` writes, as nmap's `scripts/script.db`.
//!
//! `--script` finds an installed script by name in the directory even
//! without the index, as nmap does; choosing it by category (`default`,
//! `safe`, an expression) needs the index, so a script added or changed
//! is chosen by category only after `--script-updatedb`.
//!
//! The directory is `$XDG_DATA_HOME/feroprobe/scripts`
//! (`~/.local/share/feroprobe/scripts` when that is unset; on Windows,
//! `%APPDATA%\feroprobe\scripts`). The index uses nmap's layout, one line
//! per script:
//!
//! ```text
//! Entry { filename = "my-check.lua", categories = { "discovery", "safe", } }
//! ```
//!
//! It is read as data, never run.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::{EXTENSION, Script, ScriptError, err};

/// The index's file name in the scripts directory.
pub const DB_FILE: &str = "script.db";

/// The scripts directory for these environment values, or `None` when
/// none of them is set. `XDG_DATA_HOME` is used only when it is an
/// absolute path, as the XDG base directory spec says.
pub fn dir_for(
    xdg_data_home: Option<OsString>,
    home: Option<OsString>,
    appdata: Option<OsString>,
) -> Option<PathBuf> {
    let nonempty = |v: Option<OsString>| v.filter(|v| !v.is_empty()).map(PathBuf::from);
    let base = nonempty(xdg_data_home)
        .filter(|p| p.is_absolute())
        .or_else(|| nonempty(home).map(|h| h.join(".local").join("share")))
        .or_else(|| nonempty(appdata))?;
    Some(base.join("feroprobe").join("scripts"))
}

static DIR: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();

/// Use `dir` as the scripts directory for the rest of the process, rather
/// than the one the environment names: under `sudo`, once root is given
/// up, the invoking user's. Only the first call counts.
pub fn set_dir(dir: Option<PathBuf>) {
    let _ = DIR.set(dir);
}

/// The scripts directory: the one [`set_dir`] gave, else the one this
/// process's environment names.
pub fn user_dir() -> Option<PathBuf> {
    if let Some(d) = DIR.get() {
        return d.clone();
    }
    dir_for(
        std::env::var_os("XDG_DATA_HOME"),
        std::env::var_os("HOME"),
        std::env::var_os("APPDATA"),
    )
}

/// One script in the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The file name in the scripts directory, with `.lua`.
    pub filename: String,
    pub categories: Vec<String>,
}

impl Entry {
    /// The script's name: its file name without `.lua`.
    pub fn id(&self) -> &str {
        self.filename
            .strip_suffix(&format!(".{EXTENSION}"))
            .unwrap_or(&self.filename)
    }
}

/// A name or category the index can hold: printable ASCII without
/// quotes, backslashes or path separators, so a line cannot be forged or
/// point outside the directory.
fn plain(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\\' | b'/' | b'{' | b'}'))
        && s != "."
        && s != ".."
}

/// The index as text.
pub fn render(entries: &[Entry]) -> String {
    let mut out = String::new();
    for e in entries {
        out.push_str(&format!(
            "Entry {{ filename = \"{}\", categories = {{ ",
            e.filename
        ));
        for c in &e.categories {
            out.push_str(&format!("\"{c}\", "));
        }
        out.push_str("} }\n");
    }
    out
}

/// Read the index. Each line must be exactly as [`render`] writes it.
pub fn parse(text: &str) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let bad = || format!("line {}: not an Entry line", n + 1);
        let rest = line.strip_prefix("Entry { filename = \"").ok_or_else(bad)?;
        let (filename, rest) = rest.split_once('"').ok_or_else(bad)?;
        let mut rest = rest.strip_prefix(", categories = { ").ok_or_else(bad)?;
        let mut categories = Vec::new();
        while let Some(r) = rest.strip_prefix('"') {
            let (c, r) = r.split_once('"').ok_or_else(bad)?;
            if !plain(c) {
                return Err(bad());
            }
            categories.push(c.to_string());
            rest = r.strip_prefix(", ").ok_or_else(bad)?;
        }
        if rest != "} }" || !plain(filename) || !filename.ends_with(&format!(".{EXTENSION}")) {
            return Err(bad());
        }
        entries.push(Entry {
            filename: filename.to_string(),
            categories,
        });
    }
    Ok(entries)
}

/// The index of `dir`, or no entries when there is none.
pub fn read(dir: &Path) -> Result<Vec<Entry>, ScriptError> {
    let path = dir.join(DB_FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => parse(&text).map_err(|e| {
            ScriptError(format!(
                "{}: {e}; run feroprobe --script-updatedb to rebuild it",
                path.display()
            ))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => err(format!("cannot read {}: {e}", path.display())),
    }
}

/// What `--script-updatedb` did.
#[derive(Debug, Default)]
pub struct Update {
    /// The scripts indexed.
    pub entries: Vec<Entry>,
    /// Files left out, and why.
    pub skipped: Vec<String>,
}

/// `--script-updatedb`: load every `.lua` file in `dir` (in the sandbox,
/// with no network) and write their categories to `script.db`. A file
/// that does not load, or whose name is a built-in script's, is left out
/// with the reason. `built_in` are the built-in scripts' names.
pub fn update(dir: &Path, built_in: &[&str]) -> Result<Update, ScriptError> {
    if !dir.is_dir() {
        return err(format!(
            "no scripts directory {}: create it and put your .{EXTENSION} scripts in it",
            dir.display()
        ));
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| ScriptError(format!("cannot read {}: {e}", dir.display())))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == EXTENSION))
        .collect();
    files.sort();
    let mut out = Update::default();
    for f in files {
        let name = f
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if !plain(&name) {
            out.skipped.push(format!(
                "{name}: the name has characters the index cannot hold"
            ));
            continue;
        }
        let script = match Script::from_file(&f) {
            Ok(s) => s,
            Err(e) => {
                out.skipped.push(e.0);
                continue;
            }
        };
        if built_in.contains(&script.id.as_str()) {
            out.skipped.push(format!(
                "{name}: a built-in script has this name (give the file's path to --script to run it)"
            ));
            continue;
        }
        if let Some(c) = script.categories.iter().find(|c| !plain(c)) {
            out.skipped.push(format!(
                "{name}: category {c:?} has characters the index cannot hold"
            ));
            continue;
        }
        out.entries.push(Entry {
            filename: name,
            categories: script.categories,
        });
    }
    // Written beside the old index and moved over it, so a reader never
    // sees half a file.
    let path = dir.join(DB_FILE);
    let tmp = dir.join(format!("{DB_FILE}.tmp"));
    std::fs::write(&tmp, render(&out.entries))
        .and_then(|()| std::fs::rename(&tmp, &path))
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            ScriptError(format!("cannot write {}: {e}", path.display()))
        })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_from_the_environment() {
        let d = |x: Option<&str>, h: Option<&str>, a: Option<&str>| {
            dir_for(x.map(Into::into), h.map(Into::into), a.map(Into::into))
        };
        assert_eq!(
            d(None, Some("/home/u"), None),
            Some(PathBuf::from("/home/u/.local/share/feroprobe/scripts"))
        );
        // An absolute path on this platform (C:\... on Windows).
        let data = std::env::temp_dir();
        assert_eq!(
            dir_for(
                Some(data.clone().into_os_string()),
                Some("/home/u".into()),
                None
            ),
            Some(data.join("feroprobe").join("scripts"))
        );
        // A relative XDG_DATA_HOME is ignored, as the spec says.
        assert_eq!(
            d(Some("rel"), Some("/home/u"), None),
            Some(PathBuf::from("/home/u/.local/share/feroprobe/scripts"))
        );
        assert_eq!(d(None, None, None), None);
    }

    #[test]
    fn index_round_trip() {
        let entries = vec![
            Entry {
                filename: "a.lua".into(),
                categories: vec!["default".into(), "safe".into()],
            },
            Entry {
                filename: "b-c.lua".into(),
                categories: vec![],
            },
        ];
        let text = render(&entries);
        assert_eq!(
            text,
            "Entry { filename = \"a.lua\", categories = { \"default\", \"safe\", } }\n\
             Entry { filename = \"b-c.lua\", categories = { } }\n"
        );
        assert_eq!(parse(&text).unwrap(), entries);
        assert_eq!(entries[1].id(), "b-c");
    }

    #[test]
    fn index_refuses_other_text() {
        for bad in [
            "Entry { filename = \"../x.lua\", categories = { } }",
            "Entry { filename = \"x.nse\", categories = { } }",
            "Entry { filename = \"x.lua\", categories = { \"a\" } }",
            "Entry { filename = \"x.lua\", categories = { } } os.exit()",
            "os.execute('x')",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
}
