//! Persistent settings, read from TOML files at startup.
//!
//! Two files are read, lowest precedence first:
//!
//! 1. the user's file, `$XDG_CONFIG_HOME/feroprobe/config.toml`
//!    (`~/.config/feroprobe/config.toml` when `XDG_CONFIG_HOME` is unset;
//!    `%APPDATA%\feroprobe\config.toml` on Windows when there is no `HOME`);
//! 2. `.feroproberc` in the current working directory.
//!
//! A key set in a later file overrides the same key in an earlier one, and
//! a key set in neither keeps its built-in default. Command-line options
//! always win over both files. A missing file is skipped; a file that
//! cannot be read or parsed stops the run, so a protection someone set is
//! never silently dropped. Unknown keys get a warning, not an error, so a
//! file written for a newer version still works.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// The name of the per-directory settings file.
pub const DIR_FILE: &str = ".feroproberc";

/// Settings after every file was applied over the built-in defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    /// Refuse device-hostile options (`-sV`, `-O`, `-A`) unless
    /// `--override-ics-protection` is given. Off by default.
    pub ics_protection: bool,
    /// The file that set `ics_protection`, for messages.
    pub ics_protection_source: Option<PathBuf>,
}

/// The keys one file sets. `None` leaves the setting as it was.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Layer {
    ics_protection: Option<bool>,
}

/// The settings plus anything worth telling the user about the files.
#[derive(Debug, Clone, Default)]
pub struct Loaded {
    pub settings: Settings,
    /// The files that were found and read, lowest precedence first.
    pub files: Vec<PathBuf>,
    pub warnings: Vec<String>,
}

/// The user-level settings file. `XDG_CONFIG_HOME` is used only when it is
/// an absolute path, as the XDG base directory spec says.
pub fn user_file(
    xdg_config_home: Option<OsString>,
    home: Option<OsString>,
    appdata: Option<OsString>,
) -> Option<PathBuf> {
    let nonempty = |v: Option<OsString>| v.filter(|v| !v.is_empty()).map(PathBuf::from);
    let base = nonempty(xdg_config_home)
        .filter(|p| p.is_absolute())
        .or_else(|| nonempty(home).map(|h| h.join(".config")))
        .or_else(|| nonempty(appdata))?;
    Some(base.join("feroprobe").join("config.toml"))
}

/// The files to read, lowest precedence first.
pub fn default_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Some(user) = user_file(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
        std::env::var_os("APPDATA"),
    ) {
        files.push(user);
    }
    files.push(PathBuf::from(DIR_FILE));
    files
}

/// Read the settings files in [`default_files`].
pub fn load() -> Result<Loaded> {
    load_from(&default_files())
}

/// Read `files`, lowest precedence first. Missing files are skipped.
pub fn load_from(files: &[PathBuf]) -> Result<Loaded> {
    let mut loaded = Loaded::default();
    for path in files {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(e).with_context(|| format!("reading settings file {}", path.display()));
            }
        };
        let (layer, warnings) = parse_layer(&text, path)?;
        loaded.warnings.extend(warnings);
        if let Some(on) = layer.ics_protection {
            loaded.settings.ics_protection = on;
            loaded.settings.ics_protection_source = Some(path.clone());
        }
        loaded.files.push(path.clone());
    }
    Ok(loaded)
}

/// Parse one file. Returns the keys it sets and warnings for unknown keys.
fn parse_layer(text: &str, path: &Path) -> Result<(Layer, Vec<String>)> {
    let table: toml::Table = text
        .parse()
        .with_context(|| format!("settings file {} is not valid TOML", path.display()))?;
    let mut layer = Layer::default();
    let mut warnings = Vec::new();
    for (key, value) in &table {
        match key.as_str() {
            "ics_protection" => match value.as_bool() {
                Some(b) => layer.ics_protection = Some(b),
                None => bail!(
                    "settings file {}: ics_protection must be true or false, not a {}",
                    path.display(),
                    value.type_str()
                ),
            },
            _ => warnings.push(format!(
                "settings file {}: unknown key \"{key}\", ignored",
                path.display()
            )),
        }
    }
    Ok((layer, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory under the system temp directory.
    fn temp_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "feroprobe-config-{name}-{}-{nanos}",
            std::process::id()
        ));
        // Create it exclusively (fails if it exists) and private, so no
        // other user can plant files or symlinks in it first.
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(&dir).unwrap();
        dir
    }

    fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn defaults_without_files() {
        let dir = temp_dir("none");
        let loaded = load_from(&[dir.join("config.toml"), dir.join(DIR_FILE)]).unwrap();
        assert!(!loaded.settings.ics_protection);
        assert_eq!(loaded.settings.ics_protection_source, None);
        assert!(loaded.files.is_empty());
        assert!(loaded.warnings.is_empty());
    }

    #[test]
    fn user_file_alone() {
        let dir = temp_dir("user");
        let user = write(&dir, "config.toml", "ics_protection = true\n");
        let loaded = load_from(&[user.clone(), dir.join(DIR_FILE)]).unwrap();
        assert!(loaded.settings.ics_protection);
        assert_eq!(loaded.settings.ics_protection_source, Some(user.clone()));
        assert_eq!(loaded.files, vec![user]);
    }

    #[test]
    fn directory_file_overrides_user_file() {
        let dir = temp_dir("both");
        let user = write(&dir, "config.toml", "ics_protection = true\n");
        let rc = write(&dir, DIR_FILE, "ics_protection = false\n");
        let loaded = load_from(&[user.clone(), rc.clone()]).unwrap();
        assert!(!loaded.settings.ics_protection);
        assert_eq!(loaded.settings.ics_protection_source, Some(rc.clone()));

        // And the other way round.
        let user = write(&dir, "config.toml", "ics_protection = false\n");
        let rc = write(&dir, DIR_FILE, "ics_protection = true\n");
        let loaded = load_from(&[user, rc.clone()]).unwrap();
        assert!(loaded.settings.ics_protection);
        assert_eq!(loaded.settings.ics_protection_source, Some(rc));
    }

    #[test]
    fn a_file_without_the_key_keeps_the_earlier_value() {
        let dir = temp_dir("keep");
        let user = write(&dir, "config.toml", "ics_protection = true\n");
        let rc = write(&dir, DIR_FILE, "# nothing set here\n");
        let loaded = load_from(&[user.clone(), rc.clone()]).unwrap();
        assert!(loaded.settings.ics_protection);
        assert_eq!(loaded.settings.ics_protection_source, Some(user.clone()));
        assert_eq!(loaded.files, vec![user, rc]);
    }

    #[test]
    fn unknown_keys_warn() {
        let dir = temp_dir("unknown");
        let rc = write(&dir, DIR_FILE, "ics_protection = true\nfuture_thing = 3\n");
        let loaded = load_from(&[rc]).unwrap();
        assert!(loaded.settings.ics_protection);
        assert_eq!(loaded.warnings.len(), 1);
        assert!(loaded.warnings[0].contains("future_thing"));
    }

    #[test]
    fn bad_files_stop_the_run() {
        let dir = temp_dir("bad");
        let rc = write(&dir, DIR_FILE, "ics_protection = \"yes\"\n");
        let err = load_from(&[rc]).unwrap_err().to_string();
        assert!(
            err.contains("ics_protection must be true or false"),
            "{err}"
        );
        let rc = write(&dir, DIR_FILE, "ics_protection = \n");
        let err = load_from(&[rc]).unwrap_err().to_string();
        assert!(err.contains("not valid TOML"), "{err}");
    }

    // Absolute paths are spelled the Unix way here.
    #[cfg(unix)]
    #[test]
    fn user_file_location() {
        let p = |x: Option<&str>, h: Option<&str>, a: Option<&str>| {
            user_file(x.map(Into::into), h.map(Into::into), a.map(Into::into))
        };
        assert_eq!(
            p(Some("/xdg"), Some("/home/u"), None),
            Some(PathBuf::from("/xdg/feroprobe/config.toml"))
        );
        // A relative or empty XDG_CONFIG_HOME is ignored, as the spec says.
        assert_eq!(
            p(Some("rel"), Some("/home/u"), None),
            Some(PathBuf::from("/home/u/.config/feroprobe/config.toml"))
        );
        assert_eq!(
            p(Some(""), Some("/home/u"), None),
            Some(PathBuf::from("/home/u/.config/feroprobe/config.toml"))
        );
        assert_eq!(
            p(None, None, Some("/appdata")),
            Some(PathBuf::from("/appdata/feroprobe/config.toml"))
        );
        assert_eq!(p(None, None, None), None);
    }
}
