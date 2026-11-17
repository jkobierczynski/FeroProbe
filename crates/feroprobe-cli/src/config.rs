//! Persistent settings, read from TOML files at startup.
//!
//! Files are read in this order, lowest precedence first:
//!
//! 1. the user's file, `$XDG_CONFIG_HOME/feroprobe/config.toml`
//!    (`~/.config/feroprobe/config.toml` when `XDG_CONFIG_HOME` is unset;
//!    `%APPDATA%\feroprobe\config.toml` on Windows when there is no `HOME`);
//!    under `sudo`, the invoking user's `~/.config/feroprobe/config.toml`
//!    is read next, so a setting in your own file still applies to
//!    `sudo feroprobe ...` (skipped when an absolute `XDG_CONFIG_HOME` was
//!    kept, since that already names the file to use);
//! 2. `.feroproberc` in the current working directory.
//!
//! A key set in a later file overrides the same key in an earlier one, and
//! a key set in neither keeps its built-in default, with one exception: a
//! `.feroproberc` may switch ICS protection on but never off (a directory
//! can be shared, unpacked from an archive or cloned, so its file must not
//! weaken what the user's own file set). Command-line options always win
//! over both files. A missing file is skipped; a file that cannot be read
//! or parsed stops the run, so a protection someone set is never silently
//! dropped. Unknown keys get a warning, not an error, so a file written for
//! a newer version still works.
//!
//! The files are opened carefully, since under `sudo` root reads paths an
//! ordinary user controls ([`read_settings_file`]): no symbolic links as
//! root, regular files only, at most [`MAX_FILE_SIZE`] bytes, owned by
//! root or the invoking user and not writable by everyone. A file owned by
//! someone else is skipped with a warning; parse errors name the line and
//! column, and quote the file's own message only when the invoking user
//! owns it, so the error cannot be used to read someone else's file.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// The name of the per-directory settings file.
pub const DIR_FILE: &str = ".feroproberc";

/// The largest settings file FeroProbe reads. Real files are a few lines.
pub const MAX_FILE_SIZE: u64 = 64 * 1024;

/// Whether this binary was built with ICS protection always on (the
/// `ics-protection-default` Cargo feature). Settings files cannot switch
/// it off then; only `--override-ics-protection`, for one run.
pub const ICS_BUILT_IN: bool = cfg!(feature = "ics-protection-default");

/// Settings after every file was applied over the built-in defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    /// Refuse device-hostile options (`-sV`, `-O`, `-A`) unless
    /// `--override-ics-protection` is given. Off by default.
    pub ics_protection: bool,
    /// The file that set `ics_protection`, for messages.
    pub ics_protection_source: Option<PathBuf>,
    /// Protection is built into the binary and cannot be switched off by
    /// a settings file ([`ICS_BUILT_IN`]).
    pub ics_built_in: bool,
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

/// The files to read, lowest precedence first. Fails only when the
/// invoking user of `sudo` cannot be looked up, rather than silently
/// leaving their settings out.
pub fn default_files() -> Result<Vec<PathBuf>> {
    let xdg = std::env::var_os("XDG_CONFIG_HOME");
    // A preserved, absolute XDG_CONFIG_HOME (sudo -E, or env_keep) already
    // names the invoking user's settings: use it alone, as they chose it.
    let xdg_used = xdg
        .as_ref()
        .is_some_and(|x| !x.is_empty() && std::path::Path::new(x).is_absolute());
    let own = user_file(xdg, std::env::var_os("HOME"), std::env::var_os("APPDATA"));
    let invoking = if xdg_used {
        None
    } else {
        sudo_user_home()?.and_then(|h| user_file(None, Some(h.into_os_string()), None))
    };
    Ok(files_for(own, invoking))
}

/// The file list: this user's file, then (under sudo) the invoking user's
/// file, then the working directory's. Raw scans need root, so FeroProbe
/// often runs under `sudo`, which points `HOME` at root's home: without
/// the invoking user's file, the protection they set would be skipped.
fn files_for(own: Option<PathBuf>, invoking: Option<PathBuf>) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = own.into_iter().collect();
    if let Some(f) = invoking
        && !files.contains(&f)
    {
        files.push(f);
    }
    files.push(PathBuf::from(DIR_FILE));
    files
}

/// The home directory of the user who ran `sudo`, when this process runs
/// as root under sudo (`SUDO_USER` names someone other than root). `None`
/// when not under sudo or no such account exists; an error when the
/// account database cannot be read.
#[cfg(unix)]
fn sudo_user_home() -> Result<Option<PathBuf>> {
    use std::ffi::{CStr, CString};
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(None);
    }
    let Some(user) = std::env::var_os("SUDO_USER").filter(|n| !n.is_empty() && n != "root") else {
        return Ok(None);
    };
    let Ok(name) = CString::new(user.as_bytes()) else {
        return Ok(None);
    };
    let mut size = 16 * 1024;
    loop {
        // SAFETY: passwd is plain data; getpwnam_r fills it in.
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let mut buf = vec![0 as libc::c_char; size];
        // SAFETY: every pointer is valid for the call; buf outlives the use
        // of pw's string fields below.
        let rc = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                &mut pw,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && size < 1024 * 1024 {
            size *= 4;
            continue;
        }
        if rc != 0 {
            bail!(
                "looking up SUDO_USER {} to read their settings file: {}",
                user.to_string_lossy(),
                std::io::Error::from_raw_os_error(rc)
            );
        }
        if result.is_null() || pw.pw_dir.is_null() {
            return Ok(None);
        }
        // SAFETY: getpwnam_r succeeded, so pw_dir points to a C string in buf.
        let dir = unsafe { CStr::from_ptr(pw.pw_dir) };
        let dir = PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes()));
        return Ok(dir.is_absolute().then_some(dir));
    }
}

#[cfg(not(unix))]
fn sudo_user_home() -> Result<Option<PathBuf>> {
    Ok(None)
}

/// Read the settings files in [`default_files`].
pub fn load() -> Result<Loaded> {
    load_from(&default_files()?)
}

/// Read `files`, lowest precedence first. Missing files are skipped.
pub fn load_from(files: &[PathBuf]) -> Result<Loaded> {
    load_with(files, ICS_BUILT_IN)
}

/// [`load_from`], with `built_in` standing for [`ICS_BUILT_IN`] so both
/// builds can be tested.
fn load_with(files: &[PathBuf], built_in: bool) -> Result<Loaded> {
    load_as(files, built_in, &Owners::of_this_process())
}

/// [`load_with`] for the given owners, so tests can act as root or not.
fn load_as(files: &[PathBuf], built_in: bool, owners: &Owners) -> Result<Loaded> {
    let mut loaded = Loaded::default();
    loaded.settings.ics_protection = built_in;
    loaded.settings.ics_built_in = built_in;
    for path in files {
        let Some(file) = read_settings_file(path, owners)? else {
            continue;
        };
        let text = match file {
            FileRead::Text(text) => text,
            FileRead::Skipped(why) => {
                loaded.warnings.push(why);
                continue;
            }
        };
        let (layer, warnings) = parse_layer(&text.text, path, text.quote_errors)?;
        loaded.warnings.extend(warnings);
        let directory_file = is_directory_file(path);
        if built_in && layer.ics_protection == Some(false) {
            loaded.warnings.push(format!(
                "settings file {}: ics_protection = false ignored: this FeroProbe was built \
                 with ICS protection always on; --override-ics-protection allows a single run",
                path.display()
            ));
        } else if directory_file
            && layer.ics_protection == Some(false)
            && loaded.settings.ics_protection
        {
            // Tighten only: a directory's file may not undo the user's.
            loaded.warnings.push(format!(
                "settings file {}: ics_protection = false ignored: a {DIR_FILE} in the working \
                 directory can switch ICS protection on but not off. It stays on ({}); \
                 change that file, or pass --override-ics-protection for a single run",
                path.display(),
                source_text(loaded.settings.ics_protection_source.as_deref()),
            ));
        } else if let Some(on) = layer.ics_protection {
            loaded.settings.ics_protection = on;
            loaded.settings.ics_protection_source = Some(path.clone());
        }
        loaded.files.push(path.clone());
    }
    Ok(loaded)
}

/// Whether `path` is a per-directory `.feroproberc` rather than a user's
/// own settings file.
fn is_directory_file(path: &Path) -> bool {
    path.file_name().is_some_and(|n| n == DIR_FILE)
}

/// Where protection was switched on, for messages.
fn source_text(source: Option<&Path>) -> String {
    match source {
        Some(p) => format!("ics_protection = true in {}", p.display()),
        None => "built into this FeroProbe".to_string(),
    }
}

/// Who may own a settings file: root, this process's user, and under
/// `sudo` the user who ran it.
#[derive(Debug, Clone)]
// Off Unix files carry no owner, so nothing reads these.
#[cfg_attr(not(unix), allow(dead_code))]
struct Owners {
    /// This process runs as root.
    root: bool,
    /// The user whose settings these are: `SUDO_UID` when root under
    /// sudo, else the effective user.
    invoking: u32,
    trusted: Vec<u32>,
}

impl Owners {
    #[cfg(unix)]
    fn of_this_process() -> Owners {
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        let sudo = (euid == 0).then(crate::privdrop::sudo_ids).flatten();
        let invoking = sudo.map_or(euid, |(uid, _)| uid);
        let mut trusted = vec![0, euid, invoking];
        trusted.dedup();
        Owners {
            root: euid == 0,
            invoking,
            trusted,
        }
    }

    #[cfg(not(unix))]
    fn of_this_process() -> Owners {
        Owners {
            root: false,
            invoking: 0,
            trusted: Vec::new(),
        }
    }
}

/// A settings file's text, and whether its parse errors may quote it.
struct Text {
    text: String,
    quote_errors: bool,
}

/// What [`read_settings_file`] found.
// Off Unix a file is never skipped for its owner.
#[cfg_attr(not(unix), allow(dead_code))]
enum FileRead {
    Text(Text),
    /// Not read, with the warning that says why.
    Skipped(String),
}

/// Read one settings file defensively. `Ok(None)` when it does not exist.
///
/// Under `sudo`, root opens paths an ordinary user controls: the working
/// directory's `.feroproberc` and the invoking user's `config.toml`. So:
///
/// - a file owned by anyone but root or the invoking user is skipped with
///   a warning (it is not theirs to trust, and someone else may have
///   planted it in a shared directory);
/// - as root, a symbolic link is refused (a link to `/etc/shadow` must not
///   be opened); an ordinary user may link their settings, since they can
///   only read what they could read anyway;
/// - the file is opened with `O_NONBLOCK` and must be a regular file (a
///   FIFO would hang the run, a device could be endless), at most
///   [`MAX_FILE_SIZE`] bytes, and not writable by everyone.
///
/// Anything else wrong is an error that stops the run, as before: a
/// protection someone set is never dropped quietly.
#[cfg(unix)]
fn read_settings_file(path: &Path, owners: &Owners) -> Result<Option<FileRead>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let shown = path.display();
    let link = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading settings file {shown}")),
    };
    if !owners.trusted.contains(&link.uid()) {
        return Ok(Some(FileRead::Skipped(format!(
            "settings file {shown} ignored: it belongs to user id {}, not to you or root",
            link.uid()
        ))));
    }
    if link.file_type().is_symlink() && owners.root {
        bail!(
            "settings file {shown} is a symbolic link; running as root, FeroProbe does not \
             follow links to settings files. Replace it with the file itself"
        );
    }
    let mut flags = libc::O_NONBLOCK | libc::O_NOCTTY;
    if owners.root {
        flags |= libc::O_NOFOLLOW;
    }
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        // ELOOP: swapped for a link since the check above.
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => bail!(
            "settings file {shown} is a symbolic link; running as root, FeroProbe does not \
             follow links to settings files. Replace it with the file itself"
        ),
        Err(e) => return Err(e).with_context(|| format!("reading settings file {shown}")),
    };
    // Check what was opened, not the path: it may have changed meanwhile.
    let meta = file
        .metadata()
        .with_context(|| format!("reading settings file {shown}"))?;
    if !meta.file_type().is_file() {
        bail!("settings file {shown} is not a regular file");
    }
    if !owners.trusted.contains(&meta.uid()) {
        return Ok(Some(FileRead::Skipped(format!(
            "settings file {shown} ignored: it belongs to user id {}, not to you or root",
            meta.uid()
        ))));
    }
    if meta.mode() & 0o002 != 0 {
        bail!(
            "settings file {shown} is writable by every user, so anyone could have changed \
             it; remove that permission (chmod o-w {shown})"
        );
    }
    if meta.len() > MAX_FILE_SIZE {
        bail!(
            "settings file {shown} is larger than {} KB; it cannot be a FeroProbe settings file",
            MAX_FILE_SIZE / 1024
        );
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_SIZE + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading settings file {shown}"))?;
    if bytes.len() as u64 > MAX_FILE_SIZE {
        bail!(
            "settings file {shown} is larger than {} KB; it cannot be a FeroProbe settings file",
            MAX_FILE_SIZE / 1024
        );
    }
    let quote_errors = meta.uid() == owners.invoking;
    let Ok(text) = String::from_utf8(bytes) else {
        bail!("settings file {shown} is not valid TOML: it is not UTF-8 text");
    };
    Ok(Some(FileRead::Text(Text { text, quote_errors })))
}

#[cfg(not(unix))]
fn read_settings_file(path: &Path, _owners: &Owners) -> Result<Option<FileRead>> {
    use std::io::Read;
    let shown = path.display();
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading settings file {shown}")),
    };
    let mut bytes = Vec::new();
    file.take(MAX_FILE_SIZE + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading settings file {shown}"))?;
    if bytes.len() as u64 > MAX_FILE_SIZE {
        bail!(
            "settings file {shown} is larger than {} KB; it cannot be a FeroProbe settings file",
            MAX_FILE_SIZE / 1024
        );
    }
    let Ok(text) = String::from_utf8(bytes) else {
        bail!("settings file {shown} is not valid TOML: it is not UTF-8 text");
    };
    Ok(Some(FileRead::Text(Text {
        text,
        quote_errors: true,
    })))
}

/// Parse one file. Returns the keys it sets and warnings for unknown keys.
/// A parse error names the line and column; it quotes the parser's message
/// (which can repeat a key or value from the file) only when `quote` says
/// the file is the invoking user's own, and never prints the source line.
fn parse_layer(text: &str, path: &Path, quote: bool) -> Result<(Layer, Vec<String>)> {
    let table: toml::Table = match text.parse() {
        Ok(t) => t,
        Err(e) => {
            let e: toml::de::Error = e;
            let at = e.span().map(|span| {
                let before = &text[..span.start.min(text.len())];
                let line = before.matches('\n').count() + 1;
                let column = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
                format!(" at line {line}, column {column}")
            });
            let what = if quote {
                format!(": {}", e.message().trim_end())
            } else {
                String::new()
            };
            bail!(
                "settings file {} is not valid TOML{}{what}",
                path.display(),
                at.unwrap_or_default()
            );
        }
    };
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
            // The key's name is the file's text: quoted only when it is
            // the invoking user's own file, as with parse errors.
            _ if quote => warnings.push(format!(
                "settings file {}: unknown key \"{key}\", ignored",
                path.display()
            )),
            _ => warnings.push(format!(
                "settings file {}: an unknown key, ignored",
                path.display()
            )),
        }
    }
    Ok((layer, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default build's loading, whatever features this test build has,
    /// with this test's user as the invoking one (CI also runs the tests
    /// under `sudo -E`, where SUDO_UID would name someone else).
    fn load_from(files: &[PathBuf]) -> Result<Loaded> {
        #[cfg(unix)]
        return load_as(files, false, &owners(false));
        #[cfg(not(unix))]
        load_with(files, false)
    }

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
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(), 0o700)
            .create(&dir)
            .unwrap();
        #[cfg(not(unix))]
        std::fs::DirBuilder::new().create(&dir).unwrap();
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
    fn directory_file_can_tighten_but_not_loosen() {
        let dir = temp_dir("both");
        let user = write(&dir, "config.toml", "ics_protection = true\n");
        let rc = write(&dir, DIR_FILE, "ics_protection = false\n");
        let loaded = load_from(&[user.clone(), rc.clone()]).unwrap();
        assert!(loaded.settings.ics_protection);
        assert_eq!(loaded.settings.ics_protection_source, Some(user.clone()));
        assert_eq!(loaded.warnings.len(), 1, "{:?}", loaded.warnings);
        assert!(
            loaded.warnings[0].contains("can switch ICS protection on but not off"),
            "{:?}",
            loaded.warnings
        );
        assert!(loaded.warnings[0].contains("config.toml"));
        assert_eq!(loaded.files, vec![user.clone(), rc.clone()]);

        // false over an already-off setting is no change and no warning.
        let off = write(&dir, "off.toml", "ics_protection = false\n");
        let loaded = load_from(&[off, rc.clone()]).unwrap();
        assert!(!loaded.settings.ics_protection);
        assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);

        // A later user file (sudo: the invoking user's) may still switch
        // off what root's file switched on; only the directory is limited.
        let user2 = write(&dir, "config2.toml", "ics_protection = false\n");
        let loaded = load_from(&[user.clone(), user2.clone()]).unwrap();
        assert!(!loaded.settings.ics_protection);

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
    fn sudo_adds_the_invoking_users_file() {
        let root = PathBuf::from("/root/.config/feroprobe/config.toml");
        let user = PathBuf::from("/home/u/.config/feroprobe/config.toml");
        assert_eq!(
            files_for(Some(root.clone()), Some(user.clone())),
            vec![root.clone(), user.clone(), PathBuf::from(DIR_FILE)]
        );
        // sudo -E keeps HOME: the same file is read once.
        assert_eq!(
            files_for(Some(user.clone()), Some(user.clone())),
            vec![user.clone(), PathBuf::from(DIR_FILE)]
        );
        assert_eq!(files_for(None, None), vec![PathBuf::from(DIR_FILE)]);
    }

    #[test]
    fn built_in_protection_cannot_be_switched_off_by_a_file() {
        let dir = temp_dir("builtin");
        let loaded = load_with(&[dir.join(DIR_FILE)], true).unwrap();
        assert!(loaded.settings.ics_protection);
        assert!(loaded.settings.ics_built_in);
        assert_eq!(loaded.settings.ics_protection_source, None);
        let rc = write(&dir, DIR_FILE, "ics_protection = false\n");
        let loaded = load_with(&[rc], true).unwrap();
        assert!(loaded.settings.ics_protection);
        assert_eq!(loaded.warnings.len(), 1);
        assert!(loaded.warnings[0].contains("built with ICS protection always on"));
        // The default build: off, and a file can turn it on and off.
        let loaded = load_with(&[dir.join("none.toml")], false).unwrap();
        assert!(!loaded.settings.ics_protection && !loaded.settings.ics_built_in);
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

    /// Owners as this test process sees them, acting as root (`root`) or
    /// not; root's own uid stays trusted either way.
    #[cfg(unix)]
    fn owners(root: bool) -> Owners {
        // SAFETY: geteuid has no preconditions.
        let me = unsafe { libc::geteuid() };
        Owners {
            root,
            invoking: me,
            trusted: vec![0, me],
        }
    }

    #[cfg(unix)]
    #[test]
    fn links_are_refused_as_root_and_followed_otherwise() {
        let dir = temp_dir("link");
        let target = write(&dir, "real.toml", "ics_protection = true\n");
        let rc = dir.join(DIR_FILE);
        std::os::unix::fs::symlink(&target, &rc).unwrap();
        let err = load_as(std::slice::from_ref(&rc), false, &owners(true))
            .unwrap_err()
            .to_string();
        assert!(err.contains("symbolic link"), "{err}");
        let loaded = load_as(&[rc], false, &owners(false)).unwrap();
        assert!(loaded.settings.ics_protection);
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_does_not_hang_the_run() {
        let dir = temp_dir("fifo");
        let rc = dir.join(DIR_FILE);
        let c = std::ffi::CString::new(rc.to_str().unwrap()).unwrap();
        // SAFETY: c is a valid C string.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        for root in [true, false] {
            let err = load_as(std::slice::from_ref(&rc), false, &owners(root))
                .unwrap_err()
                .to_string();
            assert!(err.contains("not a regular file"), "{err}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn oversized_and_world_writable_files_stop_the_run() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("size");
        let big = "# padding\n".repeat(8000);
        let rc = write(&dir, DIR_FILE, &big);
        let err = load_as(std::slice::from_ref(&rc), false, &owners(true))
            .unwrap_err()
            .to_string();
        assert!(err.contains("larger than 64 KB"), "{err}");
        let rc = write(&dir, DIR_FILE, "ics_protection = true\n");
        std::fs::set_permissions(&rc, std::fs::Permissions::from_mode(0o666)).unwrap();
        let err = load_as(&[rc], false, &owners(true))
            .unwrap_err()
            .to_string();
        assert!(err.contains("writable by every user"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn someone_elses_file_is_skipped_with_a_warning() {
        let dir = temp_dir("foreign");
        let rc = write(&dir, DIR_FILE, "ics_protection = true\n");
        // Trust nobody, so this test's own file counts as someone else's.
        let nobody = Owners {
            root: true,
            invoking: u32::MAX - 1,
            trusted: vec![u32::MAX - 1],
        };
        let loaded = load_as(&[rc], false, &nobody).unwrap();
        assert!(!loaded.settings.ics_protection);
        assert!(loaded.files.is_empty());
        assert_eq!(loaded.warnings.len(), 1);
        assert!(
            loaded.warnings[0].contains("not to you or root"),
            "{:?}",
            loaded.warnings
        );
    }

    #[cfg(unix)]
    #[test]
    fn parse_errors_quote_only_the_invoking_users_own_file() {
        let dir = temp_dir("quote");
        let rc = write(&dir, DIR_FILE, "root:$6$secrethash:19000:0:99999:7:::\n");
        // Root's file read under sudo: line and column only.
        let mut o = owners(true);
        o.invoking = u32::MAX - 1;
        let err = format!(
            "{:#}",
            load_as(std::slice::from_ref(&rc), false, &o).unwrap_err()
        );
        assert!(err.contains("not valid TOML at line 1, column"), "{err}");
        assert!(
            !err.contains("secrethash") && !err.contains("root:"),
            "{err}"
        );
        // The user's own file: the parser's message too, still no source line.
        let err = format!(
            "{:#}",
            load_as(std::slice::from_ref(&rc), false, &owners(false)).unwrap_err()
        );
        assert!(err.contains("not valid TOML at line 1"), "{err}");
        assert!(!err.contains("secrethash"), "{err}");
        // A file that parses: an unknown key is named only in the user's own.
        let rc = write(&dir, DIR_FILE, "[\"private-project-name\"]\n");
        let loaded = load_as(std::slice::from_ref(&rc), false, &o).unwrap();
        assert_eq!(loaded.warnings.len(), 1);
        assert!(
            !loaded.warnings[0].contains("private-project-name"),
            "{:?}",
            loaded.warnings
        );
        let loaded = load_as(&[rc], false, &owners(false)).unwrap();
        assert!(
            loaded.warnings[0].contains("private-project-name"),
            "{:?}",
            loaded.warnings
        );
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
