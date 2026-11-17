//! The script engine: Lua scripts that run after the scan, against the
//! hosts and ports it found, like nmap's scripting engine but with
//! FeroProbe's own script library (`fero`).
//!
//! A script is a Lua file that sets `description`, `categories` (and
//! optionally `author`, `license` and `dependencies`), one or more of the
//! rule functions `prerule()`, `hostrule(host)`, `portrule(host, port)` and
//! `postrule()`, and an `action` function that returns the script's
//! output: a string, a table, or both (table first). See
//! `docs/manual.md`, "Script scanning", for the library.
//!
//! Every script run is sandboxed ([`sandbox`]) and its sockets are held
//! to the host it runs against and the ports the scan probed on that host
//! ([`socket::Scope`]).

pub mod args;
mod engine;
pub mod output;
mod sandbox;
pub mod select;
mod socket;

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use args::{ArgTable, ArgValue, ArgsError};
pub use engine::ScriptScan;
pub use output::{ScriptResult, ScriptTable, ScriptValue};
pub use sandbox::{INSTRUCTION_LIMIT, MEMORY_LIMIT};
pub use socket::Scope;

/// The scripts built into FeroProbe, written for it: (id, source).
const BUILT_IN: &[(&str, &str)] = &[("banner", include_str!("../../lua-scripts/banner.lua"))];

/// The file name extension of scripts.
pub const EXTENSION: &str = "lua";

/// The rule functions a script defines.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rules {
    pub prerule: bool,
    pub hostrule: bool,
    pub portrule: bool,
    pub postrule: bool,
}

impl Rules {
    /// The names of the rules defined, in the order they run.
    pub fn names(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        for (on, name) in [
            (self.prerule, "prerule"),
            (self.hostrule, "hostrule"),
            (self.portrule, "portrule"),
            (self.postrule, "postrule"),
        ] {
            if on {
                v.push(name);
            }
        }
        v
    }
}

/// How a script was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// By its name, or a pattern of names.
    Name,
    /// By a category or an expression of categories.
    Category,
    /// As a file path.
    File,
    /// As a file in a directory given by path.
    Directory,
}

/// A loaded script.
#[derive(Debug, Clone)]
pub struct Script {
    /// The script's name: its file name without `.lua`.
    pub id: String,
    /// The file it came from; `None` for a built-in script.
    pub path: Option<PathBuf>,
    pub description: String,
    pub authors: Vec<String>,
    pub license: Option<String>,
    pub categories: Vec<String>,
    /// Scripts that must run before this one when both are chosen.
    pub dependencies: Vec<String>,
    pub rules: Rules,
    /// `+` before its rule in `--script`: it runs on every host and port
    /// whatever its rules say.
    pub forced: bool,
    pub selection: Selection,
    pub(crate) source: Arc<str>,
}

/// A script that could not be found or loaded, or a `--script` rule that
/// matched nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptError(pub String);

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ScriptError {}

fn err<T>(msg: impl Into<String>) -> Result<T, ScriptError> {
    Err(ScriptError(msg.into()))
}

/// How long loading one script (running its file to read its fields)
/// may take.
const LOAD_TIMEOUT: Duration = Duration::from_secs(2);

impl Script {
    /// Load a script from its source: run the file in a sandbox and read
    /// its fields. Nothing in it can reach the network while loading.
    pub fn load(id: &str, path: Option<PathBuf>, source: &str) -> Result<Script, ScriptError> {
        let name = path
            .as_ref()
            .map_or_else(|| format!("{id}.{EXTENSION}"), |p| p.display().to_string());
        let budget = sandbox::Budget::new();
        budget.reset(Some(Instant::now() + LOAD_TIMEOUT));
        let lua = sandbox::new_state(&budget)
            .map_err(|e| ScriptError(format!("{name}: cannot start Lua: {e}")))?;
        engine::install_library(
            &lua,
            id,
            "load",
            &ArgTable::default(),
            &Arc::new(Scope::default()),
        )
        .map_err(|e| ScriptError(format!("{name}: {e}")))?;
        lua.load(source)
            .set_name(format!("@{name}"))
            .exec()
            .map_err(|e| {
                ScriptError(format!(
                    "{name}: could not load script: {}",
                    sandbox::error_text(&e, &budget)
                ))
            })?;
        let g = lua.globals();
        let is_fn = |n: &str| matches!(g.raw_get::<mlua::Value>(n), Ok(mlua::Value::Function(_)));
        let rules = Rules {
            prerule: is_fn("prerule"),
            hostrule: is_fn("hostrule"),
            portrule: is_fn("portrule"),
            postrule: is_fn("postrule"),
        };
        if !is_fn("action") {
            return err(format!("{name}: the script has no action function"));
        }
        if rules == Rules::default() {
            return err(format!(
                "{name}: the script has no rule function (prerule, hostrule, portrule or postrule)"
            ));
        }
        let strings = |field: &str, required: bool| -> Result<Vec<String>, ScriptError> {
            match g.raw_get::<mlua::Value>(field) {
                Ok(mlua::Value::Table(t)) => t
                    .sequence_values::<String>()
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| ScriptError(format!("{name}: {field} must be a list of strings"))),
                Ok(mlua::Value::String(s)) if field == "author" => Ok(vec![s.to_string_lossy()]),
                Ok(mlua::Value::Nil) if !required => Ok(Vec::new()),
                _ => err(format!("{name}: {field} must be a list of strings")),
            }
        };
        let categories = strings("categories", true)?;
        let authors = strings("author", false)?;
        let dependencies = strings("dependencies", false)?;
        let text = |field: &str| match g.raw_get::<mlua::Value>(field) {
            Ok(mlua::Value::String(s)) => Some(s.to_string_lossy()),
            _ => None,
        };
        Ok(Script {
            id: id.to_string(),
            path,
            description: text("description").unwrap_or_default(),
            authors,
            license: text("license"),
            categories,
            dependencies,
            rules,
            forced: false,
            selection: Selection::Name,
            source: Arc::from(source),
        })
    }

    /// The built-in scripts.
    pub fn built_in() -> Result<Vec<Script>, ScriptError> {
        BUILT_IN
            .iter()
            .map(|(id, src)| Script::load(id, None, src))
            .collect()
    }

    fn from_file(path: &Path) -> Result<Script, ScriptError> {
        let source = std::fs::read_to_string(path)
            .map_err(|e| ScriptError(format!("cannot read script {}: {e}", path.display())))?;
        let id = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let id = id
            .strip_suffix(&format!(".{EXTENSION}"))
            .unwrap_or(&id)
            .to_string();
        Script::load(&id, Some(path.to_path_buf()), &source)
    }
}

/// The scripts `--script` chooses, in the order nmap would: the built-in
/// scripts any rule matches (by name, category or expression), then the
/// files and directories the other rules name. A rule that matches
/// nothing is an error, as in nmap.
pub fn choose(spec: &str) -> Result<Vec<Script>, ScriptError> {
    choose_from(spec, Script::built_in()?)
}

fn choose_from(spec: &str, built_in: Vec<Script>) -> Result<Vec<Script>, ScriptError> {
    let rules = select::split_rules(spec);
    if rules.is_empty() {
        return err("--script needs at least one script, category or path");
    }
    let parsed: Vec<Option<select::Expr>> = rules.iter().map(|r| select::parse(&r.text)).collect();
    let mut used = vec![false; rules.len()];
    let mut chosen: Vec<Script> = Vec::new();
    for script in built_in {
        let mut pick: Option<(bool, Selection)> = None;
        for (i, rule) in rules.iter().enumerate() {
            let Some(e) = &parsed[i] else { continue };
            let mut by_name = false;
            if e.matches(&script.id, &script.categories, &mut by_name) {
                used[i] = true;
                let sel = if by_name {
                    Selection::Name
                } else {
                    Selection::Category
                };
                let forced = rule.forced || pick.is_some_and(|(f, _)| f);
                pick = Some((forced, pick.map_or(sel, |(_, s)| s)));
            }
        }
        if let Some((forced, selection)) = pick {
            chosen.push(Script {
                forced,
                selection,
                ..script
            });
        }
    }
    for (i, rule) in rules.iter().enumerate() {
        if used[i] {
            continue;
        }
        let text = &rule.text;
        let path = Path::new(text);
        let with_ext = PathBuf::from(format!("{text}.{EXTENSION}"));
        let mut found = Vec::new();
        if path.is_dir() {
            if !text.ends_with('/') && !text.ends_with(std::path::MAIN_SEPARATOR) {
                return err(format!(
                    "directory '{text}' found, but will not match without '/'"
                ));
            }
            let mut files: Vec<PathBuf> = std::fs::read_dir(path)
                .map_err(|e| ScriptError(format!("cannot read directory {text}: {e}")))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == EXTENSION))
                .collect();
            files.sort();
            for f in files {
                found.push((Script::from_file(&f)?, Selection::Directory));
            }
        } else if path.is_file() {
            found.push((Script::from_file(path)?, Selection::File));
        } else if with_ext.is_file() {
            found.push((Script::from_file(&with_ext)?, Selection::File));
        } else {
            return err(format!(
                "'{text}' did not match a category, filename, or directory"
            ));
        }
        for (s, selection) in found {
            let same_file = |c: &Script| {
                c.path.is_some()
                    && c.path.as_ref().and_then(|p| p.canonicalize().ok())
                        == s.path.as_ref().and_then(|p| p.canonicalize().ok())
            };
            if chosen.iter().any(same_file) {
                continue;
            }
            chosen.push(Script {
                forced: rule.forced,
                selection,
                ..s
            });
        }
    }
    let mut ids: Vec<&str> = chosen.iter().map(|s| s.id.as_str()).collect();
    ids.sort_unstable();
    if let Some(w) = ids.windows(2).find(|w| w[0] == w[1]) {
        return err(format!("duplicate script ID: '{}'", w[0]));
    }
    Ok(chosen)
}

/// `--script-help`: each script's name, categories and description, in
/// nmap's layout (without nmap's link to its online documentation).
pub fn help_text(scripts: &[Script]) -> String {
    let mut out = String::new();
    for s in scripts {
        out.push('\n');
        out.push_str(&s.id);
        out.push('\n');
        out.push_str("Categories: ");
        out.push_str(&s.categories.join(" "));
        out.push('\n');
        match &s.path {
            Some(p) => out.push_str(&format!("File: {}\n", p.display())),
            None => out.push_str("Built into FeroProbe\n"),
        }
        for line in s.description.lines() {
            if line.is_empty() {
                out.push('\n');
            } else {
                out.push_str("  ");
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

/// The order scripts run in: each after the chosen scripts it depends on.
/// Returns the run levels, first to last, or the dependency cycle.
pub(crate) fn run_levels(scripts: &[Arc<Script>]) -> Result<Vec<Vec<Arc<Script>>>, ScriptError> {
    use std::collections::HashMap;
    let by_id: HashMap<&str, &Arc<Script>> = scripts.iter().map(|s| (s.id.as_str(), s)).collect();
    let mut level: HashMap<String, usize> = HashMap::new();
    fn visit(
        s: &Script,
        by_id: &HashMap<&str, &Arc<Script>>,
        level: &mut HashMap<String, usize>,
        chain: &mut Vec<String>,
    ) -> Result<usize, ScriptError> {
        if let Some(&l) = level.get(&s.id) {
            return Ok(l);
        }
        if chain.contains(&s.id) {
            chain.push(s.id.clone());
            return err(format!(
                "circular dependency in chain `{}`",
                chain.join("->")
            ));
        }
        chain.push(s.id.clone());
        let mut l = 1;
        for d in &s.dependencies {
            if let Some(dep) = by_id.get(d.as_str()) {
                l = l.max(visit(dep, by_id, level, chain)? + 1);
            }
        }
        chain.pop();
        level.insert(s.id.clone(), l);
        Ok(l)
    }
    for s in scripts {
        visit(s, &by_id, &mut level, &mut Vec::new())?;
    }
    let top = level.values().copied().max().unwrap_or(0);
    Ok((1..=top)
        .map(|l| {
            scripts
                .iter()
                .filter(|s| level[&s.id] == l)
                .cloned()
                .collect()
        })
        .collect())
}

#[cfg(test)]
mod tests;
