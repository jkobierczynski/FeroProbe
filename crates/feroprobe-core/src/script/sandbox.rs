//! The Lua state a script runs in. Each script run gets a fresh one, with
//! only Lua's `string`, `table`, `math`, `utf8` and `coroutine` libraries,
//! the clock and date functions of `os`, and FeroProbe's `fero` library:
//! no `io`, no `os.execute` or `os.getenv`, no `require`, `dofile`,
//! `loadfile` or `debug`, no `string.dump`, and `load` only for source
//! text, never bytecode. Lua's pattern functions are replaced by
//! FeroProbe's own (see the `pattern` module) so that the limits reach
//! them too. A memory limit, an instruction limit and a
//! deadline bound every run; once one of them trips, `pcall`, `xpcall`
//! and `coroutine.resume` pass the error on instead of catching it, so a
//! script cannot carry on past it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use mlua::{HookTriggers, Lua, LuaOptions, StdLib, Table, Value, VmState};

/// Memory one script run may use.
pub const MEMORY_LIMIT: usize = 64 * 1024 * 1024;

/// Lua instructions one script run may execute: some seconds of pure
/// computation. Time spent waiting on the network does not count.
pub const INSTRUCTION_LIMIT: u64 = 1 << 30;

/// How often (in instructions) the limits are checked.
const CHECK_EVERY: u32 = 10_000;

/// The error message of a run stopped by its deadline.
pub const TIMED_OUT: &str = "script timed out";
/// The error message of a run stopped by the instruction limit.
pub const TOO_LONG: &str = "script ran too long (instruction limit reached)";

/// A run's limits, shared with the instruction hook.
#[derive(Debug)]
pub(crate) struct Budget {
    left: AtomicU64,
    /// Milliseconds after `start`, or `u64::MAX` for none.
    deadline_ms: AtomicU64,
    start: Instant,
    tripped: AtomicBool,
}

impl Budget {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Budget {
            left: AtomicU64::new(INSTRUCTION_LIMIT),
            deadline_ms: AtomicU64::new(u64::MAX),
            start: Instant::now(),
            tripped: AtomicBool::new(false),
        })
    }

    /// Stop the run at `deadline` (or never, with `None`), with a fresh
    /// instruction allowance.
    pub(crate) fn reset(&self, deadline: Option<Instant>) {
        let ms = deadline.map_or(u64::MAX, |d| {
            d.saturating_duration_since(self.start).as_millis() as u64
        });
        self.deadline_ms.store(ms, Ordering::Relaxed);
        self.left.store(INSTRUCTION_LIMIT, Ordering::Relaxed);
        self.tripped.store(false, Ordering::Relaxed);
    }

    /// Why the run must stop, if it must, counting another
    /// [`CHECK_EVERY`] instructions.
    fn check(&self) -> Option<&'static str> {
        self.charge(u64::from(CHECK_EVERY))
    }

    /// Count `n` more units of work (instructions, or steps of Rust code
    /// run for the script such as pattern matching), and say why the run
    /// must stop, if it must.
    pub(crate) fn charge(&self, n: u64) -> Option<&'static str> {
        let left = self.left.load(Ordering::Relaxed);
        if left < n {
            self.left.store(0, Ordering::Relaxed);
            self.tripped.store(true, Ordering::Relaxed);
            return Some(TOO_LONG);
        }
        self.left.store(left - n, Ordering::Relaxed);
        let deadline = self.deadline_ms.load(Ordering::Relaxed);
        if deadline != u64::MAX && self.start.elapsed().as_millis() as u64 >= deadline {
            self.tripped.store(true, Ordering::Relaxed);
            return Some(TIMED_OUT);
        }
        None
    }

    pub(crate) fn tripped(&self) -> bool {
        self.tripped.load(Ordering::Relaxed)
    }
}

/// Lua code run in every new state, before the script: makes `load` text
/// only, and keeps `pcall`, `xpcall` and `coroutine.resume` from catching
/// the error a tripped limit raises. Written for FeroProbe.
const PRELUDE: &str = r#"
local tripped, raw_load, raw_pcall, raw_xpcall, raw_resume, error, select =
  ...
local function pass(ok, ...)
  if tripped() then error("__FEROPROBE_LIMIT__", 0) end
  return ok, ...
end
load = function(chunk, name, mode, ...)
  -- An env given, even nil, becomes the chunk's _ENV; none means _G.
  if select('#', ...) > 0 then
    return raw_load(chunk, name, "t", (...))
  end
  return raw_load(chunk, name, "t")
end
pcall = function(f, ...) return pass(raw_pcall(f, ...)) end
xpcall = function(f, h, ...) return pass(raw_xpcall(f, h, ...)) end
coroutine.resume = function(co, ...) return pass(raw_resume(co, ...)) end
"#;

/// A new sandboxed state, bounded by `budget`.
pub(crate) fn new_state(budget: &Arc<Budget>) -> mlua::Result<Lua> {
    let lua = Lua::new_with(
        StdLib::STRING
            | StdLib::TABLE
            | StdLib::MATH
            | StdLib::UTF8
            | StdLib::COROUTINE
            | StdLib::OS,
        LuaOptions::default(),
    )?;
    lua.set_memory_limit(MEMORY_LIMIT)?;
    let g = lua.globals();
    for name in ["dofile", "loadfile", "collectgarbage", "print"] {
        g.raw_set(name, Value::Nil)?;
    }
    let string: Table = g.get("string")?;
    string.raw_set("dump", Value::Nil)?;
    super::pattern::install(&lua, &string, budget)?;
    let os: Table = g.get("os")?;
    let safe_os = lua.create_table()?;
    for name in ["clock", "date", "difftime", "time"] {
        safe_os.raw_set(name, os.raw_get::<Value>(name)?)?;
    }
    g.raw_set("os", safe_os)?;

    let b = budget.clone();
    let tripped = lua.create_function(move |_, ()| Ok(b.tripped()))?;
    let coroutine: Table = g.get("coroutine")?;
    lua.load(PRELUDE).set_name("=prelude").call::<()>((
        tripped,
        g.raw_get::<Value>("load")?,
        g.raw_get::<Value>("pcall")?,
        g.raw_get::<Value>("xpcall")?,
        coroutine.raw_get::<Value>("resume")?,
        g.raw_get::<Value>("error")?,
        g.raw_get::<Value>("select")?,
    ))?;

    let b = budget.clone();
    lua.set_global_hook(
        HookTriggers::new().every_nth_instruction(CHECK_EVERY),
        move |_, _| match b.check().or_else(|| b.tripped().then_some(TIMED_OUT)) {
            Some(why) => Err(mlua::Error::runtime(why)),
            None => Ok(VmState::Continue),
        },
    )?;
    Ok(lua)
}

/// A script error's message without Lua's traceback, and the limit's own
/// message in place of the marker the prelude raises.
pub(crate) fn error_text(e: &mlua::Error, budget: &Budget) -> String {
    let text = match e {
        mlua::Error::CallbackError { cause, .. } => return error_text(cause, budget),
        mlua::Error::RuntimeError(s) => s.clone(),
        mlua::Error::MemoryError(_) => "script ran out of memory".to_string(),
        other => other.to_string(),
    };
    if text.contains("__FEROPROBE_LIMIT__") || text.contains(TIMED_OUT) || text.contains(TOO_LONG) {
        // Which limit: the deadline or the instruction count.
        if budget.left.load(Ordering::Relaxed) < u64::from(CHECK_EVERY) {
            return TOO_LONG.to_string();
        }
        return TIMED_OUT.to_string();
    }
    text.lines().next().unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn run(code: &str, deadline: Option<Duration>) -> Result<Value, String> {
        let budget = Budget::new();
        budget.reset(deadline.map(|d| Instant::now() + d));
        let lua = new_state(&budget).map_err(|e| e.to_string())?;
        lua.load(code)
            .eval::<Value>()
            .map_err(|e| error_text(&e, &budget))
    }

    #[test]
    fn dangerous_functions_are_gone() {
        for name in [
            "io",
            "debug",
            "require",
            "package",
            "dofile",
            "loadfile",
            "collectgarbage",
        ] {
            assert_eq!(
                run(&format!("return {name}"), None),
                Ok(Value::Nil),
                "{name}"
            );
        }
        for f in [
            "os.execute",
            "os.getenv",
            "os.remove",
            "os.exit",
            "string.dump",
        ] {
            assert_eq!(run(&format!("return {f}"), None), Ok(Value::Nil), "{f}");
        }
        assert!(matches!(
            run("return os.time()", None),
            Ok(Value::Integer(_))
        ));
        assert!(matches!(
            run("return ('x'):upper()", None),
            Ok(Value::String(_))
        ));
    }

    #[test]
    fn load_takes_text_only() {
        assert_eq!(
            run("return load('return 1+1')()", None),
            Ok(Value::Integer(2))
        );
        // A binary chunk starts with "\27Lua".
        let r = run(
            "local f, e = load('\\27Lua....') return f == nil and e:find('binary') ~= nil",
            None,
        );
        assert_eq!(r, Ok(Value::Boolean(true)));
        // No env: the chunk sees the globals. An env table: only that.
        let r = run(
            "return load('return tostring(1)')() == '1' \
             and load('return x', 'c', 't', {x = 5})() == 5 \
             and load('return tostring', 'c', 't', {})() == nil",
            None,
        );
        assert_eq!(r, Ok(Value::Boolean(true)));
    }

    #[test]
    fn busy_loops_stop_even_inside_pcall() {
        let e = run(
            "while true do pcall(function() while true do end end) end",
            Some(Duration::from_millis(200)),
        )
        .unwrap_err();
        assert_eq!(e, TIMED_OUT);
        let e = run(
            "local co = coroutine.create(function() while true do end end) \
             while true do coroutine.resume(co) end",
            Some(Duration::from_millis(200)),
        )
        .unwrap_err();
        assert_eq!(e, TIMED_OUT);
    }

    #[test]
    fn memory_is_limited() {
        let e = run(
            "local t = {} for i = 1, 1e9 do t[i] = ('x'):rep(1000) .. i end",
            None,
        )
        .unwrap_err();
        assert!(e.contains("memory"), "{e}");
    }
}
