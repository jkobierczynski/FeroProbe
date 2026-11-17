//! Lua 5.4's pattern functions (`string.find`, `string.match`,
//! `string.gmatch` and `string.gsub`), rewritten in Rust so that a long
//! match counts against the script's instruction limit and deadline.
//! Lua runs its own versions as one C call that neither limit can
//! interrupt, so a pattern that backtracks heavily could hold a script far
//! past its timeout. These versions charge every matching step to the
//! run's [`Budget`] and stop as soon as it runs out.
//!
//! The matching rules, results and error messages follow `lstrlib.c` of
//! Lua 5.4 (MIT licence, copyright Lua.org, PUC-Rio), with the same limits:
//! 32 captures and a nesting depth of 200.

use std::sync::{Arc, Mutex};

use mlua::{Function, Lua, MultiValue, Table, Value};

use super::sandbox::{Budget, MEMORY_LIMIT};

const MAX_CAPTURES: usize = 32;
const MAX_DEPTH: u32 = 200;
const CAP_UNFINISHED: isize = -1;
const CAP_POSITION: isize = -2;
const ESC: u8 = b'%';
const SPECIALS: &[u8] = b"^$*+?.([%-";
/// Steps counted before they are charged to the budget, the same as the
/// instruction hook's interval.
const CHARGE_EVERY: u64 = 10_000;

type Res<T> = Result<T, String>;

/// One capture: text from the subject, or a position (from 1).
#[derive(Debug, PartialEq)]
enum Capture {
    Text(usize, usize),
    Position(usize),
}

struct Matcher<'a> {
    src: &'a [u8],
    pat: &'a [u8],
    depth: u32,
    level: usize,
    caps: [(usize, isize); MAX_CAPTURES],
    budget: &'a Budget,
    pending: u64,
}

impl<'a> Matcher<'a> {
    fn new(src: &'a [u8], pat: &'a [u8], budget: &'a Budget) -> Self {
        Matcher {
            src,
            pat,
            depth: MAX_DEPTH,
            level: 0,
            caps: [(0, 0); MAX_CAPTURES],
            budget,
            pending: 0,
        }
    }

    /// Ready for a new match attempt.
    fn reset(&mut self) {
        self.depth = MAX_DEPTH;
        self.level = 0;
    }

    /// Count `n` steps of work, charging them to the budget in batches.
    fn step(&mut self, n: usize) -> Res<()> {
        self.pending = self.pending.saturating_add(n as u64);
        if self.pending >= CHARGE_EVERY {
            let n = std::mem::take(&mut self.pending);
            if let Some(why) = self.budget.charge(n) {
                return Err(why.to_string());
            }
        }
        Ok(())
    }

    fn do_match(&mut self, s: usize, p: usize) -> Res<Option<usize>> {
        if self.depth == 0 {
            return Err("pattern too complex".into());
        }
        self.depth -= 1;
        let r = self.match_here(s, p);
        self.depth += 1;
        r
    }

    fn match_here(&mut self, mut s: usize, mut p: usize) -> Res<Option<usize>> {
        let pat = self.pat;
        loop {
            self.step(1)?;
            if p == pat.len() {
                return Ok(Some(s));
            }
            match pat[p] {
                b'(' => {
                    return if pat.get(p + 1) == Some(&b')') {
                        self.start_capture(s, p + 2, CAP_POSITION)
                    } else {
                        self.start_capture(s, p + 1, CAP_UNFINISHED)
                    };
                }
                b')' => return self.end_capture(s, p + 1),
                b'$' if p + 1 == pat.len() => {
                    return Ok((s == self.src.len()).then_some(s));
                }
                ESC if pat.get(p + 1) == Some(&b'b') => match self.match_balance(s, p + 2)? {
                    Some(e) => {
                        s = e;
                        p += 4;
                    }
                    None => return Ok(None),
                },
                ESC if pat.get(p + 1) == Some(&b'f') => {
                    p += 2;
                    if pat.get(p) != Some(&b'[') {
                        return Err("missing '[' after '%f' in pattern".into());
                    }
                    let ep = self.class_end(p)?;
                    self.step(ep - p)?;
                    let previous = if s == 0 { 0 } else { self.src[s - 1] };
                    let current = self.src.get(s).copied().unwrap_or(0);
                    if !self.bracket_class(previous, p, ep - 1)
                        && self.bracket_class(current, p, ep - 1)
                    {
                        p = ep;
                    } else {
                        return Ok(None);
                    }
                }
                ESC if pat.get(p + 1).is_some_and(u8::is_ascii_digit) => {
                    match self.match_capture(s, pat[p + 1])? {
                        Some(e) => {
                            s = e;
                            p += 2;
                        }
                        None => return Ok(None),
                    }
                }
                _ => {
                    let ep = self.class_end(p)?;
                    let suffix = pat.get(ep).copied();
                    if !self.single_match(s, p, ep)? {
                        if matches!(suffix, Some(b'*' | b'?' | b'-')) {
                            p = ep + 1;
                            continue;
                        }
                        return Ok(None);
                    }
                    match suffix {
                        Some(b'?') => {
                            if let Some(e) = self.do_match(s + 1, ep + 1)? {
                                return Ok(Some(e));
                            }
                            p = ep + 1;
                        }
                        Some(b'+') => return self.max_expand(s + 1, p, ep),
                        Some(b'*') => return self.max_expand(s, p, ep),
                        Some(b'-') => return self.min_expand(s, p, ep),
                        _ => {
                            s += 1;
                            p = ep;
                        }
                    }
                }
            }
        }
    }

    /// Where the single-character class at `p` ends.
    fn class_end(&self, mut p: usize) -> Res<usize> {
        let pat = self.pat;
        let c = pat[p];
        p += 1;
        match c {
            ESC => {
                if p == pat.len() {
                    return Err("malformed pattern (ends with '%')".into());
                }
                Ok(p + 1)
            }
            b'[' => {
                if pat.get(p) == Some(&b'^') {
                    p += 1;
                }
                // The first character is part of the set even if it is ']'.
                loop {
                    if p == pat.len() {
                        return Err("malformed pattern (missing ']')".into());
                    }
                    let c = pat[p];
                    p += 1;
                    if c == ESC && p < pat.len() {
                        p += 1;
                    }
                    if pat.get(p) == Some(&b']') {
                        return Ok(p + 1);
                    }
                }
            }
            _ => Ok(p),
        }
    }

    /// Whether the subject byte at `s` matches the class `p..ep`.
    fn single_match(&mut self, s: usize, p: usize, ep: usize) -> Res<bool> {
        let Some(&c) = self.src.get(s) else {
            return Ok(false);
        };
        Ok(match self.pat[p] {
            b'.' => true,
            ESC => match_class(c, self.pat[p + 1]),
            b'[' => {
                self.step(ep - p)?;
                self.bracket_class(c, p, ep - 1)
            }
            other => other == c,
        })
    }

    /// Whether `c` is in the set `[...]` from `p` to the `]` at `ec`.
    fn bracket_class(&self, c: u8, mut p: usize, ec: usize) -> bool {
        let pat = self.pat;
        let mut sig = true;
        if pat[p + 1] == b'^' {
            sig = false;
            p += 1;
        }
        loop {
            p += 1;
            if p >= ec {
                return !sig;
            }
            if pat[p] == ESC {
                p += 1;
                if match_class(c, pat[p]) {
                    return sig;
                }
            } else if pat[p + 1] == b'-' && p + 2 < ec {
                p += 2;
                if pat[p - 2] <= c && c <= pat[p] {
                    return sig;
                }
            } else if pat[p] == c {
                return sig;
            }
        }
    }

    fn match_balance(&mut self, s: usize, p: usize) -> Res<Option<usize>> {
        if p + 1 >= self.pat.len() {
            return Err("malformed pattern (missing arguments to '%b')".into());
        }
        let (open, close) = (self.pat[p], self.pat[p + 1]);
        if self.src.get(s) != Some(&open) {
            return Ok(None);
        }
        let mut depth = 1;
        for (i, &c) in self.src.iter().enumerate().skip(s + 1) {
            self.step(1)?;
            if c == close {
                depth -= 1;
                if depth == 0 {
                    return Ok(Some(i + 1));
                }
            } else if c == open {
                depth += 1;
            }
        }
        Ok(None)
    }

    fn max_expand(&mut self, s: usize, p: usize, ep: usize) -> Res<Option<usize>> {
        let mut i = 0;
        while self.single_match(s + i, p, ep)? {
            self.step(1)?;
            i += 1;
        }
        loop {
            if let Some(e) = self.do_match(s + i, ep + 1)? {
                return Ok(Some(e));
            }
            if i == 0 {
                return Ok(None);
            }
            i -= 1;
        }
    }

    fn min_expand(&mut self, mut s: usize, p: usize, ep: usize) -> Res<Option<usize>> {
        loop {
            if let Some(e) = self.do_match(s, ep + 1)? {
                return Ok(Some(e));
            }
            if !self.single_match(s, p, ep)? {
                return Ok(None);
            }
            s += 1;
        }
    }

    fn start_capture(&mut self, s: usize, p: usize, what: isize) -> Res<Option<usize>> {
        if self.level >= MAX_CAPTURES {
            return Err("too many captures".into());
        }
        self.caps[self.level] = (s, what);
        self.level += 1;
        let r = self.do_match(s, p)?;
        if r.is_none() {
            self.level -= 1;
        }
        Ok(r)
    }

    fn end_capture(&mut self, s: usize, p: usize) -> Res<Option<usize>> {
        let Some(l) = (0..self.level)
            .rev()
            .find(|&l| self.caps[l].1 == CAP_UNFINISHED)
        else {
            return Err("invalid pattern capture".into());
        };
        self.caps[l].1 = (s - self.caps[l].0) as isize;
        let r = self.do_match(s, p)?;
        if r.is_none() {
            self.caps[l].1 = CAP_UNFINISHED;
        }
        Ok(r)
    }

    /// A back-reference `%1`-`%9`: the same text again.
    fn match_capture(&mut self, s: usize, digit: u8) -> Res<Option<usize>> {
        let l = i32::from(digit) - i32::from(b'1');
        if l < 0 || l as usize >= self.level || self.caps[l as usize].1 == CAP_UNFINISHED {
            return Err(format!("invalid capture index %{}", l + 1));
        }
        let (init, len) = self.caps[l as usize];
        if len < 0 {
            // A position capture never matches text.
            return Ok(None);
        }
        let len = len as usize;
        self.step(len)?;
        let src = self.src;
        Ok((src.len() - s >= len && src[init..init + len] == src[s..s + len]).then_some(s + len))
    }

    /// Capture `i`, or the whole match `whole` when there are no captures.
    fn capture(&self, i: usize, whole: Option<(usize, usize)>) -> Res<Capture> {
        if i >= self.level {
            return match whole {
                Some((s, e)) if i == 0 => Ok(Capture::Text(s, e)),
                _ => Err(format!("invalid capture index %{}", i + 1)),
            };
        }
        match self.caps[i] {
            (_, CAP_UNFINISHED) => Err("unfinished capture".into()),
            (init, CAP_POSITION) => Ok(Capture::Position(init + 1)),
            (init, len) => Ok(Capture::Text(init, init + len as usize)),
        }
    }

    /// All captures as Lua values: the whole match if there are none and
    /// `whole` is given.
    fn captures(&self, lua: &Lua, whole: Option<(usize, usize)>) -> mlua::Result<MultiValue> {
        let n = if self.level == 0 && whole.is_some() {
            1
        } else {
            self.level
        };
        (0..n).map(|i| self.capture_value(lua, i, whole)).collect()
    }

    fn capture_value(
        &self,
        lua: &Lua,
        i: usize,
        whole: Option<(usize, usize)>,
    ) -> mlua::Result<Value> {
        Ok(
            match self.capture(i, whole).map_err(mlua::Error::runtime)? {
                Capture::Text(s, e) => Value::String(lua.create_string(&self.src[s..e])?),
                Capture::Position(n) => Value::Integer(n as i64),
            },
        )
    }
}

impl Drop for Matcher<'_> {
    /// Charge what is left over, so that many short calls add up too. Should
    /// that trip a limit, the next check stops the script.
    fn drop(&mut self) {
        if self.pending > 0 {
            self.budget.charge(self.pending);
        }
    }
}

fn match_class(c: u8, class: u8) -> bool {
    let res = match class.to_ascii_lowercase() {
        b'a' => c.is_ascii_alphabetic(),
        b'c' => c.is_ascii_control(),
        b'd' => c.is_ascii_digit(),
        b'g' => c.is_ascii_graphic(),
        b'l' => c.is_ascii_lowercase(),
        b'p' => c.is_ascii_punctuation(),
        // C's isspace: also the vertical tab, which Rust's
        // is_ascii_whitespace leaves out.
        b's' => matches!(c, b' ' | b'\t'..=b'\r'),
        b'u' => c.is_ascii_uppercase(),
        b'w' => c.is_ascii_alphanumeric(),
        b'x' => c.is_ascii_hexdigit(),
        b'z' => c == 0,
        _ => return class == c,
    };
    if class.is_ascii_lowercase() {
        res
    } else {
        !res
    }
}

/// A start position from Lua (from 1, negative from the end) as a
/// position from 1, clipped to at least 1.
fn start_position(pos: i64, len: usize) -> usize {
    if pos > 0 {
        pos as usize
    } else if pos == 0 || pos.unsigned_abs() > len as u64 {
        1
    } else {
        len - pos.unsigned_abs() as usize + 1
    }
}

fn is_truthy(v: &Value) -> bool {
    !matches!(v, Value::Nil | Value::Boolean(false))
}

fn lua_err(e: String) -> mlua::Error {
    mlua::Error::runtime(e)
}

/// Where `needle` first occurs in `hay`, every compared byte charged.
fn plain_find(m: &mut Matcher, hay: &[u8], needle: &[u8]) -> Res<Option<usize>> {
    if needle.is_empty() {
        return Ok(Some(0));
    }
    if needle.len() > hay.len() {
        return Ok(None);
    }
    for i in 0..=hay.len() - needle.len() {
        m.step(1)?;
        if hay[i] == needle[0] {
            m.step(needle.len())?;
            if hay[i..i + needle.len()] == *needle {
                return Ok(Some(i));
            }
        }
    }
    Ok(None)
}

/// A Lua type name as Lua's argument errors give it.
fn type_name(v: Option<&Value>) -> &'static str {
    match v {
        None => "no value",
        Some(Value::Integer(_) | Value::Number(_)) => "number",
        Some(v) => v.type_name(),
    }
}

/// Argument `n` (from 1) of `f` as a string, as `luaL_checklstring` takes
/// it: a number becomes its text.
fn arg_string(lua: &Lua, args: &[Value], n: usize, f: &str) -> mlua::Result<mlua::LuaString> {
    let v = args.get(n - 1);
    match v {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(v @ (Value::Integer(_) | Value::Number(_))) => Ok(lua
            .coerce_string(v.clone())?
            .expect("a number has a text form")),
        _ => Err(lua_err(format!(
            "bad argument #{n} to 'string.{f}' (string expected, got {})",
            type_name(v)
        ))),
    }
}

/// Optional integer argument `n` of `f`, as `luaL_optinteger` takes it.
fn arg_int(lua: &Lua, args: &[Value], n: usize, f: &str, default: i64) -> mlua::Result<i64> {
    let v = args.get(n - 1);
    match v {
        None | Some(Value::Nil) => Ok(default),
        Some(Value::Integer(i)) => Ok(*i),
        Some(v) => match lua.coerce_integer(v.clone())? {
            Some(i) => Ok(i),
            None if lua.coerce_number(v.clone())?.is_some() => Err(lua_err(format!(
                "bad argument #{n} to 'string.{f}' (number has no integer representation)"
            ))),
            None => Err(lua_err(format!(
                "bad argument #{n} to 'string.{f}' (number expected, got {})",
                type_name(Some(v))
            ))),
        },
    }
}

fn find_aux(lua: &Lua, budget: &Budget, args: &[Value], find: bool) -> mlua::Result<MultiValue> {
    let name = if find { "find" } else { "match" };
    let s = arg_string(lua, args, 1, name)?;
    let p = arg_string(lua, args, 2, name)?;
    let src = s.as_bytes();
    let pat = p.as_bytes();
    let init = start_position(arg_int(lua, args, 3, name, 1)?, src.len()) - 1;
    if init > src.len() {
        return Ok(MultiValue::from_vec(vec![Value::Nil]));
    }
    let plain = find && args.get(3).is_some_and(is_truthy);
    if find && (plain || !pat.iter().any(|c| SPECIALS.contains(c))) {
        let mut m = Matcher::new(&src, &pat, budget);
        return Ok(
            match plain_find(&mut m, &src[init..], &pat).map_err(lua_err)? {
                Some(i) => MultiValue::from_vec(vec![
                    Value::Integer((init + i + 1) as i64),
                    Value::Integer((init + i + pat.len()) as i64),
                ]),
                None => MultiValue::from_vec(vec![Value::Nil]),
            },
        );
    }
    let anchor = pat.first() == Some(&b'^');
    let body = if anchor { &pat[1..] } else { &pat[..] };
    let mut m = Matcher::new(&src, body, budget);
    let mut s1 = init;
    loop {
        m.reset();
        if let Some(e) = m.do_match(s1, 0).map_err(lua_err)? {
            if !find {
                return m.captures(lua, Some((s1, e)));
            }
            let mut out = vec![Value::Integer(s1 as i64 + 1), Value::Integer(e as i64)];
            out.extend(m.captures(lua, None)?);
            return Ok(MultiValue::from_vec(out));
        }
        if anchor || s1 >= src.len() {
            return Ok(MultiValue::from_vec(vec![Value::Nil]));
        }
        s1 += 1;
    }
}

/// Append `bytes` to the result of `gsub`, which may grow no larger than
/// a script's memory limit: it is built outside Lua's memory accounting.
fn push_out(m: &mut Matcher, out: &mut Vec<u8>, bytes: &[u8]) -> mlua::Result<()> {
    m.step(bytes.len()).map_err(lua_err)?;
    if out.len() + bytes.len() > MEMORY_LIMIT {
        return Err(lua_err("not enough memory".into()));
    }
    out.extend_from_slice(bytes);
    Ok(())
}

/// The replacement string of `gsub` for the match `s..e`, with `%0`-`%9`
/// and `%%` filled in.
fn add_string(
    m: &mut Matcher,
    out: &mut Vec<u8>,
    repl: &[u8],
    s: usize,
    e: usize,
) -> mlua::Result<()> {
    let mut rest = repl;
    while let Some(i) = rest.iter().position(|&c| c == ESC) {
        push_out(m, out, &rest[..i])?;
        match rest.get(i + 1) {
            Some(&ESC) => push_out(m, out, b"%")?,
            Some(b'0') => push_out(m, out, &m.src[s..e])?,
            Some(&d) if d.is_ascii_digit() => {
                match m
                    .capture(usize::from(d - b'1'), Some((s, e)))
                    .map_err(lua_err)?
                {
                    Capture::Text(a, b) => push_out(m, out, &m.src[a..b])?,
                    Capture::Position(n) => push_out(m, out, n.to_string().as_bytes())?,
                }
            }
            _ => {
                return Err(lua_err("invalid use of '%' in replacement string".into()));
            }
        }
        rest = &rest[i + 2..];
    }
    push_out(m, out, rest)
}

/// What a replacement function or table raised, passed on unchanged.
struct Raised(Value);

/// Lua's own `pcall` and a function indexing a table, for calling the
/// replacement of `gsub` the way Lua does: what it raises reaches the
/// script as it was raised.
struct Callers {
    pcall: Function,
    index: Function,
}

fn gsub(
    lua: &Lua,
    budget: &Budget,
    callers: &Callers,
    args: &[Value],
) -> mlua::Result<Result<MultiValue, Raised>> {
    let s = arg_string(lua, args, 1, "gsub")?;
    let p = arg_string(lua, args, 2, "gsub")?;
    let repl = match args.get(2) {
        Some(Value::Function(_) | Value::Table(_)) => args[2].clone(),
        Some(Value::String(_) | Value::Integer(_) | Value::Number(_)) => {
            Value::String(arg_string(lua, args, 3, "gsub")?)
        }
        other => {
            return Err(lua_err(format!(
                "bad argument #3 to 'string.gsub' (string/function/table expected, got {})",
                type_name(other)
            )));
        }
    };
    let src = s.as_bytes();
    let pat = p.as_bytes();
    let max = arg_int(lua, args, 4, "gsub", src.len() as i64 + 1)?;
    let anchor = pat.first() == Some(&b'^');
    let body = if anchor { &pat[1..] } else { &pat[..] };
    let mut m = Matcher::new(&src, body, budget);
    let mut out = Vec::new();
    let mut at = 0;
    let mut last = None;
    let mut n = 0i64;
    let mut changed = false;
    while n < max {
        m.reset();
        match m.do_match(at, 0).map_err(lua_err)? {
            Some(e) if Some(e) != last => {
                n += 1;
                match add_value(lua, budget, callers, &mut m, &mut out, &repl, at, e)? {
                    Ok(c) => changed |= c,
                    Err(raised) => return Ok(Err(raised)),
                }
                at = e;
                last = Some(e);
            }
            _ if at < src.len() => {
                push_out(&mut m, &mut out, &src[at..at + 1])?;
                at += 1;
            }
            _ => break,
        }
        if anchor {
            break;
        }
    }
    let result = if changed {
        push_out(&mut m, &mut out, &src[at..])?;
        Value::String(lua.create_string(&out)?)
    } else {
        Value::String(s.clone())
    };
    Ok(Ok(MultiValue::from_vec(vec![result, Value::Integer(n)])))
}

/// Add the replacement for the match `s..e`; whether it changed the text,
/// or what the replacement raised.
#[allow(clippy::too_many_arguments)]
fn add_value(
    lua: &Lua,
    budget: &Budget,
    callers: &Callers,
    m: &mut Matcher,
    out: &mut Vec<u8>,
    repl: &Value,
    s: usize,
    e: usize,
) -> mlua::Result<Result<bool, Raised>> {
    let mut results = match repl {
        Value::String(text) => {
            add_string(m, out, &text.as_bytes(), s, e)?;
            return Ok(Ok(true));
        }
        Value::Function(f) => {
            let mut args = m.captures(lua, Some((s, e)))?;
            args.push_front(Value::Function(f.clone()));
            callers.pcall.call::<MultiValue>(args)?
        }
        Value::Table(t) => callers.pcall.call::<MultiValue>((
            callers.index.clone(),
            t.clone(),
            m.capture_value(lua, 0, Some((s, e)))?,
        ))?,
        _ => unreachable!("checked in gsub"),
    };
    if budget.tripped() {
        // A limit tripped inside the replacement: never caught.
        return Err(lua_err(super::sandbox::TIMED_OUT.into()));
    }
    let ok = matches!(results.pop_front(), Some(Value::Boolean(true)));
    let value = results.pop_front().unwrap_or(Value::Nil);
    if !ok {
        return Ok(Err(Raised(value)));
    }
    if !is_truthy(&value) {
        push_out(m, out, &m.src[s..e])?;
        return Ok(Ok(false));
    }
    let text = match &value {
        Value::String(t) => t.clone(),
        Value::Integer(_) | Value::Number(_) => lua
            .coerce_string(value.clone())?
            .expect("a number has a text form"),
        other => {
            return Err(lua_err(format!(
                "invalid replacement value (a {})",
                other.type_name()
            )));
        }
    };
    push_out(m, out, &text.as_bytes())?;
    Ok(Ok(true))
}

/// The next match of a `gmatch` iterator over `s` and `p`; `state` holds
/// where to look next and where the last match ended.
fn gmatch_next(
    lua: &Lua,
    budget: &Budget,
    s: &mlua::LuaString,
    p: &mlua::LuaString,
    state: &Mutex<(usize, Option<usize>)>,
) -> mlua::Result<MultiValue> {
    let src = s.as_bytes();
    let pat = p.as_bytes();
    let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
    let mut m = Matcher::new(&src, &pat, budget);
    let mut at = st.0;
    while at <= src.len() {
        m.reset();
        if let Some(e) = m.do_match(at, 0).map_err(lua_err)?
            && Some(e) != st.1
        {
            *st = (e, Some(e));
            return m.captures(lua, Some((at, e)));
        }
        at += 1;
    }
    st.0 = at;
    Ok(MultiValue::new())
}

/// An error as the value Lua's own function would raise: its message as
/// a plain string, or the very value a replacement function raised.
fn error_value(lua: &Lua, e: mlua::Error) -> mlua::Result<Value> {
    match e {
        mlua::Error::CallbackError { cause, .. } => error_value(lua, (*cause).clone()),
        mlua::Error::RuntimeError(text) => Ok(Value::String(lua.create_string(text)?)),
        mlua::Error::MemoryError(_) => Ok(Value::String(lua.create_string("not enough memory")?)),
        other => Ok(Value::Error(Box::new(other))),
    }
}

/// `true` and the results, or `false` and the error, for [`WRAPPER`] to
/// raise as Lua's own functions would.
fn status(lua: &Lua, r: mlua::Result<MultiValue>) -> mlua::Result<MultiValue> {
    Ok(match r {
        Ok(mut values) => {
            values.push_front(Value::Boolean(true));
            values
        }
        Err(e) => MultiValue::from_vec(vec![Value::Boolean(false), error_value(lua, e)?]),
    })
}

/// Raises the errors of the Rust functions as Lua's own do: the message
/// alone, with no position or traceback.
const WRAPPER: &str = r#"
local string, raw_find, raw_match, raw_gmatch, raw_gsub, error = ...
local function check(ok, ...)
  if ok then return ... end
  error((...), 0)
end
string.find = function(...) return check(raw_find(...)) end
string.match = function(...) return check(raw_match(...)) end
string.gsub = function(...) return check(raw_gsub(...)) end
string.gmatch = function(...)
  local next_match = check(raw_gmatch(...))
  -- Lua reports an error of the iterator where the loop calls it.
  local function check_next(ok, ...)
    if ok then return ... end
    error((...), 2)
  end
  return function() return check_next(next_match()) end
end
"#;

/// Replace `string.find`, `string.match`, `string.gmatch` and
/// `string.gsub` in `string` with the bounded versions.
pub(crate) fn install(lua: &Lua, string: &Table, budget: &Arc<Budget>) -> mlua::Result<()> {
    let b = budget.clone();
    let find = lua.create_function(move |lua, args: MultiValue| {
        status(lua, find_aux(lua, &b, &args.into_vec(), true))
    })?;
    let b = budget.clone();
    let match_ = lua.create_function(move |lua, args: MultiValue| {
        status(lua, find_aux(lua, &b, &args.into_vec(), false))
    })?;
    let b = budget.clone();
    let callers = Callers {
        pcall: lua.globals().get("pcall")?,
        index: lua
            .load("local t, k = ... return t[k]")
            .set_name("=string.gsub")
            .into_function()?,
    };
    let gsub = lua.create_function(move |lua, args: MultiValue| {
        match gsub(lua, &b, &callers, &args.into_vec()) {
            Ok(Err(Raised(value))) => Ok(MultiValue::from_vec(vec![Value::Boolean(false), value])),
            Ok(Ok(values)) => status(lua, Ok(values)),
            Err(e) => status(lua, Err(e)),
        }
    })?;
    let b = budget.clone();
    let gmatch = lua.create_function(move |lua, args: MultiValue| {
        let iterator = (|| {
            let args = args.into_vec();
            let s = arg_string(lua, &args, 1, "gmatch")?;
            let p = arg_string(lua, &args, 2, "gmatch")?;
            let len = s.as_bytes().len();
            let start =
                (start_position(arg_int(lua, &args, 3, "gmatch", 1)?, len) - 1).min(len + 1);
            let state = Mutex::new((start, None::<usize>));
            let b = b.clone();
            let f = lua.create_function(move |lua, ()| {
                status(lua, gmatch_next(lua, &b, &s, &p, &state))
            })?;
            Ok(MultiValue::from_vec(vec![Value::Function(f)]))
        })();
        status(lua, iterator)
    })?;
    lua.load(WRAPPER).set_name("=string").call::<()>((
        string.clone(),
        find,
        match_,
        gmatch,
        gsub,
        lua.globals().get::<Value>("error")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::super::sandbox::{Budget, TIMED_OUT, TOO_LONG, error_text, new_state};
    use mlua::Lua;
    use std::time::{Duration, Instant};

    /// Runs every case with `pcall` and writes down what came back, so
    /// that the same cases can be compared between Lua's own pattern
    /// functions and ours.
    const CASES: &str = r#"
local function show(...)
  local out = {}
  for i = 1, select('#', ...) do
    local v = select(i, ...)
    out[#out + 1] = type(v) .. ':' .. tostring(v)
  end
  return table.concat(out, ',')
end
local subjects = {
  "", "a", "hello world", "  key = value  ", "THE (quick) fox", "a.b.c",
  "x[1]=[[y]]", "aaa", "abcabc", "f(a(b)c)d", "12 34 5", "\0a\0b",
  "THE (quick) [brown] {fox} 0x1F 99%", "line1\nline2\r\n\tend\v",
  "caf\195\169 \255\254", "%d %s %%", "aaab", "ababab", "--[[x]]--",
}
local patterns = {
  "", "a", "^a", "a$", "^$", ".", "%a+", "%A+", "%d+", "%D", "%s*", "%S+",
  "%w+", "%W", "%p", "%P", "%l+", "%u+", "%x+", "%c", "%g+", "%z", "%Z",
  "[%a_][%w_]*", "[^%s]+", "[a-c]+", "[^a-c]+", "[]]", "[^]]", "[a-]",
  "[%]]", "[-a]", "a*", "a-", "a?", "a+b", "a-b", "(a)(b)", "()a()",
  "(a*(.)%w(%s*))", "%((.-)%)", "%b()", "%b[]", "%f[%w]%w+", "%f[%W]",
  "%f[%a]%a+%f[%A]", "(%a+)%s*=%s*(%a+)", "(.)%1", "(a)(b)%2%1", "%.",
  "%%", "x*$", "^(.-)%s*$", "^%s*(.-)%s*$", "(h)(e)(l)(l)(o)", "\0", "%z+",
  "[\0-\31]", "[\128-\255]+", "[%d%.]+", ".-b", "(()a)", "^(a)", "%1",
  "(", "%", "[a", "%b", "%f", "%fx", "(()", "a)", "%9", "[%", "(a)%2",
  "[^]", "(%f[a])", "..", ".*", ".+$", "a.-$", "^.", "(%d+)%s(%d+)",
}
local log = {}
local function run(name, f, ...)
  log[#log + 1] = name .. ' => ' .. show(pcall(f, ...))
end
for _, s in ipairs(subjects) do
  for _, p in ipairs(patterns) do
    local tag = string.format('%q %q', s, p)
    run('find ' .. tag, string.find, s, p)
    run('find3 ' .. tag, string.find, s, p, 3)
    run('find-2 ' .. tag, string.find, s, p, -2)
    run('findplain ' .. tag, string.find, s, p, 1, true)
    run('match ' .. tag, string.match, s, p)
    run('match2 ' .. tag, string.match, s, p, 2)
    run('gsub ' .. tag, string.gsub, s, p, '<%0>')
    run('gsub1 ' .. tag, string.gsub, s, p, '%1', 2)
    run('gsubf ' .. tag, string.gsub, s, p, function(a, b) return b or a:upper() end)
    run('gsubt ' .. tag, string.gsub, s, p, {a = 'A', [1] = 'one', b = false})
    run('gmatch ' .. tag, function()
      local out = {}
      for a, b, c in string.gmatch(s, p) do
        out[#out + 1] = show(a, b, c)
        if #out > 50 then break end
      end
      return table.concat(out, ';')
    end)
    run('gmatch2 ' .. tag, function()
      local out = {}
      for a in s:gmatch(p, 2) do out[#out + 1] = show(a) if #out > 50 then break end end
      return table.concat(out, ';')
    end)
  end
end
-- Arguments and replacement values.
run('num', string.find, 12345, 34)
run('nummatch', string.match, 3.5, '%d')
run('init0', string.find, 'abc', 'b', 0)
run('initbig', string.find, 'abc', 'b', 10)
run('initneg', string.find, 'abc', 'a', -10)
run('initfloat', string.find, 'abc', 'b', 2.0)
run('initfrac', string.find, 'abc', 'b', 2.5)
run('initstr', string.find, 'abc', 'b', '2')
run('nosubject', string.find)
run('nopattern', string.find, 'abc')
run('tablesubject', string.match, {}, 'a')
run('gsubnorepl', string.gsub, 'abc', 'b')
run('gsubbool', string.gsub, 'abc', 'b', true)
run('gsubnum', string.gsub, 'abc', 'b', 12)
run('gsubfloat', string.gsub, 'abc', 'b', 1.5)
run('gsubmax0', string.gsub, 'abc', '%w', 'x', 0)
run('gsubmaxneg', string.gsub, 'abc', '%w', 'x', -1)
run('gsubbadesc', string.gsub, 'abc', 'b', '%x')
run('gsubtrail', string.gsub, 'abc', 'b', 'x%')
run('gsubpos', string.gsub, 'abc', '()b', '%1')
run('gsubfnum', string.gsub, 'abc', '%w', function(c) return 1.5 end)
run('gsubfint', string.gsub, 'abc', '%w', function(c) return 7 end)
run('gsubftable', string.gsub, 'abc', '%w', function(c) return {} end)
run('gsubferr', string.gsub, 'abc', '%w', function(c) error('boom', 0) end)
run('gsubferrpos', string.gsub, 'abc', '%w', function(c) error('boom') end)
run('gsubferrtable', function()
  local ok, e = pcall(string.gsub, 'abc', '%w', function(c) error({code = 7}) end)
  return ok, type(e), type(e) == 'table' and e.code
end)
run('gsubmeta', string.gsub, 'abc', '%w', setmetatable({}, {__index = function(_, k) return k .. k end}))
run('method', function() return ('a,b'):gsub(',', ';') end)
run('deep', string.match, string.rep('a', 300), string.rep('a?', 300) .. string.rep('a', 300))
run('captures32', string.match, 'a', string.rep('()', 32))
run('captures33', string.match, 'a', string.rep('()', 33))
return table.concat(log, '\n')
"#;

    #[test]
    fn behaves_like_lua() {
        let text = |s: mlua::LuaString| String::from_utf8_lossy(&s.as_bytes()).into_owned();
        let ours = text(
            new_state(&Budget::new())
                .unwrap()
                .load(CASES)
                .set_name("=cases")
                .eval()
                .unwrap(),
        );
        let theirs = text(Lua::new().load(CASES).set_name("=cases").eval().unwrap());
        let mut differences = 0;
        for (a, b) in ours.lines().zip(theirs.lines()) {
            if a != b {
                differences += 1;
                if differences < 20 {
                    eprintln!("ours:   {a}\ntheirs: {b}\n");
                }
            }
        }
        assert_eq!(ours.lines().count(), theirs.lines().count());
        assert_eq!(differences, 0);
    }

    fn timed(code: &str, deadline: Duration) -> (String, Duration) {
        let budget = Budget::new();
        budget.reset(Some(Instant::now() + deadline));
        let lua = new_state(&budget).unwrap();
        let start = Instant::now();
        let e = lua.load(code).exec().unwrap_err();
        (error_text(&e, &budget), start.elapsed())
    }

    #[test]
    fn backtracking_stops_at_the_deadline() {
        // Lua's own string.find would take hours over this.
        let code = "local s = string.rep('a', 200000) \
                    while true do pcall(string.find, s, string.rep('a*', 30) .. 'b') end";
        let (e, took) = timed(code, Duration::from_millis(300));
        assert_eq!(e, TIMED_OUT);
        assert!(took < Duration::from_secs(3), "{took:?}");
        for code in [
            "string.match(string.rep('a', 200000), string.rep('a-', 30) .. 'b')",
            "string.gsub(string.rep('a', 200000), string.rep('a*', 30) .. 'b', '')",
            "for _ in string.gmatch(string.rep('a', 200000), string.rep('a*', 30) .. 'b') do end",
            "string.find(string.rep('a', 1000000), '[' .. string.rep('b', 100000) .. ']+$')",
            "string.find(string.rep('(', 1000000), '%b()')",
        ] {
            let (e, took) = timed(code, Duration::from_millis(300));
            assert_eq!(e, TIMED_OUT, "{code}");
            assert!(took < Duration::from_secs(3), "{code}: {took:?}");
        }
    }

    #[test]
    fn matching_counts_against_the_instruction_limit() {
        let budget = Budget::new();
        let lua = new_state(&budget).unwrap();
        // Most of the allowance already used, so the test stays quick.
        budget.charge(super::super::sandbox::INSTRUCTION_LIMIT - 50_000_000);
        let e = lua
            .load("string.find(string.rep('a', 200000), string.rep('a*', 30) .. 'b')")
            .exec()
            .unwrap_err();
        assert_eq!(error_text(&e, &budget), TOO_LONG);
    }

    #[test]
    fn gsub_results_are_bounded() {
        let (e, _) = timed(
            "string.gsub(string.rep('a', 1000), 'a', string.rep('b', 1000000))",
            Duration::from_secs(30),
        );
        assert!(e.contains("memory"), "{e}");
    }
}
