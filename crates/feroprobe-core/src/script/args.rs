//! `--script-args` and `--script-args-file`, read with nmap's syntax:
//! comma-separated `name=value` pairs and bare values, where a value is a
//! word, a quoted string or a `{...}` table of the same.
//!
//! ```text
//! user=admin,pass="a,b",paths={/,/admin},unsafe
//! ```
//!
//! Newlines separate entries too, so an arguments file can hold one per
//! line. A later name replaces an earlier one, as in nmap.

use std::fmt;

/// A script argument's value: a string, or a table of values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgValue {
    Str(String),
    Table(ArgTable),
}

/// A `{...}` table: the bare values in order, then the named ones.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgTable {
    pub list: Vec<ArgValue>,
    pub named: Vec<(String, ArgValue)>,
}

impl ArgTable {
    /// The value of `name`, if given.
    pub fn get(&self, name: &str) -> Option<&ArgValue> {
        self.named.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }

    fn set(&mut self, name: String, value: ArgValue) {
        match self.named.iter_mut().find(|(k, _)| *k == name) {
            Some(slot) => slot.1 = value,
            None => self.named.push((name, value)),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty() && self.named.is_empty()
    }
}

/// A `--script-args` string that does not parse, with the place it stops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgsError {
    pub at: usize,
    pub what: &'static str,
}

impl fmt::Display for ArgsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at character {}", self.what, self.at + 1)
    }
}

impl std::error::Error for ArgsError {}

/// Join `--script-args-file`'s text (trailing commas and white space
/// dropped) and
/// `--script-args`, file first, as nmap does, and parse them.
pub fn parse_combined(file: Option<&str>, cli: Option<&str>) -> Result<ArgTable, ArgsError> {
    let mut parts = Vec::new();
    if let Some(f) = file {
        let f = f.trim_end_matches(|c: char| c == ',' || c.is_ascii_whitespace());
        if !f.is_empty() {
            parts.push(f.to_string());
        }
    }
    if let Some(c) = cli {
        parts.push(c.to_string());
    }
    parse(&parts.join(","))
}

/// Parse a `--script-args` string.
pub fn parse(text: &str) -> Result<ArgTable, ArgsError> {
    let mut p = Parser {
        s: text.as_bytes(),
        i: 0,
    };
    let table = p.fields(None)?;
    p.space();
    if p.i < p.s.len() {
        return Err(p.err("unexpected character"));
    }
    Ok(table)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn err(&self, what: &'static str) -> ArgsError {
        ArgsError { at: self.i, what }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    /// Horizontal white space.
    fn hws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | 0x0b | 0x0c)) {
            self.i += 1;
        }
    }

    /// Any white space, newlines too.
    fn space(&mut self) {
        while self.peek().is_some_and(|c| c.is_ascii_whitespace()) {
            self.i += 1;
        }
    }

    /// The entries of a table, up to `close` (or the end of the text).
    fn fields(&mut self, close: Option<u8>) -> Result<ArgTable, ArgsError> {
        let mut t = ArgTable::default();
        self.space();
        if self.peek() == close || (close.is_none() && self.peek().is_none()) {
            return Ok(t);
        }
        loop {
            let first = self.value()?;
            self.hws();
            if self.peek() == Some(b'=') {
                let ArgValue::Str(key) = first else {
                    return Err(self.err("a table cannot be a name"));
                };
                self.i += 1;
                self.hws();
                let v = self.value()?;
                t.set(key, v);
            } else {
                t.list.push(first);
            }
            self.hws();
            match self.peek() {
                Some(b',' | b'\n') => {
                    self.i += 1;
                    self.space();
                    // A trailing separator, such as the last newline of
                    // an args file, ends the list.
                    if self.peek() == close {
                        return Ok(t);
                    }
                }
                c if c == close => return Ok(t),
                None => return Err(self.err("missing '}'")),
                Some(_) => return Err(self.err("expected ',' or '}'")),
            }
        }
    }

    fn value(&mut self) -> Result<ArgValue, ArgsError> {
        self.hws();
        match self.peek() {
            Some(b'{') => {
                self.i += 1;
                let t = self.fields(Some(b'}'))?;
                self.space();
                if self.peek() != Some(b'}') {
                    return Err(self.err("missing '}'"));
                }
                self.i += 1;
                Ok(ArgValue::Table(t))
            }
            Some(q @ (b'"' | b'\'')) => {
                let start = self.i;
                self.i += 1;
                let mut out = Vec::new();
                loop {
                    match self.peek() {
                        None => {
                            self.i = start;
                            return Err(self.err("unterminated quoted string"));
                        }
                        Some(b'\\') if self.i + 1 < self.s.len() => {
                            out.push(self.s[self.i + 1]);
                            self.i += 2;
                        }
                        Some(c) if c == q => {
                            self.i += 1;
                            break;
                        }
                        Some(c) => {
                            out.push(c);
                            self.i += 1;
                        }
                    }
                }
                Ok(ArgValue::Str(String::from_utf8_lossy(&out).into_owned()))
            }
            _ => {
                // A bare word: everything up to , = { } or a newline, less
                // the white space at its end.
                let start = self.i;
                while self
                    .peek()
                    .is_some_and(|c| !matches!(c, b',' | b'=' | b'{' | b'}' | b'\n'))
                {
                    self.i += 1;
                }
                let word = String::from_utf8_lossy(&self.s[start..self.i]);
                Ok(ArgValue::Str(word.trim_end().to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> ArgValue {
        ArgValue::Str(v.to_string())
    }

    #[test]
    fn names_values_and_flags() {
        let t = parse("user=admin, pass = \"a,b\" ,unsafe,x.y='it\\'s'").unwrap();
        assert_eq!(t.get("user"), Some(&s("admin")));
        assert_eq!(t.get("pass"), Some(&s("a,b")));
        assert_eq!(t.get("x.y"), Some(&s("it's")));
        assert_eq!(t.list, vec![s("unsafe")]);
    }

    #[test]
    fn tables_nest_and_later_names_win() {
        let t = parse("paths={/,/admin},cfg={depth=2,{a}},n=1\nn=2").unwrap();
        let ArgValue::Table(paths) = t.get("paths").unwrap() else {
            panic!()
        };
        assert_eq!(paths.list, vec![s("/"), s("/admin")]);
        let ArgValue::Table(cfg) = t.get("cfg").unwrap() else {
            panic!()
        };
        assert_eq!(cfg.get("depth"), Some(&s("2")));
        assert_eq!(cfg.list.len(), 1);
        assert_eq!(t.get("n"), Some(&s("2")));
    }

    #[test]
    fn empty_values_and_files() {
        assert!(parse("").unwrap().is_empty());
        assert_eq!(parse("a=").unwrap().get("a"), Some(&s("")));
        let t = parse_combined(Some("a=1\nb=2,,"), Some("c=3")).unwrap();
        assert_eq!(t.named.len(), 3);
    }

    #[test]
    fn trailing_separators_add_nothing() {
        let t = parse("a=1,b,\n").unwrap();
        assert_eq!(t.list, vec![s("b")]);
        assert_eq!(t.named.len(), 1);
        let t = parse("x={1,2,}").unwrap();
        let ArgValue::Table(x) = t.get("x").unwrap() else {
            panic!()
        };
        assert_eq!(x.list, vec![s("1"), s("2")]);
        // An args file ends in a newline.
        let t = parse_combined(Some("a=1\nflag\n"), Some("c=3")).unwrap();
        assert_eq!(t.list, vec![s("flag")]);
        assert_eq!(t.named.len(), 2);
        let t = parse_combined(Some("\n"), None).unwrap();
        assert!(t.is_empty());
    }

    #[test]
    fn errors() {
        assert!(parse("a={b").is_err());
        assert!(parse("a=\"b").is_err());
        assert!(parse("a}").is_err());
        assert!(parse("{a}=b").is_err());
    }
}
