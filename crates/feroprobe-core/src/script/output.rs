//! What a script run returns, and how it is written out: the `|_` lines
//! of the normal report and the nested elements of the XML and JSON ones.

use serde::Serialize;
use serde::ser::{SerializeMap, SerializeSeq, Serializer};

/// The output of one script on one host, port, or the whole run.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ScriptResult {
    /// The script's name, such as `banner`.
    pub id: String,
    /// The text the normal report shows: the string the script returned,
    /// or its table laid out as indented lines.
    pub output: String,
    /// The table the script returned, if it returned one, for the XML
    /// `<elem>`/`<table>` elements and the JSON report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<ScriptValue>,
}

/// A value in a script's structured output.
#[derive(Debug, Clone, PartialEq)]
pub enum ScriptValue {
    Str(String),
    Table(ScriptTable),
}

/// A table in a script's structured output: the values under keys 1, 2,
/// ... in order, then the ones under names, sorted by name.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScriptTable {
    pub list: Vec<ScriptValue>,
    pub named: Vec<(String, ScriptValue)>,
}

impl Serialize for ScriptValue {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            ScriptValue::Str(v) => s.serialize_str(v),
            ScriptValue::Table(t) => t.serialize(s),
        }
    }
}

/// A table with only numbered entries is a JSON array; otherwise an
/// object, the numbered entries under their numbers ("1", "2", ...).
/// Lua keeps `t[2]` and `t["2"]` apart, so a name that reads as a
/// positive whole number (`2`, not `02`), or that starts with a double
/// quote, is written in an added pair of double quotes (`"2"` as
/// `"\"2\""`). That is reversible: a bare whole number is always a
/// numbered entry, a key in quotes a name with the outer pair removed,
/// any other key a name as it is.
impl Serialize for ScriptTable {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.named.is_empty() {
            let mut seq = s.serialize_seq(Some(self.list.len()))?;
            for v in &self.list {
                seq.serialize_element(v)?;
            }
            return seq.end();
        }
        let mut map = s.serialize_map(Some(self.list.len() + self.named.len()))?;
        for (i, v) in self.list.iter().enumerate() {
            map.serialize_entry(&(i + 1).to_string(), v)?;
        }
        for (k, v) in &self.named {
            if needs_quotes(k) {
                map.serialize_entry(&format!("\"{k}\""), v)?;
            } else {
                map.serialize_entry(k, v)?;
            }
        }
        map.end()
    }
}

/// Whether a name must be quoted in JSON to stay apart from a numbered
/// entry: it reads as a positive whole number, or starts with a quote.
fn needs_quotes(k: &str) -> bool {
    k.starts_with('"')
        || (!k.is_empty() && !k.starts_with('0') && k.bytes().all(|b| b.is_ascii_digit()))
}

impl ScriptValue {
    /// The table as the normal report shows it, as nmap lays out a
    /// script's table: every entry on a new line, indented two spaces per
    /// level, numbered entries as their value alone and named ones as
    /// `name: value`.
    pub fn layout(&self) -> String {
        match self {
            ScriptValue::Str(s) => s.clone(),
            ScriptValue::Table(t) => {
                let mut out = String::new();
                layout_table(t, "  ", &mut out);
                out
            }
        }
    }
}

fn layout_table(t: &ScriptTable, indent: &str, out: &mut String) {
    let deeper = format!("{indent}  ");
    for v in &t.list {
        out.push('\n');
        out.push_str(indent);
        layout_value(v, &deeper, out);
    }
    for (k, v) in &t.named {
        out.push('\n');
        out.push_str(indent);
        out.push_str(k);
        out.push_str(": ");
        layout_value(v, &deeper, out);
    }
}

fn layout_value(v: &ScriptValue, indent: &str, out: &mut String) {
    match v {
        ScriptValue::Str(s) => out.push_str(s),
        ScriptValue::Table(t) => layout_table(t, indent, out),
    }
}

/// Bytes from a script as text: valid UTF-8 as it is, any other byte as
/// `\xHH`, so nothing is lost silently.
pub fn bytes_to_text(bytes: &[u8]) -> String {
    bytes_to_text_max(bytes, usize::MAX)
}

/// [`bytes_to_text`], stopping once the text is longer than `max` bytes
/// (an invalid byte takes four), so a long input is never converted whole.
pub fn bytes_to_text_max(bytes: &[u8], max: usize) -> String {
    let mut out = String::with_capacity(bytes.len().min(max.saturating_add(1)));
    for chunk in bytes.utf8_chunks() {
        let valid = chunk.valid();
        let room = max.saturating_add(1).saturating_sub(out.len());
        if valid.len() > room {
            let mut end = room;
            while !valid.is_char_boundary(end) {
                end += 1;
            }
            out.push_str(&valid[..end]);
            return out;
        }
        out.push_str(valid);
        for b in chunk.invalid() {
            if out.len() > max {
                return out;
            }
            out.push_str(&format!("\\x{b:02X}"));
        }
        if out.len() > max {
            return out;
        }
    }
    out
}

/// A script's output for a terminal: control characters other than tab
/// and newline become `\xHH`, as in nmap, so a hostile service cannot
/// send escape sequences to the screen through a script.
pub fn escape_for_screen(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c == '\t' || c == '\n' || !c.is_control() {
            out.push(c);
        } else if (c as u32) < 0x100 {
            out.push_str(&format!("\\x{:02X}", c as u32));
        } else {
            out.push_str(&format!("\\u{{{:X}}}", c as u32));
        }
    }
    out
}

/// A script result as the normal report shows it: `|_id: output` for one
/// line; for more, `| ` before every line but the last, which gets `|_`.
/// `None` when the output is empty.
pub fn normal_lines(r: &ScriptResult) -> Option<String> {
    let text = escape_for_screen(&r.output);
    if text.is_empty() {
        return None;
    }
    let lines: Vec<&str> = text.split('\n').collect();
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        out.push_str(if i + 1 < lines.len() { "| " } else { "|_" });
        if i == 0 {
            out.push_str(&r.id);
            out.push_str(": ");
        }
        out.push_str(line);
        if i + 1 < lines.len() {
            out.push('\n');
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> ScriptValue {
        ScriptValue::Str(v.into())
    }

    #[test]
    fn layout_like_nmap() {
        let t = ScriptValue::Table(ScriptTable {
            list: vec![s("first")],
            named: vec![
                (
                    "keys".into(),
                    ScriptValue::Table(ScriptTable {
                        list: vec![s("a"), s("b")],
                        named: vec![],
                    }),
                ),
                ("name".into(), s("x")),
            ],
        });
        assert_eq!(t.layout(), "\n  first\n  keys: \n    a\n    b\n  name: x");
        let r = ScriptResult {
            id: "demo".into(),
            output: t.layout(),
            data: Some(t),
        };
        assert_eq!(
            normal_lines(&r).unwrap(),
            "| demo: \n|   first\n|   keys: \n|     a\n|     b\n|_  name: x"
        );
    }

    #[test]
    fn one_line_and_escapes() {
        let r = ScriptResult {
            id: "banner".into(),
            output: "SSH-2.0\r\x1b[2J".into(),
            data: None,
        };
        assert_eq!(normal_lines(&r).unwrap(), "|_banner: SSH-2.0\\x0D\\x1B[2J");
        assert_eq!(bytes_to_text(b"ok\xff\xfe"), "ok\\xFF\\xFE");
        assert_eq!(bytes_to_text("é".as_bytes()), "é");
        assert_eq!(bytes_to_text_max(b"\xff\xff\xff\xff", 5), "\\xFF\\xFF");
        assert_eq!(bytes_to_text_max("abcé".as_bytes(), 3), "abcé");
        assert_eq!(bytes_to_text_max(b"abcdef", 2), "abc");
        let empty = ScriptResult {
            id: "x".into(),
            output: String::new(),
            data: None,
        };
        assert!(normal_lines(&empty).is_none());
    }

    #[test]
    fn json_shapes() {
        let list = ScriptValue::Table(ScriptTable {
            list: vec![s("a")],
            named: vec![],
        });
        assert_eq!(serde_json::to_string(&list).unwrap(), "[\"a\"]");
        let mixed = ScriptValue::Table(ScriptTable {
            list: vec![s("a")],
            named: vec![("k".into(), s("v"))],
        });
        assert_eq!(
            serde_json::to_string(&mixed).unwrap(),
            "{\"1\":\"a\",\"k\":\"v\"}"
        );
        // t[1], t["1"] and t['"1"'] stay three distinct keys.
        let table = |named: Vec<(&str, &str)>| {
            ScriptValue::Table(ScriptTable {
                list: vec![s("a")],
                named: named.into_iter().map(|(k, v)| (k.into(), s(v))).collect(),
            })
        };
        let json = |t: &ScriptValue| serde_json::to_value(t).unwrap();
        let both = json(&table(vec![("\"1\"", "c"), ("1", "b")]));
        assert_eq!(both["1"], "a");
        assert_eq!(both["\"1\""], "b");
        assert_eq!(both["\"\"1\"\""], "c");
        assert_eq!(both.as_object().unwrap().len(), 3);
        assert_ne!(
            json(&table(vec![("1", "b")])),
            json(&table(vec![("\"1\"", "b")]))
        );
        // {[1]="a", ["2"]="b", x="c"} and {[1]="a", [2]="b", x="c"} differ.
        let named_two = json(&table(vec![("2", "b"), ("x", "c")]));
        let numbered_two = json(&ScriptValue::Table(ScriptTable {
            list: vec![s("a"), s("b")],
            named: vec![("x".into(), s("c"))],
        }));
        assert_ne!(named_two, numbered_two);
        assert_eq!(named_two["\"2\""], "b");
        assert_eq!(numbered_two["2"], "b");
        // A purely named table cannot look like one with numbered entries.
        let named = ScriptValue::Table(ScriptTable {
            list: vec![],
            named: vec![("1".into(), s("a")), ("x".into(), s("c"))],
        });
        assert_ne!(json(&named), json(&table(vec![("x", "c")])));
        assert_eq!(json(&named)["\"1\""], "a");
        // Other names, "02" and "0" among them, are written as they are.
        let plain = json(&table(vec![("02", "b"), ("0", "z"), ("k", "v")]));
        assert_eq!(plain["02"], "b");
        assert_eq!(plain["0"], "z");
        assert_eq!(plain["k"], "v");
        let big = json(&table(vec![("123456789012345678901234567890", "n")]));
        assert_eq!(big["\"123456789012345678901234567890\""], "n");
    }
}
