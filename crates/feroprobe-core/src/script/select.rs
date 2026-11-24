//! Reading `--script`: a comma-separated list of rules, each a script
//! name (with `*` wildcards), a category, a file or directory path, or a
//! boolean expression of names and categories (`"default and safe"`,
//! `"not intrusive"`, `"(discovery or version) and not brute"`), as in
//! nmap. A rule starting with `+` runs its scripts even when their rules
//! say no.

/// One `--script` rule, its `+` taken off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub text: String,
    pub forced: bool,
}

/// Split `--script` at its commas, as nmap does (parentheses do not group
/// commas), dropping white space around each rule and empty ones.
pub fn split_rules(spec: &str) -> Vec<Rule> {
    spec.split(',')
        .filter_map(|r| {
            let r = r.trim();
            let (forced, r) = match r.strip_prefix('+') {
                Some(rest) => (true, rest.trim()),
                None => (false, r),
            };
            (!r.is_empty()).then(|| Rule {
                text: r.to_string(),
                forced,
            })
        })
        .collect()
}

/// A rule read as an expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Expr {
    Const(bool),
    /// A category, `all`, or a name pattern.
    Word(String),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Open,
    Close,
    And,
    Or,
    Not,
    Word(String),
}

fn tokens(s: &str) -> Option<Vec<Token>> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            '(' => {
                chars.next();
                out.push(Token::Open);
            }
            ')' => {
                chars.next();
                out.push(Token::Close);
            }
            c if c.is_whitespace() => {
                chars.next();
            }
            // nmap's words: printable ASCII other than space and ( ).
            c if c.is_ascii_graphic() => {
                let mut w = String::new();
                while let Some(&c) = chars.peek() {
                    if !c.is_ascii_graphic() || c == '(' || c == ')' {
                        break;
                    }
                    w.push(c);
                    chars.next();
                }
                out.push(match w.as_str() {
                    "and" => Token::And,
                    "or" => Token::Or,
                    "not" => Token::Not,
                    _ => Token::Word(w),
                });
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Parse a rule. `None` if it is not an expression, such as a path with
/// a space in it; it may still name a file.
///
/// `and` and `or` bind equally and group from the right, as in nmap:
/// `a and b or c` is `a and (b or c)`.
pub(crate) fn parse(rule: &str) -> Option<Expr> {
    let toks = tokens(rule)?;
    let mut i = 0;
    let e = expr(&toks, &mut i)?;
    (i == toks.len()).then_some(e)
}

fn expr(t: &[Token], i: &mut usize) -> Option<Expr> {
    let left = value(t, i)?;
    match t.get(*i) {
        Some(Token::And) => {
            *i += 1;
            Some(Expr::And(Box::new(left), Box::new(expr(t, i)?)))
        }
        Some(Token::Or) => {
            *i += 1;
            Some(Expr::Or(Box::new(left), Box::new(expr(t, i)?)))
        }
        _ => Some(left),
    }
}

fn value(t: &[Token], i: &mut usize) -> Option<Expr> {
    let tok = t.get(*i)?;
    *i += 1;
    match tok {
        Token::Not => Some(Expr::Not(Box::new(value(t, i)?))),
        Token::Open => {
            let e = expr(t, i)?;
            if t.get(*i) != Some(&Token::Close) {
                return None;
            }
            *i += 1;
            Some(e)
        }
        Token::Word(w) if w == "true" => Some(Expr::Const(true)),
        Token::Word(w) if w == "false" => Some(Expr::Const(false)),
        Token::Word(w) => Some(Expr::Word(w.clone())),
        _ => None,
    }
}

impl Expr {
    /// Whether a script named `id` in `categories` matches. Sets `by_name`
    /// when a name pattern (not a category) matched it.
    pub(crate) fn matches(&self, id: &str, categories: &[String], by_name: &mut bool) -> bool {
        match self {
            Expr::Const(b) => *b,
            Expr::Word(w) => {
                if w == "all" || categories.iter().any(|c| c == w) {
                    return true;
                }
                let hit = glob(super::script_id(w), id);
                *by_name |= hit;
                hit
            }
            Expr::Not(e) => !e.matches(id, categories, by_name),
            Expr::And(a, b) => {
                a.matches(id, categories, by_name) && b.matches(id, categories, by_name)
            }
            Expr::Or(a, b) => {
                // Both sides, so a name match on either is noted.
                let x = a.matches(id, categories, by_name);
                let y = b.matches(id, categories, by_name);
                x || y
            }
        }
    }

    /// Whether this rule may run a brute-force script (one in the `brute`
    /// category): only when it names the script exactly (`ftp-brute`) or
    /// uses the `brute` category word (`brute`, `brute and safe`), never
    /// through `all`, another category such as `intrusive`, or a name
    /// pattern such as `*-brute`. Checked only on a rule that already
    /// matched the script, so the `brute` word or exact name is why, or
    /// part of why, it matched.
    pub(crate) fn authorizes_brute(&self, id: &str) -> bool {
        match self {
            // `id` never holds `*`, so an equal word is an exact name, not
            // a pattern.
            Expr::Word(w) => w == "brute" || w == id,
            Expr::Not(e) => e.authorizes_brute(id),
            Expr::And(a, b) | Expr::Or(a, b) => a.authorizes_brute(id) || b.authorizes_brute(id),
            Expr::Const(_) => false,
        }
    }
}

/// Whether `name` matches `pattern`, where `*` stands for any run of
/// characters. Script names are compared by their base name.
pub(crate) fn glob(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ni));
            pi += 1;
        } else if pi < p.len() && p[pi] == n[ni] {
            pi += 1;
            ni += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp + 1;
            ni = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(rule: &str, id: &str, cats: &[&str]) -> bool {
        let cats: Vec<String> = cats.iter().map(|c| c.to_string()).collect();
        parse(rule).unwrap().matches(id, &cats, &mut false)
    }

    #[test]
    fn rules_split_like_nmap() {
        assert_eq!(
            split_rules(" banner , +safe,, x"),
            vec![
                Rule {
                    text: "banner".into(),
                    forced: false
                },
                Rule {
                    text: "safe".into(),
                    forced: true
                },
                Rule {
                    text: "x".into(),
                    forced: false
                },
            ]
        );
    }

    #[test]
    fn names_categories_and_expressions() {
        assert!(m("banner", "banner", &["safe"]));
        assert!(m("banner.lua", "banner", &[]));
        assert!(m("banner.nse", "banner", &[]));
        assert!(m("http-*", "http-title", &[]));
        assert!(!m("http-*", "ssh-hostkey", &[]));
        assert!(m("safe", "x", &["discovery", "safe"]));
        assert!(m("all", "x", &[]));
        assert!(m("default and safe", "x", &["default", "safe"]));
        assert!(!m("default and safe", "x", &["default"]));
        assert!(m("not intrusive", "x", &["safe"]));
        assert!(!m("not intrusive", "x", &["intrusive"]));
        assert!(m("(default or version) and not brute", "x", &["version"]));
        // nmap's grouping: from the right.
        assert!(!m("default and safe or vuln", "x", &["vuln"]));
        assert!(m("notice", "notice", &[]));
        assert!(m("true", "x", &[]));
    }

    #[test]
    fn not_expressions() {
        assert!(parse("my scripts/a.lua").is_none());
        assert!(parse("(a").is_none());
        assert!(parse("a and").is_none());
        assert!(parse("./dir/").is_some());
    }

    #[test]
    fn brute_is_authorized_only_by_name_or_the_word() {
        let ok = |rule: &str, id: &str| parse(rule).unwrap().authorizes_brute(id);
        // The exact name or the `brute` word authorizes it.
        assert!(ok("ftp-brute", "ftp-brute"));
        assert!(ok("brute", "ftp-brute"));
        assert!(ok("brute and safe", "ftp-brute"));
        assert!(ok("ftp-brute or http-title", "ftp-brute"));
        // A category, `all`, or a name pattern does not.
        assert!(!ok("all", "ftp-brute"));
        assert!(!ok("intrusive", "ftp-brute"));
        assert!(!ok("*-brute", "ftp-brute"));
        assert!(!ok("safe", "ftp-brute"));
        assert!(!ok("default or intrusive", "ftp-brute"));
        // A different exact name does not authorize this one.
        assert!(!ok("ssh-brute", "ftp-brute"));
    }

    #[test]
    fn globs() {
        assert!(glob("*", "x"));
        assert!(glob("a*c", "abbbc"));
        assert!(!glob("a*c", "abbb"));
        assert!(glob("*-info", "smb-os-info"));
        assert!(!glob("ab", "abc"));
    }
}
