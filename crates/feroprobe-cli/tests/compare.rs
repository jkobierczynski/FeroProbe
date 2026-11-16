//! feroprobe-diff end to end: saved reports in `tests/diff/`, and two real
//! scans of a local port that is open in the first and closed in the second.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/diff")
        .join(name)
}

fn diff(args: &[&str], a: &Path, b: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_feroprobe-diff"))
        .args(args)
        .arg(a)
        .arg(b)
        .output()
        .expect("run feroprobe-diff")
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

#[test]
fn text_shows_every_kind_of_change() {
    let o = diff(&[], &fixture("before.xml"), &fixture("after.xml"));
    assert_eq!(o.status.code(), Some(1), "the scans differ");
    let expected = std::fs::read_to_string(fixture("expected.txt")).unwrap();
    assert_eq!(stdout(&o), expected.replace("\r\n", "\n"));
}

#[test]
fn same_scan_is_equal_and_silent() {
    let o = diff(&[], &fixture("before.xml"), &fixture("before.xml"));
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(stdout(&o), "");
    // -v shows everything, still exit 0.
    let o = diff(&["-v"], &fixture("before.xml"), &fixture("before.xml"));
    assert_eq!(o.status.code(), Some(0));
    let out = stdout(&o);
    assert!(out.contains(" 53/tcp open  domain"), "{out}");
    assert!(out.contains(" Host is up."), "{out}");
}

#[test]
fn xml_marks_both_sides() {
    let o = diff(&["--xml"], &fixture("before.xml"), &fixture("after.xml"));
    assert_eq!(o.status.code(), Some(1));
    let text = stdout(&o);
    let doc = roxmltree::Document::parse(&text).expect("well-formed XML");
    let root = doc.root_element();
    assert_eq!(root.tag_name().name(), "nmapdiff");
    let hostdiffs: Vec<_> = root
        .descendants()
        .filter(|n| n.has_tag_name("hostdiff"))
        .collect();
    // 10.0.0.5 changed, 10.0.0.10 gone, 10.0.0.11 new, 10.0.0.12 renamed.
    assert_eq!(hostdiffs.len(), 4);
    let new_host = hostdiffs[2].first_element_child().unwrap();
    assert_eq!(new_host.tag_name().name(), "b");
    let tunnel = root
        .descendants()
        .filter(|n| n.has_tag_name("service"))
        .find(|n| n.attribute("tunnel") == Some("ssl"))
        .expect("the TLS change is reported");
    assert_eq!(tunnel.parent().unwrap().tag_name().name(), "b");
}

#[test]
fn bad_input_exits_2() {
    let o = diff(&[], &fixture("missing.xml"), &fixture("before.xml"));
    assert_eq!(o.status.code(), Some(2));
    let o = diff(
        &["--text", "--xml"],
        &fixture("before.xml"),
        &fixture("after.xml"),
    );
    assert_eq!(o.status.code(), Some(2));
    let o = Command::new(env!("CARGO_BIN_EXE_feroprobe-diff"))
        .arg(fixture("before.xml"))
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2), "two files are needed");
}

/// Scan one local port with a connect scan and save the XML report.
fn scan(port: u16, out: &Path) {
    let o = Command::new(env!("CARGO_BIN_EXE_feroprobe"))
        .args([
            "-sT",
            "-Pn",
            "-n",
            "-p",
            &port.to_string(),
            "127.0.0.1",
            "-oX",
        ])
        .arg(out)
        .output()
        .expect("run feroprobe");
    assert!(
        o.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

#[test]
fn real_scans_show_a_port_closing() {
    let dir = std::env::temp_dir().join(format!("feroprobe-diff-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (a, b) = (dir.join("a.xml"), dir.join("b.xml"));

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    scan(port, &a);
    drop(listener);
    scan(port, &b);

    let o = diff(&[], &a, &b);
    let out = stdout(&o);
    assert_eq!(o.status.code(), Some(1), "{out}");
    assert!(
        out.contains(" localhost (127.0.0.1):") || out.contains(" 127.0.0.1:"),
        "{out}"
    );
    assert!(out.contains(&format!("-{port}/tcp open")), "{out}");
    assert!(out.contains(&format!("+{port}/tcp closed")), "{out}");

    let o = diff(&[], &a, &a);
    assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));
    let _ = std::fs::remove_dir_all(&dir);
}
