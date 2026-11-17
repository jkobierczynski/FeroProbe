use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::model::{HostResult, PortResult, PortState, Protocol, reason};

fn script(id: &str, src: &str) -> Script {
    Script::load(id, None, src).unwrap()
}

fn host_with(ports: &[(u16, PortState)]) -> HostResult {
    let mut h = HostResult::new(IpAddr::V4(Ipv4Addr::LOCALHOST), Some("localhost".into()));
    h.up_reason = Some(reason::USER_SET);
    for &(port, state) in ports {
        h.ports.push(PortResult {
            port,
            protocol: Protocol::Tcp,
            state,
            reason: reason::SYN_ACK,
            rtt_ms: None,
            service: None,
            scripts: Vec::new(),
        });
    }
    h
}

/// A TCP server on 127.0.0.1 that greets with `greeting`, then echoes
/// one read back.
async fn greeter(greeting: &'static [u8]) -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let _ = s.write_all(greeting).await;
                let mut buf = [0u8; 256];
                if let Ok(n) = s.read(&mut buf).await {
                    let _ = s.write_all(&buf[..n]).await;
                }
            });
        }
    });
    port
}

const PORT_SCRIPT: &str = r#"
description = "test"
categories = {"safe"}
portrule = function(host, port) return port.state == "open" end
"#;

#[test]
fn built_in_scripts_load() {
    let all = Script::built_in().unwrap();
    let banner = all.iter().find(|s| s.id == "banner").unwrap();
    assert_eq!(banner.categories, ["discovery", "safe"]);
    assert!(banner.rules.portrule && !banner.rules.hostrule);
    assert!(banner.description.contains("first line"));
    let help = help_text(std::slice::from_ref(banner));
    assert!(
        help.starts_with("\nbanner\nCategories: discovery safe\nBuilt into FeroProbe\n  Shows")
    );
}

#[test]
fn load_errors() {
    let e = Script::load("x", None, "categories = {}").unwrap_err();
    assert!(e.0.contains("no action"), "{e}");
    let e = Script::load("x", None, "categories = {} action = function() end").unwrap_err();
    assert!(e.0.contains("no rule"), "{e}");
    let e = Script::load("x", None, "action = function() end hostrule = action").unwrap_err();
    assert!(e.0.contains("categories"), "{e}");
    let e = Script::load("x", None, "while true do end").unwrap_err();
    assert!(e.0.contains("timed out"), "{e}");
    let e = Script::load("x", None, "syntax error here").unwrap_err();
    assert!(e.0.contains("could not load"), "{e}");
}

#[test]
fn choosing_scripts() {
    let built = || {
        vec![
            script("alpha", &format!("{PORT_SCRIPT} action = function() end")),
            Script::load(
                "beta",
                None,
                "categories = {'default','intrusive'} hostrule = function() return true end \
                 action = function() end",
            )
            .unwrap(),
        ]
    };
    let ids = |spec: &str| -> Vec<String> {
        choose_from(spec, built())
            .unwrap()
            .into_iter()
            .map(|s| s.id)
            .collect()
    };
    assert_eq!(ids("alpha"), ["alpha"]);
    assert_eq!(ids("safe"), ["alpha"]);
    assert_eq!(ids("all"), ["alpha", "beta"]);
    assert_eq!(ids("not intrusive"), ["alpha"]);
    assert_eq!(ids("b*"), ["beta"]);
    assert_eq!(ids("alpha,beta,safe"), ["alpha", "beta"]);
    let forced = choose_from("+beta", built()).unwrap();
    assert!(forced[0].forced);
    assert_eq!(forced[0].selection, Selection::Name);
    assert_eq!(
        choose_from("safe", built()).unwrap()[0].selection,
        Selection::Category
    );
    let e = choose_from("nosuch", built()).unwrap_err();
    assert_eq!(
        e.0,
        "'nosuch' did not match a category, filename, or directory"
    );

    // Files and directories.
    let dir = std::env::temp_dir().join(format!("feroprobe-scripts-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("mine.lua");
    std::fs::write(
        &file,
        format!("{PORT_SCRIPT} action = function() return 'hi' end"),
    )
    .unwrap();
    std::fs::write(dir.join("notes.txt"), "not a script").unwrap();
    let path = file.display().to_string();
    let chosen = choose_from(&path, built()).unwrap();
    assert_eq!(chosen[0].id, "mine");
    assert_eq!(chosen[0].selection, Selection::File);
    // The extension may be left out.
    let bare = path.trim_end_matches(".lua");
    assert_eq!(choose_from(bare, built()).unwrap()[0].id, "mine");
    let d = dir.display().to_string();
    let e = choose_from(&d, built()).unwrap_err();
    assert!(e.0.contains("will not match without '/'"), "{e}");
    let chosen = choose_from(&format!("{d}/"), built()).unwrap();
    assert_eq!(chosen.len(), 1);
    assert_eq!(chosen[0].selection, Selection::Directory);
    // The same file twice is loaded once; two scripts of one name fail.
    assert_eq!(
        choose_from(&format!("{path},{d}/"), built()).unwrap().len(),
        1
    );
    std::fs::write(
        dir.join("alpha.lua"),
        format!("{PORT_SCRIPT} action = function() end"),
    )
    .unwrap();
    let e = choose_from(&format!("alpha,{d}/"), built()).unwrap_err();
    assert_eq!(e.0, "duplicate script ID: 'alpha'");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn dependencies_set_the_order() {
    let mk = |id: &str, deps: &str| {
        Arc::new(script(
            id,
            &format!("{PORT_SCRIPT} dependencies = {{{deps}}} action = function() end"),
        ))
    };
    let levels = run_levels(&[
        mk("c", "'b'"),
        mk("b", "'a'"),
        mk("a", ""),
        mk("d", "'gone'"),
    ])
    .unwrap();
    let ids: Vec<Vec<&str>> = levels
        .iter()
        .map(|l| l.iter().map(|s| s.id.as_str()).collect())
        .collect();
    assert_eq!(ids, vec![vec!["a", "d"], vec!["b"], vec!["c"]]);
    let e = run_levels(&[mk("x", "'y'"), mk("y", "'x'")]).unwrap_err();
    assert!(e.0.contains("circular dependency"), "{e}");
}

#[tokio::test]
async fn a_port_script_reads_a_banner() {
    let port = greeter(b"SSH-2.0-Test_1.0\r\nmore\r\n").await;
    let banner = Script::built_in()
        .unwrap()
        .into_iter()
        .find(|s| s.id == "banner")
        .unwrap();
    let scan = ScriptScan::new(vec![banner], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with(&[
        (port, PortState::Open),
        (1, PortState::Closed),
    ])];
    scan.scan_hosts(&mut hosts).await;
    let open = hosts[0].ports.iter().find(|p| p.port == port).unwrap();
    assert_eq!(open.scripts.len(), 1);
    assert_eq!(open.scripts[0].id, "banner");
    assert_eq!(open.scripts[0].output, "SSH-2.0-Test_1.0");
    assert!(
        hosts[0]
            .ports
            .iter()
            .find(|p| p.port == 1)
            .unwrap()
            .scripts
            .is_empty()
    );
}

#[tokio::test]
async fn sockets_stay_in_scope() {
    let port = greeter(b"hello\n").await;
    let other = greeter(b"other\n").await;
    let src = format!(
        r#"{PORT_SCRIPT}
action = function(host, port)
  local out = {{}}
  local s = fero.socket.new()
  out.same = tostring(s:connect(host.ip, port.number))
  local t = fero.socket.new()
  local ok, err = t:connect(host.ip, {other})
  out.unscanned = tostring(ok) .. " " .. err
  local u = fero.socket.new()
  ok, err = u:connect("127.0.0.2", port.number)
  out.otherhost = tostring(ok) .. " " .. err
  ok, err = u:connect("localhost", port.number)
  out.byname = tostring(ok)
  ok, err = u:connect(host, port, "udp")
  out.udp = tostring(ok) .. " " .. err
  s:send("ping\n")
  local st, data = s:receive_lines(2)
  out.echo = data
  return out
end"#
    );
    let scan = ScriptScan::new(vec![script("scope", &src)], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with(&[(port, PortState::Open)])];
    scan.scan_hosts(&mut hosts).await;
    let r = &hosts[0].ports[0].scripts[0];
    let Some(ScriptValue::Table(t)) = &r.data else {
        panic!("{r:?}")
    };
    let get = |k: &str| match &t.named.iter().find(|(n, _)| n == k).unwrap().1 {
        ScriptValue::Str(s) => s.clone(),
        _ => panic!(),
    };
    assert_eq!(get("same"), "true");
    assert!(
        get("unscanned").starts_with("false tcp port"),
        "{}",
        get("unscanned")
    );
    assert!(
        get("otherhost").starts_with("false 127.0.0.2 is outside"),
        "{}",
        get("otherhost")
    );
    assert_eq!(get("byname"), "true");
    assert!(get("udp").starts_with("false udp port"), "{}", get("udp"));
    assert_eq!(get("echo"), "hello\nping\n");
    assert!(
        r.output.starts_with("\n  byname: true\n  echo: hello"),
        "{}",
        r.output
    );
}

#[tokio::test]
async fn host_rules_args_and_whole_run_scripts() {
    let src = r#"
categories = {"safe"}
prerule = function() return true end
hostrule = function(host) return host.targetname == "localhost" end
postrule = function() return fero.args.get("post") ~= nil end
action = function(host)
  if SCRIPT_TYPE ~= "hostrule" then return SCRIPT_TYPE end
  local a, b, c, d = fero.args.get("t.name", "missing", {"nope", "flag"}, "t.list")
  return {name = a, missing = tostring(b), flag = tostring(c), list = d}, "host " .. host.ip
end"#;
    let args = args::parse("t.name=x,flag,list={1,2},post=1").unwrap();
    let scan = ScriptScan::new(vec![script("t", src)], args, None).unwrap();
    assert_eq!(scan.pre_scan().await[0].output, "prerule");
    assert_eq!(scan.post_scan().await[0].output, "postrule");
    let mut hosts = vec![host_with(&[]), host_with(&[])];
    hosts[1].hostname = None;
    scan.scan_hosts(&mut hosts).await;
    let r = &hosts[0].scripts[0];
    assert_eq!(r.output, "host 127.0.0.1");
    let Some(ScriptValue::Table(t)) = &r.data else {
        panic!()
    };
    let keys: Vec<&str> = t.named.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, ["flag", "list", "missing", "name"]);
    assert_eq!(t.named[0].1, ScriptValue::Str("true".into()));
    assert_eq!(t.named[2].1, ScriptValue::Str("nil".into()));
    assert!(hosts[1].scripts.is_empty());

    // A postrule that says no runs nothing.
    let scan = ScriptScan::new(vec![script("t", src)], ArgTable::default(), None).unwrap();
    assert!(scan.post_scan().await.is_empty());
}

#[tokio::test]
async fn timeouts_and_errors_give_no_output() {
    let slow = script(
        "slow",
        &format!("{PORT_SCRIPT} action = function() while true do end end"),
    );
    let waits = script(
        "waits",
        &format!(
            "{PORT_SCRIPT} action = function(h, p) local s = fero.socket.new() \
             s:connect(h, p) s:set_timeout(60000) s:receive_bytes(100000) return 'late' end"
        ),
    );
    let fails = script(
        "fails",
        &format!("{PORT_SCRIPT} action = function() error('boom') end"),
    );
    let ok = script(
        "ok",
        &format!("{PORT_SCRIPT} action = function() return 'fine' end"),
    );
    let port = greeter(b"").await;
    let mut scan = ScriptScan::new(
        vec![slow, waits, fails, ok],
        ArgTable::default(),
        Some(Duration::from_millis(300)),
    )
    .unwrap();
    scan.parallel = 4;
    let mut hosts = vec![host_with(&[(port, PortState::Open)])];
    let started = std::time::Instant::now();
    scan.scan_hosts(&mut hosts).await;
    assert!(started.elapsed() < Duration::from_secs(10));
    let ids: Vec<&str> = hosts[0].ports[0]
        .scripts
        .iter()
        .map(|s| s.id.as_str())
        .collect();
    assert_eq!(ids, ["ok"]);
}

#[tokio::test]
async fn forced_scripts_skip_their_rules_and_timed_out_hosts_are_skipped() {
    let src = r#"categories = {"safe"}
hostrule = function() return false end
action = function() return "ran" end"#;
    let mut s = script("f", src);
    let scan = ScriptScan::new(vec![s.clone()], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with(&[])];
    scan.scan_hosts(&mut hosts).await;
    assert!(hosts[0].scripts.is_empty());
    s.forced = true;
    let scan = ScriptScan::new(vec![s], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with(&[]), host_with(&[])];
    hosts[1].timed_out = true;
    scan.scan_hosts(&mut hosts).await;
    assert_eq!(hosts[0].scripts[0].output, "ran");
    assert!(hosts[1].scripts.is_empty());
}

#[tokio::test]
async fn rules_see_their_own_script_type() {
    let src = r#"
categories = {"safe"}
seen = {}
hostrule = function() seen[#seen + 1] = SCRIPT_TYPE return true end
portrule = function() seen[#seen + 1] = SCRIPT_TYPE return true end
action = function() return table.concat(seen, ",") .. ";" .. SCRIPT_TYPE end"#;
    let scan = ScriptScan::new(vec![script("t", src)], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with(&[(1, PortState::Open)])];
    scan.scan_hosts(&mut hosts).await;
    // Actions get a fresh state, so `seen` is empty there.
    assert_eq!(hosts[0].scripts[0].output, ";hostrule");
    assert_eq!(hosts[0].ports[0].scripts[0].output, ";portrule");
    let src = r#"
categories = {"safe"}
portrule = function() return SCRIPT_TYPE == "portrule" end
hostrule = function() return SCRIPT_TYPE == "hostrule" end
action = function() return "ran" end"#;
    let scan = ScriptScan::new(vec![script("t", src)], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with(&[(1, PortState::Open)])];
    scan.scan_hosts(&mut hosts).await;
    assert_eq!(hosts[0].scripts.len(), 1);
    assert_eq!(hosts[0].ports[0].scripts.len(), 1);
}

#[tokio::test]
async fn shared_strings_in_output_are_bounded() {
    // One 1 MiB string 1000 times over: about 1 GiB if every copy were kept.
    let src = r#"
categories = {"safe"}
hostrule = function() return true end
action = function()
  local s = ("x"):rep(1024 * 1024)
  local t = {}
  for i = 1, 1000 do t[i] = s end
  return t
end"#;
    let scan = ScriptScan::new(vec![script("t", src)], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with(&[])];
    scan.scan_hosts(&mut hosts).await;
    let r = &hosts[0].scripts[0];
    let Some(ScriptValue::Table(t)) = &r.data else {
        panic!()
    };
    let kept: usize = t
        .list
        .iter()
        .map(|v| match v {
            ScriptValue::Str(s) => s.len(),
            ScriptValue::Table(_) => 0,
        })
        .sum();
    assert!(kept <= 17 * 1024 * 1024, "{kept}");
    assert!(t.list.len() < 1000);
    assert_eq!(t.list.last(), Some(&ScriptValue::Str("...".into())));
}

#[tokio::test]
async fn too_much_data_drops_the_connection() {
    let flood: &'static [u8] = Box::leak(vec![b'x'; 17 * 1024 * 1024].into_boxed_slice());
    let port = greeter(flood).await;
    let src = format!(
        "{PORT_SCRIPT} action = function(h, p) local s = fero.socket.new() \
         s:connect(h, p) local _, e1 = s:receive_bytes(1000000000) \
         local _, e2 = s:receive_bytes(1000000000) return e1 .. ';' .. e2 end"
    );
    let scan = ScriptScan::new(vec![script("t", &src)], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with(&[(port, PortState::Open)])];
    scan.scan_hosts(&mut hosts).await;
    assert_eq!(
        hosts[0].ports[0].scripts[0].output,
        "too much data;socket is not connected"
    );
}

#[tokio::test]
async fn shared_names_in_output_are_bounded() {
    // Nested tables all named by the same 1 MiB keys.
    let src = r#"
categories = {"safe"}
hostrule = function() return true end
action = function()
  local keys = {}
  for i = 1, 8 do keys[i] = ("k"):rep(1024 * 1024 - 1) .. i end
  local t = "leaf"
  for depth = 1, 20 do
    local n = {}
    for _, k in ipairs(keys) do n[k] = t end
    t = n
  end
  return t
end"#;
    let scan = ScriptScan::new(vec![script("t", src)], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with(&[])];
    scan.scan_hosts(&mut hosts).await;
    fn text_bytes(v: &ScriptValue) -> usize {
        match v {
            ScriptValue::Str(s) => s.len(),
            ScriptValue::Table(t) => {
                t.list.iter().map(text_bytes).sum::<usize>()
                    + t.named
                        .iter()
                        .map(|(k, v)| k.len() + text_bytes(v))
                        .sum::<usize>()
            }
        }
    }
    let data = hosts[0].scripts[0].data.as_ref().unwrap();
    let kept = text_bytes(data);
    assert!(kept <= 17 * 1024 * 1024, "{kept}");
}

#[tokio::test]
async fn invalid_bytes_and_tostring_output_are_bounded() {
    // 16 MiB of invalid UTF-8 would be 64 MiB as \xHH text; a table whose
    // __tostring gives 8 MiB, referenced 100 times, 800 MiB.
    let src = r#"
categories = {"safe"}
hostrule = function() return true end
action = function()
  local big = setmetatable({}, {__tostring = function() return ("y"):rep(8 * 1024 * 1024) end})
  local t = {bad = ("\255"):rep(16 * 1024 * 1024)}
  for i = 1, 100 do t[i] = big end
  return t, ("\255"):rep(20 * 1024 * 1024)
end"#;
    let scan = ScriptScan::new(vec![script("t", src)], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with(&[])];
    scan.scan_hosts(&mut hosts).await;
    let r = &hosts[0].scripts[0];
    assert!(r.output.len() <= 16 * 1024 * 1024 + 8, "{}", r.output.len());
    assert!(r.output.starts_with("\\xFF") && r.output.ends_with("..."));
    let Some(ScriptValue::Table(t)) = &r.data else {
        panic!()
    };
    let kept: usize = t
        .list
        .iter()
        .chain(t.named.iter().map(|(_, v)| v))
        .map(|v| match v {
            ScriptValue::Str(s) => s.len(),
            ScriptValue::Table(_) => 0,
        })
        .sum();
    assert!(kept <= 16 * 1024 * 1024 + 64, "{kept}");
    assert!(t.list.len() < 100);
}

#[tokio::test]
async fn an_invalid_byte_table_value_is_bounded() {
    // 16 MiB of invalid bytes in a table: 64 MiB as \xHH text, uncut.
    let src = r#"
categories = {"safe"}
hostrule = function() return true end
action = function() return {bad = ("\255"):rep(16 * 1024 * 1024)} end"#;
    let scan = ScriptScan::new(vec![script("t", src)], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with(&[])];
    scan.scan_hosts(&mut hosts).await;
    let Some(ScriptValue::Table(t)) = &hosts[0].scripts[0].data else {
        panic!()
    };
    let ScriptValue::Str(bad) = &t.named[0].1 else {
        panic!()
    };
    assert_eq!(t.named[0].0, "bad");
    assert!(bad.len() <= 16 * 1024 * 1024 + 3, "{}", bad.len());
    assert!(bad.starts_with("\\xFF\\xFF") && bad.ends_with("..."));
}

#[tokio::test]
async fn loading_the_rule_state_has_a_deadline() {
    // The top level runs at load (refused here, to get past it), then
    // again for the rule state, where it would loop for a second.
    let src = r#"
categories = {"safe"}
hostrule = function() return true end
action = function() return "ran" end
if SCRIPT_TYPE ~= "load" then
  local t = os.clock() while os.clock() - t < 1 do end
end"#;
    let scan = ScriptScan::new(
        vec![script("t", src)],
        ArgTable::default(),
        Some(Duration::from_millis(20)),
    )
    .unwrap();
    let mut hosts = vec![host_with(&[])];
    let started = std::time::Instant::now();
    scan.scan_hosts(&mut hosts).await;
    // Rule state stopped at 20 ms; the action's state likewise.
    assert!(
        started.elapsed() < Duration::from_millis(900),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn binary_and_escaped_names_stay_apart() {
    let src = r#"
categories = {"safe"}
hostrule = function() return true end
action = function() return {[string.char(255)] = "byte", ["\\xFF"] = "text"} end"#;
    let scan = ScriptScan::new(vec![script("t", src)], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with(&[])];
    scan.scan_hosts(&mut hosts).await;
    let Some(ScriptValue::Table(t)) = &hosts[0].scripts[0].data else {
        panic!()
    };
    let names: Vec<&str> = t.named.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(names, ["\\\\xFF", "\\xFF"]);
    assert_eq!(t.named[0].1, ScriptValue::Str("text".into()));
    assert_eq!(t.named[1].1, ScriptValue::Str("byte".into()));
}

#[test]
fn debug_output_is_bounded() {
    let mut room = 10;
    assert_eq!(engine::debug_text(b"hello", &mut room), "hello");
    assert_eq!(room, 5);
    // Cut at 5 bytes, inside the second \xFF, then "...".
    assert_eq!(
        engine::debug_text(&[0xff; 1_000_000], &mut room),
        "\\xFF\\..."
    );
    assert_eq!(room, 0);
    assert_eq!(engine::debug_text(b"more", &mut room), "...");
}

#[tokio::test]
async fn print_stops_converting_once_the_line_is_full() {
    crate::debug::set_debugging(1);
    // The first argument fills the line exactly, or all but the byte the
    // tab takes: the second's __tostring must not run.
    let src = r#"
categories = {"safe"}
hostrule = function() return true end
action = function()
  local called = false
  local late = setmetatable({}, {__tostring = function() called = true return "x" end})
  print(string.rep("a", 64 * 1024), late)
  -- The tab after this one takes the last byte.
  print(string.rep("a", 64 * 1024 - 1), late)
  return called and "called" or "not called"
end"#;
    let scan = ScriptScan::new(vec![script("t", src)], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with(&[])];
    scan.scan_hosts(&mut hosts).await;
    assert_eq!(hosts[0].scripts[0].output, "not called");
}

#[test]
fn print_lines_are_bounded_tabs_included() {
    let lua = mlua::Lua::new();
    let empty = lua.create_string("").unwrap();
    let line = engine::debug_join(0..200_000, |_| Some(empty.clone()));
    assert!(line.len() <= 64 * 1024 + 3, "{}", line.len());
    assert!(line.ends_with("..."));
    let a = lua.create_string("a").unwrap();
    let b = lua.create_string("b").unwrap();
    assert_eq!(
        engine::debug_join([Some(a), None, Some(b)].into_iter(), |s| s),
        "a\t\tb"
    );
}

// ---- Script libraries: TLS, HTTP, port rules (step 7.2) ----

type Seen = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

/// Read one HTTP request (head and Content-Length body) from `s`.
async fn read_http<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..i]).to_lowercase();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .map_or(0, |v| v.trim().parse().unwrap());
            if buf.len() >= i + 4 + len {
                break;
            }
        }
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// An HTTP server on 127.0.0.1 answering each request with
/// `answer(request)`, keeping every request it got.
async fn web(answer: fn(&str) -> Vec<u8>) -> (u16, Seen) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let seen: Seen = Default::default();
    let keep = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let keep = keep.clone();
            tokio::spawn(async move {
                let req = read_http(&mut s).await;
                let reply = answer(&req);
                keep.lock().unwrap().push(req);
                let _ = s.write_all(&reply).await;
                let _ = s.shutdown().await;
            });
        }
    });
    (port, seen)
}

fn tls_acceptor() -> tokio_rustls::TlsAcceptor {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "FeroProbe Lab");
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let der = rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into());
    let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.der().clone()], der)
    .unwrap();
    tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config))
}

/// A TLS server on 127.0.0.1. With `starttls`, it first greets in plain
/// text and waits for `STARTTLS`. Inside TLS it answers one HTTP request
/// with a page titled "Secure", keeping the request.
async fn tls_web(starttls: bool) -> (u16, Seen) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let acceptor = tls_acceptor();
    let seen: Seen = Default::default();
    let keep = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let acceptor = acceptor.clone();
            let keep = keep.clone();
            tokio::spawn(async move {
                if starttls {
                    let _ = s.write_all(b"220 ready\r\n").await;
                    let mut buf = [0u8; 64];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if &buf[..n] != b"STARTTLS\r\n" {
                        return;
                    }
                    let _ = s.write_all(b"220 go ahead\r\n").await;
                }
                let Ok(mut tls) = acceptor.accept(s).await else {
                    return;
                };
                let req = read_http(&mut tls).await;
                keep.lock().unwrap().push(req);
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 30\r\n\r\n<html><title>Secure</title>hi",
                    )
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (port, seen)
}

fn built_in(id: &str) -> Script {
    Script::built_in()
        .unwrap()
        .into_iter()
        .find(|s| s.id == id)
        .unwrap()
}

fn named<'a>(v: &'a ScriptValue, k: &str) -> &'a ScriptValue {
    let ScriptValue::Table(t) = v else {
        panic!("{v:?}")
    };
    &t.named
        .iter()
        .find(|(n, _)| n == k)
        .unwrap_or_else(|| panic!("no {k} in {t:?}"))
        .1
}

fn text(v: &ScriptValue) -> &str {
    match v {
        ScriptValue::Str(s) => s,
        other => panic!("{other:?}"),
    }
}

/// A host whose open ports carry the service name `-sV` would give.
fn host_with_services(ports: &[(u16, &str)]) -> HostResult {
    let mut h = host_with(
        &ports
            .iter()
            .map(|&(p, _)| (p, PortState::Open))
            .collect::<Vec<_>>(),
    );
    for (p, &(_, name)) in h.ports.iter_mut().zip(ports) {
        p.service = Some(crate::service::ServiceInfo {
            name: name.to_string(),
            ..Default::default()
        });
    }
    h
}

#[tokio::test]
async fn http_title_follows_redirects_in_scope_only() {
    let (port, seen) = web(|req| {
        if req.starts_with("GET / ") {
            b"HTTP/1.1 302 Found\r\nLocation: /home\r\nContent-Length: 0\r\n\r\n".to_vec()
        } else if req.starts_with("GET /home ") {
            // Chunked, with an entity and spread-out whitespace.
            let mut r = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
                          Transfer-Encoding: chunked\r\n\r\n"
                .to_vec();
            for part in ["<html><TITLE>\n ", "Lab &amp; Test</ti", "tle>.", ""] {
                r.extend(format!("{:x}\r\n{part}\r\n", part.len()).bytes());
            }
            r
        } else {
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
        }
    })
    .await;
    let scan = ScriptScan::new(vec![built_in("http-title")], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with_services(&[(port, "http")])];
    scan.scan_hosts(&mut hosts).await;
    let r = &hosts[0].ports[0].scripts[0];
    assert_eq!(
        r.output,
        format!("Lab & Test\nRequested resource was http://localhost:{port}/home")
    );
    assert_eq!(text(named(r.data.as_ref().unwrap(), "title")), "Lab & Test");
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert!(
            seen[0].contains(&format!("\r\nHost: localhost:{port}\r\n")),
            "{}",
            seen[0]
        );
        assert!(seen[0].contains(&format!("\r\nUser-Agent: {USER_AGENT}\r\n")));
        assert!(seen[0].contains("\r\nConnection: close\r\n"));
    }

    // A redirect to a port the scan did not probe is not followed.
    let (port, seen) = web(|_| {
        b"HTTP/1.1 301 Moved\r\nLocation: http://localhost:1/x\r\nContent-Length: 0\r\n\r\n"
            .to_vec()
    })
    .await;
    let mut hosts = vec![host_with_services(&[(port, "http")])];
    scan.scan_hosts(&mut hosts).await;
    assert_eq!(
        hosts[0].ports[0].scripts[0].output,
        "Did not follow redirect to http://localhost:1/x"
    );
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn http_library_calls() {
    let (port, seen) = web(|req| {
        if req.starts_with("HEAD ") {
            b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\nSet-Cookie: id=7; Path=/; HttpOnly\r\nX-A: 1\r\nX-A: 2\r\n\r\n".to_vec()
        } else if req.starts_with("POST ") {
            let body = req.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
            format!("HTTP/1.1 201 Created\r\n\r\n{body}").into_bytes()
        } else {
            let mut r = b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n".to_vec();
            r.extend(std::iter::repeat_n(b'x', 5000));
            r
        }
    })
    .await;
    let src = format!(
        r#"{PORT_SCRIPT}
action = function(host, port)
  local out = {{}}
  local r = fero.http.head(host, port, "/")
  out.head = r.status .. " " .. #r.body .. " " .. r.header["x-a"] .. " "
    .. r.cookies[1].name .. "=" .. r.cookies[1].value .. " " .. tostring(r.cookies[1].httponly)
  r = fero.http.post(host, port, "/f", nil, {{ b = "x y", a = "&" }})
  out.post = r.status .. " " .. r.body
  local ok, err = fero.http.get(host, port, "/big", {{ max_body_size = 100 }})
  out.big = tostring(ok) .. " " .. err
  r = fero.http.get(host, port, "/big", {{ max_body_size = 100, truncated_ok = true }})
  out.cut = #r.body .. " " .. tostring(r.truncated)
  ok, err = fero.http.get(host, 1, "/")
  out.scope = tostring(ok) .. " " .. err
  ok, err = fero.http.get(host, port, "/a b")
  out.bad = tostring(ok) .. " " .. err
  r = fero.http.get(host, port, "/", {{ header = {{ ["User-Agent"] = "custom" }} }})
  out.b64 = fero.base64.encode("foobar") .. " " .. fero.base64.decode("Zm9vYmFy")
  out.ua = fero.http.USER_AGENT
  return out
end"#
    );
    let scan = ScriptScan::new(
        vec![script("h", &src)],
        args::parse("http.host=vhost.test").unwrap(),
        None,
    )
    .unwrap();
    let mut hosts = vec![host_with(&[(port, PortState::Open)])];
    scan.scan_hosts(&mut hosts).await;
    let r = &hosts[0].ports[0].scripts[0];
    let d = r.data.as_ref().unwrap_or_else(|| panic!("{r:?}"));
    assert_eq!(text(named(d, "head")), "200 0 1, 2 id=7 true");
    assert_eq!(text(named(d, "post")), "201 a=%26&b=x%20y");
    assert_eq!(
        text(named(d, "big")),
        "nil body exceeds the maximum size of 100 bytes"
    );
    assert_eq!(text(named(d, "cut")), "100 true");
    assert!(
        text(named(d, "scope")).starts_with("nil tcp port 1 is outside"),
        "{}",
        text(named(d, "scope"))
    );
    assert!(text(named(d, "bad")).starts_with("nil bad request path"));
    assert_eq!(text(named(d, "b64")), "Zm9vYmFy foobar");
    assert_eq!(text(named(d, "ua")), USER_AGENT);
    let seen = seen.lock().unwrap();
    // --script-args http.host sets the Host header.
    assert!(seen[0].contains("\r\nHost: vhost.test\r\n"), "{}", seen[0]);
    let post = seen.iter().find(|r| r.starts_with("POST")).unwrap();
    assert!(post.contains("\r\nContent-Type: application/x-www-form-urlencoded\r\n"));
    assert!(post.contains("\r\nContent-Length: 13\r\n"));
    // A User-Agent the script sets replaces the signature, as in nmap.
    let last = seen.last().unwrap();
    assert!(last.contains("\r\nUser-Agent: custom\r\n"), "{last}");
    assert!(!last.contains("FeroProbe"));
}

#[tokio::test]
async fn ssl_cert_and_https_fallback() {
    let (port, seen) = tls_web(false).await;
    // The port number and its service ("unknown") suggest plain HTTP: the
    // client tries that first, gets no HTTP answer, then tries TLS.
    let scan = ScriptScan::new(
        vec![built_in("http-title"), built_in("ssl-cert")],
        ArgTable::default(),
        None,
    )
    .unwrap();
    let mut hosts = vec![host_with_services(&[(port, "http")])];
    scan.scan_hosts(&mut hosts).await;
    let scripts = &hosts[0].ports[0].scripts;
    assert_eq!(scripts.len(), 1, "{scripts:?}");
    assert_eq!(scripts[0].output, "Secure");
    assert!(seen.lock().unwrap()[0].contains(&format!("Host: localhost:{port}")));

    // ssl-cert runs where -sV found TLS.
    let mut hosts = vec![host_with_services(&[(port, "http")])];
    hosts[0].ports[0].service.as_mut().unwrap().tunnel = Some("ssl");
    scan.scan_hosts(&mut hosts).await;
    let scripts = &hosts[0].ports[0].scripts;
    assert_eq!(scripts.len(), 2, "{scripts:?}");
    let cert = &scripts[1];
    assert_eq!(cert.id, "ssl-cert");
    let lines: Vec<&str> = cert.output.lines().collect();
    assert_eq!(
        lines[0],
        "Subject: commonName=localhost/organizationName=FeroProbe Lab"
    );
    assert_eq!(lines[1], "Subject Alternative Name: DNS:localhost");
    assert_eq!(lines[3], "Public Key type: ec");
    assert_eq!(lines[4], "Public Key bits: 256");
    assert_eq!(lines[5], "Signature Algorithm: ecdsa-with-SHA256");
    assert!(lines[6].starts_with("Not valid before: "));
    assert!(lines[9].starts_with("SHA-256: ") && lines[9].len() == 9 + 64);
    let data = cert.data.as_ref().unwrap();
    assert_eq!(
        text(named(named(data, "subject"), "commonName")),
        "localhost"
    );
    // The http-title fetch, already over TLS this time, went first.
    assert_eq!(scripts[0].output, "Secure");
}

#[tokio::test]
async fn sockets_upgrade_to_tls() {
    let (port, _) = tls_web(true).await;
    let src = format!(
        r#"{PORT_SCRIPT}
action = function(host, port)
  local out = {{}}
  local s = fero.socket.new()
  s:set_timeout(5000)
  assert(s:connect(host, port))
  local _, greeting = s:receive_lines(1)
  out.greeting = greeting
  local ok, err = s:get_ssl_certificate()
  out.plain = tostring(ok) .. " " .. err
  s:send("STARTTLS\r\n")
  s:receive_lines(1)
  out.upgrade = tostring(s:reconnect_ssl())
  local info = s:get_tls_info()
  out.version = info.version
  out.cipher = tostring(info.cipher ~= nil)
  local st, lip, lport, rip, rport = s:get_info()
  out.info = tostring(st) .. " " .. lip .. " " .. rip .. " " .. tostring(rport == port.number)
  out.cn = s:get_ssl_certificate().subject.commonName
  s:send("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
  local _, page = s:receive_bytes(20)
  out.page = page:match("^HTTP/1.1 200") ~= nil
  out.again = select(2, s:reconnect_ssl())
  local u = fero.socket.new()
  out.ssludp = select(2, u:connect(host, port, "dtls"))
  return out
end"#
    );
    let scan = ScriptScan::new(vec![script("t", &src)], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with(&[(port, PortState::Open)])];
    scan.scan_hosts(&mut hosts).await;
    let r = &hosts[0].ports[0].scripts[0];
    let d = r.data.as_ref().unwrap_or_else(|| panic!("{r:?}"));
    assert_eq!(text(named(d, "greeting")), "220 ready\r\n");
    assert_eq!(text(named(d, "plain")), "false not an SSL socket");
    assert_eq!(text(named(d, "upgrade")), "true");
    assert_eq!(text(named(d, "version")), "TLSv1.3");
    assert_eq!(text(named(d, "cipher")), "true");
    assert_eq!(text(named(d, "info")), "true 127.0.0.1 127.0.0.1 true");
    assert_eq!(text(named(d, "cn")), "localhost");
    assert_eq!(text(named(d, "page")), "true");
    assert_eq!(text(named(d, "again")), "socket already speaks TLS");
    assert_eq!(text(named(d, "ssludp")), "unsupported protocol dtls");
}

#[tokio::test]
async fn port_rule_helpers() {
    let src = r#"
description = "t"
categories = {"safe"}
portrule = function(host, port)
  return fero.portrule.match({7}, "echo-ish")(host, port)
    or fero.portrule.http(host, port)
    or fero.portrule.ssl(host, port)
end
action = function(host, port) return port.service end
"#;
    let scan = ScriptScan::new(vec![script("r", src)], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with_services(&[
        (7, "echo"),
        (8, "echo-ish"),
        (9, "discard"),
        (80, "unknown"),
        (8081, "https-alt"),
        (993, "imaps"),
        (5555, "foo"),
    ])];
    hosts[0].ports[6].service.as_mut().unwrap().tunnel = Some("ssl");
    // Port rules only see the ports their rule sets accept.
    scan.scan_hosts(&mut hosts).await;
    let ran: Vec<u16> = hosts[0]
        .ports
        .iter()
        .filter(|p| !p.scripts.is_empty())
        .map(|p| p.port)
        .collect();
    assert_eq!(ran, [7, 8, 80, 8081, 993, 5555]);
}

#[tokio::test]
async fn title_references_decode_once() {
    let (port, _) = web(|_| {
        b"HTTP/1.1 200 OK\r\nContent-Length: 90\r\n\r\n<title>&#38;lt; &#xFFFFFFFFFFFFFFFF; &#x41;&AMP;&#99999999;&#00000066;&#x00000043;</title>"
            .to_vec()
    })
    .await;
    let scan = ScriptScan::new(vec![built_in("http-title")], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with_services(&[(port, "http")])];
    scan.scan_hosts(&mut hosts).await;
    assert_eq!(
        hosts[0].ports[0].scripts[0].output,
        "&lt; &#xFFFFFFFFFFFFFFFF; A&&#99999999;BC"
    );
}

#[tokio::test]
async fn credentials_stay_on_their_port_and_forms_keep_values() {
    // The second server's port, filled in once both are up.
    static NEXT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
    let (other, seen_other) =
        web(|_| b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()).await;
    NEXT.store(other, std::sync::atomic::Ordering::Relaxed);
    let (port, seen) = web(|req| {
        if req.starts_with("POST") {
            let body = req.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
            return format!("HTTP/1.1 200 OK\r\n\r\n{body}").into_bytes();
        }
        let to = NEXT.load(std::sync::atomic::Ordering::Relaxed);
        format!(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{to}/\r\nContent-Length: 0\r\n\r\n"
        )
        .into_bytes()
    })
    .await;
    let src = format!(
        r#"{PORT_SCRIPT}
action = function(host, port)
  if port.number ~= {port} then return nil end
  local r = fero.http.get(host, port, "/", {{ auth = {{ username = "u", password = "p" }},
    cookies = "s=1" }})
  local f = fero.http.post(host, port, "/", nil, {{ "a", "b", x = "y" }})
  return r.status .. " " .. f.body
end"#
    );
    let scan = ScriptScan::new(vec![script("c", &src)], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with(&[
        (port, PortState::Open),
        (other, PortState::Open),
    ])];
    scan.scan_hosts(&mut hosts).await;
    assert_eq!(hosts[0].ports[0].scripts[0].output, "200 1=a&2=b&x=y");
    assert!(seen.lock().unwrap()[0].contains("\r\nAuthorization: Basic dTpw\r\n"));
    let o = seen_other.lock().unwrap();
    assert!(
        !o[0].contains("Authorization") && !o[0].contains("Cookie"),
        "{}",
        o[0]
    );
}
