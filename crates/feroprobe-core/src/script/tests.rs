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
fn installed_scripts_and_their_index() {
    let built = || {
        vec![script(
            "alpha",
            &format!("{PORT_SCRIPT} action = function() end"),
        )]
    };
    let dir = std::env::temp_dir().join(format!("feroprobe-installed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // No directory: --script-updatedb says so; choosing still works.
    let e = db::update(&dir, &["alpha"]).unwrap_err();
    assert!(e.0.contains("no scripts directory"), "{e}");
    assert_eq!(choose_in("alpha", built(), Some(&dir)).unwrap().len(), 1);
    std::fs::create_dir_all(&dir).unwrap();
    let mine = "description = 'mine' categories = {'default', 'safe'} \
                hostrule = function() return true end action = function() return 'x' end";
    std::fs::write(dir.join("mine.lua"), mine).unwrap();
    std::fs::write(dir.join("broken.lua"), "syntax error here").unwrap();
    std::fs::write(dir.join("alpha.lua"), mine).unwrap();
    std::fs::write(dir.join("notes.txt"), "not a script").unwrap();
    let ids = |spec: &str| -> Vec<String> {
        choose_in(spec, built(), Some(&dir))
            .unwrap()
            .into_iter()
            .map(|s| s.id)
            .collect()
    };
    // By name without the index, as nmap; not by category yet.
    assert_eq!(ids("mine"), ["mine"]);
    assert_eq!(ids("mine.lua"), ["mine"]);
    assert_eq!(ids("safe"), ["alpha"]);
    // Only a plain name is looked up in the directory.
    assert!(choose_in("../mine", built(), Some(&dir)).is_err());

    let done = db::update(&dir, &["alpha"]).unwrap();
    let names: Vec<&str> = done.entries.iter().map(|e| e.filename.as_str()).collect();
    assert_eq!(names, ["mine.lua"]);
    assert_eq!(done.skipped.len(), 2, "{:?}", done.skipped);
    assert!(done.skipped.iter().any(|s| s.contains("broken.lua")));
    assert!(done.skipped.iter().any(|s| s.contains("built-in")));
    assert_eq!(
        std::fs::read_to_string(dir.join(db::DB_FILE)).unwrap(),
        "Entry { filename = \"mine.lua\", categories = { \"default\", \"safe\", } }\n"
    );
    // Now by category and expression too; the built-in alpha keeps its name.
    assert_eq!(ids("safe"), ["alpha", "mine"]);
    assert_eq!(ids("default and not alpha"), ["mine"]);
    let chosen = choose_in("default", built(), Some(&dir)).unwrap();
    assert_eq!(chosen[0].selection, Selection::Category);
    assert_eq!(chosen[0].path, Some(dir.join("mine.lua")));
    assert!(help_text(&chosen).contains("File: "));
    // The same file by index and by path is loaded once.
    let path = dir.join("mine.lua").display().to_string();
    assert_eq!(ids(&format!("safe,{path}")), ["alpha", "mine"]);
    // ...and a + on the path still forces it.
    let chosen = choose_in(&format!("safe,+{path}"), built(), Some(&dir)).unwrap();
    assert!(chosen.iter().any(|s| s.id == "mine" && s.forced));
    // A script the index lists but that is gone names the fix.
    std::fs::remove_file(dir.join("mine.lua")).unwrap();
    let e = choose_in("safe", built(), Some(&dir)).unwrap_err();
    assert!(e.0.contains("--script-updatedb"), "{e}");
    // A damaged index is an error, not a silent empty one.
    std::fs::write(dir.join(db::DB_FILE), "os.exit()").unwrap();
    let e = choose_in("alpha", built(), Some(&dir)).unwrap_err();
    assert!(e.0.contains("not an Entry line"), "{e}");
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

#[tokio::test]
async fn credentials_never_fall_back_from_tls_to_plain_text() {
    // A plain HTTP server on a port -sV said speaks TLS: the TLS attempt
    // fails, and only a request without credentials may retry in plain text.
    let (port, seen) = web(|_| b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()).await;
    let src = format!(
        r#"{PORT_SCRIPT}
action = function(host, port)
  local out = {{}}
  for _, h in ipairs({{ "Authorization", "Proxy-Authorization", "Cookie" }}) do
    local r, err = fero.http.get(host, port, "/" .. h, {{ header = {{ [h] = "secret" }}, timeout = 1000 }})
    out[#out + 1] = h .. " " .. tostring(r and r.status)
  end
  local r = fero.http.get(host, port, "/plain", {{ timeout = 1000 }})
  out[#out + 1] = "none " .. tostring(r and r.status)
  return table.concat(out, ",")
end"#
    );
    let scan = ScriptScan::new(vec![script("f", &src)], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with_services(&[(port, "http")])];
    hosts[0].ports[0].service.as_mut().unwrap().tunnel = Some("ssl");
    scan.scan_hosts(&mut hosts).await;
    assert_eq!(
        hosts[0].ports[0].scripts[0].output,
        "Authorization nil,Proxy-Authorization nil,Cookie nil,none 200"
    );
    let seen = seen.lock().unwrap();
    assert!(seen.iter().all(|r| !r.contains("secret")), "{seen:?}");
    assert!(seen.iter().any(|r| r.starts_with("GET /plain ")));
}

// ---- The default scripts (-sC), each against a local stand-in server ----

/// Run one built-in script on `host`; the outputs per port, by number.
async fn run_built_in(id: &str, host: HostResult) -> Vec<(u16, String)> {
    let scan = ScriptScan::new(vec![built_in(id)], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host];
    scan.scan_hosts(&mut hosts).await;
    hosts[0]
        .ports
        .iter()
        .flat_map(|p| p.scripts.iter().map(move |s| (p.port, s.output.clone())))
        .collect()
}

/// The one output of `id` on a host whose only port is `port`, known as
/// `service`.
async fn output_of(id: &str, port: u16, service: &str) -> Option<String> {
    let out = run_built_in(id, host_with_services(&[(port, service)])).await;
    assert!(out.len() <= 1, "{out:?}");
    out.into_iter().next().map(|(_, o)| o)
}

/// A line-protocol server on 127.0.0.1: sends `greeting`, then answers
/// each line it reads with `answer(line)` (closing on `None`), keeping
/// every line it got.
async fn line_server(greeting: &'static str, answer: fn(&str) -> Option<String>) -> (u16, Seen) {
    use tokio::io::AsyncBufReadExt;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let seen: Seen = Default::default();
    let keep = seen.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let keep = keep.clone();
            tokio::spawn(async move {
                let (rd, mut wr) = s.into_split();
                let mut rd = tokio::io::BufReader::new(rd);
                if wr.write_all(greeting.as_bytes()).await.is_err() {
                    return;
                }
                let mut line = String::new();
                while rd.read_line(&mut line).await.unwrap_or(0) > 0 {
                    let got = line.trim_end().to_string();
                    keep.lock().unwrap().push(got.clone());
                    line.clear();
                    match answer(&got) {
                        Some(reply) => {
                            if wr.write_all(reply.as_bytes()).await.is_err() {
                                return;
                            }
                        }
                        None => return,
                    }
                }
            });
        }
    });
    (port, seen)
}

/// A TCP server on 127.0.0.1 running `talk` on each connection.
async fn tcp_server<F, Fut>(talk: F) -> u16
where
    F: Fn(tokio::net::TcpStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            tokio::spawn(talk(s));
        }
    });
    port
}

#[tokio::test]
async fn ftp_anon_and_ftp_syst() {
    let (port, seen) = line_server("220 Lab FTP\r\n", |line| {
        Some(
            match line.split(' ').next().unwrap() {
                "USER" => "331 Password please\r\n",
                "PASS" => "230 Welcome\r\n",
                "SYST" => "215 UNIX Type: L8\r\n",
                "STAT" => {
                    "211-FTP server status:\r\n     Connected to 127.0.0.1\r\n211 End of status\r\n"
                }
                "QUIT" => return None,
                _ => "500 ?\r\n",
            }
            .to_string(),
        )
    })
    .await;
    assert_eq!(
        output_of("ftp-anon", port, "ftp").await.as_deref(),
        Some("Anonymous FTP login allowed (FTP code 230)")
    );
    {
        let seen = seen.lock().unwrap();
        assert_eq!(&seen[..2], ["USER anonymous", "PASS feroprobe@"]);
    }
    assert_eq!(
        output_of("ftp-syst", port, "ftp").await.as_deref(),
        Some(
            "SYST: UNIX Type: L8\nSTAT:\n  FTP server status:\n       Connected to 127.0.0.1\n  End of status"
        )
    );

    // A refused login, and STAT refused before login: nothing, and SYST
    // only.
    let (port, _) = line_server("220-Lab\r\n220 FTP\r\n", |line| {
        Some(
            match line.split(' ').next().unwrap() {
                "USER" => "530 Not allowed\r\n",
                "SYST" => "215 Windows_NT\r\n",
                "QUIT" => return None,
                _ => "530 Log in first\r\n",
            }
            .to_string(),
        )
    })
    .await;
    assert_eq!(output_of("ftp-anon", port, "ftp").await, None);
    assert_eq!(
        output_of("ftp-syst", port, "ftp").await.as_deref(),
        Some("SYST: Windows_NT")
    );

    // "2300" is not reply 230.
    let (port, _) = line_server("220 Lab FTP\r\n", |line| {
        Some(
            match line.split(' ').next().unwrap() {
                "USER" => "331 Password please\r\n",
                "PASS" => "2300 denied\r\n",
                "QUIT" => return None,
                _ => "500 ?\r\n",
            }
            .to_string(),
        )
    })
    .await;
    assert_eq!(output_of("ftp-anon", port, "ftp").await, None);
}

#[tokio::test]
async fn reader_bounds_lines_and_reply_codes() {
    // A line over 64 KiB is refused even when its newline comes in a later
    // read; a reply code must end at a space, a hyphen or the line's end.
    // The long line breaks the stream, so the replies come on a second
    // connection.
    let long = tcp_server(|mut s| async move {
        let _ = s.write_all(&vec![b'A'; 65536]).await;
        let _ = s.flush().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = s.write_all(b"B\n").await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    })
    .await;
    let port = tcp_server(|mut s| async move {
        let _ = s.write_all(b"2300 denied\n230\n230-a\n230 b\n").await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    })
    .await;
    let src = format!(
        "{PORT_SCRIPT}{}",
        r#"
action = function(host, port)
  local sock = fero.socket.new()
  sock:set_timeout(2000)
  local out = {}
  if port.number == LONG then
    sock:connect(host, port)
    local line, err = fero.reader(sock):line()
    sock:close()
    return tostring(line) .. "/" .. tostring(err)
  end
  sock:connect(host, port)
  local r = fero.reader(sock)
  local code, msg = r:reply()
  out[#out + 1] = tostring(code) .. "/" .. tostring(msg)
  code, msg = r:reply()
  out[#out + 1] = tostring(code)
  code, msg = r:reply()
  out[#out + 1] = tostring(code) .. "/" .. #msg
  sock:close()
  return table.concat(out, " ")
end
"#
    )
    .replace("LONG", &long.to_string());
    let scan = ScriptScan::new(vec![script("rd", &src)], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with(&[
        (long, PortState::Open),
        (port, PortState::Open),
    ])];
    scan.scan_hosts(&mut hosts).await;
    let out: Vec<_> = hosts[0]
        .ports
        .iter()
        .map(|p| p.scripts[0].output.as_str())
        .collect();
    assert_eq!(
        out,
        [
            "nil/line too long",
            "nil/not a numbered reply: 2300 denied 230 230/2"
        ]
    );
}

#[tokio::test]
async fn smtp_pop3_and_imap_capabilities() {
    let (port, seen) = line_server("220-mail.lab ESMTP\r\n220 ready\r\n", |line| {
        if line.starts_with("EHLO") {
            Some("250-mail.lab\r\n250-PIPELINING\r\n250-SIZE 1000\r\n250 STARTTLS\r\n".into())
        } else {
            None
        }
    })
    .await;
    assert_eq!(
        output_of("smtp-commands", port, "smtp").await.as_deref(),
        Some("mail.lab, PIPELINING, SIZE 1000, STARTTLS")
    );
    assert_eq!(seen.lock().unwrap()[0], "EHLO feroprobe.invalid");

    let (port, _) = line_server("+OK ready <1.2@lab>\r\n", |line| match line {
        "CAPA" => Some("+OK List\r\nTOP\r\nUIDL\r\nSASL PLAIN LOGIN\r\n.\r\n".into()),
        _ => None,
    })
    .await;
    assert_eq!(
        output_of("pop3-capabilities", port, "pop3")
            .await
            .as_deref(),
        Some("TOP UIDL SASL(PLAIN LOGIN) APOP")
    );

    // IMAP keywords are case-insensitive.
    let (port, seen) = line_server("* ok ready\r\n", |line| match line {
        "fp1 CAPABILITY" => {
            Some("* capability IMAP4rev1 IDLE AUTH=PLAIN\r\nfp1 OK done\r\n".into())
        }
        _ => Some("* BYE\r\nfp2 OK\r\n".into()),
    })
    .await;
    assert_eq!(
        output_of("imap-capabilities", port, "imap")
            .await
            .as_deref(),
        Some("IMAP4rev1 IDLE AUTH=PLAIN")
    );
    assert_eq!(seen.lock().unwrap()[0], "fp1 CAPABILITY");
}

#[tokio::test]
async fn sshv1_reads_the_greeting_only() {
    let port = greeter(b"SSH-1.99-OldServer\r\n").await;
    assert_eq!(
        output_of("sshv1", port, "ssh").await.as_deref(),
        Some("Server supports SSHv1 (announces protocol 1.99)")
    );
    let port = greeter(b"Hello\r\nSSH-2.0-NewServer\r\n").await;
    assert_eq!(output_of("sshv1", port, "ssh").await, None);
}

/// An SSH packet (RFC 4253 section 6) around `payload`, unencrypted.
fn ssh_packet(payload: &[u8]) -> Vec<u8> {
    let mut pad = 8 - (5 + payload.len()) % 8;
    if pad < 4 {
        pad += 8;
    }
    let mut out = ((1 + payload.len() + pad) as u32).to_be_bytes().to_vec();
    out.push(pad as u8);
    out.extend_from_slice(payload);
    out.extend(std::iter::repeat_n(0, pad));
    out
}

fn ssh_string(s: &[u8]) -> Vec<u8> {
    let mut out = (s.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(s);
    out
}

/// The test server's host keys: an Ed25519 key and a 2048-bit RSA key.
fn ssh_test_keys() -> (Vec<u8>, Vec<u8>) {
    let ed = [ssh_string(b"ssh-ed25519"), ssh_string(&[0x11; 32])].concat();
    let mut n = vec![0u8, 0xc0];
    n.extend(std::iter::repeat_n(0x5a, 255));
    let rsa = [
        ssh_string(b"ssh-rsa"),
        ssh_string(&[1, 0, 1]),
        ssh_string(&n),
    ]
    .concat();
    (ed, rsa)
}

/// A lab SSH server offering `kex`, answering a key exchange with its
/// host key, after checking the client's public value as OpenSSH does.
async fn ssh_lab(kex: &'static [u8]) -> (u16, Seen) {
    use tokio::io::AsyncBufReadExt;
    let idents: Seen = Default::default();
    let keep = idents.clone();
    let port = tcp_server(move |s| {
        let keep = keep.clone();
        async move {
            let mut s = tokio::io::BufReader::new(s);
            if s.write_all(b"SSH-2.0-LabSSH\r\n").await.is_err() {
                return;
            }
            let mut ident = String::new();
            if s.read_line(&mut ident).await.is_err() {
                return;
            }
            keep.lock().unwrap().push(ident.trim_end().to_string());
            let mut kexinit = vec![20u8];
            kexinit.extend([0u8; 16]);
            for list in [
                kex,
                b"ssh-ed25519,rsa-sha2-256",
                b"aes128-ctr",
                b"aes128-ctr",
                b"hmac-sha2-256",
                b"hmac-sha2-256",
                b"none",
                b"none",
                b"",
                b"",
            ] {
                kexinit.extend(ssh_string(list));
            }
            kexinit.extend([0, 0, 0, 0, 0]);
            if s.write_all(&ssh_packet(&kexinit)).await.is_err() {
                return;
            }
            let (ed, rsa) = ssh_test_keys();
            let mut key = None;
            loop {
                let mut head = [0u8; 5];
                if s.read_exact(&mut head).await.is_err() {
                    return;
                }
                let len = u32::from_be_bytes(head[..4].try_into().unwrap()) as usize;
                let mut rest = vec![0u8; len - 1];
                if s.read_exact(&mut rest).await.is_err() {
                    return;
                }
                let payload = &rest[..len - 1 - head[4] as usize];
                match payload[0] {
                    20 => {
                        // The client's host key algorithms: the second
                        // name-list.
                        let text = String::from_utf8_lossy(payload);
                        key = Some(if text.contains("ssh-ed25519") {
                            ed.clone()
                        } else {
                            rsa.clone()
                        });
                        keep.lock()
                            .unwrap()
                            .push(format!("kex {}", text.contains("curve25519-sha256,")));
                    }
                    30 => {
                        let e = &payload[5..];
                        // The client puts curve25519 first.
                        if kex.windows(10).any(|w| w == b"curve25519") {
                            assert_eq!(e.len(), 32);
                        } else {
                            // Finite-field DH: OpenSSH's dh_pub_is_valid
                            // wants a positive 1 < e < p-1 with at least
                            // 4 bits set, else it drops the connection.
                            let bits: u32 = e.iter().map(|b| b.count_ones()).sum();
                            if e.is_empty() || e[0] & 0x80 != 0 || e.len() > 256 || bits < 4 {
                                keep.lock().unwrap().push("bad e".into());
                                return;
                            }
                        }
                        let mut reply = vec![31u8];
                        reply.extend(ssh_string(key.as_ref().unwrap()));
                        reply.extend(ssh_string(&[0x22; 32]));
                        reply.extend(ssh_string(b"signature"));
                        let _ = s.write_all(&ssh_packet(&reply)).await;
                        return;
                    }
                    _ => return,
                }
            }
        }
    })
    .await;
    (port, idents)
}

#[tokio::test]
async fn ssh_hostkey_reads_each_key_from_the_key_exchange() {
    check_ssh_hostkey(b"diffie-hellman-group14-sha256,curve25519-sha256").await;
}

#[tokio::test]
async fn ssh_hostkey_sends_a_valid_dh_public_value() {
    check_ssh_hostkey(b"diffie-hellman-group14-sha256").await;
}

async fn check_ssh_hostkey(kex: &'static [u8]) {
    let (port, idents) = ssh_lab(kex).await;
    let out = output_of("ssh-hostkey", port, "ssh").await.unwrap();
    let (ed, rsa) = ssh_test_keys();
    let md5 = |k: &[u8]| {
        super::digest::md5(k)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    assert_eq!(
        out,
        format!("\n  2048 {} (RSA)\n  256 {} (ED25519)", md5(&rsa), md5(&ed))
    );
    // Three connections: the first learns there is no DSA key, the ECDSA
    // one is skipped since the server offers none.
    let idents = idents.lock().unwrap();
    assert_eq!(
        idents
            .iter()
            .filter(|i| *i == "SSH-2.0-FeroProbe_Scripting_Engine")
            .count(),
        3,
        "{idents:?}"
    );
    assert!(idents.iter().all(|i| i != "kex false"), "{idents:?}");
}

#[tokio::test]
async fn mysql_info_reads_the_greeting() {
    let port = tcp_server(|mut s| async move {
        let mut p = vec![10u8];
        p.extend(b"8.0.36\0");
        p.extend(7u32.to_le_bytes());
        p.extend(b"abcdefgh");
        p.push(0);
        p.extend(0xffffu16.to_le_bytes());
        p.push(0xff);
        p.extend(2u16.to_le_bytes());
        p.extend(0x0008u16.to_le_bytes());
        p.push(21);
        p.extend([0u8; 10]);
        p.extend(b"ijklmnopqrst\0");
        p.extend(b"caching_sha2_password\0");
        let mut packet = (p.len() as u32).to_le_bytes()[..3].to_vec();
        packet.push(0);
        packet.extend(p);
        let _ = s.write_all(&packet).await;
    })
    .await;
    let out = output_of("mysql-info", port, "mysql").await.unwrap();
    for want in [
        "\n  Protocol: 10\n  Version: 8.0.36\n  Thread ID: 7\n  Capabilities flags: 589823\n",
        "PROTOCOL_41",
        "PLUGIN_AUTH",
        "\n  Status: Autocommit\n  Salt: abcdefghijklmnopqrst\n  Auth Plugin Name: caching_sha2_password",
    ] {
        assert!(out.contains(want), "{want:?} in {out}");
    }

    // A server that refuses the connection says why.
    let port = tcp_server(|mut s| async move {
        let msg = b"Host 'x' is not allowed to connect";
        let mut p = vec![0xffu8];
        p.extend(1130u16.to_le_bytes());
        p.extend(msg);
        let mut packet = (p.len() as u32).to_le_bytes()[..3].to_vec();
        packet.push(0);
        packet.extend(p);
        let _ = s.write_all(&packet).await;
    })
    .await;
    assert_eq!(
        output_of("mysql-info", port, "mysql").await.as_deref(),
        Some("Error 1130: Host 'x' is not allowed to connect")
    );
}

#[tokio::test]
async fn vnc_info_and_x11_access() {
    let port = tcp_server(|mut s| async move {
        let _ = s.write_all(b"RFB 003.008\n").await;
        let mut v = [0u8; 12];
        if s.read_exact(&mut v).await.is_ok() && &v == b"RFB 003.008\n" {
            let _ = s.write_all(&[2, 2, 1]).await;
        }
        let _ = s.read(&mut v).await;
    })
    .await;
    assert_eq!(
        output_of("vnc-info", port, "vnc").await.as_deref(),
        Some(
            "\n  Protocol version: 3.8\n  Security types:\n    VNC Authentication (2)\n    None (1)\n  \
             WARNING: the server accepts connections without authentication"
        )
    );

    let port = tcp_server(|mut s| async move {
        let mut req = [0u8; 12];
        if s.read_exact(&mut req).await.is_ok() && req[0] == b'l' && req[2] == 11 {
            let _ = s.write_all(&[1, 0, 11, 0, 0, 0, 0, 0]).await;
        }
    })
    .await;
    assert_eq!(
        output_of("x11-access", port, "X11").await.as_deref(),
        Some("X server access is granted")
    );
    let port = tcp_server(|mut s| async move {
        let mut req = [0u8; 12];
        let _ = s.read_exact(&mut req).await;
        let _ = s.write_all(&[0, 20, 11, 0, 0, 0, 5, 0]).await;
    })
    .await;
    assert_eq!(output_of("x11-access", port, "X11").await, None);
}

#[tokio::test]
async fn rpcinfo_dumps_the_portmapper_over_tcp() {
    let port = tcp_server(|mut s| async move {
        let mut mark = [0u8; 4];
        if s.read_exact(&mut mark).await.is_err() {
            return;
        }
        let n = (u32::from_be_bytes(mark) & 0x7fff_ffff) as usize;
        let mut call = vec![0u8; n];
        if s.read_exact(&mut call).await.is_err() {
            return;
        }
        // Program 100000 version 2 procedure 4 (DUMP).
        assert_eq!(&call[12..24], &[0, 1, 0x86, 0xa0, 0, 0, 0, 2, 0, 0, 0, 4]);
        let mut reply = call[..4].to_vec();
        for w in [1u32, 0, 0, 0, 0] {
            reply.extend(w.to_be_bytes());
        }
        for (prog, vers, prot, port) in [
            (100000u32, 4u32, 6u32, 111u32),
            (100000, 3, 6, 111),
            (100000, 2, 6, 111),
            (100000, 2, 17, 111),
            (100003, 3, 6, 2049),
        ] {
            for w in [1, prog, vers, prot, port] {
                reply.extend(w.to_be_bytes());
            }
        }
        reply.extend(0u32.to_be_bytes());
        // Two record fragments.
        let (a, b) = reply.split_at(30);
        let mut out = (a.len() as u32).to_be_bytes().to_vec();
        out.extend(a);
        out.extend((0x8000_0000 | b.len() as u32).to_be_bytes());
        out.extend(b);
        let _ = s.write_all(&out).await;
    })
    .await;
    assert_eq!(
        output_of("rpcinfo", port, "rpcbind").await.as_deref(),
        Some(
            "\n  program  version      port/proto  service\
             \n  100000   2,3,4          111/tcp   rpcbind\
             \n  100000   2              111/udp   rpcbind\
             \n  100003   3             2049/tcp   nfs"
        )
    );
}

#[tokio::test]
async fn ntp_info_asks_for_the_time_and_the_system_variables() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = server.recv_from(&mut buf).await {
            let reply = match buf[0] & 7 {
                3 if n == 48 => {
                    let mut r = vec![0u8; 48];
                    r[0] = 0x24;
                    // 2026-01-01T00:00:00Z in NTP seconds.
                    r[32..36].copy_from_slice(&3_976_214_400u32.to_be_bytes());
                    r
                }
                6 => {
                    // Two fragments, the last one first: the script must
                    // wait for the whole reply.
                    let data = b"version=\"ntpd 4.2.8p15\", stratum=2,\r\nrefid=192.0.2.1";
                    let (a, b) = data.split_at(20);
                    for (more, offset, part) in [(0, 20u16, b), (0x20, 0, a)] {
                        let mut r = vec![0x16, 0x82 | more, 0, 1, 0, 0, 0, 0];
                        r.extend(offset.to_be_bytes());
                        r.extend((part.len() as u16).to_be_bytes());
                        r.extend(part);
                        let _ = server.send_to(&r, from).await;
                    }
                    continue;
                }
                _ => continue,
            };
            let _ = server.send_to(&reply, from).await;
        }
    });
    let mut host = host_with(&[(port, PortState::Open)]);
    host.ports[0].protocol = Protocol::Udp;
    host.ports[0].service = Some(crate::service::ServiceInfo {
        name: "ntp".into(),
        ..Default::default()
    });
    let out = run_built_in("ntp-info", host).await;
    assert_eq!(
        out,
        [(
            port,
            "\n  receive time stamp: 2026-01-01T00:00:00\n  version: ntpd 4.2.8p15\
             \n  stratum: 2\n  refid: 192.0.2.1"
                .to_string()
        )]
    );
}

#[tokio::test]
async fn ntp_info_drops_overlapping_fragments() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((_, from)) = server.recv_from(&mut buf).await {
            if buf[0] & 7 != 6 {
                continue;
            }
            for (more, offset, part) in [(0x20, 0u16, &b"version=ab"[..]), (0, 9, b"bc, stratum=2")]
            {
                let mut r = vec![0x16, 0x82 | more, 0, 1, 0, 0, 0, 0];
                r.extend(offset.to_be_bytes());
                r.extend((part.len() as u16).to_be_bytes());
                r.extend(part);
                let _ = server.send_to(&r, from).await;
            }
        }
    });
    let mut host = host_with(&[(port, PortState::Open)]);
    host.ports[0].protocol = Protocol::Udp;
    host.ports[0].service = Some(crate::service::ServiceInfo {
        name: "ntp".into(),
        ..Default::default()
    });
    let args = super::args::parse("ntp-info.timeout=300").unwrap();
    let scan = ScriptScan::new(vec![built_in("ntp-info")], args, None).unwrap();
    let mut hosts = vec![host];
    scan.scan_hosts(&mut hosts).await;
    assert!(
        hosts[0].ports[0].scripts.is_empty(),
        "{:?}",
        hosts[0].ports[0].scripts
    );
}

#[tokio::test]
async fn http_robots_and_methods() {
    let (port, seen) = web(|req| {
        if req.starts_with("GET /robots.txt ") {
            b"HTTP/1.1 200 OK\r\nContent-Length: 70\r\n\r\nUser-agent: *\nDisallow: /admin # private\nDisallow: /tmp/\nAllow: /pub\n"
                .to_vec()
        } else if req.starts_with("OPTIONS / ") {
            b"HTTP/1.1 200 OK\r\nAllow: GET, HEAD, POST, OPTIONS, TRACE, put\r\nContent-Length: 0\r\n\r\n"
                .to_vec()
        } else {
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
        }
    })
    .await;
    assert_eq!(
        output_of("http-robots.txt", port, "http").await.as_deref(),
        Some("2 disallowed entries\n/admin /tmp/")
    );
    assert_eq!(
        output_of("http-methods", port, "http").await.as_deref(),
        Some(
            "\n  Supported Methods: GET HEAD POST OPTIONS TRACE PUT\n  Potentially risky methods: TRACE PUT"
        )
    );
    assert_eq!(seen.lock().unwrap().len(), 2);

    // No robots.txt: nothing.
    let (port, _) = web(|_| b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
    assert_eq!(output_of("http-robots.txt", port, "http").await, None);
    assert_eq!(output_of("http-methods", port, "http").await, None);
}

#[tokio::test]
async fn http_headers_and_server_header() {
    let (port, seen) = web(|req| {
        if req.starts_with("HEAD / ") {
            b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nX-Frame-Options: DENY\r\nContent-Length: 5\r\n\r\n"
                .to_vec()
        } else if req.starts_with("GET / ") {
            b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nserver: extra\r\nServer: nginx/1.24.0\r\nContent-Length: 5\r\n\r\nhello"
                .to_vec()
        } else {
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
        }
    })
    .await;
    assert_eq!(
        output_of("http-headers", port, "http").await.as_deref(),
        Some(
            "\n  Server: nginx/1.24.0\n  X-Frame-Options: DENY\n  Content-Length: 5\n  \n  (Request type: HEAD)"
        )
    );
    // Repeats left out, other spellings kept.
    assert_eq!(
        output_of("http-server-header", port, "http")
            .await
            .as_deref(),
        Some("nginx/1.24.0\nextra")
    );
    assert_eq!(seen.lock().unwrap().len(), 2);

    // HEAD refused: GET instead, and said so.
    let (port, seen) = web(|req| {
        if req.starts_with("HEAD ") {
            b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n".to_vec()
        } else {
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()
        }
    })
    .await;
    assert_eq!(
        output_of("http-headers", port, "http").await.as_deref(),
        Some("\n  Content-Length: 2\n  \n  (Request type: GET)")
    );
    assert_eq!(seen.lock().unwrap().len(), 2);
    // No Server header: nothing.
    assert_eq!(output_of("http-server-header", port, "http").await, None);
}

#[test]
fn the_default_category() {
    let defaults: Vec<String> = choose("default")
        .unwrap()
        .into_iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(
        defaults,
        [
            "ftp-anon",
            "ftp-syst",
            "http-methods",
            "http-robots.txt",
            "http-title",
            "imap-capabilities",
            "mysql-info",
            "ntp-info",
            "pop3-capabilities",
            "rpcinfo",
            "smtp-commands",
            "ssh-hostkey",
            "ssl-cert",
            "sshv1",
            "vnc-info",
            "x11-access",
        ]
    );
    // Every default script is also safe, as in nmap.
    for s in choose("default").unwrap() {
        assert!(s.categories.iter().any(|c| c == "safe"), "{}", s.id);
    }
}
