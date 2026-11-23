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

/// A built-in script as `--script default` would choose it, so it sees
/// the plain `-v` level; [`Selection::Name`] would add one.
fn built_in(id: &str) -> Script {
    let mut s = Script::built_in()
        .unwrap()
        .into_iter()
        .find(|s| s.id == id)
        .unwrap();
    s.selection = Selection::Category;
    s
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

/// A lab SSH server that sends an IGNORE message and then a KEXINIT with
/// `lists` (the ten name-lists of RFC 4253 section 7.1), and keeps the
/// client's version line and the type of each packet it gets.
async fn ssh_kexinit_lab(lists: [&'static [u8]; 10]) -> (u16, Seen) {
    use tokio::io::AsyncBufReadExt;
    let seen: Seen = Default::default();
    let keep = seen.clone();
    let port = tcp_server(move |s| {
        let keep = keep.clone();
        async move {
            let mut s = tokio::io::BufReader::new(s);
            if s.write_all(b"Welcome\r\nSSH-2.0-LabSSH_1.0\r\n")
                .await
                .is_err()
            {
                return;
            }
            let mut ident = String::new();
            if s.read_line(&mut ident).await.is_err() {
                return;
            }
            keep.lock().unwrap().push(ident.trim_end().to_string());
            let mut out = ssh_packet(&[2, 0, 0, 0, 3, b'h', b'e', b'y']);
            let mut kexinit = vec![20u8];
            kexinit.extend([0x42u8; 16]);
            for list in lists {
                kexinit.extend(ssh_string(list));
            }
            kexinit.extend([0, 0, 0, 0, 0]);
            out.extend(ssh_packet(&kexinit));
            if s.write_all(&out).await.is_err() {
                return;
            }
            let mut head = [0u8; 6];
            if s.read_exact(&mut head).await.is_ok() {
                keep.lock().unwrap().push(format!("packet {}", head[5]));
            }
        }
    })
    .await;
    (port, seen)
}

const SSH_LAB_LISTS: [&[u8]; 10] = [
    b"curve25519-sha256,diffie-hellman-group14-sha256,kex-strict-s-v00@openssh.com",
    b"rsa-sha2-512,ssh-ed25519",
    b"chacha20-poly1305@openssh.com,aes256-ctr",
    b"chacha20-poly1305@openssh.com,aes256-ctr",
    b"hmac-sha2-256-etm@openssh.com",
    b"hmac-sha2-256-etm@openssh.com",
    b"none,zlib@openssh.com",
    b"none",
    b"",
    b"",
];

/// `ssh2-enum-algos` with `fero.verbosity()` fixed at `level`: the global
/// verbosity is shared with tests running at the same time.
async fn ssh2_enum_algos_at(level: u8, port: u16) -> ScriptResult {
    let src = Script::built_in()
        .unwrap()
        .into_iter()
        .find(|s| s.id == "ssh2-enum-algos")
        .unwrap()
        .source
        .replace("fero.verbosity()", &level.to_string());
    let scan = ScriptScan::new(
        vec![script("ssh2-enum-algos", &src)],
        ArgTable::default(),
        None,
    )
    .unwrap();
    let mut hosts = vec![host_with_services(&[(port, "ssh")])];
    scan.scan_hosts(&mut hosts).await;
    assert_eq!(hosts[0].ports[0].scripts.len(), 1);
    hosts[0].ports[0].scripts[0].clone()
}

#[tokio::test]
async fn ssh2_enum_algos_counts_the_server_algorithms() {
    let (port, seen) = ssh_kexinit_lab(SSH_LAB_LISTS).await;
    let r = ssh2_enum_algos_at(0, port).await;
    assert_eq!(
        r.output,
        "\n  kex_algorithms: (3)\n  server_host_key_algorithms: (2)\
         \n  encryption_algorithms: (2)\n  mac_algorithms: (1)\
         \n  compression_algorithms_client_to_server: (2)\
         \n  compression_algorithms_server_to_client: (1)"
    );
    // The full lists are in the structured output whatever the verbosity,
    // in the order the server sent them and the groups in nmap's order.
    let data = r.data.as_ref().unwrap();
    let ScriptValue::Table(t) = data else {
        panic!("{data:?}")
    };
    let names: Vec<&str> = t.named.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        names,
        [
            "kex_algorithms",
            "server_host_key_algorithms",
            "encryption_algorithms",
            "mac_algorithms",
            "compression_algorithms_client_to_server",
            "compression_algorithms_server_to_client"
        ]
    );
    let ScriptValue::Table(hk) = named(data, "server_host_key_algorithms") else {
        panic!()
    };
    assert_eq!(
        hk.list,
        [
            ScriptValue::Str("rsa-sha2-512".into()),
            ScriptValue::Str("ssh-ed25519".into())
        ]
    );
    // FeroProbe's version line, then its KEXINIT (message 20). The lab's
    // connection task notes the packet after the script may have finished,
    // so wait for it (2 s at most).
    for _ in 0..200 {
        if seen.lock().unwrap().len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let seen = seen.lock().unwrap();
    assert_eq!(
        *seen,
        ["SSH-2.0-FeroProbe_Scripting_Engine", "packet 20"],
        "{seen:?}"
    );
}

#[tokio::test]
async fn ssh2_enum_algos_lists_each_algorithm_with_v() {
    let (port, _) = ssh_kexinit_lab(SSH_LAB_LISTS).await;
    let r = ssh2_enum_algos_at(1, port).await;
    assert_eq!(
        r.output,
        "\n  kex_algorithms: (3)\
         \n      curve25519-sha256\
         \n      diffie-hellman-group14-sha256\
         \n      kex-strict-s-v00@openssh.com\
         \n  server_host_key_algorithms: (2)\
         \n      rsa-sha2-512\
         \n      ssh-ed25519\
         \n  encryption_algorithms: (2)\
         \n      chacha20-poly1305@openssh.com\
         \n      aes256-ctr\
         \n  mac_algorithms: (1)\
         \n      hmac-sha2-256-etm@openssh.com\
         \n  compression_algorithms_client_to_server: (2)\
         \n      none\
         \n      zlib@openssh.com\
         \n  compression_algorithms_server_to_client: (1)\
         \n      none"
    );
}

#[tokio::test]
async fn ssh2_enum_algos_needs_an_ssh2_server() {
    let port = greeter(b"SSH-1.5-OldServer\r\n").await;
    assert_eq!(output_of("ssh2-enum-algos", port, "ssh").await, None);
    // A server that closes after its version line gives no output.
    let port = greeter(b"SSH-2.0-Quiet\r\n").await;
    assert_eq!(output_of("ssh2-enum-algos", port, "ssh").await, None);
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
            "clock-skew",
            "dns-nsid",
            "ftp-anon",
            "ftp-syst",
            "http-auth",
            "http-cookie-flags",
            "http-cors",
            "http-favicon",
            "http-generator",
            "http-git",
            "http-methods",
            "http-ntlm-info",
            "http-robots.txt",
            "http-title",
            "http-webdav-scan",
            "imap-capabilities",
            "imap-ntlm-info",
            "ms-sql-ntlm-info",
            "mysql-info",
            "nbstat",
            "nntp-ntlm-info",
            "ntp-info",
            "pop3-capabilities",
            "pop3-ntlm-info",
            "rdp-ntlm-info",
            "rpcinfo",
            "smb-os-discovery",
            "smb-security-mode",
            "smb2-security-mode",
            "smb2-time",
            "smtp-commands",
            "smtp-ntlm-info",
            "snmp-info",
            "snmp-interfaces",
            "snmp-sysdescr",
            "ssh-hostkey",
            "ssl-date",
            "ssl-cert",
            "sshv1",
            "sslv2",
            "telnet-ntlm-info",
            "tls-alpn",
            "tls-nextprotoneg",
            "vnc-info",
            "x11-access",
        ]
    );
    // Every default script is also safe, as in nmap.
    for s in choose("default").unwrap() {
        assert!(s.categories.iter().any(|c| c == "safe"), "{}", s.id);
    }
}

/// A stand-in SMB2 server: answers a NEGOTIATE with signing `mode`, the
/// dialect 3.1.1 and the clock `now` (Unix seconds), keeping each request.
/// With `netbios`, a NetBIOS session request comes first.
async fn smb_server(mode: u16, now: i64, netbios: bool) -> (u16, Seen) {
    let seen: Seen = Default::default();
    let keep = seen.clone();
    let port = tcp_server(move |mut s| {
        let keep = keep.clone();
        async move {
            let mut head = [0u8; 4];
            if netbios {
                if s.read_exact(&mut head).await.is_err() || head[0] != 0x81 {
                    return;
                }
                let mut names = vec![0u8; u16::from_be_bytes([head[2], head[3]]) as usize];
                if s.read_exact(&mut names).await.is_err() {
                    return;
                }
                keep.lock()
                    .unwrap()
                    .push(format!("session {}", String::from_utf8_lossy(&names)));
                let _ = s.write_all(&[0x82, 0, 0, 0]).await;
            }
            if s.read_exact(&mut head).await.is_err() {
                return;
            }
            let len = u32::from_be_bytes(head) as usize;
            let mut req = vec![0u8; len];
            if s.read_exact(&mut req).await.is_err() {
                return;
            }
            keep.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&req).into_owned());
            let filetime = |t: i64| ((t + 11_644_473_600) * 10_000_000).to_le_bytes();
            let mut m = b"\xfeSMB".to_vec();
            m.extend(64u16.to_le_bytes());
            m.extend([0u8; 58]);
            m.extend(65u16.to_le_bytes());
            m.extend(mode.to_le_bytes());
            m.extend(0x0311u16.to_le_bytes());
            m.extend(0u16.to_le_bytes());
            m.extend(*b"server-guid-0123");
            m.extend([0u8; 16]);
            m.extend(filetime(now));
            m.extend([0u8; 8]); // no start time
            m.extend([0u8; 9]);
            let mut out = (m.len() as u32).to_be_bytes().to_vec();
            out.extend(m);
            let _ = s.write_all(&out).await;
        }
    })
    .await;
    (port, seen)
}

/// The host-script outputs of built-in `id` on a host whose only port is
/// `port`, known as `service`, with `args`.
async fn host_output_of(id: &str, port: u16, service: &str, args: &str) -> Vec<String> {
    let scan = ScriptScan::new(vec![built_in(id)], args::parse(args).unwrap(), None).unwrap();
    let mut hosts = vec![host_with_services(&[(port, service)])];
    scan.scan_hosts(&mut hosts).await;
    hosts[0].scripts.iter().map(|s| s.output.clone()).collect()
}

#[tokio::test]
async fn smb2_security_mode_and_time() {
    // 2026-01-02T03:04:05Z
    let now = 1_767_323_045;
    let (port, seen) = smb_server(1, now, false).await;
    let arg = format!("smbport={port}");
    assert_eq!(
        host_output_of("smb2-security-mode", port, "microsoft-ds", &arg).await,
        ["\n  3:1:1: \n    Message signing enabled but not required"]
    );
    assert_eq!(
        host_output_of("smb2-time", port, "microsoft-ds", &arg).await,
        ["\n  date: 2026-01-02T03:04:05\n  start_date: N/A"]
    );
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        // The FeroProbe client GUID marks each NEGOTIATE.
        assert!(
            seen.iter()
                .all(|r| r.starts_with("\u{fffd}SMB") && r.contains("FeroProbeSMBScan"))
        );
    }

    // Signing required, over a NetBIOS session (port 139's service).
    let (port, seen) = smb_server(3, now, true).await;
    let arg = format!("smbport={port}");
    assert_eq!(
        host_output_of("smb2-security-mode", port, "netbios-ssn", &arg).await,
        ["\n  3:1:1: \n    Message signing enabled and required"]
    );
    assert!(seen.lock().unwrap()[0].starts_with("session  CKFDENECFDEFFCFGEFFCCACACACACACA"));

    // No SMB port open (smbport names one the scan did not find open):
    // the hostrule says no, and nothing is sent.
    assert!(
        host_output_of("smb2-time", port, "netbios-ssn", "smbport=1")
            .await
            .is_empty()
    );
    // A server that gives no clock: N/A, as for the start time.
    let (port, _) = smb_server(1, -11_644_473_600, false).await;
    let arg = format!("smbport={port}");
    assert_eq!(
        host_output_of("smb2-time", port, "microsoft-ds", &arg).await,
        ["\n  date: N/A\n  start_date: N/A"]
    );
    // A server that does not speak SMB2: no output.
    let port = tcp_server(|mut s| async move {
        let _ = s.write_all(b"\0\0\0\x08\xffSMBjunk").await;
    })
    .await;
    let arg = format!("smbport={port}");
    assert!(
        host_output_of("smb2-time", port, "microsoft-ds", &arg)
            .await
            .is_empty()
    );
}

/// An NTLM CHALLENGE message as a Windows server sends it: target name
/// "LAB", the usual AV pairs, version 10.0.14393 and the clock `now`.
fn ntlm_challenge(now: i64) -> Vec<u8> {
    ntlm_challenge_naming(
        now,
        &[
            (2, "LAB"),
            (1, "SRV01"),
            (4, "lab.local"),
            (3, "srv01.lab.local"),
            (5, "lab.local"),
        ],
    )
}

/// UTF-16LE text.
fn u16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// An NTLM CHALLENGE (target name "LAB", version 10.0.14393, the clock
/// `now`) with the name AV pairs `names`.
fn ntlm_challenge_naming(now: i64, names: &[(u16, &str)]) -> Vec<u8> {
    let name = u16le("LAB");
    let mut info = Vec::new();
    for &(id, v) in names {
        let v = u16le(v);
        info.extend(id.to_le_bytes());
        info.extend((v.len() as u16).to_le_bytes());
        info.extend(v);
    }
    info.extend(7u16.to_le_bytes());
    info.extend(8u16.to_le_bytes());
    info.extend(((now + 11_644_473_600) * 10_000_000).to_le_bytes());
    info.extend([0u8; 4]);
    let mut m = b"NTLMSSP\0".to_vec();
    m.extend(2u32.to_le_bytes());
    m.extend((name.len() as u16).to_le_bytes());
    m.extend((name.len() as u16).to_le_bytes());
    m.extend(56u32.to_le_bytes());
    m.extend(0xe28a_8215u32.to_le_bytes());
    m.extend(*b"chalenge");
    m.extend([0u8; 8]);
    m.extend((info.len() as u16).to_le_bytes());
    m.extend((info.len() as u16).to_le_bytes());
    m.extend((56 + name.len() as u32).to_le_bytes());
    m.extend([10, 0]);
    m.extend(14393u16.to_le_bytes());
    m.extend([0, 0, 0, 15]);
    m.extend(name);
    m.extend(info);
    m
}

/// A stand-in RDP server: confirms the connection selecting `protocol`,
/// then (for CredSSP) speaks TLS and answers the TSRequest with an NTLM
/// challenge. Keeps the connection request and the TSRequest.
async fn rdp_server(protocol: u32, now: i64) -> (u16, Seen) {
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
                let mut head = [0u8; 4];
                if s.read_exact(&mut head).await.is_err() {
                    return;
                }
                let mut req = vec![0u8; u16::from_be_bytes([head[2], head[3]]) as usize - 4];
                if s.read_exact(&mut req).await.is_err() {
                    return;
                }
                keep.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&req).into_owned());
                let mut cc = vec![0x0e, 0xd0, 0, 0, 0x12, 0x34, 0];
                cc.extend([2, 0x1f, 8, 0]);
                cc.extend(protocol.to_le_bytes());
                let mut out = vec![3, 0, 0, (cc.len() + 4) as u8];
                out.extend(cc);
                if s.write_all(&out).await.is_err() {
                    return;
                }
                if protocol & 0x0a == 0 {
                    // No CredSSP: the client must close without starting
                    // TLS. Keep what it sends, if anything, until it closes.
                    let mut got = Vec::new();
                    let how =
                        match tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut got))
                            .await
                        {
                            Ok(Ok(_)) => "closed",
                            Ok(Err(_)) => "error",
                            Err(_) => "timeout",
                        };
                    keep.lock()
                        .unwrap()
                        .push(format!("after: {how}: {}", String::from_utf8_lossy(&got)));
                    return;
                }
                let Ok(mut tls) = acceptor.accept(s).await else {
                    return;
                };
                let mut buf = [0u8; 512];
                let n = tls.read(&mut buf).await.unwrap_or(0);
                keep.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[..n]).into_owned());
                let token = ntlm_challenge(now);
                let mut body = vec![0xa0, 3, 2, 1, 6, 0xa1, 0x82];
                body.extend(((token.len() + 8) as u16).to_be_bytes());
                body.extend([0x30, 0x82]);
                body.extend(((token.len() + 4) as u16).to_be_bytes());
                body.extend([0x04, 0x82]);
                body.extend((token.len() as u16).to_be_bytes());
                body.extend(token);
                let mut reply = vec![0x30, 0x82];
                reply.extend((body.len() as u16).to_be_bytes());
                reply.extend(body);
                let _ = tls.write_all(&reply).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (port, seen)
}

#[tokio::test]
async fn rdp_ntlm_info_reads_the_challenge() {
    // 2026-01-02T03:04:05Z
    let (port, seen) = rdp_server(2, 1_767_323_045).await;
    assert_eq!(
        output_of("rdp-ntlm-info", port, "ms-wbt-server")
            .await
            .as_deref(),
        Some(
            "\n  Target_Name: LAB\n  NetBIOS_Domain_Name: LAB\n  \
             NetBIOS_Computer_Name: SRV01\n  DNS_Domain_Name: lab.local\n  \
             DNS_Computer_Name: srv01.lab.local\n  DNS_Tree_Name: lab.local\n  \
             Product_Version: 10.0.14393\n  System_Time: 2026-01-02T03:04:05+00:00"
        )
    );
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "{seen:?}");
        // The cookie names FeroProbe; the CredSSP message carries only an
        // NTLM NEGOTIATE.
        assert!(
            seen[0].contains("Cookie: mstshash=FeroProbe\r\n"),
            "{seen:?}"
        );
        assert!(seen[1].contains("NTLMSSP\0\u{1}\0\0\0"), "{seen:?}");
    }
    // A server that offers only TLS (no CredSSP): no output, no TLS.
    let (port, seen) = rdp_server(1, 0).await;
    assert_eq!(
        output_of("rdp-ntlm-info", port, "ms-wbt-server").await,
        None
    );
    for _ in 0..100 {
        if seen.lock().unwrap().len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(seen.lock().unwrap()[1], "after: closed: ");

    // An OEM (not Unicode) target name is read as bytes, not UTF-16.
    let src = r#"
categories = {"safe"}
prerule = function() return true end
action = function()
  local m = "NTLMSSP\0" .. string.pack("<I4I2I2I4I4", 2, 3, 3, 48, 2)
    .. string.rep("\0", 24) .. "LAB"
  return fero.ntlm.parse_challenge(m).target_name
end"#;
    let scan = ScriptScan::new(vec![script("oem", src)], ArgTable::default(), None).unwrap();
    assert_eq!(scan.pre_scan().await[0].output, "LAB");
}

#[tokio::test]
async fn scripts_chosen_by_name_see_one_more_verbosity_level() {
    // As in nmap: chosen by name, name pattern or file path, a script sees
    // -v plus one; chosen by category or directory it sees -v as given.
    let src = r#"
categories = {"safe"}
prerule = function() return true end
action = function() return tostring(fero.verbosity()) end"#;
    let base = crate::debug::verbosity();
    for (selection, extra) in [
        (Selection::Name, 1),
        (Selection::File, 1),
        (Selection::Category, 0),
        (Selection::Directory, 0),
    ] {
        let mut s = script("v", src);
        s.selection = selection;
        let scan = ScriptScan::new(vec![s], ArgTable::default(), None).unwrap();
        assert_eq!(
            scan.pre_scan().await[0].output,
            (base + extra).to_string(),
            "{selection:?}"
        );
    }
}

/// A stand-in TLS server that answers each ClientHello with a bare
/// ServerHello record whose gmt_unix_time is `time()`, keeping each hello.
async fn hello_server(
    time: fn() -> u32,
    split: bool,
) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
    let seen: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Default::default();
    let keep = seen.clone();
    let port = tcp_server(move |mut s| {
        let keep = keep.clone();
        async move {
            let mut head = [0u8; 5];
            if s.read_exact(&mut head).await.is_err() {
                return;
            }
            let mut body = vec![0u8; u16::from_be_bytes([head[3], head[4]]) as usize];
            if s.read_exact(&mut body).await.is_err() {
                return;
            }
            let mut hello = head.to_vec();
            hello.extend(body);
            keep.lock().unwrap().push(hello);
            let mut hs = vec![3, 3];
            hs.extend(time().to_be_bytes());
            hs.extend([7u8; 28]);
            hs.extend([0, 0xc0, 0x2f, 0]);
            let mut rec = vec![2, 0, 0, hs.len() as u8];
            rec.extend(hs);
            // The handshake message whole in one record, or with its first
            // 10 bytes in a record each (RFC 5246 6.2.1 allows it).
            let parts: Vec<&[u8]> = if split {
                let mut p: Vec<&[u8]> = rec[..10].chunks(1).collect();
                p.push(&rec[10..]);
                p
            } else {
                vec![&rec[..]]
            };
            let mut out = Vec::new();
            for part in parts {
                out.extend([22, 3, 3]);
                out.extend((part.len() as u16).to_be_bytes());
                out.extend(part);
            }
            let _ = s.write_all(&out).await;
            let mut rest = [0u8; 64];
            let _ = s.read(&mut rest).await;
        }
    })
    .await;
    (port, seen)
}

#[tokio::test]
async fn ssl_date_reads_the_server_hello_time() {
    fn ahead() -> u32 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (now + 5) as u32
    }
    let (port, seen) = hello_server(ahead, false).await;
    let out = output_of("ssl-date", port, "https").await.unwrap();
    let (date, rest) = out.split_once("; ").unwrap();
    assert!(date.ends_with("+00:00") && date.len() == 25, "{out}");
    assert!(
        ["+4s", "+5s", "+6s"]
            .map(|d| format!("{d} from scanner time."))
            .contains(&rest.to_string()),
        "{out}"
    );
    {
        // Two hellos, or three when the first two came within one second.
        let seen = seen.lock().unwrap();
        assert!(matches!(seen.len(), 2 | 3), "{}", seen.len());
        for hello in seen.iter() {
            // A TLS 1.2 ClientHello whose random carries the mark, with the
            // target's name as SNI.
            assert_eq!(&hello[..3], &[22, 3, 1]);
            assert_eq!(hello[5], 1);
            assert_eq!(&hello[9..11], &[3, 3]);
            assert_eq!(&hello[15..31], b"FeroProbeSSLDate");
            assert!(hello.windows(9).any(|w| w == b"localhost"));
        }
    }

    // Random bytes where the time should be.
    fn random() -> u32 {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0x1234_5678);
        N.fetch_add(0x0bad_cafe, std::sync::atomic::Ordering::Relaxed)
    }
    let (port, seen) = hello_server(random, false).await;
    assert_eq!(
        output_of("ssl-date", port, "https").await.as_deref(),
        Some("TLS randomness does not represent time")
    );
    assert_eq!(seen.lock().unwrap().len(), 2);

    // A field that never changes: a third hello once our clock has moved
    // two seconds tells it from a real clock asked twice within a second.
    fn fixed() -> u32 {
        0x5f00_0000
    }
    let (port, seen) = hello_server(fixed, false).await;
    assert_eq!(
        output_of("ssl-date", port, "https").await.as_deref(),
        Some("TLS randomness does not represent time")
    );
    assert_eq!(seen.lock().unwrap().len(), 3);

    // A ServerHello split across eleven records.
    let (port, _) = hello_server(ahead, true).await;
    let out = output_of("ssl-date", port, "https").await.unwrap();
    assert!(out.ends_with(" from scanner time."), "{out}");
}

#[tokio::test]
async fn ssl_date_stops_a_trickling_server_at_its_timeout() {
    // Answers each ClientHello with a ServerHello one byte every 400 ms:
    // every receive stays under the 1 s timeout, but the bytes it needs would take
    // 12 s in all.
    let port = tcp_server(|mut s| async move {
        let mut head = [0u8; 5];
        if s.read_exact(&mut head).await.is_err() {
            return;
        }
        let mut body = vec![0u8; u16::from_be_bytes([head[3], head[4]]) as usize];
        if s.read_exact(&mut body).await.is_err() {
            return;
        }
        let mut out = vec![22, 3, 3, 0, 42, 2, 0, 0, 38, 3, 3];
        out.extend([0x5f, 0, 0, 0]);
        out.extend([7u8; 28]);
        for b in out {
            if s.write_all(&[b]).await.is_err() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        }
    })
    .await;
    let scan = ScriptScan::new(
        vec![built_in("ssl-date")],
        args::parse("ssl-date.timeout=1000").unwrap(),
        None,
    )
    .unwrap();
    let mut hosts = vec![host_with_services(&[(port, "https")])];
    let start = std::time::Instant::now();
    scan.scan_hosts(&mut hosts).await;
    // One connection gives up within the 1 s budget (2 s with whole-second
    // rounding), and the script ends there.
    assert!(
        start.elapsed() < std::time::Duration::from_secs(4),
        "{:?}",
        start.elapsed()
    );
    assert!(hosts[0].ports[0].scripts.is_empty());
}

/// A stand-in NetBIOS name service: answers a NODE STATUS request with a
/// name table, keeping each request. With `user` the table has ALICE<03>;
/// with `bad_first` the first answer is a registration response (OPCODE 5)
/// carrying MAC ff:ff:ff:ff:ff:ff, which must be ignored.
async fn nbns_server(
    reply_mac: [u8; 6],
    user: bool,
    bad_first: bool,
) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    let seen: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Default::default();
    let keep = seen.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = server.recv_from(&mut buf).await {
            let first = {
                let mut seen = keep.lock().unwrap();
                seen.push(buf[..n].to_vec());
                seen.len() == 1
            };
            let bad = bad_first && first;
            // Machine LAB-PC serves files as FILES and has an alias NAS;
            // their <03> names come first, and none of them is a user.
            let all: [(&[u8], u8, u16); 8] = [
                (b"LAB-PC", 0x00, 0x0400),
                (b"WORKGROUP", 0x00, 0x8400),
                (b"FILES", 0x20, 0x0400),
                (b"NAS", 0x20, 0x0400),
                (b"LAB-PC", 0x03, 0x0400),
                (b"FILES", 0x03, 0x0400),
                (b"NAS", 0x03, 0x0400),
                (b"ALICE", 0x03, 0x0400),
            ];
            let names = if user { &all[..] } else { &all[..7] };
            // The header (response, authoritative), the question's name in
            // full, type NBSTAT, class IN, TTL 0.
            let mut r = buf[..2].to_vec();
            r.extend([if bad { 0xac } else { 0x84 }, 0x00, 0, 0, 0, 1, 0, 0, 0, 0]);
            r.extend(&buf[12..46]);
            r.extend([0, 0x21, 0, 1, 0, 0, 0, 0]);
            let mut rdata = vec![names.len() as u8];
            for &(name, suffix, flags) in names {
                let mut padded = name.to_vec();
                padded.resize(15, b' ');
                rdata.extend(padded);
                rdata.push(suffix);
                rdata.extend(flags.to_be_bytes());
            }
            rdata.extend(if bad { [0xff; 6] } else { reply_mac });
            rdata.extend([0u8; 40]);
            r.extend((rdata.len() as u16).to_be_bytes());
            r.extend(rdata);
            let _ = server.send_to(&r, from).await;
        }
    });
    (port, seen)
}

#[tokio::test]
async fn nbstat_reads_the_name_table() {
    async fn run(port: u16, args: &str) -> Vec<String> {
        let scan =
            ScriptScan::new(vec![built_in("nbstat")], args::parse(args).unwrap(), None).unwrap();
        let mut host = host_with(&[(port, PortState::OpenFiltered)]);
        host.ports[0].protocol = Protocol::Udp;
        let mut hosts = vec![host];
        scan.scan_hosts(&mut hosts).await;
        hosts[0].scripts.iter().map(|s| s.output.clone()).collect()
    }
    let (port, seen) = nbns_server([0x00, 0x0c, 0x29, 0x01, 0x02, 0x03], true, false).await;
    let out = run(port, &format!("nbstat.port={port}")).await;
    assert_eq!(out.len(), 1, "{out:?}");
    assert!(
        out[0].starts_with(
            "NetBIOS name: FILES, NetBIOS user: ALICE, NetBIOS MAC: 00:0c:29:01:02:03 ("
        ),
        "{}",
        out[0]
    );
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        let q = &seen[0];
        // Transaction ID "FP", one question: "*" padded with NULs, NBSTAT, IN.
        assert_eq!(&q[..12], b"FP\0\0\0\x01\0\0\0\0\0\0");
        assert_eq!(q[12], 32);
        assert_eq!(&q[13..45], b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(&q[45..], &[0, 0, 0x21, 0, 1]);
    }

    // Samba gives a zero MAC; nothing is sent when the port was not scanned.
    let (port, _) = nbns_server([0; 6], true, false).await;
    let out = run(port, &format!("nbstat.port={port}")).await;
    assert_eq!(
        out,
        ["NetBIOS name: FILES, NetBIOS user: ALICE, NetBIOS MAC: <unknown>"]
    );
    let (other, seen) = nbns_server([0; 6], true, false).await;
    assert!(run(port, &format!("nbstat.port={other}")).await.is_empty());
    assert!(seen.lock().unwrap().is_empty());

    // Only the machine's own <03> names: no user. A non-query answer is
    // ignored and the request sent again.
    let (port, seen) = nbns_server([0x00, 0x0c, 0x29, 0x01, 0x02, 0x03], false, true).await;
    let out = run(port, &format!("nbstat.port={port}")).await;
    assert_eq!(out.len(), 1, "{out:?}");
    assert!(
        out[0].starts_with(
            "NetBIOS name: FILES, NetBIOS user: <unknown>, NetBIOS MAC: 00:0c:29:01:02:03 ("
        ),
        "{}",
        out[0]
    );
    assert_eq!(seen.lock().unwrap().len(), 2);
}

/// A stand-in DNS server's answer to `q`: CHAOS TXT for id.server
/// ("ns1.lab") and version.bind ("9.18" and ".24", two strings), and the
/// NSID "ns1" when the query asks for it. Without EDNS support a query
/// with an OPT record gets FORMERR (see [`Edns`]). With `odd`, a
/// version.bind answer starts with two unrelated CHAOS TXT records
/// (hostname.bind, and the single label "version.bind"), which must be
/// skipped.
fn dns_answer(q: &[u8], edns: Edns, odd: bool) -> Vec<u8> {
    let ar = u16::from_be_bytes([q[10], q[11]]);
    let mut end = 12;
    while q[end] != 0 {
        end += 1 + q[end] as usize;
    }
    let question = &q[12..end + 5];
    let mut r = q[..2].to_vec();
    match edns {
        Edns::Yes => {}
        Edns::FormErr if ar > 0 => {
            r.extend([0x80, 0x01, 0, 1, 0, 0, 0, 0, 0, 0]);
            r.extend(question);
            return r;
        }
        Edns::EmptyFormErr if ar > 0 => {
            // The header alone: every count zero, nothing after it.
            r.extend([0x80, 0x01, 0, 0, 0, 0, 0, 0, 0, 0]);
            return r;
        }
        Edns::BareFormErr if ar > 0 || question.starts_with(b"\x07version") => {
            // No question, and an answer that must not be taken: FORMERR
            // for EDNS, REFUSED for version.bind.
            r.extend([
                0x80,
                if ar > 0 { 0x01 } else { 0x05 },
                0,
                0,
                0,
                1,
                0,
                0,
                0,
                0,
            ]);
            r.extend(&q[12..end + 5]);
            r.extend(b"\0\0\0\0\0\x06\x05wrong");
            return r;
        }
        _ => {}
    }
    let id_server = question.starts_with(b"\x02id\x06server\0");
    let extra = odd && !id_server;
    r.extend([
        0x84,
        0x00,
        0,
        1,
        0,
        1 + 2 * extra as u8,
        0,
        0,
        0,
        (ar > 0) as u8,
    ]);
    r.extend(question);
    if extra {
        r.extend(b"\x08hostname\x04bind\0\0\x10\0\x03\0\0\0\0\0\x06\x05wrong");
        // One label "version.bind", not the name version.bind.
        r.extend(b"\x0cversion.bind\0\0\x10\0\x03\0\0\0\0\0\x06\x05wrong");
    }
    let txt: &[&[u8]] = if id_server {
        &[b"ns1.lab"]
    } else {
        &[b"9.18", b".24"]
    };
    let mut rdata = Vec::new();
    for s in txt {
        rdata.push(s.len() as u8);
        rdata.extend(*s);
    }
    r.extend([0xc0, 0x0c, 0, 16, 0, 3, 0, 0, 0, 0]);
    r.extend((rdata.len() as u16).to_be_bytes());
    r.extend(rdata);
    if ar > 0 {
        r.extend([0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 7, 0, 3, 0, 3]);
        r.extend(b"ns1");
    }
    r
}

/// How a stand-in DNS server treats a query with an OPT record.
#[derive(Clone, Copy)]
enum Edns {
    /// Answers it, with the NSID.
    Yes,
    /// FORMERR, with the question.
    FormErr,
    /// FORMERR as a 12-byte header with every count zero.
    EmptyFormErr,
    /// FORMERR with only the header and an answer record, and the same
    /// (REFUSED) for version.bind: no value may come from either.
    BareFormErr,
}

type Queries = std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>;

/// With `odd`, the first answer to version.bind carries the id.server
/// question instead (a reply to another query, to be ignored), and the
/// answers start with an unrelated record (see [`dns_answer`]).
async fn dns_udp_server(edns: Edns, odd: bool) -> (u16, Queries) {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    let seen: Queries = Default::default();
    let keep = seen.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = server.recv_from(&mut buf).await {
            let first_version = {
                let mut seen = keep.lock().unwrap();
                seen.push(buf[..n].to_vec());
                let is_version = |q: &Vec<u8>| q[12..].starts_with(b"\x07version");
                is_version(&buf[..n].to_vec()) && seen.iter().filter(|q| is_version(q)).count() == 1
            };
            let mut a = dns_answer(&buf[..n], edns, odd);
            if odd && first_version {
                // The id.server question and answer in its place.
                let mut other = buf[..12].to_vec();
                other.extend(b"\x02id\x06server\0\0\x10\0\x03");
                a = dns_answer(&other, edns, false);
            }
            let _ = server.send_to(&a, from).await;
        }
    });
    (port, seen)
}

async fn dns_tcp_server() -> (u16, Queries) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let seen: Queries = Default::default();
    let keep = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let keep = keep.clone();
            tokio::spawn(async move {
                let mut len = [0u8; 2];
                if s.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                if s.read_exact(&mut q).await.is_err() {
                    return;
                }
                keep.lock().unwrap().push(q.clone());
                let a = dns_answer(&q, Edns::Yes, false);
                let mut out = (a.len() as u16).to_be_bytes().to_vec();
                out.extend(a);
                // In two writes, so the reply arrives in pieces.
                let _ = s.write_all(&out[..5]).await;
                let _ = s.flush().await;
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                let _ = s.write_all(&out[5..]).await;
            });
        }
    });
    (port, seen)
}

#[tokio::test]
async fn dns_nsid_asks_for_the_nsid_and_the_chaos_names() {
    const FULL: &str = "\n  NSID: ns1 (6e7331)\n  id.server: ns1.lab\n  bind.version: 9.18.24";
    fn dns_host(port: u16, protocol: Protocol) -> HostResult {
        let mut host = host_with(&[(port, PortState::Open)]);
        host.ports[0].protocol = protocol;
        host.ports[0].service = Some(crate::service::ServiceInfo {
            name: "domain".into(),
            ..Default::default()
        });
        host
    }
    let (port, seen) = dns_udp_server(Edns::Yes, false).await;
    let out = run_built_in("dns-nsid", dns_host(port, Protocol::Udp)).await;
    assert_eq!(out, [(port, FULL.to_string())]);
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        // ID "FP", no flags (no recursion), one question, one OPT record
        // asking for the NSID; then version.bind without EDNS.
        assert_eq!(&seen[0][..12], b"FP\x01\0\0\x01\0\0\0\0\0\x01");
        assert_eq!(&seen[0][12..27], b"\x02id\x06server\0\0\x10\0\x03");
        assert_eq!(&seen[0][27..], b"\0\0\x29\x04\xd0\0\0\0\0\0\x04\0\x03\0\0");
        assert_eq!(
            seen[1],
            b"FP\x01\0\0\x01\0\0\0\0\0\0\x07version\x04bind\0\0\x10\0\x03"
        );
    }

    // A server without EDNS: id.server is asked again plainly, also when
    // its FORMERR has no question (whose answer records are not taken).
    for (edns, version) in [
        (Edns::FormErr, "\n  bind.version: 9.18.24"),
        (Edns::EmptyFormErr, "\n  bind.version: 9.18.24"),
        (Edns::BareFormErr, ""),
    ] {
        let (port, seen) = dns_udp_server(edns, false).await;
        let out = run_built_in("dns-nsid", dns_host(port, Protocol::Udp)).await;
        assert_eq!(out, [(port, format!("\n  id.server: ns1.lab{version}"))]);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 3);
        assert_eq!(&seen[1][..12], b"FP\x01\0\0\x01\0\0\0\0\0\0");
        assert_eq!(&seen[1][12..], b"\x02id\x06server\0\0\x10\0\x03");
    }

    // A reply to another question is ignored and the query sent again; a
    // CHAOS TXT record for another name is skipped.
    let (port, seen) = dns_udp_server(Edns::Yes, true).await;
    let out = run_built_in("dns-nsid", dns_host(port, Protocol::Udp)).await;
    assert_eq!(out, [(port, FULL.to_string())]);
    assert_eq!(seen.lock().unwrap().len(), 3);

    // Over TCP, with the reply in pieces.
    let (port, seen) = dns_tcp_server().await;
    let out = run_built_in("dns-nsid", dns_host(port, Protocol::Tcp)).await;
    assert_eq!(out, [(port, FULL.to_string())]);
    assert_eq!(seen.lock().unwrap().len(), 2);
}

// ---- Script libraries, part 2: ordered output, registry, receive_buf ----

#[tokio::test]
async fn output_tables_keep_their_order() {
    let src = r#"
categories = {"safe"}
prerule = function() return true end
action = function()
  local t = fero.output_table()
  t.zeta = "1"
  t.alpha = "2"
  t[1] = "first"
  t.mid = fero.output_table()
  t.mid.y = "a"
  t.mid.x = "b"
  t.gone = "x"
  t.gone = nil
  t.again = "3"
  t.alpha = "changed"
  rawset(t, "raw", "4")
  t.gone = "back"
  return t
end"#;
    let scan = ScriptScan::new(vec![script("ordered", src)], ArgTable::default(), None).unwrap();
    let r = scan.pre_scan().await;
    assert_eq!(
        r[0].output,
        "\n  first\n  zeta: 1\n  alpha: changed\n  mid: \n    y: a\n    x: b\n  again: 3\n  gone: back\n  raw: 4"
    );
    let json = serde_json::to_string(r[0].data.as_ref().unwrap()).unwrap();
    assert_eq!(
        json,
        r#"{"1":"first","zeta":"1","alpha":"changed","mid":{"y":"a","x":"b"},"again":"3","gone":"back","raw":"4"}"#
    );
    // A plain table is still sorted.
    let src = r#"
categories = {"safe"}
prerule = function() return true end
action = function() return { zeta = "1", alpha = "2" } end"#;
    let scan = ScriptScan::new(vec![script("plain", src)], ArgTable::default(), None).unwrap();
    assert_eq!(scan.pre_scan().await[0].output, "\n  alpha: 2\n  zeta: 1");
}

#[tokio::test]
async fn the_registry_carries_values_between_scripts() {
    let writer = r#"
categories = {"safe"}
prerule = function() return true end
hostrule = function() return true end
action = function(host)
  if SCRIPT_TYPE == "prerule" then
    fero.registry.set("seen", { "pre" })
    return nil
  end
  fero.host_registry.set("note", { ip = host.ip })
  fero.registry.append("hosts", host.ip)
end"#;
    let reader = r#"
categories = {"safe"}
dependencies = {"writer"}
hostrule = function() return fero.host_registry.get("note") ~= nil end
postrule = function() return true end
action = function(host)
  if SCRIPT_TYPE == "postrule" then
    local h = fero.registry.get("hosts")
    table.sort(h)
    return fero.registry.get("seen")[1] .. " " .. table.concat(h, ",")
  end
  return "note " .. fero.host_registry.get("note").ip
end"#;
    let scan = ScriptScan::new(
        vec![script("reader", reader), script("writer", writer)],
        ArgTable::default(),
        None,
    )
    .unwrap();
    assert!(scan.pre_scan().await.is_empty());
    let mut other = host_with(&[]);
    other.addr = "127.0.0.2".parse().unwrap();
    let mut hosts = vec![host_with(&[]), other];
    scan.scan_hosts(&mut hosts).await;
    assert_eq!(hosts[0].scripts[0].output, "note 127.0.0.1");
    assert_eq!(hosts[1].scripts[0].output, "note 127.0.0.2");
    let post = scan.post_scan().await;
    assert_eq!(post[0].output, "pre 127.0.0.1,127.0.0.2");
}

#[tokio::test]
async fn receive_buf_splits_at_the_delimiter() {
    let port = greeter(b"one\r\ntwo\nthree;four").await;
    let src = r#"
categories = {"safe"}
portrule = function() return true end
action = function(host, port)
  local s = fero.socket.new()
  s:set_timeout(1000)
  assert(s:connect(host, port))
  local out = {}
  local function add(...) out[#out + 1] = table.concat({ tostring(select(1, ...)), tostring(select(2, ...)) }, "=") end
  add(s:receive_buf("\r?\n", false))
  add(s:receive_buf("\n", true))
  add(s:receive_buf(function(buf) return buf:find(";", 1, true) end, false))
  s:set_timeout(300)
  add(s:receive_buf("never", false))
  add(s:receive())
  local ok, err = pcall(s.receive_buf, s, 5, false)
  add(ok, err ~= nil)
  return table.concat(out, "|")
end"#;
    let scan = ScriptScan::new(vec![script("rb", src)], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with(&[(port, PortState::Open)])];
    scan.scan_hosts(&mut hosts).await;
    assert_eq!(
        hosts[0].ports[0].scripts[0].output,
        "true=one|true=two\n|true=three|false=TIMEOUT|true=four|false=true"
    );
}

/// `t` (Unix seconds) as an IMF-fixdate.
fn http_date(t: i64) -> String {
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    // Civil date from days since 1970-01-01.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let wd = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][days.rem_euclid(7) as usize];
    let mon = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][(m - 1) as usize];
    format!(
        "{wd}, {d:02} {mon} {y} {:02}:{:02}:{:02} GMT",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// An HTTP server whose Date header is `date(now)`, keeping each request.
async fn date_web(date: fn(i64) -> String) -> (u16, Seen) {
    let seen: Seen = Default::default();
    let keep = seen.clone();
    let port = tcp_server(move |mut s| {
        let keep = keep.clone();
        async move {
            let req = read_http(&mut s).await;
            keep.lock().unwrap().push(req);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let reply = format!(
                "HTTP/1.1 200 OK\r\nDate: {}\r\nContent-Length: 2\r\n\r\nok",
                date(now)
            );
            let _ = s.write_all(reply.as_bytes()).await;
            let _ = s.shutdown().await;
        }
    })
    .await;
    (port, seen)
}

#[test]
fn http_dates_format() {
    assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
    assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
}

#[tokio::test]
async fn http_date_reads_the_date_header() {
    // Each of the three HTTP-date forms.
    for (date, iso) in [
        ("Sun, 06 Nov 1994 08:49:37 GMT", "1994-11-06T08:49:37+00:00"),
        (
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "1994-11-06T08:49:37+00:00",
        ),
        ("Sun Nov  6 08:49:37 1994", "1994-11-06T08:49:37+00:00"),
    ] {
        let reply: &'static str = Box::leak(
            format!("HTTP/1.1 200 OK\r\nDate: {date}\r\nContent-Length: 0\r\n\r\n")
                .into_boxed_str(),
        );
        let port = tcp_server(move |mut s| async move {
            let _ = read_http(&mut s).await;
            let _ = s.write_all(reply.as_bytes()).await;
        })
        .await;
        let scan = ScriptScan::new(vec![built_in("http-date")], ArgTable::default(), None).unwrap();
        let mut hosts = vec![host_with_services(&[(port, "http")])];
        scan.scan_hosts(&mut hosts).await;
        let r = &hosts[0].ports[0].scripts[0];
        assert!(
            r.output.starts_with(&format!("{date}; -")) && r.output.ends_with(" from local time."),
            "{}",
            r.output
        );
        assert_eq!(text(named(r.data.as_ref().unwrap(), "date")), iso);
    }
    // An hour ahead, carrying the User-Agent signature.
    let (port, seen) = date_web(|now| http_date(now + 3600)).await;
    let out = output_of("http-date", port, "http").await.unwrap();
    assert!(
        ["+59m59s", "+1h00m00s", "+1h00m01s"]
            .iter()
            .any(|d| out.ends_with(&format!("; {d} from local time."))),
        "{out}"
    );
    assert!(seen.lock().unwrap()[0].contains(USER_AGENT));
    // No Date header, or one that does not parse: nothing.
    let (port, _) = web(|_| b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
    assert_eq!(output_of("http-date", port, "http").await, None);
    let (port, _) =
        web(|_| b"HTTP/1.1 200 OK\r\nDate: yesterday\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
    assert_eq!(output_of("http-date", port, "http").await, None);
}

#[tokio::test]
async fn clock_skew_sums_up_what_the_date_scripts_saw() {
    // A stand-in for ssl-date (so clock-skew runs after it) that notes a
    // fixed skew per host: 127.0.0.1 one of 5 s, 127.0.0.2 three of 3600,
    // 3600 and 3610 s, 127.0.0.3 none.
    let recorder = r#"
categories = {"safe"}
hostrule = function() return true end
action = function(host)
  local now = os.time()
  if host.ip == "127.0.0.1" then
    fero.record_skew(now + 5, now)
  elseif host.ip == "127.0.0.2" then
    fero.record_skew(now + 3600, now)
    fero.record_skew(now + 3600, now)
    fero.record_skew(now + 3610, now)
  end
end"#;
    let scan = ScriptScan::new(
        vec![built_in("clock-skew"), script("ssl-date", recorder)],
        ArgTable::default(),
        None,
    )
    .unwrap();
    let mut hosts: Vec<HostResult> = ["127.0.0.1", "127.0.0.2", "127.0.0.3"]
        .iter()
        .map(|ip| {
            let mut h = host_with(&[]);
            h.addr = ip.parse().unwrap();
            h.hostname = None;
            h
        })
        .collect();
    scan.scan_hosts(&mut hosts).await;
    let out =
        |h: &HostResult| -> Vec<String> { h.scripts.iter().map(|s| s.output.clone()).collect() };
    assert_eq!(out(&hosts[0]), ["5s"]);
    assert_eq!(
        out(&hosts[1]),
        ["mean: 1h00m03s, deviation: 5s, median: 1h00m00s"]
    );
    assert!(out(&hosts[2]).is_empty());
    let json = serde_json::to_string(hosts[1].scripts[0].data.as_ref().unwrap()).unwrap();
    assert_eq!(
        json,
        r#"{"mean":"3603","stddev":"5","median":"3600","count":"3"}"#
    );
    // After the scan: the hosts grouped by their median.
    let post = scan.post_scan().await;
    assert_eq!(post.len(), 1);
    assert_eq!(
        post[0].output,
        "\n  5s: \n    127.0.0.1\n  1h00m00s: \n    127.0.0.2"
    );
}

// ---- NTLM-info scripts and the STARTTLS helper (v0.7.0 step 2) ----

/// The NTLM NEGOTIATE every script sends, as IDS rules 9100016 (base64)
/// and 9100017 (raw) match it.
const NEGOTIATE_B64: &str = "TlRMTVNTUAABAAAAB6IIogAAAAAAAAAACQAJACgAAAAAAAAAAAAAD0ZFUk9QUk9CRQ==";

/// What every *-ntlm-info script (but rdp's) shows for [`ntlm_challenge`].
const NTLM_INFO: &str = "\n  Target_Name: LAB\n  NetBIOS_Domain_Name: LAB\n  \
    NetBIOS_Computer_Name: SRV01\n  DNS_Domain_Name: lab.local\n  \
    DNS_Computer_Name: srv01.lab.local\n  DNS_Tree_Name: lab.local\n  \
    Product_Version: 10.0.14393";

/// What `seen` holds once it has `n` entries (or after 5 s): a server
/// may still be reading the client's last words when the script is done.
async fn seen_once(seen: &Seen, n: usize) -> Vec<String> {
    for _ in 0..100 {
        if seen.lock().unwrap().len() >= n {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    seen.lock().unwrap().clone()
}

fn challenge_b64() -> String {
    super::base64::encode(&ntlm_challenge(1_767_323_045))
}

#[tokio::test]
async fn the_ntlm_negotiate_names_feroprobe() {
    let src = r#"
categories = {"safe"}
prerule = function() return true end
action = function()
  return fero.ntlm.negotiate_base64() .. " " .. fero.hex(fero.ntlm.negotiate_message())
end"#;
    let scan = ScriptScan::new(vec![script("n", src)], ArgTable::default(), None).unwrap();
    let out = scan.pre_scan().await[0].output.clone();
    let (b64, hex) = out.split_once(' ').unwrap();
    assert_eq!(b64, NEGOTIATE_B64);
    assert_eq!(
        hex,
        "4e544c4d535350000100000007a208a2000000000000000009000900280000000000000000\
         00000f4645524f50524f4245"
    );
    assert_eq!(super::base64::decode(b64.as_bytes()).unwrap().len(), 49);
}

#[tokio::test]
async fn http_ntlm_info_reads_the_www_authenticate_challenge() {
    let (port, seen) = web(|req| {
        if req.contains("Authorization: NTLM ") {
            format!(
                "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate\r\n\
                 WWW-Authenticate: ntlm {}\r\nContent-Length: 0\r\n\r\n",
                challenge_b64()
            )
            .into_bytes()
        } else {
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()
        }
    })
    .await;
    assert_eq!(
        output_of("http-ntlm-info", port, "http").await.as_deref(),
        Some(NTLM_INFO)
    );
    {
        let seen = seen.lock().unwrap();
        assert!(seen[0].starts_with("GET / "), "{seen:?}");
        assert!(
            seen[0].contains(&format!("Authorization: NTLM {NEGOTIATE_B64}\r\n")),
            "{seen:?}"
        );
        assert!(seen[0].contains("FeroProbe Scripting Engine"), "{seen:?}");
    }
    // No NTLM offered: nothing.
    let (port, _) =
        web(|_| b"HTTP/1.1 401 No\r\nWWW-Authenticate: Basic realm=x\r\n\r\n".to_vec()).await;
    assert_eq!(output_of("http-ntlm-info", port, "http").await, None);
}

/// The plain-text side of a line-protocol AUTH exchange shared by the
/// SMTP, POP3, IMAP and NNTP stand-ins: the server's answer to `line`.
fn mail_answer(line: &str) -> Option<String> {
    let chal = challenge_b64();
    Some(match line {
        l if l.starts_with("EHLO ") => "250-mail.lab\r\n250 AUTH NTLM LOGIN\r\n".into(),
        "STARTTLS" => "502 not here\r\n".into(),
        "STLS" => "-ERR not here\r\n".into(),
        "AUTH NTLM" => "334 \r\n".into(),
        "AUTHINFO GENERIC NTLM" => "381 go on\r\n".into(),
        "fp1 AUTHENTICATE NTLM" => "+\r\n".into(),
        l if l == NEGOTIATE_B64 => format!("334 {chal}\r\n"),
        l if l == format!("AUTHINFO GENERIC {NEGOTIATE_B64}") => format!("381 {chal}\r\n"),
        "*" => "501 cancelled\r\n".into(),
        "QUIT" => "221 bye\r\n".into(),
        _ => return None,
    })
}

#[tokio::test]
async fn smtp_ntlm_info_falls_back_to_plain_text() {
    let (port, seen) = line_server("220 mail.lab ESMTP\r\n", mail_answer).await;
    assert_eq!(
        output_of("smtp-ntlm-info", port, "smtp").await.as_deref(),
        Some(NTLM_INFO)
    );
    assert_eq!(
        seen_once(&seen, 8).await,
        [
            "EHLO feroprobe.invalid",
            "STARTTLS",
            "QUIT",
            "EHLO feroprobe.invalid",
            "AUTH NTLM",
            NEGOTIATE_B64,
            "*",
            "QUIT",
        ]
    );
}

#[tokio::test]
async fn pop3_and_nntp_ntlm_info() {
    let (port, seen) = line_server("+OK ready\r\n", |line| match line {
        "AUTH NTLM" => Some("+ \r\n".into()),
        l if l == NEGOTIATE_B64 => Some(format!("+ {}\r\n", challenge_b64())),
        "*" => Some("-ERR cancelled\r\n".into()),
        _ => mail_answer(line),
    })
    .await;
    assert_eq!(
        output_of("pop3-ntlm-info", port, "pop3").await.as_deref(),
        Some(NTLM_INFO)
    );
    assert_eq!(
        seen_once(&seen, 6).await,
        ["STLS", "QUIT", "AUTH NTLM", NEGOTIATE_B64, "*", "QUIT"]
    );

    let (port, seen) = line_server("200 news.lab ready\r\n", mail_answer).await;
    assert_eq!(
        output_of("nntp-ntlm-info", port, "nntp").await.as_deref(),
        Some(NTLM_INFO)
    );
    assert_eq!(
        seen_once(&seen, 5).await,
        [
            "STARTTLS".to_string(),
            "QUIT".into(),
            "AUTHINFO GENERIC NTLM".into(),
            format!("AUTHINFO GENERIC {NEGOTIATE_B64}"),
            "QUIT".into(),
        ]
    );
}

/// A server that speaks plain text until it switches to TLS: it sends
/// each step's reply once what it read contains the step's expected bytes
/// (at once for an empty one), then takes a TLS handshake and answers the
/// lines it reads inside TLS with `tls_answer` (closing on `None`). Keeps
/// the plain bytes it read, then each line read inside TLS as "tls: ...".
async fn starttls_server(
    steps: &'static [(&'static [u8], &'static [u8])],
    tls_answer: fn(&str) -> Option<String>,
) -> (u16, Seen) {
    use tokio::io::AsyncBufReadExt;
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
                let mut buf = Vec::new();
                for (expect, reply) in steps {
                    while !expect.is_empty() && !buf.windows(expect.len()).any(|w| w == *expect) {
                        let mut chunk = [0u8; 1024];
                        match s.read(&mut chunk).await {
                            Ok(0) | Err(_) => {
                                keep.lock()
                                    .unwrap()
                                    .push(String::from_utf8_lossy(&buf).into());
                                return;
                            }
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    if s.write_all(reply).await.is_err() {
                        return;
                    }
                }
                keep.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf).into());
                let Ok(tls) = acceptor.accept(s).await else {
                    return;
                };
                let (rd, mut wr) = tokio::io::split(tls);
                let mut rd = tokio::io::BufReader::new(rd);
                let mut line = String::new();
                while rd.read_line(&mut line).await.unwrap_or(0) > 0 {
                    let got = line.trim_end().to_string();
                    keep.lock().unwrap().push(format!("tls: {got}"));
                    line.clear();
                    match tls_answer(&got) {
                        Some(reply) if wr.write_all(reply.as_bytes()).await.is_ok() => {}
                        _ => break,
                    }
                }
                let _ = wr.shutdown().await;
            });
        }
    });
    (port, seen)
}

const SMTP_STARTTLS: &[(&[u8], &[u8])] = &[
    (b"", b"220 mail.lab ESMTP\r\n"),
    (
        b"EHLO feroprobe.invalid\r\n",
        b"250-mail.lab\r\n250 STARTTLS\r\n",
    ),
    (b"STARTTLS\r\n", b"220 go ahead\r\n"),
];

#[tokio::test]
async fn smtp_ntlm_info_and_ssl_cert_over_starttls() {
    let (port, seen) = starttls_server(SMTP_STARTTLS, mail_answer).await;
    assert_eq!(
        output_of("smtp-ntlm-info", port, "smtp").await.as_deref(),
        Some(NTLM_INFO)
    );
    assert_eq!(
        seen_once(&seen, 6).await,
        [
            "EHLO feroprobe.invalid\r\nSTARTTLS\r\n".to_string(),
            "tls: EHLO feroprobe.invalid".into(),
            "tls: AUTH NTLM".into(),
            format!("tls: {NEGOTIATE_B64}"),
            "tls: *".into(),
            "tls: QUIT".into(),
        ]
    );
    // ssl-cert reads the certificate after STARTTLS on an SMTP port.
    let (port, _) = starttls_server(SMTP_STARTTLS, |_| None).await;
    let out = output_of("ssl-cert", port, "smtp").await.unwrap();
    assert!(
        out.starts_with("Subject: commonName=localhost/organizationName=FeroProbe Lab"),
        "{out}"
    );
}

#[tokio::test]
async fn imap_ntlm_info_switches_to_tls_when_offered() {
    const STEPS: &[(&[u8], &[u8])] = &[
        (b"", b"* OK IMAP4rev1 ready\r\n"),
        (
            b"fp1 CAPABILITY\r\n",
            b"* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\nfp1 OK done\r\n",
        ),
        (b"fp2 STARTTLS\r\n", b"fp2 OK begin TLS\r\n"),
    ];
    let (port, seen) = starttls_server(STEPS, |line| match line {
        "fp1 AUTHENTICATE NTLM" => Some("+ \r\n".into()),
        l if l == NEGOTIATE_B64 => Some(format!("+ {}\r\n", challenge_b64())),
        "*" => Some("fp1 BAD cancelled\r\n".into()),
        _ => Some("* BYE\r\nfp2 OK\r\n".into()),
    })
    .await;
    assert_eq!(
        output_of("imap-ntlm-info", port, "imap").await.as_deref(),
        Some(NTLM_INFO)
    );
    assert_eq!(
        seen_once(&seen, 5).await,
        [
            "fp1 CAPABILITY\r\nfp2 STARTTLS\r\n".to_string(),
            "tls: fp1 AUTHENTICATE NTLM".into(),
            format!("tls: {NEGOTIATE_B64}"),
            "tls: *".into(),
            "tls: fp2 LOGOUT".into(),
        ]
    );
}

#[tokio::test]
async fn starttls_switches_each_protocol_to_tls() {
    const FTP: &[(&[u8], &[u8])] = &[
        (b"", b"220-Lab FTP\r\n220 ready\r\n"),
        (b"AUTH TLS\r\n", b"234 go\r\n"),
    ];
    const POP3: &[(&[u8], &[u8])] = &[(b"", b"+OK ready\r\n"), (b"STLS\r\n", b"+OK go\r\n")];
    const NNTP: &[(&[u8], &[u8])] = &[(b"", b"201 ready\r\n"), (b"STARTTLS\r\n", b"382 go\r\n")];
    const LMTP: &[(&[u8], &[u8])] = &[
        (b"", b"220 lmtp ready\r\n"),
        (b"LHLO feroprobe.invalid\r\n", b"250 STARTTLS\r\n"),
        (b"STARTTLS\r\n", b"220 go\r\n"),
    ];
    const LDAP: &[(&[u8], &[u8])] = &[(
        b"\x30\x1d\x02\x01\x01\x77\x18\x80\x161.3.6.1.4.1.1466.20037",
        b"\x30\x0c\x02\x01\x01\x78\x07\x0a\x01\x00\x04\x00\x04\x00",
    )];
    const POSTGRES: &[(&[u8], &[u8])] = &[(b"\x00\x00\x00\x08\x04\xd2\x16\x2f", b"S")];
    const XMPP: &[(&[u8], &[u8])] = &[
        (
            b"to='localhost' version='1.0'>",
            b"<?xml version='1.0'?><stream:stream from='lab' version='1.0'><stream:features>\
              <starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>\
              </stream:features>",
        ),
        (
            b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
            b"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
        ),
    ];
    let src = r#"
categories = {"safe"}
portrule = function() return true end
action = function(host, port)
  local sock, err = fero.starttls.connect(host, port, { protocol = fero.args.get("p") })
  if not sock then return "failed: " .. tostring(err) end
  local cert = sock:get_ssl_certificate()
  sock:close()
  return cert and cert.subject.commonName
end"#;
    // A prefixed answer element in the TLS namespace counts too.
    const XMPP_PREFIXED: &[(&[u8], &[u8])] = &[
        (
            b"version='1.0'>",
            b"<stream:stream version='1.0'><stream:features><starttls \
              xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:features>",
        ),
        (
            b"<starttls",
            b"<tls:proceed xmlns:tls='urn:ietf:params:xml:ns:xmpp-tls'/>",
        ),
    ];
    // So does a prefix the stream header binds to the TLS namespace.
    const XMPP_STREAM_PREFIX: &[(&[u8], &[u8])] = &[
        (
            b"version='1.0'>",
            b"<stream:stream xmlns:tls=\"urn:ietf:params:xml:ns:xmpp-tls\" version='1.0'>\
              <stream:features><tls:starttls/></stream:features>",
        ),
        (b"<starttls", b"<tls:proceed/>"),
    ];
    for (proto, steps) in [
        ("ftp", FTP),
        ("pop3", POP3),
        ("nntp", NNTP),
        ("lmtp", LMTP),
        ("ldap", LDAP),
        ("postgresql", POSTGRES),
        ("xmpp", XMPP),
        ("xmpp", XMPP_PREFIXED),
        ("xmpp", XMPP_STREAM_PREFIX),
    ] {
        let (port, _) = starttls_server(steps, |_| None).await;
        let scan = ScriptScan::new(
            vec![script("s", src)],
            args::parse(&format!("p={proto}")).unwrap(),
            None,
        )
        .unwrap();
        let mut hosts = vec![host_with_services(&[(port, "unknown")])];
        scan.scan_hosts(&mut hosts).await;
        assert_eq!(hosts[0].ports[0].scripts[0].output, "localhost", "{proto}");
    }
    // A binding on the answer element overrides the stream's: this
    // <tls:proceed/> is in another namespace, so nothing is switched.
    const XMPP_OVERRIDDEN: &[(&[u8], &[u8])] = &[
        (
            b"version='1.0'>",
            b"<stream:stream xmlns:tls='urn:ietf:params:xml:ns:xmpp-tls' version='1.0'>\
              <stream:features><tls:starttls/></stream:features>",
        ),
        (
            b"<starttls",
            b"<tls:proceed xmlns:tls='urn:other'/><tls:failure/>",
        ),
    ];
    let (port, _) = starttls_server(XMPP_OVERRIDDEN, |_| None).await;
    let scan =
        ScriptScan::new(vec![script("s", src)], args::parse("p=xmpp").unwrap(), None).unwrap();
    let mut hosts = vec![host_with_services(&[(port, "unknown")])];
    scan.scan_hosts(&mut hosts).await;
    assert_eq!(
        hosts[0].ports[0].scripts[0].output,
        "failed: STARTTLS refused"
    );
    // A prefix bound only on <stream:features> is out of scope for the
    // answer, so its <tls:proceed/> does not count either.
    const XMPP_FEATURES_ONLY: &[(&[u8], &[u8])] = &[
        (
            b"version='1.0'>",
            b"<stream:stream version='1.0'><stream:features \
              xmlns:tls='urn:ietf:params:xml:ns:xmpp-tls'><tls:starttls/></stream:features>",
        ),
        (b"<starttls", b"<tls:proceed/><failure/>"),
    ];
    let (port, _) = starttls_server(XMPP_FEATURES_ONLY, |_| None).await;
    let scan =
        ScriptScan::new(vec![script("s", src)], args::parse("p=xmpp").unwrap(), None).unwrap();
    let mut hosts = vec![host_with_services(&[(port, "unknown")])];
    scan.scan_hosts(&mut hosts).await;
    assert_eq!(
        hosts[0].ports[0].scripts[0].output,
        "failed: STARTTLS refused"
    );
    // A refusal is reported, and nothing is switched.
    let (port, _) = line_server("+OK ready\r\n", mail_answer).await;
    let scan =
        ScriptScan::new(vec![script("s", src)], args::parse("p=pop3").unwrap(), None).unwrap();
    let mut hosts = vec![host_with_services(&[(port, "pop3")])];
    scan.scan_hosts(&mut hosts).await;
    assert_eq!(hosts[0].ports[0].scripts[0].output, "failed: STLS refused");
    // A truncated LDAP answer is a refusal, not a script error.
    const LDAP_SHORT: &[(&[u8], &[u8])] = &[(b"1.3.6.1.4.1.1466.20037", b"\x30\x01\x02")];
    let (port, _) = starttls_server(LDAP_SHORT, |_| None).await;
    let scan =
        ScriptScan::new(vec![script("s", src)], args::parse("p=ldap").unwrap(), None).unwrap();
    let mut hosts = vec![host_with_services(&[(port, "ldap")])];
    scan.scan_hosts(&mut hosts).await;
    assert_eq!(
        hosts[0].ports[0].scripts[0].output,
        "failed: not an LDAP message"
    );
}

#[tokio::test]
async fn clock_skew_waits_for_the_ntlm_scripts() {
    let (port, _) = line_server("220 mail.lab ESMTP\r\n", mail_answer).await;
    let scan = ScriptScan::new(
        vec![built_in("clock-skew"), built_in("smtp-ntlm-info")],
        ArgTable::default(),
        None,
    )
    .unwrap();
    let mut hosts = vec![host_with_services(&[(port, "smtp")])];
    scan.scan_hosts(&mut hosts).await;
    assert_eq!(hosts[0].ports[0].scripts.len(), 1);
    let skew: Vec<_> = hosts[0].scripts.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(skew, ["clock-skew"]);
}

#[tokio::test]
async fn telnet_ntlm_info_reads_the_auth_reply() {
    let seen: Seen = Default::default();
    let keep = seen.clone();
    let port = tcp_server(move |mut s| {
        let keep = keep.clone();
        async move {
            // The server's own negotiation first: DO AUTHENTICATION.
            let _ = s.write_all(b"\xff\xfd\x25").await;
            let mut buf = vec![0u8; 256];
            let n = s.read(&mut buf).await.unwrap_or(0);
            keep.lock().unwrap().push(fero_hex(&buf[..n]));
            // A challenge whose nonce holds 0xff bytes, doubled on the wire.
            let mut chal = ntlm_challenge(1_767_323_045);
            chal[24..32].copy_from_slice(&[0xff; 8]);
            let mut data = vec![0x0f, 0x00, 0x01];
            data.extend((chal.len() as u32).to_le_bytes());
            data.extend(2u32.to_le_bytes());
            data.extend(chal);
            let mut out = b"\xff\xfa\x25\x02".to_vec();
            for b in data {
                out.push(b);
                if b == 0xff {
                    out.push(0xff);
                }
            }
            out.extend(b"\xff\xf0");
            // In two pieces, the end of the sub-negotiation last.
            let (a, b) = out.split_at(out.len() - 5);
            let _ = s.write_all(a).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = s.write_all(b).await;
        }
    })
    .await;
    assert_eq!(
        output_of("telnet-ntlm-info", port, "telnet")
            .await
            .as_deref(),
        Some(NTLM_INFO)
    );
    let negotiate = fero_hex(&super::base64::decode(NEGOTIATE_B64.as_bytes()).unwrap());
    assert_eq!(
        seen.lock().unwrap()[0],
        format!(
            "fffa25000f000031000000020000004e544c4d{}fff0",
            &negotiate[8..]
        )
    );
}

fn fero_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[tokio::test]
async fn ms_sql_ntlm_info_logs_in_with_integrated_security() {
    let seen: Seen = Default::default();
    let keep = seen.clone();
    let port = tcp_server(move |mut s| {
        let keep = keep.clone();
        async move {
            let mut head = [0u8; 8];
            if s.read_exact(&mut head).await.is_err() {
                return;
            }
            let mut body = vec![0u8; u16::from_be_bytes([head[2], head[3]]) as usize - 8];
            if s.read_exact(&mut body).await.is_err() {
                return;
            }
            keep.lock().unwrap().push(fero_hex(&head));
            keep.lock().unwrap().push(fero_hex(&body));
            let chal = ntlm_challenge(1_767_323_045);
            let mut tokens = vec![0xed];
            tokens.extend((chal.len() as u16).to_le_bytes());
            tokens.extend(chal);
            // Two packets: the second one ends the message.
            let (a, b) = tokens.split_at(20);
            for (part, status) in [(a, 0u8), (b, 1)] {
                let mut p = vec![0x04, status];
                p.extend(((part.len() + 8) as u16).to_be_bytes());
                p.extend([0, 0, 1, 0]);
                p.extend(part);
                let _ = s.write_all(&p).await;
            }
        }
    })
    .await;
    let out = output_of("ms-sql-ntlm-info", port, "ms-sql-s")
        .await
        .unwrap();
    assert_eq!(
        out,
        format!(
            "\n  127.0.0.1:{port}: {}",
            NTLM_INFO.replace("\n  ", "\n    ")
        )
    );
    let seen = seen.lock().unwrap();
    // A LOGIN7 packet, alone in its message.
    assert!(seen[0].starts_with("1001"), "{seen:?}");
    let body = &seen[1];
    // TDS 7.1, integrated security, and the NEGOTIATE at the end.
    assert_eq!(&body[8..16], "01000071");
    assert_eq!(&body[50..52], "83");
    let negotiate = fero_hex(&super::base64::decode(NEGOTIATE_B64.as_bytes()).unwrap());
    assert!(body.ends_with(&negotiate), "{body}");
    // The host name FEROPROBE, in UTF-16.
    assert!(
        body.contains("4600450052004f00500052004f0042004500"),
        "{body}"
    );
}

// ---- nmap's remaining HTTP default scripts (v0.7.0 step 4) ----

/// The port script result of built-in `id` (its source changed by
/// `edit`, if given) on a host whose only port is `port`, known as
/// `service`, with `args`.
async fn http_result(
    id: &str,
    port: u16,
    service: &str,
    args: &str,
    edit: Option<(&str, &str)>,
) -> Option<ScriptResult> {
    let mut src = Script::built_in()
        .unwrap()
        .into_iter()
        .find(|s| s.id == id)
        .unwrap()
        .source;
    if let Some((from, to)) = edit {
        assert!(src.contains(from));
        src = src.replace(from, to).into();
    }
    let scan = ScriptScan::new(vec![script(id, &src)], args::parse(args).unwrap(), None).unwrap();
    let mut hosts = vec![host_with_services(&[(port, service)])];
    scan.scan_hosts(&mut hosts).await;
    assert!(hosts[0].ports[0].scripts.len() <= 1);
    hosts[0].ports[0].scripts.first().cloned()
}

async fn http_output(id: &str, port: u16, args: &str) -> Option<String> {
    http_result(id, port, "http", args, None)
        .await
        .map(|r| r.output)
}

#[tokio::test]
async fn http_auth_lists_the_challenges() {
    let (port, seen) = web(|req| {
        if req.starts_with("GET /private/ ") {
            b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Lab Admin\"\r\n\
              WWW-Authenticate: Digest realm=\"lab\", qop=\"auth,auth-int\", nonce=\"a\\\"b\", algorithm=MD5, NTLM\r\n\
              WWW-Authenticate: Negotiate YIIBhg==\r\nContent-Length: 0\r\n\r\n"
                .to_vec()
        } else if req.starts_with("GET /bare ") {
            b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n".to_vec()
        } else if req.starts_with("GET /odd ") {
            b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"open\r\nContent-Length: 0\r\n\r\n"
                .to_vec()
        } else {
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()
        }
    })
    .await;
    let r = http_result("http-auth", port, "http", "http-auth.path=/private/", None)
        .await
        .unwrap();
    assert_eq!(
        r.output,
        "\nHTTP/1.1 401 Unauthorized\n  Basic realm=Lab Admin\
         \n  Digest realm=lab qop=auth,auth-int nonce=a\"b algorithm=MD5\n  NTLM\n  Negotiate YIIBhg=="
    );
    let data = format!("{:?}", r.data);
    assert!(data.contains("scheme") && data.contains("realm"), "{data}");
    assert!(seen.lock().unwrap()[0].contains("FeroProbe Scripting Engine"));
    assert_eq!(
        http_output("http-auth", port, "http-auth.path=/bare")
            .await
            .as_deref(),
        Some(
            "\nHTTP/1.1 401 Unauthorized\n  Server returned status 401 but no WWW-Authenticate header."
        )
    );
    assert_eq!(
        http_output("http-auth", port, "http-auth.path=/odd")
            .await
            .as_deref(),
        Some(
            "\nHTTP/1.1 401 Unauthorized\n  Server returned status 401 but the WWW-Authenticate header could not be parsed.\
             \n  WWW-Authenticate: Basic realm=\"open"
        )
    );
    // No login asked for: nothing.
    assert_eq!(http_output("http-auth", port, "").await, None);
}

#[tokio::test]
async fn http_cookie_flags_reports_session_cookies() {
    let (port, _) = web(|req| {
        if req.starts_with("GET / ") {
            b"HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=1; path=/\r\n\
              Set-Cookie: JSESSIONID=2; Path=/; HttpOnly\r\nSet-Cookie: my_session-id=3\r\n\
              Set-Cookie: theme=dark\r\nContent-Length: 0\r\n\r\n"
                .to_vec()
        } else {
            b"HTTP/1.1 200 OK\r\nSet-Cookie: JSESSIONID=2; Path=/; HttpOnly\r\nContent-Length: 0\r\n\r\n"
                .to_vec()
        }
    })
    .await;
    assert_eq!(
        http_output("http-cookie-flags", port, "").await.as_deref(),
        Some(
            "\n  /: \n    PHPSESSID: \n      httponly flag not set\n    my_session-id: \n      httponly flag not set"
        )
    );
    // One cookie by name, whatever it is called.
    assert_eq!(
        http_output("http-cookie-flags", port, "http-cookie-flags.cookie=theme")
            .await
            .as_deref(),
        Some("\n  /: \n    theme: \n      httponly flag not set")
    );
    // All flags set: nothing.
    assert_eq!(
        http_output("http-cookie-flags", port, "http-cookie-flags.path=/login").await,
        None
    );
}

#[tokio::test]
async fn http_git_reads_an_exposed_repository() {
    let (port, seen) = web(|req| {
        let body: &[u8] = if req.starts_with("GET /.git/HEAD ") {
            b"ref: refs/heads/main\n"
        } else if req.starts_with("GET /.git/config ") {
            b"[core]\n\tbare = false\n[remote \"origin\"]\n\turl = https://git.example/site.git\n[user]\n\tname = dev\n"
        } else if req.starts_with("GET /.git/description ") {
            b"The lab site, a repository with a rather long description line\n"
        } else if req.starts_with("GET /.gitignore ") {
            b"*.pyc\nlocal_settings.py\n"
        } else {
            return b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec();
        };
        let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        r.extend_from_slice(body);
        r
    })
    .await;
    assert_eq!(
        http_output("http-git", port, "").await,
        Some(format!(
            "\n  127.0.0.1:{port}/.git/\n    Git repository found!\
             \n    .git/config matched patterns 'user'\
             \n    Repository description: The lab site, a repository with a rather long description li...\
             \n    Remotes:\n      https://git.example/site.git\
             \n    Project type: Django web application (guessed from .gitignore)"
        ))
    );
    assert_eq!(seen.lock().unwrap().len(), 7);
    // Another root, and none there: nothing, after one request.
    seen.lock().unwrap().clear();
    assert_eq!(
        http_output("http-git", port, "http-git.root=app").await,
        None
    );
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].starts_with("GET /app/.git/HEAD "), "{seen:?}");
}

#[tokio::test]
async fn http_webdav_scan_reads_options_and_propfind() {
    let (port, seen) = web(|req| {
        if req.starts_with("OPTIONS / ") {
            b"HTTP/1.1 200 OK\r\nDAV: 1,2\r\nAllow: GET, PROPFIND, MKCOL\r\nServer: Apache/2.4.58\r\n\
              Date: Thu, 19 Nov 2026 10:00:00 GMT\r\nContent-Length: 0\r\n\r\n"
                .to_vec()
        } else if req.starts_with("PROPFIND / ") {
            let body = "<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\">\
                <d:response><d:href>/</d:href><d:propstat><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>\
                <d:response><d:href>/notes.txt</d:href><d:prop>host 192.168.1.20, 10.0.0.300, 8.8.8.8</d:prop></d:response>\
                </d:multistatus>";
            format!(
                "HTTP/1.1 207 Multi-Status\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .into_bytes()
        } else {
            b"HTTP/1.1 405 No\r\nContent-Length: 0\r\n\r\n".to_vec()
        }
    })
    .await;
    assert_eq!(
        http_output("http-webdav-scan", port, "").await.as_deref(),
        Some(
            "\n  Allowed Methods: GET, PROPFIND, MKCOL\n  Server Type: Apache/2.4.58\
             \n  Server Date: Thu, 19 Nov 2026 10:00:00 GMT\n  WebDAV type: Unknown\
             \n  Exposed Internal IPs: \n    192.168.1.20\n  Directory Listing: \n    /\n    /notes.txt"
        )
    );
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        let pf = seen.iter().find(|r| r.starts_with("PROPFIND")).unwrap();
        assert!(
            pf.contains("\r\nDepth: 1\r\n") && pf.contains("\r\nContent-Length: 0\r\n"),
            "{pf}"
        );
    }
    // No WebDAV: nothing.
    let (port, _) =
        web(|_| b"HTTP/1.1 200 OK\r\nAllow: GET\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
    assert_eq!(http_output("http-webdav-scan", port, "").await, None);
}

#[tokio::test]
async fn http_favicon_hashes_the_icon() {
    let (port, seen) = web(|req| {
        if req.starts_with("GET / ") {
            b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n<html><LINK href='/static/i.ico' rel=\"shortcut icon\"></html>    "
                .to_vec()
        } else if req.starts_with("GET /static/i.ico ") {
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nICON".to_vec()
        } else if req.starts_with("GET /favicon.ico ") {
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nico".to_vec()
        } else {
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
        }
    })
    .await;
    let verbose = Some(("fero.verbosity()", "1"));
    let icon = |r: Option<ScriptResult>| r.map(|r| r.output);
    // MD5("ICON")
    assert_eq!(
        icon(http_result("http-favicon", port, "http", "", verbose).await).as_deref(),
        Some("Unknown favicon MD5: DD912956B69FB3E570820021206968A3")
    );
    assert_eq!(seen.lock().unwrap().len(), 2);
    // Without -v an unknown icon is not shown, as in nmap.
    assert_eq!(
        icon(
            http_result(
                "http-favicon",
                port,
                "http",
                "",
                Some(("fero.verbosity()", "0"))
            )
            .await
        ),
        None
    );
    // favicon.uri is fetched as it is; MD5("ico").
    assert_eq!(
        icon(
            http_result(
                "http-favicon",
                port,
                "http",
                "favicon.uri=favicon.ico",
                verbose
            )
            .await
        )
        .as_deref(),
        Some("Unknown favicon MD5: 65F034C0F853471ED478CEB34164523B")
    );
    // An icon on another host is not fetched: /favicon.ico instead.
    let (port, seen) = web(|req| {
        if req.starts_with("GET / ") {
            b"HTTP/1.1 200 OK\r\nContent-Length: 53\r\n\r\n<link rel=icon href=\"http://other.example/i.ico\">    "
                .to_vec()
        } else if req.starts_with("GET /favicon.ico ") {
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nICON".to_vec()
        } else {
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
        }
    })
    .await;
    assert_eq!(
        icon(http_result("http-favicon", port, "http", "", verbose).await).as_deref(),
        Some("Unknown favicon MD5: DD912956B69FB3E570820021206968A3")
    );
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2, "{seen:?}");
}

#[tokio::test]
async fn http_generator_reads_the_meta_tag() {
    let (port, _) = web(|req| {
        if req.starts_with("GET / ") {
            b"HTTP/1.1 200 OK\r\nContent-Length: 88\r\n\r\n<head><meta charset=utf-8><META content=\"WordPress 6.4.2\" NAME='Generator' /></head>    "
                .to_vec()
        } else {
            b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n<p>plain</p>\n".to_vec()
        }
    })
    .await;
    assert_eq!(
        http_output("http-generator", port, "").await.as_deref(),
        Some("WordPress 6.4.2")
    );
    assert_eq!(
        http_output("http-generator", port, "http-generator.path=/x").await,
        None
    );
}

#[tokio::test]
async fn http_cors_lists_the_allowed_methods() {
    let (port, seen) = web(|req| {
        if !req.starts_with("OPTIONS ") {
            return b"HTTP/1.1 405 No\r\nContent-Length: 0\r\n\r\n".to_vec();
        }
        let origin = if req.contains("\r\nOrigin: https://app.example\r\n") {
            "https://app.example"
        } else if req.starts_with("OPTIONS /star ") {
            "*"
        } else {
            "https://app.example"
        };
        format!(
            "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: {origin}\r\n\
             Access-Control-Allow-Methods: GET,POST, OPTIONS\r\n\r\n"
        )
        .into_bytes()
    })
    .await;
    assert_eq!(
        http_output("http-cors", port, "http-cors.path=/star")
            .await
            .as_deref(),
        Some("GET POST OPTIONS")
    );
    assert_eq!(seen.lock().unwrap().len(), 9);
    // The origin allowed by name.
    assert_eq!(
        http_output("http-cors", port, "http-cors.origin=https://app.example")
            .await
            .as_deref(),
        Some("GET POST OPTIONS")
    );
    // Another origin: nothing.
    assert_eq!(http_output("http-cors", port, "").await, None);
    let seen = seen.lock().unwrap();
    assert!(
        seen.iter().any(
            |r| r.contains("\r\nAccess-Control-Request-Method: PATCH\r\n")
                && r.contains("\r\nOrigin: example.com\r\n")
        ),
        "{seen:?}"
    );
}

#[tokio::test]
async fn http_cookie_flags_checks_a_redirect_and_merges_repeats() {
    let (port, seen) = web(|req| {
        if req.starts_with("GET / ") {
            b"HTTP/1.1 302 Found\r\nLocation: /home\r\nSet-Cookie: JSESSIONID=1; Secure\r\n\
              Content-Length: 0\r\n\r\n"
                .to_vec()
        } else {
            b"HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=2; HttpOnly\r\nSet-Cookie: PHPSESSID=3\r\n\
              Content-Length: 0\r\n\r\n"
                .to_vec()
        }
    })
    .await;
    // The redirect's own cookie lacks HttpOnly, and so does one of the
    // page's two of one name (merged, each issue once).
    assert_eq!(
        http_output("http-cookie-flags", port, "").await.as_deref(),
        Some(
            "\n  /: \n    JSESSIONID: \n      httponly flag not set\n    PHPSESSID: \n      httponly flag not set"
        )
    );
    assert_eq!(seen.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn http_cors_needs_a_successful_answer() {
    let (port, _) = web(|req| {
        if req.starts_with("OPTIONS /denied ") {
            b"HTTP/1.1 403 Forbidden\r\nAccess-Control-Allow-Origin: *\r\n\
              Access-Control-Allow-Methods: *\r\nContent-Length: 0\r\n\r\n"
                .to_vec()
        } else if req.starts_with("OPTIONS /two ") {
            b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: example.com https://other.example\r\n\
              Access-Control-Allow-Methods: GET\r\nContent-Length: 0\r\n\r\n"
                .to_vec()
        } else {
            b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: example.com\r\n\
              Access-Control-Allow-Methods: *\r\nContent-Length: 0\r\n\r\n"
                .to_vec()
        }
    })
    .await;
    // "*" allows every method.
    assert_eq!(
        http_output("http-cors", port, "").await.as_deref(),
        Some("HEAD GET POST PUT DELETE TRACE OPTIONS CONNECT PATCH")
    );
    // A refused preflight allows nothing, whatever its headers say.
    assert_eq!(
        http_output("http-cors", port, "http-cors.path=/denied").await,
        None
    );
    // Two origins in one header are no valid answer.
    assert_eq!(
        http_output("http-cors", port, "http-cors.path=/two").await,
        None
    );
}

#[tokio::test]
async fn http_git_skips_fallback_pages_and_hides_passwords() {
    let (port, _) = web(|req| {
        let body: &[u8] = if req.starts_with("GET /.git/HEAD ") {
            // Served as HTML by a careless server: the body decides.
            return b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 41\r\n\r\n\
                     0123456789abcdef0123456789abcdef01234567\n"
                .to_vec();
        } else if req.starts_with("GET /.git/config ") {
            b"[remote \"origin\"]\n\turl = \"https://dev:s3cret@git.example/site.git\"\n\
              [remote \"backup\"]\n\turl = git@backup.example:site.git\n\
              [remote \"query\"]\n\turl = \"https://git.example?owner=dev@example.org\"\n\
              [submodule \"lib\"]\n\turl = https://git.example/lib.git\n"
        } else if req.starts_with("GET /.git/description ") {
            b"Site\n"
        } else if req.starts_with("GET /.git/COMMIT_EDITMSG ") {
            return b"HTTP/1.1 302 Found\r\nLocation: /login\r\nContent-Length: 0\r\n\r\n".to_vec();
        } else {
            // Every other path: the site's own page.
            b"<!DOCTYPE html><html><title>Shop</title></html>"
        };
        let mut r =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        r.extend_from_slice(body);
        r
    })
    .await;
    assert_eq!(
        http_output("http-git", port, "").await,
        Some(format!(
            "\n  127.0.0.1:{port}/.git/\n    Potential Git repository found (found 2/6 expected files)\
             \n    Remotes:\n      https://git.example/site.git\n      git@backup.example:site.git\
             \n      https://git.example?owner=dev@example.org"
        ))
    );
    // A HEAD that is no Git reference: nothing.
    let (port, _) =
        web(|_| b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nref: unavailable".to_vec()).await;
    assert_eq!(http_output("http-git", port, "").await, None);
    // Every other path answered with a 200 naming the path: the
    // free-text files cannot be believed, and a "config" without
    // [section] lines is no config.
    let (port, _) = web(|req| {
        let body: Vec<u8> = if req.starts_with("GET /.git/HEAD ") {
            b"ref: refs/heads/main\n".to_vec()
        } else if req.starts_with("GET /.git/feroprobe-no-such-file ") {
            // The missing file gets an HTML page; its 200 still counts.
            b"<html><body>No such page</body></html>".to_vec()
        } else {
            let path = req.split(' ').nth(1).unwrap_or("");
            format!("Not found: {path}\n").into_bytes()
        };
        let body = &body[..];
        let mut r = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        r.extend_from_slice(body);
        r
    })
    .await;
    assert_eq!(
        http_output("http-git", port, "").await,
        Some(format!(
            "\n  127.0.0.1:{port}/.git/\n    Potential Git repository found (found 1/6 expected files)"
        ))
    );
}

#[tokio::test]
async fn http_webdav_scan_reads_any_prefix() {
    let (port, _) = web(|req| {
        if req.starts_with("OPTIONS ") {
            b"HTTP/1.1 204 No Content\r\nDAV: 1, 2, <http://apache.org/dav/propset/fs/1>\r\n\
              Allow: GET, PROPFIND\r\n\r\n"
                .to_vec()
        } else if req.starts_with("PROPFIND ") {
            let body = "<?xml version=\"1.0\"?><x.d:multistatus xmlns:x.d=\"DAV:\" xmlns=\"DAV:\">\
                <response><href>/a%20b?x=1&amp;y=2</href><propstat><prop>\
                <otherresponse><otherhref>/phantom</otherhref></otherresponse>\
                <o:response xmlns:o=\"urn:other\"><o:href>/other</o:href></o:response>\
                </prop></propstat></response>\
                <x.d:response><x.d:href>/second</x.d:href><x.d:propstat><x.d:prop>\
                <x.d:lockdiscovery><x.d:activelock><x.d:lockroot><x.d:href>/</x.d:href></x.d:lockroot>\
                </x.d:activelock></x.d:lockdiscovery></x.d:prop>\
                <x.d:status>HTTP/1.1 403 Forbidden</x.d:status></x.d:propstat></x.d:response>\
                </x.d:multistatus>";
            format!(
                "HTTP/1.1 207 Multi-Status\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .into_bytes()
        } else {
            b"HTTP/1.1 405 No\r\nContent-Length: 0\r\n\r\n".to_vec()
        }
    })
    .await;
    assert_eq!(
        http_output("http-webdav-scan", port, "").await.as_deref(),
        Some(
            "\n  Allowed Methods: GET, PROPFIND\n  WebDAV type: Apache DAV\n  Directory Listing: \n    /a%20b?x=1&y=2\n    /second"
        )
    );
    // "DAV: 11" is not class 1, and a 207 outside the DAV: namespace is
    // no WebDAV answer.
    let (port, _) = web(|req| {
        if req.starts_with("OPTIONS ") {
            b"HTTP/1.1 200 OK\r\nDAV: 11\r\nContent-Length: 0\r\n\r\n".to_vec()
        } else {
            b"HTTP/1.1 207 Multi-Status\r\nContent-Length: 50\r\n\r\n<m:multistatus xmlns:m=\"urn:other\"></m:multistatus>"
                .to_vec()
        }
    })
    .await;
    assert_eq!(http_output("http-webdav-scan", port, "").await, None);
}

#[tokio::test]
async fn http_favicon_and_generator_read_quoted_values() {
    let (port, _) = web(|req| {
        let body: &[u8] = if req.starts_with("GET / ") {
            b"<link title=\"rel=icon href=/wrong.ico\" rel=stylesheet href=/style.css>\
              <link data-ui_href=/wrong.ico rel=\"icon\" title=\"a > b\" href=\"/site's.ico\">\
              <meta title=\"> name=generator content=Fake\" name=viewport content=width=device-width>\
              <meta data-ui_content=placeholder name=generator content=\"CMS > 2\">"
        } else if req.starts_with("GET /site's.ico ") {
            b"ICON"
        } else {
            return b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec();
        };
        let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        r.extend_from_slice(body);
        r
    })
    .await;
    assert_eq!(
        http_result(
            "http-favicon",
            port,
            "http",
            "",
            Some(("fero.verbosity()", "1"))
        )
        .await
        .map(|r| r.output)
        .as_deref(),
        Some("Unknown favicon MD5: DD912956B69FB3E570820021206968A3")
    );
    // favicon.uri with a leading slash names the same path.
    assert_eq!(
        http_result(
            "http-favicon",
            port,
            "http",
            "favicon.uri=/site's.ico",
            Some(("fero.verbosity()", "1"))
        )
        .await
        .map(|r| r.output)
        .as_deref(),
        Some("Unknown favicon MD5: DD912956B69FB3E570820021206968A3")
    );
    assert_eq!(
        http_output("http-generator", port, "").await.as_deref(),
        Some("CMS > 2")
    );
}

// ---- SMB1 scripts and smb2-capabilities (v0.7.0 step 5) ----

/// How the stand-in SMB server of [`smb1_server`] behaves.
#[derive(Clone)]
struct SmbLab {
    /// Answers SMB1 (NT LM 0.12); else drops an SMB1 NEGOTIATE, as
    /// Windows with SMB1 turned off does.
    smb1: bool,
    /// The SMB1 SecurityMode byte.
    mode: u8,
    /// The session setup answer's strings in UTF-16 (with the pad byte).
    unicode: bool,
    /// The domain or workgroup the plain NEGOTIATE names.
    domain: &'static str,
    /// The plain NEGOTIATE's names in OEM text (an old CIFS server), not
    /// UTF-16.
    oem_names: bool,
    /// Leaves Unicode out of the plain NEGOTIATE reply's Flags2 even when
    /// the names are UTF-16.
    no_unicode_flag: bool,
    /// The names in the NTLM challenge.
    names: Vec<(u16, &'static str)>,
    /// The newest SMB2 dialect it speaks (0: none).
    smb2_top: u16,
}

impl Default for SmbLab {
    fn default() -> Self {
        SmbLab {
            smb1: true,
            mode: 0x03,
            unicode: false,
            domain: "LAB",
            oem_names: false,
            no_unicode_flag: false,
            names: vec![
                (2, "LAB"),
                (1, "SRV01"),
                (4, "lab.local"),
                (3, "srv01.lab.local"),
                (5, "lab.local"),
            ],
            smb2_top: 0x0311,
        }
    }
}

/// The SMB clock of [`smb1_server`]: 2026-01-02T03:04:05Z.
const SMB_NOW: i64 = 1_767_323_045;

/// An SMB1 reply to `req` (its command and MID echoed).
fn smb1_reply(req: &[u8], status: u32, flags2: u16, words: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = b"\xffSMB".to_vec();
    m.push(req[4]);
    m.extend(status.to_le_bytes());
    m.push(0x98);
    m.extend(flags2.to_le_bytes());
    m.extend([0u8; 12]);
    m.extend(&req[24..32]);
    m.push((words.len() / 2) as u8);
    m.extend(words);
    m.extend((data.len() as u16).to_le_bytes());
    m.extend(data);
    m
}

/// The answer of `lab` to one SMB message, or `None` to hang up.
fn smb_lab_answer(lab: &SmbLab, req: &[u8], seen: &Seen) -> Option<Vec<u8>> {
    let filetime = |t: i64| ((t + 11_644_473_600) * 10_000_000).to_le_bytes();
    if req.starts_with(b"\xffSMB") && req.len() >= 35 {
        seen.lock()
            .unwrap()
            .push(format!("smb1 {:02x} {}", req[4], hexs(req)));
        if !lab.smb1 {
            return None;
        }
        let flags2 = u16::from_le_bytes([req[10], req[11]]);
        let extended = flags2 & 0x0800 != 0;
        let wc = req[32] as usize;
        let data = &req[35 + 2 * wc..];
        if req[4] == 0x72 {
            let mut w = vec![0u8, 0, lab.mode, 50, 0, 1, 0];
            w.extend(16644u32.to_le_bytes());
            w.extend(65536u32.to_le_bytes());
            w.extend(0x1234u32.to_le_bytes());
            let caps: u32 = 0xe3fd | if extended { 0x8000_0000 } else { 0 };
            w.extend(caps.to_le_bytes());
            w.extend(filetime(SMB_NOW));
            w.extend((-60i16).to_le_bytes()); // UTC+1
            w.push(if extended { 0 } else { 8 });
            let mut d = Vec::new();
            if extended {
                d.extend(*b"server-guid-0123");
                d.extend(b"\x60\x06spnego");
            } else {
                d.extend(*b"chalenge");
                for n in [lab.domain, "SRV01"] {
                    if lab.oem_names {
                        d.extend(n.as_bytes());
                        d.push(0);
                    } else {
                        d.extend(u16le(n));
                        d.extend([0, 0]);
                    }
                }
            }
            let unicode = if lab.oem_names || lab.no_unicode_flag {
                0
            } else {
                0x8000
            };
            return Some(smb1_reply(
                req,
                0,
                0x4001 | unicode | (flags2 & 0x0800),
                &w,
                &d,
            ));
        }
        if req[4] == 0x73 {
            let blob = ntlm_challenge_naming(SMB_NOW, &lab.names);
            let mut b = b"\xa1\x81\x00wrapped".to_vec();
            b.extend(&blob);
            let mut w = vec![0xff, 0, 0, 0, 0, 0];
            w.extend((b.len() as u16).to_le_bytes());
            let mut d = b.clone();
            let strings = [
                "Windows Server 2003 3790 Service Pack 2",
                "Windows Server 2003 5.2",
                "LAB",
            ];
            if lab.unicode {
                // Unicode strings start on an even offset from the header.
                if (32 + 1 + w.len() + 2 + d.len()) % 2 == 1 {
                    d.push(0);
                }
                for t in strings {
                    d.extend(u16le(t));
                    d.extend([0, 0]);
                }
            } else {
                for t in strings {
                    d.extend(t.as_bytes());
                    d.push(0);
                }
            }
            let _ = data;
            let f2 = 0x4801 | if lab.unicode { 0x8000 } else { 0 };
            return Some(smb1_reply(req, 0xc000_0016, f2, &w, &d));
        }
        return None;
    }
    if req.starts_with(b"\xfeSMB") && req.len() >= 100 {
        let count = u16::from_le_bytes([req[66], req[67]]) as usize;
        let offered: Vec<u16> = (0..count)
            .map(|i| u16::from_le_bytes([req[100 + 2 * i], req[101 + 2 * i]]))
            .collect();
        let caps = u32::from_le_bytes([req[72], req[73], req[74], req[75]]);
        seen.lock()
            .unwrap()
            .push(format!("smb2 {offered:04x?} caps {caps:x}"));
        let d = offered
            .iter()
            .copied()
            .filter(|&d| d <= lab.smb2_top)
            .max()?;
        let mut m = b"\xfeSMB".to_vec();
        m.extend(64u16.to_le_bytes());
        m.extend([0u8; 58]);
        m.extend(65u16.to_le_bytes());
        m.extend(1u16.to_le_bytes());
        m.extend(d.to_le_bytes());
        m.extend(0u16.to_le_bytes());
        m.extend(*b"server-guid-0123");
        // Capabilities: DFS from 2.0.2, leasing and multi-credit from 2.1,
        // none at all for 3.0.2 (to show "All capabilities are disabled").
        let caps: u32 = match d {
            0x0202 => 0x01,
            0x0302 => 0,
            _ => 0x07,
        };
        m.extend(caps.to_le_bytes());
        m.extend([0u8; 12]);
        m.extend(filetime(SMB_NOW));
        m.extend([0u8; 8]);
        m.extend([0u8; 9]);
        return Some(m);
    }
    None
}

/// A stand-in SMB server behaving as `lab` (NetBIOS session requests
/// accepted), keeping a line for each request.
async fn smb1_server(lab: SmbLab) -> (u16, Seen) {
    let seen: Seen = Default::default();
    let keep = seen.clone();
    let port = tcp_server(move |mut s| {
        let keep = keep.clone();
        let lab = lab.clone();
        async move {
            loop {
                let mut head = [0u8; 4];
                if s.read_exact(&mut head).await.is_err() {
                    return;
                }
                let len = u32::from_be_bytes([0, head[1], head[2], head[3]]) as usize;
                let mut req = vec![0u8; len];
                if s.read_exact(&mut req).await.is_err() {
                    return;
                }
                if head[0] == 0x81 {
                    keep.lock().unwrap().push("netbios session".into());
                    let _ = s.write_all(&[0x82, 0, 0, 0]).await;
                    continue;
                }
                let Some(reply) = smb_lab_answer(&lab, &req, &keep) else {
                    return;
                };
                let mut out = (reply.len() as u32).to_be_bytes().to_vec();
                out.extend(reply);
                if s.write_all(&out).await.is_err() {
                    return;
                }
            }
        }
    })
    .await;
    (port, seen)
}

/// Every output of built-in `id` against `lab`, on a port known as
/// `service`.
async fn smb_lab_output(id: &str, lab: SmbLab, service: &str) -> (Vec<String>, Seen) {
    let (port, seen) = smb1_server(lab).await;
    let out = host_output_of(id, port, service, &format!("smbport={port}")).await;
    (out, seen)
}

#[tokio::test]
async fn smb_os_discovery_reads_a_domain_member() {
    let (out, seen) = smb_lab_output("smb-os-discovery", SmbLab::default(), "microsoft-ds").await;
    assert_eq!(
        out,
        [
            "\n  OS: Windows Server 2003 3790 Service Pack 2 (Windows Server 2003 5.2)\
          \n  OS CPE: cpe:/o:microsoft:windows_server_2003::sp2\
          \n  Computer name: srv01\
          \n  NetBIOS computer name: SRV01\
          \n  Domain name: lab.local\
          \n  Forest name: lab.local\
          \n  FQDN: srv01.lab.local\
          \n  NetBIOS domain name: LAB\
          \n  System time: 2026-01-02T04:04:05+01:00"
        ]
    );
    let seen = seen.lock().unwrap().clone();
    // A plain NEGOTIATE, then one with extended security and the session
    // setup on a second connection.
    assert_eq!(seen.len(), 3, "{seen:?}");
    // The plain NEGOTIATE, byte for byte (IDS rule 9100018): FeroProbe's
    // process ID "FP", NT LM 0.12 only.
    assert_eq!(
        seen[0],
        "smb1 72 ff534d4272000000001801400000000000000000000000000000465000000100\
         000c00024e54204c4d20302e313200"
    );
    assert!(seen[1].starts_with("smb1 72 ff534d4272000000001801480000"));
    // The session setup: SPNEGO around FeroProbe's NTLM NEGOTIATE (rule
    // 9100017), NativeOS and NativeLanMan "FeroProbe".
    let neg = hexs(
        b"NTLMSSP\x00\x01\x00\x00\x00\x07\xa2\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\
          \x09\x00\x09\x00\x28\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0fFEROPROBE",
    );
    assert!(seen[2].starts_with("smb1 73 "));
    assert!(seen[2].contains(&format!("{neg}{}", hexs(b"FeroProbe\0FeroProbe\0"))));
    assert!(seen[2].contains("2b0601050502")); // the SPNEGO OID
}

#[tokio::test]
async fn smb_os_discovery_reads_a_workgroup_host_in_unicode() {
    let lab = SmbLab {
        unicode: true,
        domain: "WORKGROUP",
        names: vec![(2, "SRV01"), (1, "SRV01"), (4, "srv01"), (3, "srv01")],
        ..SmbLab::default()
    };
    let (out, _) = smb_lab_output("smb-os-discovery", lab, "netbios-ssn").await;
    assert_eq!(
        out,
        [
            "\n  OS: Windows Server 2003 3790 Service Pack 2 (Windows Server 2003 5.2)\
          \n  OS CPE: cpe:/o:microsoft:windows_server_2003::sp2\
          \n  Computer name: srv01\
          \n  NetBIOS computer name: SRV01\
          \n  Workgroup: WORKGROUP\
          \n  System time: 2026-01-02T04:04:05+01:00"
        ]
    );
}

#[tokio::test]
async fn smb_os_discovery_reads_oem_negotiate_names() {
    let lab = SmbLab {
        domain: "WORKGROUP",
        oem_names: true,
        names: vec![(2, "SRV01"), (1, "SRV01"), (4, "srv01"), (3, "srv01")],
        ..SmbLab::default()
    };
    let (out, _) = smb_lab_output("smb-os-discovery", lab, "microsoft-ds").await;
    assert_eq!(out.len(), 1);
    assert!(out[0].contains("\n  Workgroup: WORKGROUP\n"), "{out:?}");
}

#[tokio::test]
async fn smb_os_discovery_picks_the_negotiate_name_encoding() {
    // UTF-16 names without the Flags2 Unicode bit, the first character
    // outside Latin-1 (its high byte is not zero).
    let lab = SmbLab {
        domain: "ДОМ",
        no_unicode_flag: true,
        names: vec![(2, "SRV01"), (1, "SRV01"), (4, "srv01"), (3, "srv01")],
        ..SmbLab::default()
    };
    let (out, _) = smb_lab_output("smb-os-discovery", lab, "microsoft-ds").await;
    assert!(out[0].contains("\n  Workgroup: ДОМ\n"), "{out:?}");
    // A one-letter OEM name: its terminator makes a UTF-16 character.
    let lab = SmbLab {
        domain: "A",
        oem_names: true,
        names: vec![(2, "SRV01"), (1, "SRV01"), (4, "srv01"), (3, "srv01")],
        ..SmbLab::default()
    };
    let (out, _) = smb_lab_output("smb-os-discovery", lab, "microsoft-ds").await;
    assert!(out[0].contains("\n  Workgroup: A\n"), "{out:?}");
}

#[tokio::test]
async fn smb1_scripts_stay_quiet_without_smb1() {
    let lab = SmbLab {
        smb1: false,
        ..SmbLab::default()
    };
    for id in ["smb-os-discovery", "smb-security-mode"] {
        let (out, seen) = smb_lab_output(id, lab.clone(), "microsoft-ds").await;
        assert!(out.is_empty(), "{id}: {out:?}");
        assert!(!seen.lock().unwrap().is_empty());
    }
    let (out, _) = smb_lab_output("smb-protocols", lab, "microsoft-ds").await;
    assert_eq!(
        out,
        ["\n  dialects: \n    2:0:2\n    2:1:0\n    3:0:0\n    3:0:2\n    3:1:1"]
    );
}

#[tokio::test]
async fn smb_security_mode_reads_the_negotiate() {
    let (out, seen) = smb_lab_output("smb-security-mode", SmbLab::default(), "microsoft-ds").await;
    assert_eq!(
        out,
        [
            "\n  authentication_level: user\n  challenge_response: supported\
          \n  message_signing: disabled (dangerous, but default)"
        ]
    );
    // One NEGOTIATE, with extended security, and no login.
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].starts_with("smb1 72 ff534d4272000000001801480000"));

    let lab = SmbLab {
        mode: 0x0d, // user level, plaintext only, signing required
        ..SmbLab::default()
    };
    let (out, _) = smb_lab_output("smb-security-mode", lab, "microsoft-ds").await;
    assert_eq!(
        out,
        [
            "\n  authentication_level: user\n  challenge_response: plaintext-only (dangerous)\
          \n  message_signing: required"
        ]
    );
    let lab = SmbLab {
        mode: 0x06, // share level, signing supported
        ..SmbLab::default()
    };
    let (out, _) = smb_lab_output("smb-security-mode", lab, "microsoft-ds").await;
    assert_eq!(
        out,
        [
            "\n  authentication_level: share (dangerous)\n  challenge_response: supported\
          \n  message_signing: supported"
        ]
    );
}

#[tokio::test]
async fn smb_protocols_lists_every_dialect() {
    let lab = SmbLab {
        smb2_top: 0x0300,
        ..SmbLab::default()
    };
    let (out, seen) = smb_lab_output("smb-protocols", lab, "microsoft-ds").await;
    assert_eq!(
        out,
        [
            "\n  dialects: \n    NT LM 0.12 (SMBv1) [dangerous, but default]\n    2:0:2\n    2:1:0\n    3:0:0"
        ]
    );
    let smb2: Vec<String> = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|l| l.starts_with("smb2"))
        .cloned()
        .collect();
    // All together, then each older one alone.
    assert_eq!(
        smb2,
        [
            // SMB3 client capabilities only when an SMB3 dialect is offered.
            "smb2 [0202, 0210, 0300, 0302, 0311] caps 7f",
            "smb2 [0202] caps 0",
            "smb2 [0210] caps 0"
        ]
    );
    // Nothing accepted: no output.
    let lab = SmbLab {
        smb1: false,
        smb2_top: 0,
        ..SmbLab::default()
    };
    let (out, _) = smb_lab_output("smb-protocols", lab, "microsoft-ds").await;
    assert!(out.is_empty());
}

#[tokio::test]
async fn smb2_capabilities_per_dialect() {
    let (out, _) = smb_lab_output("smb2-capabilities", SmbLab::default(), "microsoft-ds").await;
    assert_eq!(
        out,
        ["\n  2:0:2: \n    Distributed File System\
          \n  2:1:0: \n    Distributed File System\n    Leasing\n    Multi-credit operations\
          \n  3:0:0: \n    Distributed File System\n    Leasing\n    Multi-credit operations\
          \n  3:0:2: \n    All capabilities are disabled\
          \n  3:1:1: \n    Distributed File System\n    Leasing\n    Multi-credit operations"]
    );
    let lab = SmbLab {
        smb2_top: 0,
        ..SmbLab::default()
    };
    let (out, _) = smb_lab_output("smb2-capabilities", lab, "microsoft-ds").await;
    assert!(out.is_empty());
}

/// Bytes as lower-case hex.
fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---- The TLS scripts (fero.tls), against a stand-in TLS server ----

/// What the stand-in TLS server takes: per version, its suites (in its
/// order of preference when `server_pref`), plus ALPN and NPN protocols.
#[derive(Clone, Default)]
struct TlsLab {
    /// (version, suites, server_pref), for each version it speaks.
    versions: Vec<(u16, Vec<u16>, bool)>,
    alpn: Vec<&'static str>,
    npn: Vec<&'static str>,
}

type Hellos = std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>;

fn tls_record(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut r = vec![kind, 3, 3];
    r.extend((body.len() as u16).to_be_bytes());
    r.extend(body);
    r
}

fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut h = vec![kind];
    h.extend(&(body.len() as u32).to_be_bytes()[1..]);
    h.extend(body);
    h
}

/// A ClientHello's legacy version, suites, and extensions (type, data).
type ClientHello = (u16, Vec<u16>, Vec<(u16, Vec<u8>)>);

/// The parts of a ClientHello the stand-in needs.
fn parse_client_hello(rec: &[u8]) -> Option<ClientHello> {
    let b = rec.get(5..)?;
    if *b.first()? != 1 {
        return None;
    }
    let b = &b[4..];
    let version = u16::from_be_bytes([b[0], b[1]]);
    let mut p = 34;
    p += 1 + b[p] as usize;
    let n = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
    let suites = b[p + 2..p + 2 + n]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    p += 2 + n;
    p += 1 + b[p] as usize;
    let mut exts = Vec::new();
    if p + 2 <= b.len() {
        let end = p + 2 + u16::from_be_bytes([b[p], b[p + 1]]) as usize;
        p += 2;
        while p + 4 <= end {
            let kind = u16::from_be_bytes([b[p], b[p + 1]]);
            let len = u16::from_be_bytes([b[p + 2], b[p + 3]]) as usize;
            exts.push((kind, b[p + 4..p + 4 + len].to_vec()));
            p += 4 + len;
        }
    }
    Some((version, suites, exts))
}

/// The stand-in server's answer to one ClientHello record.
fn tls_lab_answer(lab: &TlsLab, hello: &[u8], cert: &[u8]) -> Vec<u8> {
    let alert = |code: u8| tls_record(21, &[2, code]);
    let Some((legacy, offered, exts)) = parse_client_hello(hello) else {
        return alert(10);
    };
    let ext = |k: u16| exts.iter().find(|(t, _)| *t == k).map(|(_, d)| d.clone());
    let version = match ext(0x002b) {
        Some(d) => u16::from_be_bytes([d[1], d[2]]),
        None => legacy,
    };
    let Some((_, suites, server_pref)) = lab.versions.iter().find(|(v, _, _)| *v == version) else {
        return alert(70);
    };
    let pick = if *server_pref {
        suites.iter().find(|s| offered.contains(s)).copied()
    } else {
        offered.iter().find(|s| suites.contains(s)).copied()
    };
    let Some(cipher) = pick else {
        return alert(40);
    };
    let mut sh_exts = Vec::new();
    let mut add = |kind: u16, data: Vec<u8>| {
        sh_exts.extend(kind.to_be_bytes());
        sh_exts.extend((data.len() as u16).to_be_bytes());
        sh_exts.extend(data);
    };
    if version >= 0x0304 {
        add(0x002b, 0x0304u16.to_be_bytes().to_vec());
        let mut ks = vec![0, 29, 0, 32];
        ks.extend([9u8; 32]);
        add(0x0033, ks);
    }
    if let Some(d) = ext(0x0010) {
        // The client's list, then the first of ours that is in it.
        let mut names = Vec::new();
        let mut p = 2;
        while p < d.len() {
            let n = d[p] as usize;
            names.push(String::from_utf8_lossy(&d[p + 1..p + 1 + n]).to_string());
            p += 1 + n;
        }
        if let Some(name) = lab.alpn.iter().find(|a| names.iter().any(|n| n == *a)) {
            let mut list = vec![name.len() as u8];
            list.extend(name.as_bytes());
            let mut data = (list.len() as u16).to_be_bytes().to_vec();
            data.extend(list);
            add(0x0010, data);
        }
    }
    if ext(0x3374).is_some() && !lab.npn.is_empty() {
        let mut data = Vec::new();
        for n in &lab.npn {
            data.push(n.len() as u8);
            data.extend(n.as_bytes());
        }
        add(0x3374, data);
    }
    let mut sh = std::cmp::min(version, 0x0303).to_be_bytes().to_vec();
    sh.extend([7u8; 32]);
    sh.push(0);
    sh.extend(cipher.to_be_bytes());
    sh.push(0);
    sh.extend((sh_exts.len() as u16).to_be_bytes());
    sh.extend(sh_exts);
    let mut flight = handshake(2, &sh);
    if version < 0x0304 {
        let mut certs = (cert.len() as u32).to_be_bytes()[1..].to_vec();
        certs.extend(cert);
        let mut msg = ((certs.len()) as u32).to_be_bytes()[1..].to_vec();
        msg.extend(certs);
        flight.extend(handshake(11, &msg));
        let ske = match cipher {
            // ECDHE: secp256r1, an uncompressed point (no signature check).
            0xc02c | 0xc009 | 0xc008 => {
                let mut s = vec![3, 0, 23, 65, 4];
                s.extend([5u8; 64]);
                s.extend([4, 3, 0, 2, 0, 0]);
                Some(s)
            }
            // DH_anon: a 1024-bit prime, g = 2, Ys.
            0x0034 => {
                let mut s = vec![0, 128, 0xff];
                s.extend([0xabu8; 127]);
                s.extend([0, 1, 2, 0, 1, 5]);
                Some(s)
            }
            _ => None,
        };
        if let Some(s) = ske {
            flight.extend(handshake(12, &s));
        }
        flight.extend(handshake(14, &[]));
    }
    // Split over two records, as servers may.
    let cut = flight.len() / 2;
    let mut out = tls_record(22, &flight[..cut]);
    out.extend(tls_record(22, &flight[cut..]));
    out
}

/// A stand-in TLS server following `lab`, keeping each ClientHello.
async fn tls_lab(lab: TlsLab) -> (u16, Hellos) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap()
        .der()
        .to_vec();
    let seen: Hellos = Default::default();
    let keep = seen.clone();
    let port = tcp_server(move |mut s| {
        let (lab, keep, cert) = (lab.clone(), keep.clone(), cert.clone());
        async move {
            let mut head = [0u8; 5];
            if s.read_exact(&mut head).await.is_err() {
                return;
            }
            let mut rec = head.to_vec();
            if head[0] & 0x80 != 0 {
                // An SSLv2 CLIENT-HELLO: this stand-in speaks no SSLv2.
                keep.lock().unwrap().push(rec);
                return;
            }
            let mut body = vec![0u8; u16::from_be_bytes([head[3], head[4]]) as usize];
            if s.read_exact(&mut body).await.is_err() {
                return;
            }
            rec.extend(body);
            keep.lock().unwrap().push(rec.clone());
            let _ = s.write_all(&tls_lab_answer(&lab, &rec, &cert)).await;
            let mut rest = [0u8; 64];
            let _ = s.read(&mut rest).await;
        }
    })
    .await;
    (port, seen)
}

#[tokio::test]
async fn ssl_enum_ciphers_lists_suites_grades_and_preference() {
    let lab = TlsLab {
        versions: vec![
            // TLS 1.2 by the server's order: ECDHE AES-256-GCM, ECDHE
            // AES-128-CBC, ECDHE 3DES, anonymous DH.
            (0x0303, vec![0xc02c, 0xc009, 0xc008, 0x0034], true),
            // TLS 1.3 by the client's order.
            (0x0304, vec![0x1302, 0x1301], false),
        ],
        ..TlsLab::default()
    };
    let (port, seen) = tls_lab(lab).await;
    let out = output_of("ssl-enum-ciphers", port, "https").await.unwrap();
    assert_eq!(
        out,
        "\n  TLSv1.2: \
         \n    ciphers: \
         \n      TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A\
         \n      TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (secp256r1) - A\
         \n      TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA (secp256r1) - C\
         \n      TLS_DH_anon_WITH_AES_128_CBC_SHA (dh 1024) - F\
         \n    compressors: \
         \n      NULL\
         \n    cipher preference: server\
         \n    warnings: \
         \n      64-bit block cipher 3DES vulnerable to SWEET32 attack\
         \n      Anonymous key exchange, score capped at F\
         \n  TLSv1.3: \
         \n    ciphers: \
         \n      TLS_AKE_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A\
         \n      TLS_AKE_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A\
         \n    cipher preference: client\
         \n  least strength: F"
    );
    let seen = seen.lock().unwrap();
    for hello in seen.iter() {
        // Every hello carries the mark after the time bytes, and the
        // target's name as SNI (no extensions in an SSLv3 hello).
        assert_eq!(hello[0], 22);
        assert_eq!(&hello[15..31], b"FeroProbeTLSScan");
        if hello[2] != 0 {
            assert!(hello.windows(9).any(|w| w == b"localhost"));
        }
    }
    // SSLv3 and TLS 1.0 and 1.1 are asked once each, then given up.
    for v in [0x0300u16, 0x0301, 0x0302] {
        let n = seen
            .iter()
            .filter(|h| {
                parse_client_hello(h)
                    .is_some_and(|(l, _, e)| l == v && e.iter().all(|(t, _)| *t != 0x002b))
            })
            .count();
        assert_eq!(n, 1, "version {v:#06x}");
    }
}

#[tokio::test]
async fn ssl_enum_ciphers_with_one_suite() {
    let lab = TlsLab {
        versions: vec![(0x0303, vec![0xc02c], false)],
        ..TlsLab::default()
    };
    let (port, _) = tls_lab(lab).await;
    let out = output_of("ssl-enum-ciphers", port, "https").await.unwrap();
    assert_eq!(
        out,
        "\n  TLSv1.2: \
         \n    ciphers: \
         \n      TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A\
         \n    compressors: \
         \n      NULL\
         \n    cipher preference: indeterminate\
         \n    cipher preference error: Too few ciphers supported\
         \n  least strength: A"
    );
    // ssl-enum-ciphers is not a default script, as in nmap.
    let s = built_in("ssl-enum-ciphers");
    assert_eq!(s.categories, ["discovery", "intrusive"]);
}

#[tokio::test]
async fn tls_alpn_and_nextprotoneg() {
    let lab = TlsLab {
        versions: vec![(0x0303, vec![0xc02c], true)],
        alpn: vec!["h2", "http/1.1"],
        npn: vec!["spdy/3", "http/1.1"],
    };
    let (port, seen) = tls_lab(lab).await;
    assert_eq!(
        output_of("tls-alpn", port, "https").await.as_deref(),
        Some("\n  h2\n  http/1.1")
    );
    // One hello per protocol found, and one the server takes none from.
    assert_eq!(seen.lock().unwrap().len(), 3);
    assert_eq!(
        output_of("tls-nextprotoneg", port, "https")
            .await
            .as_deref(),
        Some("\n  spdy/3\n  http/1.1")
    );
    // A server without ALPN or NPN: no output.
    let lab = TlsLab {
        versions: vec![(0x0303, vec![0xc02c], true)],
        ..TlsLab::default()
    };
    let (port, _) = tls_lab(lab).await;
    assert_eq!(output_of("tls-alpn", port, "https").await, None);
    assert_eq!(output_of("tls-nextprotoneg", port, "https").await, None);
    // A TLS stand-in sends no SSLv2 SERVER-HELLO.
    assert_eq!(output_of("sslv2", port, "https").await, None);
}

#[tokio::test]
async fn sslv2_lists_the_server_ciphers() {
    let seen: Hellos = Default::default();
    let keep = seen.clone();
    let port = tcp_server(move |mut s| {
        let keep = keep.clone();
        async move {
            let mut head = [0u8; 2];
            if s.read_exact(&mut head).await.is_err() {
                return;
            }
            let mut body = vec![0u8; (u16::from_be_bytes(head) & 0x7fff) as usize];
            if s.read_exact(&mut body).await.is_err() {
                return;
            }
            keep.lock().unwrap().push(body);
            // SERVER-HELLO: no session hit, X.509, version 2, a 3-byte
            // "certificate", two cipher kinds, a 16-byte connection ID.
            let mut m = vec![4, 0, 1, 0, 2, 0, 3, 0, 6, 0, 16];
            m.extend(b"crt");
            m.extend([0x01, 0x00, 0x80, 0x07, 0x00, 0xc0]);
            m.extend([1u8; 16]);
            let mut out = (0x8000u16 | m.len() as u16).to_be_bytes().to_vec();
            out.extend(m);
            let _ = s.write_all(&out).await;
        }
    })
    .await;
    assert_eq!(
        output_of("sslv2", port, "https").await.as_deref(),
        Some(
            "\n  SSLv2 supported\n  ciphers: \
             \n    SSL2_RC4_128_WITH_MD5\n    SSL2_DES_192_EDE3_CBC_WITH_MD5"
        )
    );
    let seen = seen.lock().unwrap();
    // CLIENT-HELLO, version 2, eight cipher kinds, no session, and the mark
    // as the challenge.
    assert_eq!(&seen[0][..9], &[1, 0, 2, 0, 24, 0, 0, 0, 16]);
    assert!(seen[0].ends_with(b"FeroProbeTLSScan"));
}

#[tokio::test]
async fn sslv2_reads_padded_records() {
    // A three-byte record header: the third byte counts padding at the end,
    // which never stands in for a missing connection ID.
    async fn answer(with_id: bool) -> Option<String> {
        let port = tcp_server(move |mut s| async move {
            let mut head = [0u8; 2];
            if s.read_exact(&mut head).await.is_err() {
                return;
            }
            let mut body = vec![0u8; (u16::from_be_bytes(head) & 0x7fff) as usize];
            if s.read_exact(&mut body).await.is_err() {
                return;
            }
            let mut m = vec![4, 0, 1, 0, 2, 0, 0, 0, 3, 0, 16];
            m.extend([0x01, 0x00, 0x80]);
            if with_id {
                m.extend([1u8; 16]);
            }
            m.extend([0u8; 16]);
            let mut out = (m.len() as u16).to_be_bytes().to_vec();
            out.push(16);
            out.extend(m);
            let _ = s.write_all(&out).await;
        })
        .await;
        output_of("sslv2", port, "https").await
    }
    assert_eq!(
        answer(true).await.as_deref(),
        Some("\n  SSLv2 supported\n  ciphers: \n    SSL2_RC4_128_WITH_MD5")
    );
    assert_eq!(answer(false).await, None);
}

#[tokio::test]
async fn tls_library_reads_suite_names() {
    let probe = script(
        "probe",
        r#"
description = "test"
categories = {"safe"}
portrule = function() return true end
action = function()
  local t = fero.tls
  local i = t.cipher_info("TLS_RSA_WITH_3DES_EDE_CBC_SHA")
  local j = t.cipher_info("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
  local k = t.cipher_info("TLS_DH_anon_EXPORT_WITH_RC4_40_MD5")
  local hello = t.client_hello({ version = 0x0300, ciphers = { 0x002f } })
  return table.concat({
    i.cipher, i.size, i.block, i.mode, i.hash, tostring(i.forward_secrecy),
    j.cipher, j.size, j.mode, j.hash, tostring(j.forward_secrecy), tostring(j.tls12),
    k.cipher, k.size, tostring(k.export), tostring(k.anon),
    t.cipher_name(0x1301), t.cipher_code("TLS_RSA_WITH_AES_128_CBC_SHA"),
    t.group_name(23), t.group_strength("secp384r1"),
    -- An SSLv3 hello: record version 3.0 and no extensions.
    string.format("%02x%02x", hello:byte(2, 3)), #hello,
  }, " ")
end
"#,
    );
    let port = greeter(b"").await;
    let scan = ScriptScan::new(vec![probe], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with(&[(port, PortState::Open)])];
    scan.scan_hosts(&mut hosts).await;
    assert_eq!(
        hosts[0].ports[0].scripts[0].output,
        "3DES 112 64 CBC SHA false AES 256 GCM SHA384 true true RC4 40 true true \
         TLS_AKE_WITH_AES_128_GCM_SHA256 47 secp256r1 7680 0300 50"
    );
}

#[tokio::test]
async fn tls_library_checks_server_hello_extensions() {
    let probe = script(
        "probe",
        r#"
description = "test"
categories = {"safe"}
portrule = function() return true end
action = function()
  local t = fero.tls
  local function sh(exts)
    local e = ""
    for _, x in ipairs(exts) do e = e .. string.pack(">I2s2", x[1], x[2]) end
    return t.parse_server_hello(string.pack(">I2", 0x0303) .. string.rep("\7", 32)
      .. "\0" .. string.pack(">I2B", 0xc02f, 0) .. string.pack(">s2", e))
  end
  local one = sh({ { 0x0010, string.pack(">s2", string.pack(">s1", "h2")) } })
  local two = sh({ { 0x0010, string.pack(">s2", string.pack(">s1", "h2") .. string.pack(">s1", "http/1.1")) } })
  local npn = sh({ { 0x3374, string.pack(">s1", "spdy/3") .. string.pack(">s1", "http/1.1") } })
  local cut = sh({ { 0x3374, string.pack(">s1", "spdy/3") .. "\9ab" } })
  -- A TLS 1.3 hello offering only secp256r1 sends an empty key share.
  local h = t.client_hello({ version = 0x0304, groups = { 23 } })
  local ks = h:find("\0\51\0\2\0\0", 1, true) ~= nil
  return table.concat({
    tostring(one.alpn), tostring(two.alpn), table.concat(npn.npn, ","), tostring(cut.npn),
    t.cipher_info("TLS_PSK_DHE_WITH_AES_128_CCM_8").kex,
    tostring(t.cipher_info("TLS_PSK_WITH_AES_128_CBC_SHA256").tls12),
    tostring(ks),
  }, " ")
end
"#,
    );
    let port = greeter(b"").await;
    let scan = ScriptScan::new(vec![probe], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with(&[(port, PortState::Open)])];
    scan.scan_hosts(&mut hosts).await;
    assert_eq!(
        hosts[0].ports[0].scripts[0].output,
        "h2 nil spdy/3,http/1.1 nil DHE_PSK false true"
    );
}

/// BER for the stand-in SNMP agent: a TLV with a short or long length.
fn ber(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 0x80 {
        out.push(value.len() as u8);
    } else {
        let len = (value.len() as u32).to_be_bytes();
        let skip = len.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (4 - skip) as u8);
        out.extend(&len[skip..]);
    }
    out.extend(value);
    out
}

fn ber_uint(tag: u8, v: u64) -> Vec<u8> {
    let b = v.to_be_bytes();
    let mut skip = b.iter().take_while(|&&x| x == 0).count().min(7);
    let mut c = b[skip..].to_vec();
    if c[0] >= 0x80 {
        skip = 0;
        c.insert(skip, 0);
    }
    ber(tag, &c)
}

fn ber_oid(arcs: &[u32]) -> Vec<u8> {
    let mut c = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &a in &arcs[2..] {
        let mut b = vec![(a & 0x7f) as u8];
        let mut n = a >> 7;
        while n > 0 {
            b.insert(0, 0x80 | (n & 0x7f) as u8);
            n >>= 7;
        }
        c.extend(b);
    }
    ber(0x06, &c)
}

/// The elements of BER contents: (tag, contents) pairs.
fn ber_items(mut s: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    while s.len() >= 2 {
        let tag = s[0];
        let (len, head) = if s[1] < 0x80 {
            (s[1] as usize, 2)
        } else {
            let n = (s[1] & 0x7f) as usize;
            let mut l = 0usize;
            for &b in &s[2..2 + n] {
                l = (l << 8) | b as usize;
            }
            (l, 2 + n)
        };
        out.push((tag, s[head..head + len].to_vec()));
        s = &s[head + len..];
    }
    out
}

fn ber_int(c: &[u8]) -> i64 {
    let mut v: i64 = if c[0] >= 0x80 { -1 } else { 0 };
    for &b in c {
        v = (v << 8) | b as i64;
    }
    v
}

fn oid_arcs(c: &[u8]) -> Vec<u32> {
    let mut out = vec![u32::from(c[0] / 40), u32::from(c[0] % 40)];
    let mut n = 0u32;
    for &b in &c[1..] {
        n = (n << 7) | u32::from(b & 0x7f);
        if b < 0x80 {
            out.push(n);
            n = 0;
        }
    }
    out
}

fn arcs_of(s: &str) -> Vec<u32> {
    s.split('.').map(|a| a.parse().unwrap()).collect()
}

/// A stand-in SNMP agent on 127.0.0.1: community "public", SNMPv1/v2c
/// Get and GetNext over a small MIB (system group, ifTable with two
/// interfaces, one down, and ipAddrTable), and an SNMPv3 Report to the
/// engine discovery request. Keeps every request. With `late` it first
/// sends a stale answer (wrong request-id) before each real one.
async fn snmp_agent(late: bool) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
    use std::collections::BTreeMap;
    let mut mib: BTreeMap<Vec<u32>, Vec<u8>> = BTreeMap::new();
    let mut put = |oid: &str, v: Vec<u8>| {
        mib.insert(arcs_of(oid), v);
    };
    put(
        "1.3.6.1.2.1.1.1.0",
        ber(0x04, b"Linux lab 6.8.0 #1 SMP x86_64\r\nsecond line"),
    );
    put("1.3.6.1.2.1.1.3.0", ber_uint(0x43, 248_153_900));
    put("1.3.6.1.2.1.1.5.0", ber(0x04, b"lab"));
    for (i, name, ty, speed, mac, status, rx, tx) in [
        (
            1u32,
            &b"lo"[..],
            24u64,
            10_000_000u64,
            &b""[..],
            1u64,
            1_270_000u64,
            1_270_000u64,
        ),
        (
            2,
            b"eth0",
            6,
            1_000_000_000,
            b"\x00\x0c\x29\x01\x02\x03",
            1,
            28_430_000,
            4_200,
        ),
        (
            3,
            b"eth1",
            6,
            100_000_000,
            b"\x00\x0c\x29\x0a\x0b\x0c",
            2,
            0,
            0,
        ),
    ] {
        let p = "1.3.6.1.2.1.2.2.1";
        put(&format!("{p}.1.{i}"), ber_uint(0x02, i.into()));
        put(&format!("{p}.2.{i}"), ber(0x04, name));
        put(&format!("{p}.3.{i}"), ber_uint(0x02, ty));
        put(&format!("{p}.5.{i}"), ber_uint(0x42, speed));
        put(&format!("{p}.6.{i}"), ber(0x04, mac));
        put(&format!("{p}.8.{i}"), ber_uint(0x02, status));
        put(&format!("{p}.10.{i}"), ber_uint(0x41, rx));
        put(&format!("{p}.16.{i}"), ber_uint(0x41, tx));
    }
    for (addr, ifi, mask) in [
        ([127u8, 0, 0, 1], 1u64, [255u8, 0, 0, 0]),
        ([10, 77, 0, 2], 2, [255, 255, 255, 0]),
        ([10, 77, 1, 2], 2, [255, 255, 255, 0]),
    ] {
        let idx = format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
        let p = "1.3.6.1.2.1.4.20.1";
        put(&format!("{p}.1.{idx}"), ber(0x40, &addr));
        put(&format!("{p}.2.{idx}"), ber_uint(0x02, ifi));
        put(&format!("{p}.3.{idx}"), ber(0x40, &mask));
    }
    put("1.3.6.1.2.1.25.1.1.0", ber_uint(0x43, 1));

    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    let seen: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Default::default();
    let keep = seen.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = server.recv_from(&mut buf).await {
            let req = buf[..n].to_vec();
            keep.lock().unwrap().push(req.clone());
            let top = ber_items(&ber_items(&req)[0].1);
            let version = ber_int(&top[0].1);
            let reply = if version == 3 {
                // msgID from msgGlobalData; the Report carries the engine
                // ID (net-snmp, enterprise 8072, MAC format), boots, time.
                let global = ber_items(&top[1].1);
                let msg_id = ber_int(&global[0].1) as u64;
                let mut g = ber_uint(0x02, msg_id);
                g.extend(ber_uint(0x02, 65507));
                g.extend(ber(0x04, b"\x00"));
                g.extend(ber_uint(0x02, 3));
                let engine = b"\x80\x00\x1f\x88\x03\x00\x0c\x29\x01\x02\x03";
                let mut usm = ber(0x04, engine);
                usm.extend(ber_uint(0x02, 6));
                usm.extend(ber_uint(0x02, 31_000_000));
                for _ in 0..3 {
                    usm.extend(ber(0x04, b""));
                }
                let usm = ber(0x30, &usm);
                let mut vb = ber_oid(&arcs_of("1.3.6.1.6.3.15.1.1.4.0"));
                vb.extend(ber_uint(0x41, 1));
                let mut pdu = ber_uint(0x02, 0x4650);
                pdu.extend(ber_uint(0x02, 0));
                pdu.extend(ber_uint(0x02, 0));
                pdu.extend(ber(0x30, &ber(0x30, &vb)));
                let mut scoped = ber(0x04, engine);
                scoped.extend(ber(0x04, b""));
                scoped.extend(ber(0xa8, &pdu));
                let mut m = ber_uint(0x02, 3);
                m.extend(ber(0x30, &g));
                m.extend(ber(0x04, &usm));
                m.extend(ber(0x30, &scoped));
                ber(0x30, &m)
            } else {
                if top[1].1 != b"public" {
                    continue;
                }
                let pdu_tag = top[2].0;
                let p = ber_items(&top[2].1);
                let req_id = ber_int(&p[0].1);
                let binds = ber_items(&p[3].1);
                let mut out_binds = Vec::new();
                let mut error = 0u64;
                for (_, b) in &binds {
                    let name = oid_arcs(&ber_items(b)[0].1);
                    let found = if pdu_tag == 0xa0 {
                        mib.get(&name).map(|v| (name.clone(), v.clone()))
                    } else {
                        mib.range((
                            std::ops::Bound::Excluded(name.clone()),
                            std::ops::Bound::Unbounded,
                        ))
                        .next()
                        .map(|(k, v)| (k.clone(), v.clone()))
                    };
                    let mut vb = Vec::new();
                    match found {
                        Some((k, v)) => {
                            vb.extend(ber_oid(&k));
                            vb.extend(v);
                        }
                        None => {
                            // v1: noSuchName (2); v2c: an exception.
                            vb.extend(ber_oid(&name));
                            if version == 0 {
                                error = 2;
                                vb.extend(ber(0x05, b""));
                            } else if pdu_tag == 0xa0 {
                                vb.extend(ber(0x80, b""));
                            } else {
                                vb.extend(ber(0x82, b""));
                            }
                        }
                    }
                    out_binds.extend(ber(0x30, &vb));
                }
                let build = |id: i64| {
                    let mut pdu = ber_uint(0x02, id as u64);
                    pdu.extend(ber_uint(0x02, error));
                    pdu.extend(ber_uint(0x02, if error > 0 { 1 } else { 0 }));
                    pdu.extend(ber(0x30, &out_binds));
                    let mut m = ber_uint(0x02, version as u64);
                    m.extend(ber(0x04, b"public"));
                    m.extend(ber(0xa2, &pdu));
                    ber(0x30, &m)
                };
                if late {
                    let _ = server.send_to(&build(req_id + 1), from).await;
                }
                build(req_id)
            };
            let _ = server.send_to(&reply, from).await;
        }
    });
    (port, seen)
}

/// Run `id` against the stand-in agent on UDP `port` (named snmp).
async fn run_snmp(id: &str, port: u16, args: &str) -> Vec<String> {
    let scan = ScriptScan::new(vec![built_in(id)], args::parse(args).unwrap(), None).unwrap();
    let mut host = host_with_services(&[(port, "snmp")]);
    host.ports[0].protocol = Protocol::Udp;
    host.ports[0].state = PortState::OpenFiltered;
    let mut hosts = vec![host];
    scan.scan_hosts(&mut hosts).await;
    hosts[0].ports[0]
        .scripts
        .iter()
        .map(|s| s.output.clone())
        .collect()
}

#[tokio::test]
async fn snmp_sysdescr_reads_description_and_uptime() {
    let (port, seen) = snmp_agent(false).await;
    let out = run_snmp("snmp-sysdescr", port, "").await;
    assert_eq!(
        out,
        [
            "Linux lab 6.8.0 #1 SMP x86_64\nsecond line\n  System uptime: 28d17h18m59.00s (248153900 timeticks)"
        ]
    );
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    // v1, community public, GetRequest with request-id 0x4650 ("FP").
    assert_eq!(&seen[0][2..14], b"\x02\x01\x00\x04\x06public\xa0");
    assert!(
        seen[0]
            .windows(10)
            .any(|w| w == b"\x02\x02\x46\x50\x02\x01\x00\x02\x01\x00"),
        "{:02x?}",
        seen[0]
    );
}

#[tokio::test]
async fn snmp_skips_late_answers_and_other_communities() {
    // A stale answer (other request-id) comes before every real one.
    let (port, seen) = snmp_agent(true).await;
    let out = run_snmp("snmp-sysdescr", port, "snmp.version=v2c").await;
    assert_eq!(out.len(), 1, "{out:?}");
    assert!(out[0].starts_with("Linux lab"));
    assert_eq!(seen.lock().unwrap()[0][4], 1, "v2c");
    // The agent ignores community "private": no output, two tries each.
    let (port, seen) = snmp_agent(false).await;
    let out = run_snmp(
        "snmp-sysdescr",
        port,
        "creds.snmp=:private,snmp.timeout=300ms",
    )
    .await;
    assert!(out.is_empty(), "{out:?}");
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert!(seen[0].windows(7).any(|w| w == b"private"));
}

#[tokio::test]
async fn snmp_info_reads_the_engine_id() {
    let (port, seen) = snmp_agent(false).await;
    let out = run_snmp("snmp-info", port, "").await;
    assert_eq!(
        out,
        [
            "\n  enterprise: net-snmp\n  engineIDFormat: mac\n  engineIDData: 00:0c:29:01:02:03\n  snmpEngineBoots: 6\n  snmpEngineTime: 358d19h06m40s"
        ]
    );
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    // SNMPv3, msgID 0x4650, reportable, USM; request-id 0x4650.
    assert_eq!(&seen[0][2..5], b"\x02\x01\x03");
    assert!(seen[0].windows(4).any(|w| w == b"\x02\x02\x46\x50"));
    assert!(
        seen[0]
            .windows(10)
            .any(|w| w == b"\x02\x02\x46\x50\x02\x01\x00\x02\x01\x00")
    );
}

#[tokio::test]
async fn snmp_interfaces_walks_the_tables() {
    // v1, v2c, and v1 with a stale answer before every real one.
    for (version, late) in [("v1", false), ("v2c", false), ("v1", true)] {
        let (port, _) = snmp_agent(late).await;
        let out = run_snmp("snmp-interfaces", port, &format!("snmp.version={version}")).await;
        assert_eq!(out.len(), 1, "{out:?}");
        let text = &out[0];
        assert!(
            text.starts_with(
                "\n  lo\n    IP address: 127.0.0.1  Netmask: 255.0.0.0\n    Type: softwareLoopback  Speed: 10 Mbps\n    Traffic stats: 1.27 Mb sent, 1.27 Mb received\n  eth0\n    IP address: 10.77.0.2  Netmask: 255.255.255.0\n    IP address: 10.77.1.2  Netmask: 255.255.255.0\n    MAC address: 00:0c:29:01:02:03 ("
            ),
            "{text}"
        );
        assert!(
            text.ends_with(
                ")\n    Type: ethernetCsmacd  Speed: 1 Gbps\n    Traffic stats: 4.20 Kb sent, 28.43 Mb received"
            ),
            "{text}"
        );
        // eth1 is down: listed only with -v.
        assert!(!text.contains("eth1"), "{text}");
    }
    // With -v every interface, with its status.
    let src = Script::built_in()
        .unwrap()
        .into_iter()
        .find(|s| s.id == "snmp-interfaces")
        .unwrap()
        .source
        .replace("fero.verbosity()", "1");
    let (port, _) = snmp_agent(false).await;
    let scan = ScriptScan::new(
        vec![script("snmp-interfaces", &src)],
        ArgTable::default(),
        None,
    )
    .unwrap();
    let mut host = host_with_services(&[(port, "snmp")]);
    host.ports[0].protocol = Protocol::Udp;
    let mut hosts = vec![host];
    scan.scan_hosts(&mut hosts).await;
    let text = &hosts[0].ports[0].scripts[0].output;
    assert!(text.contains("\n    Status: up\n"), "{text}");
    assert!(
        text.ends_with(
            ")\n    Type: ethernetCsmacd  Speed: 100 Mbps\n    Status: down\n    Traffic stats: 0.00 Kb sent, 0.00 Kb received"
        ),
        "{text}"
    );
    // The vendor comes from the system's OUI list, if it has one.
    assert!(
        text.contains("\n  eth1\n    MAC address: 00:0c:29:0a:0b:0c ("),
        "{text}"
    );
}

#[test]
fn snmp_scripts_stay_on_scanned_udp() {
    // The portrule wants UDP 161 or a UDP port named snmp; TCP 161 and a
    // closed port are not asked.
    let scan = ScriptScan::new(
        vec![built_in("snmp-sysdescr")],
        args::parse("").unwrap(),
        None,
    )
    .unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let tcp = host_with(&[(161, PortState::Open)]);
    let mut closed = host_with(&[(161, PortState::Closed)]);
    closed.ports[0].protocol = Protocol::Udp;
    let mut hosts = vec![tcp, closed];
    rt.block_on(scan.scan_hosts(&mut hosts));
    assert!(hosts.iter().all(|h| h.ports[0].scripts.is_empty()));
}

#[tokio::test]
async fn snmp_library_walk_ends_at_end_of_mib_and_encodes_oids() {
    // The agent's last variable is 1.3.6.1.2.1.25.1.1.0: a v2c walk past
    // it gets endOfMibView for the OID asked, which ends the walk at once.
    let (port, seen) = snmp_agent(false).await;
    let src = r#"
description = "test"
categories = { "safe" }
portrule = fero.portrule.match({}, { "snmp" }, "udp")
action = function(host, port)
  local s = fero.snmp.session(host, port, { version = 1 })
  local vars = s:walk("1.3.6.1.2.1.25.1")
  s:close()
  local m = fero.snmp.message(0, "public", 0xa0, { "2.100.3" })
  return string.format("%d %s %s", #vars, vars[1].oid, fero.hex(m:sub(-7)))
end
"#;
    let scan = ScriptScan::new(vec![script("snmp-lib", src)], ArgTable::default(), None).unwrap();
    let mut host = host_with_services(&[(port, "snmp")]);
    host.ports[0].protocol = Protocol::Udp;
    let mut hosts = vec![host];
    let start = std::time::Instant::now();
    scan.scan_hosts(&mut hosts).await;
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "{:?}",
        start.elapsed()
    );
    // "2.100.3": first subidentifier 180 in base 128 (81 34), then 03.
    assert_eq!(
        hosts[0].ports[0].scripts[0].output,
        "1 1.3.6.1.2.1.25.1.1.0 06038134030500"
    );
    assert_eq!(seen.lock().unwrap().len(), 2);
}

// ---- NSE compatibility layer (roadmap 7.6) ----

/// An NSE-style script's head: the modules most scripts ask for.
const NSE_HEAD: &str = r#"
local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
description = "test"
categories = { "safe" }
"#;

#[test]
fn nse_modules_load_and_unknown_ones_are_named() {
    let s = script(
        "n",
        &format!(
            "{NSE_HEAD}portrule = shortport.port_or_service(22, \"ssh\")\naction = function() end"
        ),
    );
    assert!(s.rules.portrule);
    let e = Script::load(
        "n",
        None,
        "local io = require \"io\"\ncategories = {}\nprerule = function() end\naction = function() end",
    )
    .unwrap_err();
    assert!(
        e.0.contains("module 'io' is not available in FeroProbe"),
        "{e}"
    );
    // Every module loads on its own.
    for m in [
        "base64",
        "comm",
        "datetime",
        "http",
        "ipOps",
        "match",
        "nmap",
        "openssl",
        "outlib",
        "rand",
        "shortport",
        "stdnse",
        "stringaux",
        "tableaux",
        "url",
        "_G",
        "string",
    ] {
        let src = format!(
            "local m = require \"{m}\"\nassert(type(m) == \"table\")\nassert(require \"{m}\" == m)\ncategories = {{}}\nprerule = function() end\naction = function() end"
        );
        Script::load("n", None, &src).unwrap_or_else(|e| panic!("{m}: {e}"));
    }
}

#[tokio::test]
async fn nse_helper_modules() {
    let src = format!(
        r#"{NSE_HEAD}
local ipOps = require "ipOps"
local url = require "url"
local stringaux = require "stringaux"
local tableaux = require "tableaux"
local datetime = require "datetime"
local openssl = require "openssl"
local base64 = require "base64"
local rand = require "rand"
local match = require "match"
prerule = function() return true end
action = function()
  local o = stdnse.output_table()
  o.hex = stdnse.tohex("\1\2\171") .. " " .. stdnse.tohex("\1\2\3\4", {{ separator = ":", group = 4 }})
    .. " " .. stdnse.fromhex("41 42:43")
  o.fmt = stdnse.format_output(true, {{ "a", {{ name = "b", "c", {{ "d" }} }}, "e\nf" }})
  o.err = tostring(stdnse.format_output(false, "boom"))
  o.timespec = string.format("%s %s %s %s", stdnse.parse_timespec("1500ms"),
    stdnse.parse_timespec("2m"), stdnse.parse_timespec("3"), stdnse.parse_timespec("x"))
  o.ip = ipOps.str_to_ip(ipOps.ip_to_str("2001:db8:0:0:0:0:0:1")) .. " "
    .. ipOps.str_to_ip(ipOps.ip_to_str("::")) .. " " .. ipOps.str_to_ip(ipOps.ip_to_str("1::"))
    .. " " .. ipOps.expand_ip("::ffff:1.2.3.4") .. " " .. ipOps.todword("1.2.3.4")
    .. " " .. ipOps.fromdword(16909060)
  local first, last = ipOps.get_ips_from_range("192.168.7.9/22")
  o.range = first .. "-" .. last .. " " .. tostring(ipOps.ip_in_range("10.1.2.3", "10.0.0.0/8"))
    .. " " .. tostring(ipOps.isPrivate("172.20.1.1")) .. " " .. tostring(ipOps.isPrivate("8.8.8.8"))
    .. " " .. tostring(ipOps.compare_ip("1.2.3.4", "lt", "::1")) .. " " .. ipOps.subnet_to_cidr("255.255.240.0")
  local u = url.parse("https://u:p@[2001:db8::1]:8443/a/b;x?q=1#f")
  o.url = string.format("%s %s %s %s %d %s %s %s %s", u.scheme, u.user, u.password, u.host, u.port,
    u.path, u.params, u.query, u.fragment)
  o.abs = url.absolute("http://h/a/b/c?x", "../d") .. " " .. url.absolute("http://h/a/b", "//o/p")
    .. " " .. url.absolute("http://h/a/b?x", "?y") .. " " .. url.escape("a b/&")
  o.split = table.concat(stringaux.strsplit(",%s*", "a, b,c"), "|") .. " "
    .. ("HeLLo"):match(stringaux.ipattern("hello"))
  local ok, key = tableaux.contains({{ x = 1, y = 2 }}, 2)
  o.tab = tostring(ok) .. " " .. key .. " " .. #tableaux.keys({{ a = 1, b = 2 }})
  o.date = datetime.format_timestamp(0) .. " " .. datetime.format_timestamp(3600, 3600)
    .. " " .. datetime.date_to_timestamp({{ year = 2000, month = 3, day = 1, hour = 0 }})
    .. " " .. datetime.format_time(90000, 1000)
  o.hmac = stdnse.tohex(openssl.hmac("sha256", "Jefe", "what do ya want for nothing?")) .. " "
    .. stdnse.tohex(openssl.hmac("MD5", "Jefe", "what do ya want for nothing?")) .. " "
    .. stdnse.tohex(openssl.md5("abc"))
  o.b64 = base64.enc("foobar") .. " " .. base64.dec("Zm9vYmFy")
  o.rand = #rand.random_alpha(12) .. " " .. tostring(not rand.random_alpha(30):find("[^%a]"))
  o.match = tostring(match.numbytes(3)("abcd")) .. " " .. tostring(match.pattern_limit("x", 2)("aaax"))
  o.mac = stdnse.format_mac("\0\12\41\1\2\3") .. " " .. stdnse.get_hostname({{ ip = "1.2.3.4", name = "" }})
  local try = nmap.new_try()
  o.try = try(true, "v") .. " " .. tostring(select(2, pcall(try, false, "failed")))
  return o
end"#
    );
    let scan = ScriptScan::new(vec![script("helpers", &src)], ArgTable::default(), None).unwrap();
    let r = scan.pre_scan().await;
    let d = r[0].data.as_ref().unwrap_or_else(|| panic!("{r:?}"));
    for (k, want) in [
        ("hex", "0102ab 0102:0304 ABC"),
        ("fmt", "\n  a\n  b\n    c\n      d\n  e\n  f"),
        ("err", "nil"),
        ("timespec", "1.5 120 3 nil"),
        (
            "ip",
            "2001:db8::1 :: 1:: 0000:0000:0000:0000:0000:ffff:0102:0304 16909060 1.2.3.4",
        ),
        ("range", "192.168.4.0-192.168.7.255 true true false true 20"),
        ("url", "https u p 2001:db8::1 8443 /a/b x q=1 f"),
        ("abs", "http://h/a/d http://o/p http://h/a/b?y a%20b%2F%26"),
        ("split", "a|b|c HeLLo"),
        ("tab", "true y 2"),
        (
            "date",
            "1970-01-01T00:00:00 1970-01-01T02:00:00+01:00 951868800 1m30s",
        ),
        (
            "hmac",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843 \
             750c783e6ab0b503eaa86e310a5db738 900150983cd24fb0d6963f7d28e17f72",
        ),
        ("b64", "Zm9vYmFy foobar"),
        ("rand", "12 true"),
        ("match", "3 2"),
        ("mac", "00:0c:29:01:02:03 1.2.3.4"),
        ("try", "v failed"),
    ] {
        assert_eq!(text(named(d, k)), want, "{k}");
    }
}

#[tokio::test]
async fn nse_sockets_comm_and_http() {
    let port = greeter(b"220 hello\r\n").await;
    let (web_port, seen) = web(|req| {
        if req.starts_with("GET /missing") {
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
        } else {
            b"HTTP/1.1 200 OK\r\nWWW-Authenticate: Basic realm=\"x y\", Digest realm=\"r\", nonce=\"n\"\r\nContent-Length: 11\r\n\r\n<b>hello</b".to_vec()
        }
    })
    .await;
    let src = format!(
        r#"{NSE_HEAD}
local comm = require "comm"
local http = require "http"
portrule = function(host, port) return port.state == "open" end
action = function(host, port)
  if port.number == {web_port} then
    local r = http.get(host, port, "/")
    local miss = http.get(host, port, "/missing")
    local out = http.get(host, 1, "/")
    local auth = http.parse_www_authenticate(r.header["www-authenticate"])
    local found, word = http.response_contains(r, "<B>(%a+)")
    local post = http.post(host, port, "/p", nil, nil, {{ a = "b c" }})
    return string.format("%d %s %d %s %s %s %s %s %s %s %s", r.status, r.body, miss.status,
      tostring(out.status), out["status-line"]:match("outside") or out["status-line"],
      auth[1].scheme, auth[1].params.realm, auth[2].scheme, auth[2].params.nonce,
      tostring(found) .. "/" .. tostring(word), tostring(post.status))
  end
  local status, banner = comm.get_banner(host, port, {{ lines = 1 }})
  local ok, echo = comm.exchange(host, port, "ping\n")
  local s = nmap.new_socket()
  local try = nmap.new_try(function() s:close() end)
  try(s:connect(host, port))
  local greeting = try(s:receive_buf("\r\n", false))
  try(s:send("x\n"))
  local back = try(s:receive_buf((require "match").numbytes(1), true))
  s:close()
  return string.format("%s %s|%s %s|%s|%s|%s", tostring(status), banner:gsub("\r\n", ""),
    tostring(ok), echo:gsub("[\r\n]", ""), greeting, back, host.bin_ip == "\127\0\0\1" and "bin" or "?")
end"#
    );
    let scan = ScriptScan::new(vec![script("nse-net", &src)], ArgTable::default(), None).unwrap();
    let mut hosts = vec![host_with(&[
        (port, PortState::Open),
        (web_port, PortState::Open),
    ])];
    scan.scan_hosts(&mut hosts).await;
    let out = |p: u16| {
        let port = hosts[0].ports.iter().find(|x| x.port == p).unwrap();
        port.scripts
            .first()
            .map(|s| s.output.clone())
            .unwrap_or_default()
    };
    assert_eq!(
        out(port),
        "true 220 hello|true 220 helloping|220 hello|x|bin"
    );
    assert_eq!(
        out(web_port),
        "200 <b>hello</b 404 nil outside Basic x y Digest n true/hello 200"
    );
    let seen = seen.lock().unwrap();
    // The signature User-Agent, as for FeroProbe's own scripts.
    assert!(seen[0].contains(USER_AGENT), "{}", seen[0]);
    let post = seen.iter().find(|r| r.starts_with("POST")).unwrap();
    assert!(post.ends_with("\r\n\r\na=b%20c"), "{post}");
}

#[tokio::test]
async fn nse_registries_are_shared_like_nmaps() {
    // Every host's run adds itself to a list and a count in the run's
    // registry; the postrule reads them all. host.registry carries a
    // value from one script to the next on the same host.
    let writer = format!(
        r#"{NSE_HEAD}
hostrule = function() return true end
postrule = function() return true end
action = function(host)
  if SCRIPT_TYPE == "postrule" then
    local seen = nmap.registry.seen or {{}}
    table.sort(seen)
    return #seen .. " " .. table.concat(seen, ",") .. " " .. tostring(nmap.registry.info.count)
  end
  nmap.registry.seen = nmap.registry.seen or {{}}
  table.insert(nmap.registry.seen, host.ip)
  -- Not a list: the last writer wins, as each run sets it.
  nmap.registry.info = nmap.registry.info or {{}}
  nmap.registry.info.count = (nmap.registry.info.count or 0) + 1
  host.registry.mark = {{ from = SCRIPT_NAME }}
  stdnse.sleep(0.05)
end"#
    );
    let reader = format!(
        r#"{NSE_HEAD}
dependencies = {{ "writer" }}
hostrule = function() return true end
action = function(host) return host.registry.mark and host.registry.mark.from end"#
    );
    let scan = ScriptScan::new(
        vec![script("writer", &writer), script("reader", &reader)],
        ArgTable::default(),
        None,
    )
    .unwrap();
    let mut hosts: Vec<HostResult> = (1..=3)
        .map(|i| {
            let mut h = host_with(&[]);
            h.addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, i));
            h
        })
        .collect();
    scan.scan_hosts(&mut hosts).await;
    for h in &hosts {
        let r = h.scripts.iter().find(|s| s.id == "reader").unwrap();
        assert_eq!(r.output, "writer");
    }
    let post = scan.post_scan().await;
    let out = &post.iter().find(|s| s.id == "writer").unwrap().output;
    // All three list entries survive the concurrent runs; the count is
    // a plain value, so at least one write is kept.
    assert!(out.starts_with("3 127.0.0.1,127.0.0.2,127.0.0.3 "), "{out}");
}

#[test]
fn nse_files_are_scripts_too() {
    let dir = std::env::temp_dir().join(format!("feroprobe-nse-files-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let nse = format!("{NSE_HEAD}portrule = shortport.http\naction = function() return 'x' end");
    std::fs::write(dir.join("web.nse"), &nse).unwrap();
    std::fs::write(dir.join("dup.lua"), &nse).unwrap();
    std::fs::write(dir.join("dup.nse"), &nse).unwrap();
    let ids = |spec: &str| -> Vec<String> {
        choose_in(spec, Vec::new(), Some(&dir))
            .unwrap_or_else(|e| panic!("{spec}: {e}"))
            .into_iter()
            .map(|s| s.id)
            .collect()
    };
    assert_eq!(ids("web"), ["web"]);
    assert_eq!(ids("web.nse"), ["web"]);
    let path = dir.join("web").display().to_string();
    assert_eq!(ids(&path), ["web"]);
    let chosen = choose_in("dup", Vec::new(), Some(&dir)).unwrap();
    assert_eq!(chosen[0].path, Some(dir.join("dup.lua")));
    let done = db::update(&dir, &[]).unwrap();
    let names: Vec<&str> = done.entries.iter().map(|e| e.filename.as_str()).collect();
    assert_eq!(names, ["dup.lua", "web.nse"]);
    assert!(
        done.skipped[0].starts_with("dup.nse: dup.lua has the same name"),
        "{:?}",
        done.skipped
    );
    assert_eq!(ids("safe"), ["dup", "web"]);
    // A directory with both files has the name twice, which is an error.
    let dirspec = format!("{}/", dir.display());
    let e = choose_in(&dirspec, Vec::new(), Some(&dir)).unwrap_err();
    assert!(e.0.contains("duplicate script ID: 'dup'"), "{e}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn nse_registry_views_merge_and_keep_number_keys() {
    let reg = Arc::new(registry::Registry::default());
    let state = || {
        let budget = sandbox::Budget::new();
        let lua = sandbox::new_state(&budget).unwrap();
        engine::install_library(
            &lua,
            "t",
            "action",
            &ArgTable::default(),
            &Arc::new(socket::Scope::default()),
            &reg,
            false,
        )
        .unwrap();
        lua.load("nmap = require 'nmap'").exec().unwrap();
        (lua, budget)
    };
    let (a, _ba) = state();
    let (b, _bb) = state();
    let run = |l: &mlua::Lua, code: &str| l.load(code).exec().unwrap();
    let add = |who: &str| {
        format!("nmap.registry.l = nmap.registry.l or {{}} table.insert(nmap.registry.l, '{who}')")
    };
    run(&a, &add("a"));
    run(&b, &add("b"));
    run(&b, "fero.__nse_flush()");
    run(&a, "fero.__nse_flush()");
    // A second flush with no further change must not drop b's entry.
    run(&a, "fero.__nse_flush()");
    run(
        &a,
        "nmap.registry.m = {} nmap.registry.m[443] = 'https' nmap.registry.m[1] = nil fero.__nse_flush()",
    );
    // After a flush the script sees the merged list, so editing and
    // removing an entry by the index it sees now leaves other scripts'
    // entries alone.
    let (d, _bd) = state();
    let (e, _be) = state();
    run(
        &d,
        "nmap.registry.q = nmap.registry.q or {} table.insert(nmap.registry.q, 'd1')",
    );
    run(
        &e,
        "nmap.registry.q = nmap.registry.q or {} table.insert(nmap.registry.q, 'e1')",
    );
    run(&e, "fero.__nse_flush()");
    run(&d, "fero.__nse_flush()");
    let seen: String = d
        .load("return table.concat(nmap.registry.q, ',')")
        .eval()
        .unwrap();
    assert_eq!(seen, "e1,d1");
    run(&d, "nmap.registry.q[2] = 'd2' fero.__nse_flush()");
    run(&d, "table.remove(nmap.registry.q, 2) fero.__nse_flush()");
    // One table under two names: after a flush each name has its own
    // copy, and a second flush without changes keeps another script's
    // update.
    run(
        &d,
        "local t = { n = 1 } nmap.registry.w = { a = t, b = t } fero.__nse_flush()",
    );
    run(&e, "nmap.registry.w.a.n = 5 fero.__nse_flush()");
    run(&d, "fero.__nse_flush()");
    let both = "return nmap.registry.w.a.n .. ' ' .. nmap.registry.w.b.n";
    let w: String = d.load(both).eval().unwrap();
    assert_eq!(w, "5 1");
    run(&d, "fero.__nse_flush()");
    let (f, _bf) = state();
    let w: String = f.load(both).eval().unwrap();
    assert_eq!(w, "5 1");
    // A table the script added and still holds stays tied to its own
    // entry after another script's addition moved it along the list.
    run(
        &d,
        "nmap.registry.r = nmap.registry.r or {} mine = { who = 'd' } table.insert(nmap.registry.r, mine)",
    );
    run(
        &e,
        "nmap.registry.r = nmap.registry.r or {} table.insert(nmap.registry.r, { who = 'e' })",
    );
    run(&e, "fero.__nse_flush()");
    run(&d, "fero.__nse_flush() mine.who = 'd2' fero.__nse_flush()");
    let (h, _bh) = state();
    let r: String = h
        .load("return nmap.registry.r[1].who .. ',' .. nmap.registry.r[2].who")
        .eval()
        .unwrap();
    assert_eq!(r, "e,d2");
    let held: bool = d.load("return nmap.registry.r[2] == mine").eval().unwrap();
    assert!(held);
    // A name that cannot be stored does not make another name's list
    // addition be stored again on every flush.
    let (j, _bj) = state();
    run(
        &j,
        "nmap.registry.p = {} table.insert(nmap.registry.p, 'once') nmap.registry.bad = print \
         assert(not pcall(fero.__nse_flush)) assert(not pcall(fero.__nse_flush))",
    );
    let (k, _bk) = state();
    let p: i64 = k.load("return #nmap.registry.p").eval().unwrap();
    assert_eq!(p, 1);
    // A table put under a second name is stored as the script left it,
    // even when another script changed the first name meanwhile.
    run(&d, "nmap.registry.x = { n = 1 } fero.__nse_flush()");
    run(&d, "nmap.registry.y = nmap.registry.x");
    run(&e, "nmap.registry.x.n = 7 fero.__nse_flush()");
    run(&d, "fero.__nse_flush()");
    let (g, _bg) = state();
    let xy: String = g
        .load("return nmap.registry.x.n .. ' ' .. nmap.registry.y.n")
        .eval()
        .unwrap();
    assert_eq!(xy, "7 1");
    let (c, _bc) = state();
    let q: String = c
        .load("return table.concat(nmap.registry.q, ',')")
        .eval()
        .unwrap();
    assert_eq!(q, "e1");
    let got: String = c
        .load(
            "local l = nmap.registry.l table.sort(l) \
             return table.concat(l, ',') .. ' ' .. tostring(nmap.registry.m[443]) .. ' ' .. tostring(nmap.registry.m[1])",
        )
        .eval()
        .unwrap();
    assert_eq!(got, "a,b https nil");
    // stdnse.make_buffer gives the data itself; new_thread's second
    // result is nmap's status function.
    let got: String = c
        .load(
            "local stdnse = require 'stdnse' \
             local fake = { receive_buf = function() return true, 'line' end } \
             local co, info = stdnse.new_thread(function() error('x', 0) end) \
             local st, err = info() \
             return stdnse.make_buffer(fake)() .. ' ' .. st .. ' ' .. err .. ' ' .. coroutine.status(co)",
        )
        .eval()
        .unwrap();
    assert_eq!(got, "line dead x dead");
}
