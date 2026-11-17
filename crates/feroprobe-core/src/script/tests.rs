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
