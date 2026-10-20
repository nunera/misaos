//! Portable graph to Dinit tree: graph rules run before the adapter, negotiation
//! reports every shortfall, output is a pure function of its inputs, and Dinit's
//! defaults never leak into a service the plan did not ask for.
use misa_service::dinit;
use serde_json::{Value, json};

const SVCRUN: &str = "/nix/store/00000000000000000000000000000000-misa-host/bin/misa-svcrun";
const SPECS: &str = "/nix/store/11111111111111111111111111111111-specs";

fn process(id: &str, extra: Value) -> Value {
    let mut node = json!({
        "id": id, "kind": "longrun", "scope": {"kind": "system"},
        "requires": [], "wants": [], "after": [], "requiredFeatures": [],
        "command": "/nix/store/22222222222222222222222222222222-app/bin/app",
        "argv": ["app"], "cwd": "/", "env": {}, "identity": {"uid": 0, "gid": 0},
        "readiness": {"kind": "exec-started"}, "restart": {"kind": "never"},
        "stop": {"signal": "SIGTERM", "gracePeriod": 10, "killProcessGroup": true},
        "directories": [], "sockets": [], "capabilities": []
    });
    for (key, value) in extra.as_object().unwrap() {
        node[key] = value.clone();
    }
    node
}

fn milestone(id: &str, requires: &[&str]) -> Value {
    json!({"id": id, "kind": "milestone", "scope": {"kind": "system"},
           "requires": requires, "wants": [], "after": [], "requiredFeatures": []})
}

fn graph(mut services: Vec<Value>) -> Value {
    services.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    json!({"services": services, "targets": {}})
}

fn compile(graph: &Value) -> Result<dinit::Compiled, misa_plan::Error> {
    dinit::compile(graph, "0.22.0", SVCRUN, SPECS)
}

#[test]
fn compiling_twice_is_byte_identical() {
    let g = graph(vec![
        milestone("boot", &["logd"]),
        process(
            "logd",
            json!({"readiness": {"kind": "fd-newline", "fd": 5, "timeout": 10}}),
        ),
        process("appd", json!({"requires": ["logd"]})),
    ]);
    let (a, b) = (compile(&g).unwrap(), compile(&g).unwrap());
    assert_eq!(a.services, b.services);
    assert_eq!(a.specs, b.specs);
    assert_eq!(a.tree, b.tree);
    let tree: Value = serde_json::from_slice(&a.tree).unwrap();
    assert_eq!(
        tree["graphDigest"],
        json!(misa_service::graph::Graph::digest(&g).unwrap())
    );
    assert_eq!(tree["capabilities"]["upstream"]["release"], json!("0.22.0"));
}

#[test]
fn graph_rules_reject_before_any_tree_is_emitted() {
    let cycle = graph(vec![
        milestone("boot", &["a"]),
        process("a", json!({"requires": ["b"]})),
        process("b", json!({"after": ["a"]})),
    ]);
    let error = compile(&cycle).err().unwrap();
    assert_eq!(error.code, "E_SCHEMA");
    assert!(
        error.message.contains('a') && error.message.contains('b'),
        "{error}"
    );

    let user = process("u", json!({"scope": {"kind": "user", "uid": 1000}}));
    let system_requires_user = graph(vec![milestone("boot", &["u"]), user]);
    assert_eq!(
        compile(&system_requires_user).err().unwrap().code,
        "E_SCHEMA"
    );

    let no_boot = graph(vec![milestone("base", &["a"]), process("a", json!({}))]);
    assert_eq!(compile(&no_boot).err().unwrap().code, "E_SCHEMA");
}

#[test]
fn negotiation_reports_every_unsupported_capability_at_once() {
    let g = graph(vec![
        milestone("boot", &["probe", "sock"]),
        process(
            "probe",
            json!({"readiness": {"kind": "probe", "program": "/bin/true", "args": [], "timeout": 5}}),
        ),
        process(
            "sock",
            json!({"sockets": [{"id": "s", "kind": "unix-stream", "path": "/run/s.sock",
                                "owner": {"uid": 0, "gid": 0}, "mode": "0600"}]}),
        ),
    ]);
    let error = compile(&g).err().unwrap();
    assert_eq!(error.code, "E_CAPABILITY");
    assert!(
        error
            .message
            .contains("(probe, readiness, readiness-probe, none)"),
        "{error}"
    );
    assert!(
        error
            .message
            .contains("(sock, sockets, socket-activation, none)"),
        "{error}"
    );
}

#[test]
fn dinit_defaults_never_stand_in_for_the_plan() {
    let g = graph(vec![
        milestone("boot", &["flaky", "group", "never"]),
        process("never", json!({})),
        process(
            "flaky",
            json!({"restart": {"kind": "on-failure", "burst": 3, "window": 30, "delay": 1},
                   "readiness": {"kind": "fd-newline", "fd": 7, "timeout": 9}}),
        ),
        process(
            "group",
            json!({"stop": {"signal": "SIGHUP", "gracePeriod": 4, "killProcessGroup": false}}),
        ),
    ]);
    let tree = compile(&g).unwrap();
    let text = |id: &str| String::from_utf8(tree.services[id].clone()).unwrap();
    // Dinit restarts by default; a plan that never restarts must say so.
    assert!(text("never").contains("restart = no\n"));
    let flaky = text("flaky");
    for line in [
        "restart = on-failure\n",
        "restart-delay = 1\n",
        "restart-limit-interval = 30\n",
        "restart-limit-count = 3\n",
        "ready-notification = pipefd:4\n",
        "start-timeout = 9\n",
        &format!("command = {SVCRUN} --spec {SPECS}/flaky.json --ready-fd 4\n"),
    ] {
        assert!(flaky.contains(line), "missing {line:?} in\n{flaky}");
    }
    let spec: Value = serde_json::from_slice(&tree.specs["flaky.json"]).unwrap();
    assert_eq!(spec["readinessFd"], json!(7));
    let group = text("group");
    assert!(group.contains("term-signal = HUP\n") && group.contains("stop-timeout = 4\n"));
    assert!(group.contains("options: signal-process-only\n"));
}

#[test]
fn unbounded_or_ambiguous_dinit_settings_are_refused() {
    let unbounded = graph(vec![
        milestone("boot", &["a"]),
        process(
            "a",
            json!({"stop": {"signal": "SIGTERM", "gracePeriod": 0, "killProcessGroup": true}}),
        ),
    ]);
    assert_eq!(compile(&unbounded).err().unwrap().code, "E_SCHEMA");
    let oneshot_fd = graph(vec![
        milestone("boot", &["a"]),
        process(
            "a",
            json!({"kind": "oneshot", "readiness": {"kind": "fd-newline", "fd": 5, "timeout": 5}}),
        ),
    ]);
    assert_eq!(compile(&oneshot_fd).err().unwrap().code, "E_SCHEMA");
}
