# S3a acceptance, run by the stock nixos-test-driver against Misa-owned guests.
# `S3A` (prepended) names every generation, entry and plan the guests boot. All
# verdicts come from the serial console, the backdoor shell and the guests' own
# /proc and efivarfs, never from Misa's exit statuses alone.
import os
import re
import time

GEN = S3A["generations"]


def entry_name(scenario):
    return [n for n in os.listdir(S3A["entries"][scenario]) if n.endswith(".conf")][0]


def j(machine, command):
    return json.loads(machine.succeed(command))

def no_init_ran(machine):
    log = machine.get_console_log()
    assert "misa-handoff: verified" not in log, "handoff must not verify"
    # Dinit reports each started service as "[  OK  ] name" (colour codes optional).
    assert not re.search(r"\[\s*(?:\x1b\[[0-9;]*m)?\s*OK", log), "no Dinit service may have started"


def refused(machine, code, field=None, also=None):
    machine.start()
    machine.wait_for_console_text(r"misa-handoff: refused \{.*\"code\":\"" + code + r"\"")
    machine.wait_for_console_text(r"reboot: System halted")
    log = machine.get_console_log()
    line = [l for l in log.splitlines() if "misa-handoff: refused" in l][-1]
    error = json.loads(line.split("misa-handoff: refused ", 1)[1])
    assert error["code"] == code, error
    if field is not None:
        assert error["field"] == field, error
    if also is not None:
        assert re.search(also, log), also
    no_init_ran(machine)
    machine.crash()
    return error

def booted(machine, scenario, banner):
    g = GEN[scenario]
    machine.start()
    machine.wait_for_console_text(banner)
    machine.wait_for_console_text(r"misa-handoff: verified generation sha256:" + g["id"])
    machine.connect()

    # PID 1 is the pinned Dinit binary the manifest names, exec'd by the handoff.
    manifest = json.load(open(g["manifest"]))
    init = manifest["boot"]["init"]
    assert machine.succeed("readlink /proc/1/exe").strip() == init["path"]
    assert "sha256:" + machine.succeed("sha256sum /proc/1/exe").split()[0] == init["sha256"]
    argv = machine.succeed("tr '\\0' ' ' < /proc/1/cmdline").split()
    assert argv == ["dinit", "--services-dir", "/run/misa/dinit/services"], argv
    assert S3A["dinitVersion"] in init["path"]

    # The handoff record describes this boot, verified by on-disk content.
    record = j(machine, "cat /run/misa/handoff.json")
    assert record["generation"] == "sha256:" + g["id"], record
    assert record["checks"] == ["V1", "V2", "V3", "V4", "V6", "V7", "V8", "V9", "V10", "V11", "V12"], record
    assert record["root"]["selector"] == "partuuid=" + S3A["rootPartUuid"], record
    assert record["root"]["verifiedBy"] == "gpt-partition-guid", record
    assert record["stage1"] == "borrowed" and record["journal"] == "absent", record
    cmdline_digest = machine.succeed("printf %s \"$(cat /proc/cmdline)\" | sha256sum").split()[0]
    assert record["cmdlineSha256"] == "sha256:" + cmdline_digest, record
    assert "misa.generation=" + g["id"] in machine.succeed("cat /proc/cmdline")

    # Stable paths point at this generation; the loaded tree is the manifest's build.
    assert machine.succeed("readlink /run/current-system").strip() == g["toplevel"]
    assert machine.succeed("readlink /run/misa/dinit/services").strip() == g["toplevel"] + "/init-tree"
    tree = "sha256:" + machine.succeed("sha256sum /run/misa/dinit/services/tree.json").split()[0]
    assert tree == init["adapterBuildId"] == manifest["adapterIdentity"]

    # The base milestone and its services are up, including mdevd's fd readiness.
    for service in ["boot", "base", "early-mounts", "kernel-modules", "hostname", "mdevd", "mdevd-coldplug", "backdoor"]:
        machine.succeed(f"dinitctl is-started {service}")
    assert machine.succeed("cat /proc/sys/kernel/hostname").strip() == "s3a"

    # The loader that ran is systemd-boot, it booted exactly the published entry,
    # and it advertises boot counting for the next slice to use (B6).
    loader = j(machine, "misa-activate loader-info")
    assert loader["loader"] == "systemd-boot " + S3A["systemdVersion"], loader
    # systemd-boot 260 reports a type 1 entry's identifier as its file name, .conf included.
    assert loader["entrySelected"] == entry_name(scenario), loader
    assert loader["bootCounting"] is True, loader
    return machine


def log(machine, service):
    return machine.succeed(f"cat /run/misa-fixture/{service}/log").splitlines()


def stamps(lines, kind):
    return [int(l.split()[1]) for l in lines if l.startswith(kind + " ")]


def pid(machine, service):
    status = machine.succeed(f"dinitctl status {service}")
    return int(re.search(r"Process ID:\s*(\d+)", status).group(1))


def vectors(m):
    """Chapter 13 graph, readiness, restart and identity vectors on the pinned Dinit."""
    with subtest("V-GR-03 V-RDY-01: a dependent starts only after its requirement is ready"):
        m.succeed("dinitctl start fx-appd")
        ready = stamps(log(m, "fx-logd"), "ready")[0]
        logd_exec = stamps(log(m, "fx-logd"), "exec")[0]
        appd_exec = stamps(log(m, "fx-appd"), "exec")[0]
        assert ready - logd_exec >= 2_000_000_000 * 0.9, (logd_exec, ready)
        assert appd_exec > ready, (ready, appd_exec)

    with subtest("V-GR-04 V-RDY-03: a requirement that never signals fails at its timeout; the dependent never runs"):
        started = time.monotonic()
        m.fail("dinitctl start fx-blocked")
        assert time.monotonic() - started < 20
        m.succeed("dinitctl is-failed fx-never")
        m.fail("test -e /run/misa-fixture/fx-blocked/log")
        m.fail("pgrep -f 'misa-fixture fx-never'")

    with subtest("V-RDY-02: exit before the newline is a failure"):
        m.fail("dinitctl start fx-early-dep")
        # Dinit 0.22 reports the start failure on the console, but `is-failed` lists an
        # exit before readiness as plain STOPPED (a start timeout does count, V-GR-04).
        m.wait_for_console_text(r"\[FAILED\].*fx-early-exit")
        assert len(stamps(log(m, "fx-early-exit"), "exec")) == 1
        assert stamps(log(m, "fx-early-exit"), "ready") == []
        m.fail("dinitctl is-started fx-early-exit")
        m.fail("test -e /run/misa-fixture/fx-early-dep/log")

    with subtest("V-GR-05: a failing weak dependency does not block its dependent"):
        m.succeed("dinitctl start fx-weak-user")
        assert len(stamps(log(m, "fx-weak-fail"), "exec")) == 1
        m.succeed("dinitctl is-started fx-weak-user")

    with subtest("V-RDY-04: bytes before the newline are ignored"):
        m.succeed("dinitctl start fx-noise")
        lines = log(m, "fx-noise")
        assert stamps(lines, "ready")[0] - stamps(lines, "exec")[0] >= 900_000_000, lines

    with subtest("V-RDY-05: after a restart the service is not ready until a new newline"):
        m.succeed("dinitctl start fx-restart-ready")
        m.wait_until_succeeds("test $(grep -c '^exec' /run/misa-fixture/fx-restart-ready/log) -eq 2", timeout=10)
        m.fail("dinitctl is-started fx-restart-ready")
        m.wait_until_succeeds("dinitctl is-started fx-restart-ready", timeout=15)
        lines = log(m, "fx-restart-ready")
        assert len(stamps(lines, "ready")) == 2, lines
        assert stamps(lines, "ready")[1] - stamps(lines, "exec")[1] >= 3_500_000_000, lines

    with subtest("V-RDY-06: only stdio and the declared descriptor reach the service"):
        m.succeed("dinitctl start fx-fds")
        fds = sorted(int(n) for n in m.succeed(f"ls /proc/{pid(m, 'fx-fds')}/fd").split())
        assert fds == [0, 1, 2, 7], fds

    with subtest("V-RST-01: exit 1 restarts, exit 0 does not"):
        m.succeed("dinitctl start fx-crash-once")
        m.wait_until_succeeds("test $(grep -c '^exec' /run/misa-fixture/fx-crash-once/log) -eq 2", timeout=10)
        time.sleep(3)
        assert len(stamps(log(m, "fx-crash-once"), "exec")) == 2
        m.fail("dinitctl is-started fx-crash-once")

    with subtest("V-RST-02: a crash loop above burst/window stops for good"):
        m.execute("dinitctl start fx-crashloop")
        time.sleep(4)
        count = len(stamps(log(m, "fx-crashloop"), "exec"))
        assert count == 4, count  # the first start plus burst=3 restarts
        time.sleep(10)  # 2 x window
        assert len(stamps(log(m, "fx-crashloop"), "exec")) == count
        m.fail("dinitctl is-started fx-crashloop")

    with subtest("V-RST-03: SIGKILL and SIGSEGV restart; an outside TERM does not"):
        m.succeed("dinitctl start fx-signals")
        first = pid(m, "fx-signals")
        m.succeed(f"kill -KILL {first}")
        m.wait_until_succeeds("test $(grep -c '^exec' /run/misa-fixture/fx-signals/log) -eq 2", timeout=10)
        m.wait_until_succeeds("dinitctl is-started fx-signals", timeout=10)
        second = pid(m, "fx-signals")
        m.succeed(f"kill -SEGV {second}")
        m.wait_until_succeeds("test $(grep -c '^exec' /run/misa-fixture/fx-signals/log) -eq 3", timeout=10)
        m.wait_until_succeeds("dinitctl is-started fx-signals", timeout=10)
        m.succeed(f"kill -TERM {pid(m, 'fx-signals')}")
        time.sleep(3)
        assert len(stamps(log(m, "fx-signals"), "exec")) == 3
        m.fail("dinitctl is-started fx-signals")

    with subtest("V-RST-04: restart delay spaces the spawns"):
        m.execute("dinitctl start fx-delay")
        time.sleep(6)
        execs = stamps(log(m, "fx-delay"), "exec")
        assert len(execs) == 4, execs
        gaps = [b - a for a, b in zip(execs, execs[1:])]
        assert min(gaps) >= 900_000_000, gaps

    with subtest("V-SEC-03: declared identity, no supplementary groups, no_new_privs"):
        m.succeed("dinitctl start fx-identity")
        status = m.succeed(f"cat /proc/{pid(m, 'fx-identity')}/status")
        field = lambda name: re.search(rf"^{name}:[ \t]*(.*)$", status, re.M).group(1).split()
        assert field("Uid") == ["1000"] * 4 and field("Gid") == ["1000"] * 4, status
        assert field("Groups") == [] and field("NoNewPrivs") == ["1"], status
        assert m.succeed("stat -c '%u:%g %a' /run/misa-fixture/fx-identity").strip() == "1000:1000 750"


with subtest("production generations carry no test instrumentation"):
    plan = json.load(open(S3A["production"]["plan"]))
    ids = [s["id"] for s in plan["serviceGraph"]["services"]]
    assert "backdoor" not in ids and not [i for i in ids if i.startswith("fx-")], ids
    tree = os.listdir(S3A["production"]["initTree"])
    assert "backdoor" not in tree, tree

with subtest("not-os stage 1 boots the verified generation into Dinit"):
    booted(notos, "notos", r"MisaOS stage 1: not-os fa6ba60 adaptation")
    vectors(notos)
    notos.crash()

with subtest("NixOS scripted stage 1 boots the verified generation into Dinit"):
    booted(scripted, "scripted", r"<<< NixOS Stage 1 >>>")
    scripted.succeed("dinitctl is-started base")
    scripted.crash()

with subtest("a manifest edited after publication is refused before init"):
    refused(neg_tampered, "E_BOOT_MANIFEST_HASH")
    refused(neg_tampered_scripted, "E_BOOT_MANIFEST_HASH")

with subtest("an init that differs from its pinned digest is refused"):
    refused(neg_init_hash, "E_BOOT_INIT_INVALID", "/boot/init/sha256")

with subtest("an init for another machine is refused"):
    refused(neg_init_elf, "E_BOOT_INIT_INVALID", "/boot/init/elfMachine")

with subtest("a hand-edited root selector is refused even though stage 1 mounted the right disk"):
    refused(neg_selector, "E_BOOT_ROOT_SELECTOR", "misa.root", also=r"misa stage-1: root fsuuid=")
