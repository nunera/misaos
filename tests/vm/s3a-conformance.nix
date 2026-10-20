# Test-generation-only services for the Chapter 13 graph, readiness, restart and
# identity vectors. None is a member of `boot`; the test starts each with dinitctl.
{ lib, config, pkgs, ... }:
let
  fixture = pkgs.writeShellScript "misa-fixture" (builtins.readFile ./s3a-fixture.sh);
  # One owner per path: each fixture records into its own runtime directory.
  logDir = id: { path = "/run/misa-fixture/${id}"; owner = { uid = 0; gid = 0; }; mode = "0755"; lifetime = "runtime"; };
  svc = id: mode: args: extra: lib.recursiveUpdate {
    kind = "longrun";
    command = "${fixture}";
    argv = [ "misa-fixture" id mode ] ++ args;
    env.PATH = lib.makeBinPath [ pkgs.coreutils pkgs.gnugrep pkgs.bash ];
    directories = [ (logDir id) ];
  } extra;
  fd = n: timeout: { readiness = { kind = "fd-newline"; fd = n; inherit timeout; }; };
  onFailure = burst: window: delay: { restart = { kind = "on-failure"; inherit burst window delay; }; };
in
lib.mkIf config.misa.testing.backdoor {
  misa.services = {
    # V-GR-03, V-RDY-01: appd starts only after slow logd reported ready.
    fx-logd = svc "fx-logd" "ready-after" [ "2" "5" ] (fd 5 10);
    fx-appd = svc "fx-appd" "run" [ ] { requires = [ "fx-logd" ]; };
    # V-GR-04, V-RDY-03: a requirement that never becomes ready blocks its dependent.
    fx-never = svc "fx-never" "never-ready" [ ] (fd 5 3);
    fx-blocked = svc "fx-blocked" "run" [ ] { requires = [ "fx-never" ]; };
    # V-RDY-02: exit before the newline is a failure; the dependent never runs.
    fx-early-exit = svc "fx-early-exit" "exit" [ "0" ] (fd 5 5);
    fx-early-dep = svc "fx-early-dep" "run" [ ] { requires = [ "fx-early-exit" ]; };
    # V-GR-05: a failing weak dependency does not stop its dependent.
    fx-weak-fail = svc "fx-weak-fail" "exit" [ "1" ] { kind = "oneshot"; };
    fx-weak-user = svc "fx-weak-user" "run" [ ] { wants = [ "fx-weak-fail" ]; };
    # V-RDY-04: bytes before the newline are ignored.
    fx-noise = svc "fx-noise" "noise-then-ready" [ "6" ] (fd 6 5);
    # V-RDY-05: after a restart the service is not ready until a new newline.
    fx-restart-ready = svc "fx-restart-ready" "ready-then-crash" [ "5" ]
      (lib.recursiveUpdate (fd 5 10) (onFailure 5 60 0));
    # V-RDY-06: only stdio and the declared descriptor survive misa-svcrun.
    fx-fds = svc "fx-fds" "keep-ready-fd" [ "7" ] (fd 7 5);
    # V-RST-01..04.
    fx-crash-once = svc "fx-crash-once" "fail-then-succeed" [ ] (onFailure 5 60 0);
    fx-crashloop = svc "fx-crashloop" "exit" [ "1" ] (onFailure 3 5 0);
    fx-signals = svc "fx-signals" "run" [ ] (onFailure 10 60 0);
    fx-delay = svc "fx-delay" "exit" [ "1" ] (onFailure 3 60 1);
    # V-SEC-03: declared identity, no supplementary groups, no_new_privs; and a
    # declared runtime directory created with its owner and mode before the drop.
    fx-identity = svc "fx-identity" "run" [ ] {
      identity = { uid = 1000; gid = 1000; };
      directories = [{ path = "/run/misa-fixture/fx-identity"; owner = { uid = 1000; gid = 1000; }; mode = "0750"; lifetime = "runtime"; }];
    };
  };
}
