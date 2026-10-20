# Test instrumentation, only when misa.testing.backdoor is set: a root shell on the
# virtio console speaking the NixOS test driver's protocol (the sentinel line, then a
# non-interactive bash on /dev/hvc0). Production generations never contain it.
{ lib, config, pkgs, ... }:
let
  backdoor = pkgs.writeShellScript "misa-test-backdoor" ''
    export USER=root HOME=/root PATH=/run/current-system/sw/bin PAGER=
    mkdir -p /root
    cd /tmp
    while [ ! -e /dev/hvc0 ]; do sleep 0.1; done
    exec < /dev/hvc0 > /dev/hvc0
    while ! exec 2> /dev/ttyS0; do sleep 0.1; done
    echo "connecting to host..." >&2
    stty -F /dev/hvc0 raw -echo
    echo "Spawning backdoor root shell..."
    PS1="" exec ${pkgs.bashNonInteractive}/bin/bash --norc /dev/hvc0
  '';
in
lib.mkIf config.misa.testing.backdoor {
  misa.kernel.modules = [ "virtio_console" ];
  misa.services.backdoor = {
    kind = "longrun";
    command = "${backdoor}";
    argv = [ "misa-test-backdoor" ];
    requires = [ "base" ];
    stop = { signal = "SIGHUP"; gracePeriod = 5; killProcessGroup = true; };
  };
  misa.services.boot.wants = [ "backdoor" ];
  misa.annotations.testing = "Test generation: contains the backdoor root shell on /dev/hvc0.";
}
