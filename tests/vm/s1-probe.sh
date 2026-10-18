#!/bin/sh
# Fixture program shipped inside the publisher-signed, Debian-derived S1 image
# (/usr/local/bin/misa-probe). It only reports what the foreign root observes
# so tests/vm/s1.nix can assert real launcher behaviour; it is not part of any
# Debian package.
set -u

mode=${1:-identity}
if [ "$#" -gt 0 ]; then
  shift
fi

case "$mode" in
  identity)
    printf 'release=%s\n' "$(cat /etc/misa-fixture-release)"
    printf 'os=%s\n' "$(. /etc/os-release && printf '%s-%s' "$ID" "$VERSION_ID")"
    printf 'uid=%s\n' "$(id -u)"
    printf 'marker=%s\n' "$(ls /usr/share/misa-fixture | grep -- '-only$' | tr '\n' ',')"
    ;;
  args)
    n=0
    for arg in "$@"; do
      printf 'arg[%d]=%s\n' "$n" "$arg"
      n=$((n + 1))
    done
    printf 'argc=%d\n' "$n"
    ;;
  env)
    env | sort
    ;;
  denied)
    # Report, never fail, so the caller can assert the exact visibility of each path.
    rc=0
    for path in "$@"; do
      if [ -e "$path" ] || [ -L "$path" ]; then
        printf 'VISIBLE %s\n' "$path"
        rc=3
      else
        printf 'ABSENT %s\n' "$path"
      fi
    done
    exit "$rc"
    ;;
  write-root)
    rc=0
    for path in /usr/misa-write-test /etc/misa-write-test /misa-write-test; do
      if (printf x >"$path") 2>/dev/null; then
        printf 'WRITABLE %s\n' "$path"
        rc=4
      else
        printf 'READONLY %s\n' "$path"
      fi
    done
    exit "$rc"
    ;;
  share-write)
    printf '%s\n' "$1" >/mnt/share/probe.txt && printf 'SHARE_WRITTEN\n'
    ;;
  hold)
    # Long-lived process: proves a running export keeps its own root while newer
    # roots are imported and the host configuration is switched.
    n=0
    while :; do
      n=$((n + 1))
      printf 'release=%s tick=%d\n' "$(cat /etc/misa-fixture-release)" "$n" >/mnt/share/heartbeat.tmp &&
        mv /mnt/share/heartbeat.tmp /mnt/share/heartbeat
      sleep 1
    done
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
