#!/usr/bin/env bash
# Conformance fixture service for the S3a graph, readiness and restart vectors.
# Usage: misa-fixture ID MODE [ARGS...]. Every start appends "exec <ns> pid=<pid>"
# to /run/misa-fixture/ID/log; readiness writes "ready <ns>" before the newline.
set -u
id=$1 mode=$2
shift 2
log=/run/misa-fixture/$id/log
now() { date +%s%N; }
echo "exec $(now) pid=$$" >> "$log"
starts=$(grep -c '^exec' "$log")

notify() { # FD: write the readiness newline and close the descriptor (R2)
  echo "ready $(now)" >> "$log"
  echo >&"$1"
  eval "exec $1>&-"
}

case $mode in
  run) exec sleep infinity ;;
  ready-after) sleep "$1"; notify "$2"; exec sleep infinity ;;
  never-ready) exec sleep infinity ;;
  exit) exit "$1" ;;
  noise-then-ready)
    printf 'not-a-newline' >&"$1"
    sleep 1
    notify "$1"
    exec sleep infinity
    ;;
  ready-then-crash)
    if [ "$starts" -eq 1 ]; then
      notify "$1"; sleep 1; exit 1
    fi
    sleep 4; notify "$1"; exec sleep infinity
    ;;
  fail-then-succeed)
    [ "$starts" -eq 1 ] && exit 1
    exit 0
    ;;
  keep-ready-fd)
    # Ready, but keep the descriptor so its number stays visible in /proc/PID/fd.
    echo "ready $(now)" >> "$log"
    echo >&"$1"
    exec sleep infinity
    ;;
  *) echo "unknown mode $mode" >&2; exit 100 ;;
esac
