#!/bin/sh
# Runs real systemd-resolved and a private system bus without contacting host services.
set -eu
resolved_binary=${WGE_RESOLVED_BINARY:-/lib/systemd/systemd-resolved}
if [ "${WGE_RESOLVED_ISOLATED:-}" != 1 ]; then
    test "$(id -u)" != 0 || { echo 'Run as an ordinary user, not root.' >&2; exit 1; }
    test -c /dev/net/tun || { echo 'Expose /dev/net/tun in this environment to run isolated resolver tests.' >&2; exit 1; }
    test -x "$resolved_binary" || { echo 'systemd-resolved is required for this test.' >&2; exit 1; }
    command -v dbus-daemon >/dev/null
    "$resolved_binary" --version | head -n 1
    build_output=$(mktemp)
    trap 'rm -f "$build_output"' EXIT
    cargo test -p wge-platform --lib --no-run --locked --message-format=json-render-diagnostics > "$build_output"
    test_binary=$(python3 -c 'import json,sys; print(next(x["executable"] for line in open(sys.argv[1]) if (x:=json.loads(line)).get("reason")=="compiler-artifact" and x.get("executable") and x["target"]["name"]=="wge_platform"))' "$build_output")
    rm "$build_output"
    trap - EXIT
    export WGE_HOST_NETNS=$(readlink /proc/self/ns/net)
    export WGE_HOST_MNTNS=$(readlink /proc/self/ns/mnt)
    export WGE_HOST_PIDNS=$(readlink /proc/self/ns/pid)
    export WGE_RESOLVED_ISOLATED=1
    exec timeout 60 unshare --user --map-current-user --keep-caps --mount --net --pid --fork --mount-proc --kill-child "$0" "$test_binary"
fi

test "$(readlink /proc/self/ns/net)" != "$WGE_HOST_NETNS"
test "$(readlink /proc/self/ns/mnt)" != "$WGE_HOST_MNTNS"
test "$(readlink /proc/self/ns/pid)" != "$WGE_HOST_PIDNS"
resolv_target=$(readlink -f /etc/resolv.conf)
mount --make-rprivate /
mount -t tmpfs -o mode=755 tmpfs /run
mkdir -p /run/dbus /run/systemd/resolve /run/wge-systemd
printf 'nameserver 127.0.0.53\n' > /run/wge-resolv.conf
case "$resolv_target" in
    /run/*)
        mkdir -p "$(dirname "$resolv_target")"
        cp /run/wge-resolv.conf "$resolv_target"
        ;;
    *) mount --bind /run/wge-resolv.conf /etc/resolv.conf ;;
esac
cat > /run/wge-systemd/resolved.conf <<'CONFIG'
[Resolve]
DNS=
FallbackDNS=
LLMNR=no
MulticastDNS=no
DNSSEC=no
DNSOverTLS=no
Cache=no
ReadEtcHosts=no
CONFIG
mount --bind /run/wge-systemd /etc/systemd
cat > /run/dbus/config <<'DBUS'
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>system</type><listen>unix:path=/run/dbus/system_bus_socket</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>
DBUS
export DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket
export SYSTEMD_LOG_TARGET=console
export SYSTEMD_LOG_LEVEL=${WGE_RESOLVED_LOG_LEVEL:-warning}
export WGE_RESOLVED_TEST=1
dbus-daemon --config-file=/run/dbus/config --fork
"$resolved_binary" &
"$1" linux_resolved_test::resolved_service_split_full_and_recovery --ignored --exact --nocapture --test-threads=1
