#!/bin/sh
###############################################################################
# CSF 2.0 - Core Shield Firewall
# load-xdp.sh - build, load and attach the OPTIONAL XDP fast-drop program.
#
# This is opt-in. CSF works fully without XDP. Run only on a host with a recent
# kernel (>= 5.10 recommended), clang, libbpf-devel and bpftool installed, and
# an XDP-capable NIC driver.
#
# Usage:   ./load-xdp.sh <iface>          # build + attach
#          ./load-xdp.sh --unload <iface> # detach + unpin
#
# Copyright (C) 2026 CSF - Core Shield Firewall. GNU GPL v3.
###############################################################################
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
PINDIR="/sys/fs/bpf/csf"
OBJ="$HERE/csf_xdp.bpf.o"
SRC="$HERE/csf_xdp.bpf.c"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1"; exit 1; }; }

if [ "$1" = "--unload" ]; then
    IFACE="$2"
    [ -n "$IFACE" ] || { echo "usage: $0 --unload <iface>"; exit 1; }
    ip link set dev "$IFACE" xdp off 2>/dev/null || true
    rm -f "$PINDIR"/deny4 "$PINDIR"/deny6 "$PINDIR"/csf_xdp 2>/dev/null || true
    echo "XDP unloaded from $IFACE"
    exit 0
fi

IFACE="$1"
[ -n "$IFACE" ] || { echo "usage: $0 <iface>"; exit 1; }

need clang
need bpftool
need ip

echo "==> Building $OBJ"
clang -O2 -g -target bpf -c "$SRC" -o "$OBJ"

echo "==> Pinning maps under $PINDIR"
mkdir -p "$PINDIR"
# Load program + maps and pin (LIBBPF_PIN_BY_NAME pins deny4/deny6 by name).
bpftool prog loadall "$OBJ" "$PINDIR/csf_xdp" pinmaps "$PINDIR"

echo "==> Attaching XDP to $IFACE"
ip link set dev "$IFACE" xdp pinned "$PINDIR/csf_xdp/csf_xdp_drop"

echo "==> Done. Maps: $PINDIR/deny4 $PINDIR/deny6"
echo "    CSF will populate them when XDP_ENABLE=1 and severe attackers are blocked."
