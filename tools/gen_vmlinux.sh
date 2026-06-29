#!/usr/bin/env bash
# Generate tools/vmlinux.h from the running kernel's BTF.
#
# Usage: ./tools/gen_vmlinux.sh [output_path]
# Requires: bpftool, and a kernel built with CONFIG_DEBUG_INFO_BTF (the norm on
# modern distros). `make` invokes this implicitly via the vmlinux.h target.
set -euo pipefail

OUT="${1:-$(dirname "$0")/vmlinux.h}"

if [[ ! -e /sys/kernel/btf/vmlinux ]]; then
	echo "error: /sys/kernel/btf/vmlinux not found." >&2
	echo "       Your kernel lacks BTF (CONFIG_DEBUG_INFO_BTF). FiveM-Sentinel" >&2
	echo "       needs a BTF-enabled 6.8+ kernel for CO-RE." >&2
	exit 1
fi

if ! command -v bpftool >/dev/null 2>&1; then
	echo "error: bpftool not found (install linux-tools / bpftool)." >&2
	exit 1
fi

mkdir -p "$(dirname "$OUT")"
bpftool btf dump file /sys/kernel/btf/vmlinux format c >"$OUT"
echo "wrote $OUT ($(wc -l <"$OUT") lines)"
