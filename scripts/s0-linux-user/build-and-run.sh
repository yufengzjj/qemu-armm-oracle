#!/bin/sh
# S0 (WSL half): build vanilla linux-user qemu-arm at the baseline commit,
# build prog.S, and run it with -cpu cortex-m55.
#
# Run inside WSL Alpine, with these apk packages installed:
#   build-base python3 py3-pip ninja meson glib-dev glib-static pkgconf git
#   bash perl bison flex clang lld llvm linux-headers zlib-dev zlib-static
#   pcre2-dev pcre2-static libffi-dev gettext-dev gettext-static util-linux-dev
# Usage:
#   sh build-and-run.sh            build qemu-arm if missing, then run tests
#   sh build-and-run.sh trace      also print -d in_asm,cpu traces
#
# WORK defaults to ~/qemu-armm-spike (Linux filesystem, for build speed).

set -eu

here=$(cd "$(dirname "$0")" && pwd)
MODE=${1:-}
WORK=${WORK:-$HOME/qemu-armm-spike}
QEMU_COMMIT=8ee6c77176cfee03be0ec7665b6652b2f31f1531
QEMU_ARM=$WORK/build/qemu-arm
OUT=$WORK/s0-out

if [ ! -x "$QEMU_ARM" ]; then
    mkdir -p "$WORK"
    if [ ! -d "$WORK/qemu" ]; then
        git clone --filter=blob:none --no-checkout \
            https://gitlab.com/qemu-project/qemu.git "$WORK/qemu"
    fi
    git -C "$WORK/qemu" checkout -q "$QEMU_COMMIT"
    rm -rf "$WORK/build"
    mkdir -p "$WORK/build"
    # musl 1.2.5 <sys/mman.h> lacks MADV_POPULATE_*, which linux-user/mmap.c uses.
    (cd "$WORK/build" && time ../qemu/configure \
        --target-list=arm-linux-user --static --disable-docs \
        --extra-cflags='-DMADV_POPULATE_READ=22 -DMADV_POPULATE_WRITE=23')
    (cd "$WORK/build" && time ninja qemu-arm)
fi
"$QEMU_ARM" --version | head -1

mkdir -p "$OUT"
clang --target=armv8.1m.main-none-eabi -march=armv8.1-m.main+mve.fp+fp.dp \
    -mfloat-abi=hard -mthumb -c "$here/prog.S" -o "$OUT/prog.o"
ld.lld -static -e _start "$OUT/prog.o" -o "$OUT/prog"
readelf -h "$OUT/prog" | grep -E 'OS/ABI|ABI Version|Type|Entry|Flags'

run() {
    rc=0
    "$QEMU_ARM" -cpu cortex-m55 "$@" || rc=$?
    echo "exit status: $rc" >&2
}

echo "== vadd.i32 (no extra args)"
run "$OUT/prog" > "$OUT/vadd.bin"
od -A d -t x4 "$OUT/vadd.bin"
set -- $(od -A n -t x4 -v "$OUT/vadd.bin")
echo "q0 lanes: [0]=0x$1 [1]=0x$2 [2]=0x$3 [3]=0x$4 (expect 0000000b 00000016 80000000 00000000)"
echo "CONTROL=0x$5 FPSCR=0x$6 VPR=0x$7 (0x5e5e5e5e: VMRS VPR did nothing) P0=0x$8"

echo "== udf #0 (1 extra arg)"
run "$OUT/prog" x

echo "== load from 0xdead0000 (2 extra args)"
run "$OUT/prog" x y

if [ "$MODE" = trace ]; then
    echo "== trace: vadd path"
    run -one-insn-per-tb -d in_asm,cpu,fpu,vpu,exec -D "$OUT/trace-vadd.log" "$OUT/prog" > /dev/null
    echo "log: $OUT/trace-vadd.log"
    echo "== trace: udf path"
    run -one-insn-per-tb -d in_asm,cpu,exec,int -D "$OUT/trace-udf.log" "$OUT/prog" x
    echo "log: $OUT/trace-udf.log"
fi
