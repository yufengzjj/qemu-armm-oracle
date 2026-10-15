#!/bin/sh
# Build armm_oracle.dll in build/oracle-win and stage it with the MSYS2
# runtime DLLs it needs in build/oracle-win/dist. Run in an MSYS2 CLANG64
# shell.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
build="$root/build/oracle-win"
dist="$build/dist"

sh "$root/scripts/apply-patches.sh"

if [ ! -f "$build/build.ninja" ]; then
    mkdir -p "$build"
    (cd "$build" && "$root/qemu/configure" --target-list=arm-softmmu \
        --without-default-features --enable-tcg --disable-docs --disable-tools \
        --disable-guest-agent --disable-plugins --disable-werror)
fi

ninja -C "$build" armm-oracle

mkdir -p "$dist"
cp -f "$build/oracle/armm_oracle.dll" "$dist/"
# Every non-system DLL that armm_oracle.dll pulls in comes from the
# toolchain's bin directory.
bindir=$(dirname "$(command -v clang)")
ldd "$dist/armm_oracle.dll" | awk '{print $3}' | while read -r dll; do
    case "$dll" in
    "$bindir"/*) cp -f "$dll" "$dist/" ;;
    esac
done
ls "$dist"
