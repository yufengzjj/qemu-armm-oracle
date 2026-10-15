#!/bin/sh
# Apply patches/*.patch to the qemu submodule and link qemu/oracle to
# frontend/ (a directory junction on Windows, a symlink elsewhere).
#   --reset   first restore the submodule files and remove the link
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
qemu="$root/qemu"
link="$qemu/oracle"

is_windows() {
    case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) return 0 ;;
    *) return 1 ;;
    esac
}

remove_link() {
    [ -e "$link" ] || [ -L "$link" ] || return 0
    if is_windows; then
        # rmdir removes only the junction; rm -r would follow it into frontend/.
        MSYS2_ARG_CONV_EXCL='*' cmd.exe /c rmdir "$(cygpath -w "$link")"
    else
        rm "$link"
    fi
}

if grep -q "$(printf '\r')" "$qemu/configure"; then
    echo "qemu/ has CRLF line endings (core.autocrlf=true); check it out again:" >&2
    echo "  git -C qemu config core.autocrlf false" >&2
    echo "  git -C qemu rm -q -r --cached . && git -C qemu reset -q --hard" >&2
    exit 1
fi

if [ "${1:-}" = "--reset" ]; then
    remove_link
    git -C "$qemu" reset -q
    git -C "$qemu" checkout -- .
    echo "submodule reset"
fi

for p in "$root"/patches/*.patch; do
    name=$(basename "$p")
    if git -C "$qemu" apply --reverse --check -C2 "$p" 2>/dev/null; then
        echo "already applied: $name"
    else
        # --3way merges through upstream context drift. It needs the index
        # to match the files (earlier patches leave them modified, and Git
        # for Windows and MSYS2's git record stat data differently), so
        # stage them first; it stages the result, so unstage afterwards to
        # keep the index at HEAD for --reset.
        git -C "$qemu" add -u
        git -C "$qemu" apply --3way "$p"
        git -C "$qemu" reset -q
        echo "applied: $name"
    fi
done

if [ ! -e "$link" ]; then
    if is_windows; then
        MSYS2_ARG_CONV_EXCL='*' cmd.exe /c mklink /J \
            "$(cygpath -w "$link")" "$(cygpath -w "$root/frontend")" >/dev/null
    else
        ln -s ../frontend "$link"
    fi
    echo "linked qemu/oracle -> frontend/"
fi

exclude=$(cd "$qemu" && git rev-parse --path-format=absolute --git-path info/exclude)
mkdir -p "$(dirname "$exclude")"
grep -qx '/oracle' "$exclude" 2>/dev/null || echo '/oracle' >> "$exclude"
