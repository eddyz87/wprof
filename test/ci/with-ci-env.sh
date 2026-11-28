#!/bin/bash
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cache_home=$(realpath -ms -- "${XDG_CACHE_HOME:-$HOME/.cache}")
cache=$cache_home/wprof-selftests
image=localhost/wprof-selftests:ci

declare -A dirs=(["$repo"]=rw ["$cache"]=rw [/tmp]=rw)
if [[ -d /boot ]]; then dirs[/boot]=ro; fi
if [[ -d /lib/modules ]]; then dirs[/lib/modules]=ro; fi

usage() {
    echo "usage: ${0##*/} [--ro-dir DIR | --rw-dir DIR]... [--] COMMAND [ARG...]" >&2
    exit 2
}

while (($#)); do
    case $1 in
        --ro-dir|--rw-dir)
            (($# >= 2)) || usage
            if [[ ! -d $2 ]]; then
                echo "$1: directory does not exist: $2" >&2
                exit 2
            fi
            dir=$(realpath -ms -- "$2")
            if [[ $1 == --ro-dir ]]; then dirs["$dir"]=ro; else dirs["$dir"]=rw; fi
            shift 2 ;;
        --) shift; break ;;
        -*) usage ;;
        *) break ;;
    esac
done
(($#)) || usage

mkdir -p -- "$cache/home" "$cache/cargo"
mounts=()
for dir in "${!dirs[@]}"; do
    # Podman parses --mount as CSV. Quote path fields including embedded quotes.
    path=${dir//\"/\"\"}
    mounts+=(--mount "type=bind,\"src=$path\",\"dst=$path\",${dirs[$dir]}")
done
if [[ -r /dev/kvm && -w /dev/kvm ]]; then mounts+=(--device /dev/kvm); fi
image_id=$(podman image inspect --format '{{.Id}}' "$image")

tty_args=()
if [[ -t 0 && -t 1 ]]; then tty_args=(-it); fi
# virtme-ng looks up SSH keys through the passwd entry even when HOME is set.
passwd_entry="\$USERNAME:*:\$UID:\$GID:\$NAME:$cache/home:/bin/sh"
exec podman run "${tty_args[@]}" --rm --init --pull=never --network=host --pids-limit=-1 \
    --userns=keep-id --passwd-entry "$passwd_entry" --group-add=keep-groups "${mounts[@]}" \
    --env "HOME=$cache/home" --env "CARGO_HOME=$cache/cargo" \
    --env "XDG_CACHE_HOME=$cache_home" --env "WPROF_IMAGE_ID=$image_id" \
    --workdir "$PWD" "$image" "$@"
