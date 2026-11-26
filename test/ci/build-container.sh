#!/bin/bash
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)

BASE_IMAGE=
DEBIAN_MIRROR=http://deb.debian.org
APT_PROXY=
APT_CA_FILE=

config=${WPROF_TEST_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/wprof-selftests/config}
if [[ -f "$config" ]]; then
    source "$config"
fi

context=$(mktemp -d)
trap 'rm -rf "$context"' EXIT
cp "$repo/test/ci/Dockerfile" "$context/"
mkdir -p "$context/apt/apt.conf.d" "$context/apt/sources.list.d"

mirror=${DEBIAN_MIRROR%/}
cat > "$context/apt/sources.list.d/debian.sources" <<EOF
Types: deb
URIs: $mirror/debian
Suites: trixie trixie-updates trixie-backports
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp

Types: deb
URIs: $mirror/debian-security
Suites: trixie-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp
EOF
scheme=${DEBIAN_MIRROR%%:*}
mirror_host=$(python3 -c 'import sys, urllib.parse; print(urllib.parse.urlsplit(sys.argv[1]).hostname)' "$DEBIAN_MIRROR")
if [[ -n $APT_PROXY ]]; then
    printf 'Acquire::%s::Proxy::%s "%s";\n' "$scheme" "$mirror_host" "$APT_PROXY" \
        >> "$context/apt/apt.conf.d/99wprof-mirror"
fi
if [[ -n $APT_CA_FILE ]]; then
    cp "$APT_CA_FILE" "$context/apt/wprof-ca.pem"
    printf 'Acquire::https::%s::CAInfo "/etc/apt/wprof-ca.pem";\n' "$mirror_host" \
        >> "$context/apt/apt.conf.d/99wprof-mirror"
fi
# Let APT's _apt user read these files even with a restrictive build-time umask.
chmod -R a+rX "$context/apt"

optional_args=()
if [[ -n $BASE_IMAGE ]]; then
    optional_args=(--build-arg "BASE_IMAGE=$BASE_IMAGE")
fi
podman build --layers --network=host --tag localhost/wprof-selftests:ci "${optional_args[@]}" "$context"
