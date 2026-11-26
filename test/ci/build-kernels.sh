#!/bin/bash
set -euo pipefail

read_recipe() {
    local cache test_dir config checksums
    local -a files=(ci/build-kernels.sh)

    cache=$(realpath -m -- "$1")
    tag=$2
    repo=$3
    revision=$4
    profile=$5
    features=$6
    shift 6
    source_dir=$cache/linux-$tag
    bundle=$cache/bundles/$tag
    marker=$bundle/build-inputs
    test_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

    configs=()
    for config in "$@"; do
        configs+=("$(realpath -- "$config")")
        files+=("$(realpath --relative-to="$test_dir" -- "$config")")
    done
    if [[ -n $profile ]]; then
        profile=$(realpath -- "$profile")
        files+=("$(realpath --relative-to="$test_dir" -- "$profile")")
    fi
    checksums=$(cd "$test_dir" && sha256sum -- "${files[@]}")
    inputs=("tag=$tag" "revision=$revision" "features=$features" "configs=$#" "$checksums")
}

checkout_source() {
    git init -q "$source_dir"
    # Skip the fetch when the pinned commit is already available locally.
    if ! git -C "$source_dir" cat-file -e "$revision^{commit}" 2>/dev/null; then
        if [[ -d $repo ]]; then repo=$(realpath -- "$repo"); fi
        git -C "$source_dir" fetch --no-tags --depth=1 "$repo" "$revision"
    fi
    git -C "$source_dir" checkout -q --detach "$revision"
}

build_kernel() {
    build_dir=$(mktemp -d "${TMPDIR:-/tmp}/wprof-build-$tag-XXXXXXXX")
    build_dir=$(realpath -- "$build_dir")
    trap 'rm -rf -- "$build_dir"' EXIT

    # v6.16's host libbpf predates glibc 2.43's const-preserving string macros.
    make_args=(-C "$source_dir" O="$build_dir" ARCH=x86 LLVM=1
               HOSTCFLAGS=-Wno-error=incompatible-pointer-types-discards-qualifiers)
    if [[ -n $profile ]]; then
        make_args+=("CLANG_AUTOFDO_PROFILE=$profile")
    fi

    make "${make_args[@]}" x86_64_defconfig
    # merge_config.sh creates temporary files in its working directory.
    (
        cd "$build_dir"
        "$source_dir/scripts/kconfig/merge_config.sh" -m -O "$build_dir" "$build_dir/.config" "${configs[@]}"
    )
    make "${make_args[@]}" olddefconfig
    make "${make_args[@]}" -j bzImage modules
}

install_bundle() {
    local release modules_dir

    release=$(make -s --no-print-directory "${make_args[@]}" kernelrelease)
    # Leave the previous bundle usable through compilation. Once installation starts,
    # a missing build-inputs marker makes an interrupted install retryable.
    rm -f -- "$marker"
    rm -rf -- "$bundle"
    mkdir -p -- "$bundle"
    make "${make_args[@]}" INSTALL_MOD_PATH="$bundle" INSTALL_MOD_STRIP=1 modules_install
    modules_dir="$bundle/lib/modules/$release"
    rm -f "$modules_dir/build" "$modules_dir/source"
    cp "$build_dir/vmlinux" "$modules_dir/vmlinux-$release"
    cp "$build_dir/arch/x86/boot/bzImage" "$build_dir/.config" "$bundle/"
    printf '%s\n' "$release" > "$bundle/release"
    printf '%s\n' "$features" > "$bundle/features"
    printf '%s\n' "${inputs[@]}" > "$marker"
}

read_recipe "$@"
if printf '%s\n' "${inputs[@]}" | cmp -s - "$marker"; then
    echo "Using cached kernel: $bundle"
    exit 0
fi

echo "Building $tag at $revision"
checkout_source
build_kernel
install_bundle
