# Wprof selftests

## Overview

Test harness consists of the following components:
- [`test/selftests.py`](selftests.py) - the launcher script.
- [`test/cases/*.py`](cases/) - Python modules containing the test
  case definitions.
- [`Makefile`](Makefile) - build instructions for "kernel bundles",
  a set of predefined Linux kernel revisions used for testing.
- [`kernel/`](kernel) - configuration fragments for kernel
  bundles compilation.

The test harness runs selftests directly on the host or in a VM.
A VM can boot the host's kernel, a custom-built kernel, or one of the
predefined kernels used in CI.

Test harness allows to:
- Run the tests in parallel across multiple VMs.
- Run the suite locally in the same environment used by CI.
- Connect to a VM over SSH and run individual tests manually to
  investigate failures.

Tests are ordinary Python functions grouped into modules under `test/cases/*.py`.
These functions are supposed to:
- Spawn child processes to execute the `wprof`
- Spawn child processes with workloads triggering various kernel and
  user-space events.
- Inspect captured `wprof` output and assert if it matches the
  test expectations.

## Quick start

### Run the CI suite locally

On an x86-64 Linux host with rootless Podman and access to `/dev/kvm`,
build the CI environment image, compile wprof and the kernel bundles,
then run the eligible tests in two VMs per kernel.

```sh
./test/ci/build-container.sh
./test/ci/with-ci-env.sh make -C test all
./test/ci/with-ci-env.sh python3 -B test/selftests.py --all-kernels --no-hugetlb --vms 2
```

The combined report is `/tmp/wprof-selftests-current/report.json`.

### Add a test and run it on the host kernel in a VM

The host environment must provide:
- Python 3.11+
- virtme-ng
- QEMU
- Compiled wprof ([details](../README.md#building-wprof)).

Save the following under `test/cases/example.py`:

```python
import time

from selftests import Sh, test

@test
def test_background_write(sh: Sh) -> None:
    def write_loop():
        # Spam write system calls every 10 ms.
        with open("/dev/null", "wb", buffering=0) as sink:
            while True:
                sink.write(b"x")
                time.sleep(0.01)

    # Run the workload in a child process.
    writer = sh.fork(write_loop)
    # Start a wprof process to record the writer's write syscall exits.
    process, artifacts = sh.wprof(
        """-d 1s --no-stacks -p $pid
           -U 'tp:syscalls:sys_exit_write | name:write_syscall |'
           -D $data -J $json""",
        pid=writer.pid,
    )
    # wait for wprof to exit (for about one second (`-d 1s`))
    assert process.wait(timeout=130) == 0, artifacts.stderr
    # artifacts.json holds the parsed trace from -J $json, check its contents.
    writes = artifacts.json.select(t="utrace_instant", name="write_syscall")
    assert any(event.task.pid == writer.pid for event in writes), "no write from the worker"
```

Run the test case using the following command:

```sh
make -C test wprof
python3 -B test/selftests.py -t example/test_background_write
```

Which should output:

```sh
selected tests: 1
vm0: example/test_background_write:                                            passed
1 passed, 0 failed, 0 skipped, 0 infrastructure errors
Report: /tmp/wprof-selftests-current/report.json (elapsed time: 6.04s)
```

This command spins up a VM that boots host's `/boot/vmlinuz-$(uname -r)`
with read-only access to host's filesystem, including the shared
libraries under `/usr/lib` and `/lib`, kernel modules under
`/lib/modules/$(uname -r)`, and debug symbols under `/usr/lib/debug`.

## Command-line parameters

Invoke the launcher as `python3 -B test/selftests.py [options]`.

### Kernel selection

By default, the launcher boots `/boot/vmlinuz-$(uname -r)` in a VM.
Choose at most one of the following options to change the target.

| Option                         | Effect and default                                                                                         |
|--------------------------------|------------------------------------------------------------------------------------------------------------|
| `--no-vm`                      | Run the tests directly on the running host kernel. The harness invokes wprof as root or through `sudo -n`. |
| `--kernel IMAGE\|DIR\|@RECIPE` | Boot a VM from an image file, a kernel build directory, or a named bundle.                                 |
| `--all-kernels`                | Run eligible tests on each configured bundle in Makefile order.                                            |

`--kernel` accepts three forms:

- **Image file** (`--kernel /boot/vmlinuz-6.16.0`). Boots that image.
  For an installed kernel, the guest uses the matching modules under
  `/lib/modules/<release>/`.
- **Build directory** (`--kernel ./build`). Boots the kernel from a
  local build after `make bzImage modules`.
- **Bundle name** (`--kernel @v6.16`). Boots one of the CI kernel bundles.
  The bundles have to be compiled beforehand (`make -C test kernel-v6.16`).

### Test filtering

Each test has a set of associated features required by it. A test runs
when its name matches the filter and the kernel provides all the
features it requires. For CI kernel bundles the feature set is
declared in the corresponding [`Makefile`](Makefile) section,
for `--no-vm`, host kernel and `--kernel` runs the feature set is
considered empty, but can be overridden by the `--kernel-features`
parameter.

| Option                         | Effect and default                                                         |
|--------------------------------|----------------------------------------------------------------------------|
| `-t GLOB`                      | Match the `test/cases/*.py` base file name without `.py`. Defaults to `*`. |
| `-t GLOB/GLOB`                 | First glob matches the file name, second glob matches the function.        |
| `--kernel-features [GLOB ...]` | Replace the available features with names matching the supplied globs.     |

For example:
- `-t 'utrace/test_vfs_write_inline_and_outline'`
- `-t 'utrace/*vfs_write*'`
- `-t '*/*vfs_write*'`
- Select `v6.16` kernel bundle and execute the tests from
  `test/cases/utrace.py`, but only if the features required by those
  tests are provided by the `v6.16` bundle:

```
python3 -B test/selftests.py --kernel @v6.16 -t 'utrace/*'
```

- Execute the same tests in the VM using the host's kernel assuming
  that `vfs-write-inlined` feature is defined:

```
python3 -B test/selftests.py -t 'utrace/*' --kernel-features vfs-write-inlined
```

### VM configuration

| Option                           | Effect and default                                                     |
|----------------------------------|------------------------------------------------------------------------|
| `--vms N`                        | Maximum parallel guests per kernel, default 1.                         |
| `--vm-cpus N`, `--vm-memory GiB` | CPUs and RAM per guest, default 2 CPUs and 4 GiB.                      |
| `--vm-timeout SECONDS`           | Timeout for each VM's boot and test execution. Defaults to 5 minutes.  |
| `--no-hugetlb`                   | Disable hugepage backing for guest RAM.                                |

### Filesystem configuration

| Option               | Effect and default                                                                         |
|----------------------|--------------------------------------------------------------------------------------------|
| `--cache-dir DIR`    | Kernel sources and bundles. Defaults to `${XDG_CACHE_HOME:-$HOME/.cache}/wprof-selftests`. |
| `--basetemp DIR`     | Base directory for run reports, VM logs and test artifacts. Defaults to `/tmp`.            |
| `--report-json PATH` | Final JSON report. Defaults to `<basetemp>/wprof-selftests-current/report.json`.           |

Test harness uses `--cache-dir` to check out source code and build CI
kernel bundles. Each bundle's checkout takes about 2 GB, compiled
bundle takes about 400 MB.

Each invocation creates a fresh `<basetemp>/wprof-selftests-current`
If a current directory already exists, the launcher first renames it
to `<basetemp>/wprof-selftests-previous`. Test artifacts include
`std{out,err}` and `wprof` captures. Here is an example of the
directory layout:

```
wprof-selftests-current/
    report.json
    v6.16/
        vm-0.log.gz
        utrace-test_vfs_write_span/
            test-stdout.log.gz
            test-stderr.log.gz
            wprof-stdout.log.gz
            wprof-stderr.log.gz
            trace.json.gz
```

By default artifacts are retained only for failing test cases.

Example `report.json` for an `--all-kernels` run:

```json
{
  "results": [
    {
      "name": "utrace/test_vfs_write_span",
      "artifacts": "v6.16/utrace-test_vfs_write_span",
      "outcome": "failed",
      "complete": true,
      "details": ["...\n    assert write_count >= 20, ...\nAssertionError: write_count=0"],
      "kernel_tag": "@v6.16"
    }
  ],
  "errors": ["v6.18: Incomplete kernel bundle: missing .../bundles/v6.18/bzImage.\nRun ..."],
  "complete": true
}
```

### Other options

| Option             | Effect and default                                                                           |
|--------------------|----------------------------------------------------------------------------------------------|
| `-v`, `--verbose`  | Show selected names, commands, timings and verbose test output.                              |
| `-h`, `--help`     | Print the launcher usage.                                                                    |
| `--ssh [PORT]`     | Prepare a guest VM for manual testing and disable its timeout. The default SSH port is 2222. |
| `--keep-artifacts` | Retain per-test artifacts for both failing and passing cases.                                |
| `--wprof PATH`     | Profiler binary, default `src/wprof` in the checkout.                                        |

## CI kernel bundles

A bundle packages a bootable kernel, its matching modules, debug
image, and the feature names used to select tests. Bundles are defined
in the [`test/Makefile`](Makefile) as follows:

```make
KERNEL_TAGS := v6.16 ...
...
kernel-v6.16: revision := 038d61fd642278bab63ee8ef722c50d10ab01e8f
kernel-v6.16: configs := $(COMMON_CONFIGS) kernel/v6.16/autofdo.config
kernel-v6.16: profile := kernel/v6.16/vfs_write.prof
kernel-v6.16: features := vfs-write-inlined
```

- `revision` pins the Linux Git commit.
- `configs` lists the kernel configuration fragments to apply on top
  of `x86_64_defconfig`.
- `profile` optionally supplies an LLVM sample profile to Kbuild through
  `CLANG_AUTOFDO_PROFILE`. Here `vfs_write.prof` guides Clang to inline
  `vfs_write` on the write path.
- `features` lists the space-separated feature names used for
  test selection, such as those marked `@test(requires=["vfs-write-inlined"])`.

The following targets are available:

```sh
make -C test kernel-v6.16       # build the bundle for tag v6.16
make -C test kernels            # build all bundles
make -C test wprof              # build wprof

make -C test clean-kernel-v6.16 # remove the bundle for tag v6.16
make -C test clean-kernels      # remove all configured bundles
make -C test clean-sources      # remove the kernel source checkouts
make -C test clean              # remove all configured bundles and run make -C src clean
make -C test clean-all          # remove all configured bundles and source checkouts and run make -C src clean-all
```

The kernel series of targets manages kernel source code checkout
getting the code either from the internet mirror, or from a repository
specified by the `KERNEL_REPO` variable.

The bundles are compiled and stored under the directory controlled by
`CACHE_DIR` variable, which defaults to
`${XDG_CACHE_HOME:-$HOME/.cache}/wprof-selftests`:

```
<cache>/
  linux-v6.16/                 source checkout at the pinned revision.
  bundles/v6.16/               bundle contents.
```

## SSH into a VM

It is possible to obtain SSH access into the test VM, e.g. issue the
following command:

```sh
# This starts a single guest VM with selected kernel.
# The VM waits for SSH connection.
python3 -B test/selftests.py --ssh 2222 -t 'utrace/test_udp_diag*'
```

Connect to the VM via one of the following commands:
- `vng --ssh-client 2222 --ssh-tcp`
- `ssh -F ~/.cache/virtme-ng/.ssh/virtme-ng-ssh.conf -p 2222 virtme-ng`
- `./test/ci/with-ci-env.sh ssh -p 2222 root@localhost`
  if VM was started in the CI container.

At the guest prompt, run the guest-local prepared script:

```sh
# Encapsulates test selection from the `-t` parameter.
/tmp/run-selftests.sh
```

## GitHub CI integration

### CI environment image

`./test/ci/build-container.sh` builds the local Podman image
`localhost/wprof-selftests:ci`. It provides Debian Trixie, virtme-ng,
QEMU, kernel build dependencies, Rust, Cargo and LLVM 21.

The image can be configured to accommodate local runs from the
environments where access to standard apt repositories is blocked.
Build script looks for configuration file under the following
locations:
- `$WPROF_TEST_CONFIG` environment variable.
- `${XDG_CONFIG_HOME:-$HOME/.config}/wprof-selftests/config`.

The following can be configured:

```sh
DEBIAN_MIRROR=<your-debian-mirror>
APT_PROXY=<proxy-mode>
APT_CA_FILE=<your-certificate-for-the-mirror>
```

### with-ci-env.sh

Test harness uses a wrapper script to execute build and test commands
locally and on CI machines within an identical environment:

`./test/ci/with-ci-env.sh [--ro-dir DIR | --rw-dir DIR]... [--] COMMAND [ARG...]`
runs a command in the caller's working directory inside the local CI
environment image using Podman.

The idea is to allow transparent build and test commands execution:
- Using either the host environment:
```sh
make -C test all
python3 -B test/selftests.py --all-kernels --no-hugetlb --vms 2
```
- Or using the CI environment:
```sh
./test/ci/build-container.sh
./test/ci/with-ci-env.sh make -C test all
./test/ci/with-ci-env.sh python3 -B test/selftests.py --all-kernels --no-hugetlb --vms 2
```

The wrapper can be executed by an ordinary non-root user and shares
the following with the host:
- Networking configuration;
- one-to-one mount points for the following directories:
  - Repository checkout (read/write), in order to share `src/wprof`
    and its build outputs.
  - Kernel and Cargo build cache
    (`${XDG_CACHE_HOME:-$HOME/.cache}/wprof-selftests`, read/write).
  - `/tmp` (read/write), in order to share test run artifacts.
  - `/boot`, `/lib/modules` (read only), in order to allow booting
    from the host kernel.
  - Any directories specified as `--rw-dir DIR`, `--ro-dir`.
  - `/dev/kvm`.

For example, here is how to use local kernel repository to check out
source for the kernel bundle from a local repository instead of a
network mirror:

```sh
./test/ci/with-ci-env.sh --ro-dir "$HOME/bpf-next" -- \
    make -C test kernel-v6.16 KERNEL_REPO="$HOME/bpf-next"
```

### Current GitHub workflow

The `selftests` workflow runs on pull requests and pushes to `master`.
The workflow is designed to:
- Execute the tests for each registered kernel bundle.
- Cache CI environment image.
- Cache kernel bundle artifacts.

[Selftests workflow](../.github/workflows/selftests.yml)
