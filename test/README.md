# Wprof selftests

## Overview

Test harness consists of the following components:
- [`test/selftests.py`](selftests.py) - the launcher script.
- [`test/cases/*.py`](cases/) - Python modules containing the test
  case definitions.

The test harness runs selftests directly on the host or in a VM.

Test harness allows to:
- Run the tests in parallel across multiple VMs.
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

| Option                         | Effect and default                                                                                         |
|--------------------------------|------------------------------------------------------------------------------------------------------------|
| `--no-vm`                      | Run the tests directly on the running host kernel. The harness invokes wprof as root or through `sudo -n`. |
| `--kernel IMAGE\|DIR`          | Boot a VM from an image file or a kernel build directory.                                                 |

- **Image file** (`--kernel /boot/vmlinuz-6.16.0`). Boots that image.
  For an installed kernel, the guest uses the matching modules under
  `/lib/modules/<release>/`.
- **Build directory** (`--kernel ./build`). Boots the kernel from a
  local build after `make bzImage modules`.

### Test filtering

| Option                         | Effect and default                                                         |
|--------------------------------|----------------------------------------------------------------------------|
| `-t GLOB`                      | Match the `test/cases/*.py` base file name without `.py`. Defaults to `*`. |
| `-t GLOB/GLOB`                 | First glob matches the file name, second glob matches the function.        |

For example:
- `-t 'utrace/test_vfs_write_inline_and_outline'`
- `-t 'utrace/*vfs_write*'`
- `-t '*/*vfs_write*'`

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
| `--basetemp DIR`     | Base directory for run reports, VM logs and test artifacts. Defaults to `/tmp`.            |
| `--report-json PATH` | Final JSON report. Defaults to `<basetemp>/wprof-selftests-current/report.json`.           |

Each invocation creates a fresh `<basetemp>/wprof-selftests-current`
If a current directory already exists, the launcher first renames it
to `<basetemp>/wprof-selftests-previous`. Test artifacts include
`std{out,err}` and `wprof` captures. Here is an example of the
directory layout:

```
wprof-selftests-current/
    report.json
```

By default artifacts are retained only for failing test cases.

### Other options

| Option             | Effect and default                                                                           |
|--------------------|----------------------------------------------------------------------------------------------|
| `-v`, `--verbose`  | Show selected names, commands, timings and verbose test output.                              |
| `-h`, `--help`     | Print the launcher usage.                                                                    |
| `--ssh [PORT]`     | Prepare a guest VM for manual testing and disable its timeout. The default SSH port is 2222. |
| `--keep-artifacts` | Retain per-test artifacts for both failing and passing cases.                                |
| `--wprof PATH`     | Profiler binary, default `src/wprof` in the checkout.                                        |

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

At the guest prompt, run the guest-local prepared script:

```sh
# Encapsulates test selection from the `-t` parameter.
/tmp/run-selftests.sh
```
