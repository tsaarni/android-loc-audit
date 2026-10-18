"""adb access. The only module that talks to the phone.

Everything here is read-only unless a caller passes a command that writes. Commands used by the
tool: getprop, pm list packages, dumpsys, pm path, cmd package, adb pull. None of them change the
phone.
"""
import subprocess


class DeviceError(RuntimeError):
    """The phone is missing, unauthorised, or an adb command failed."""


def adb(*args, serial=None, timeout=600, binary=False):
    """Run one adb command and return its output.

    Line endings are normalised once, here: `adb shell` emits CRLF, and a stray \r breaks every
    exact comparison later (docs/reference/pitfalls.md#crlf-in-adb-output).
    """
    cmd = ["adb"] + (["-s", serial] if serial else []) + list(args)
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        raise DeviceError("adb not found in PATH")
    except subprocess.TimeoutExpired:
        raise DeviceError(f"adb timed out after {timeout}s: {' '.join(args)}")
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip() or "no stderr"
        raise DeviceError(f"adb {' '.join(args)} failed: {detail}")
    if binary:
        return proc.stdout
    text = proc.stdout.decode("utf-8", "replace")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def shell(command, **kwargs):
    return adb("shell", command, **kwargs)


def devices():
    """[(serial, state)] as `adb devices` reports them."""
    rows = []
    for line in adb("devices").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            rows.append((parts[0], parts[1]))
    return rows


def one_device():
    """The serial of the single authorised phone. Refuses zero or several."""
    rows = devices()
    ready = [serial for serial, state in rows if state == "device"]
    if len(ready) == 1:
        return ready[0]
    if not ready:
        shown = ", ".join(f"{s} ({st})" for s, st in rows) or "none"
        raise DeviceError(f"no authorised phone; adb devices shows: {shown}. "
                          "Unlock the phone and accept the USB debugging prompt.")
    raise DeviceError(f"{len(ready)} authorised phones ({', '.join(ready)}); "
                      "connect exactly one so a capture belongs to one device")
