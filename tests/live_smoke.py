"""Run a short privileged loopback capture against generated UDP traffic."""

import select
import socket
import subprocess
import sys


def main() -> None:
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    port = receiver.getsockname()[1]
    process = subprocess.Popen(
        [sys.argv[1], "-i", "lo", "--filter", f"udp port {port}", "--count", "5", "--workers", "2"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        if not select.select([process.stdout], [], [], 10)[0]:
            raise AssertionError("NetScope did not start a loopback capture")
        first_line = process.stdout.readline()
        if "Capturing lo" not in first_line:
            raise AssertionError(f"Unexpected startup output: {first_line!r}")
        for _ in range(30):
            sender.sendto(b"netscope-live-test", ("127.0.0.1", port))
        output, errors = process.communicate(timeout=10)
        output = first_line + output
        if process.returncode != 0:
            raise AssertionError(f"NetScope failed ({process.returncode}):\n{errors}\n{output}")
        for expected in ("Captured: 5", "Processed: 5", "Queue dropped: 0", "UDP: 5"):
            if expected not in output:
                raise AssertionError(f"Missing {expected!r}:\n{errors}\n{output}")
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
        receiver.close()
        sender.close()


if __name__ == "__main__":
    main()
