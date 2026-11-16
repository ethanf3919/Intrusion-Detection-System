
#!/usr/bin/env python3
"""
Terminal Chaos Lab - Diagnostic Edition
Ubuntu Server 24.04

Features:
- Fake system diagnostics and progress bars
- Simulated errors and warnings
- Matrix-style terminal output
- Combined random effects
- Ctrl+X exit shortcut
- Ctrl+C emergency stop
- Automatic terminal restoration
- Maximum 15-second runtime

All diagnostics are simulated.
"""

import argparse
import random
import select
import shutil
import sys
import termios
import time
import tty

RESET = "\033[0m"

MESSAGES = [
    "[SIMULATION] ERROR: Connection refused",
    "[SIMULATION] WARNING: Unexpected process activity",
    "[SIMULATION] ERROR: Authentication failed",
    "[SIMULATION] WARNING: Service response delayed",
    "[SIMULATION] ERROR: Network timeout",
    "[SIMULATION] WARNING: Resource usage elevated",
    "[SIMULATION] ERROR: Dependency verification failed",
    "[SIMULATION] WARNING: Additional verification required",
]

CHECKS = [
    "Checking system integrity",
    "Analyzing network interfaces",
    "Checking SSH connectivity",
    "Inspecting running processes",
    "Verifying filesystem health",
    "Checking service dependencies",
    "Analyzing system logs",
    "Testing DNS resolution",
    "Checking memory allocation",
    "Verifying network connections",
    "Checking Postfix service status",
    "Inspecting firewall configuration",
]

RESULTS = [
    "WARNING: Response delayed",
    "ERROR: Simulated timeout",
    "WARNING: Unexpected response",
    "ERROR: Simulated connection failure",
    "WARNING: Retry required",
    "NOTICE: Additional verification needed",
]


def terminal_size():
    size = shutil.get_terminal_size((80, 24))
    return min(size.columns, 120), min(size.lines, 50)


def banner():
    print("=" * 55)
    print("                  TERMINAL CHAOS LAB")
    print("                  DIAGNOSTIC EDITION")
    print("=" * 55)
    print("[LAB] All diagnostic results are simulated.")
    print("[LAB] Press Ctrl+X to exit.")
    print("[LAB] Ctrl+C remains available for emergencies.\n")


def warnings():
    print(random.choice(MESSAGES), flush=True)


def matrix():
    width, _ = terminal_size()
    characters = "01abcdef"

    line = "".join(
        random.choice(characters)
        for _ in range(max(1, width - 2))
    )

    print(line, flush=True)


def check_exit_key():
    """
    Check whether Ctrl+X has been pressed.
    Requires terminal cbreak mode.
    """
    if select.select([sys.stdin], [], [], 0)[0]:
        key = sys.stdin.read(1)
        return key == "\x18"

    return False


def wait_or_exit(seconds, deadline):
    """
    Wait in short intervals so Ctrl+X can
    interrupt even during progress bars.
    """
    end = min(time.monotonic() + seconds, deadline)

    while time.monotonic() < end:
        if check_exit_key():
            return True

        time.sleep(
            min(0.025, max(0, end - time.monotonic()))
        )

    return check_exit_key()


def fake_diagnostics(deadline):
    """Perform one entirely simulated diagnostic check."""

    check = random.choice(CHECKS)
    print(f"\n[DIAGNOSTIC] {check}...")

    for progress in range(0, 101, 10):
        if time.monotonic() >= deadline:
            print()
            return False

        filled = progress // 5
        bar = "#" * filled + "-" * (20 - filled)

        sys.stdout.write(
            f"\r[{bar}] {progress:3d}%"
        )
        sys.stdout.flush()

        if wait_or_exit(0.12, deadline):
            print()
            return True

    print()
    print("[SIMULATION] " + random.choice(RESULTS))
    print("[DIAGNOSTIC] Retrying verification...\n")

    return False


def restore_screen():
    """Restore original terminal display."""
    sys.stdout.write(RESET)
    sys.stdout.write("\033[?25h")
    sys.stdout.write("\033[?1049l")
    sys.stdout.flush()

    print("[LAB] Demonstration ended. Terminal restored.")


def run_demo(mode, seconds):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print(
            "An interactive terminal is required.",
            file=sys.stderr,
        )
        return 2

    duration = max(1, min(seconds, 15))
    deadline = time.monotonic() + duration

    fd = sys.stdin.fileno()
    original_settings = termios.tcgetattr(fd)
    alternate_screen = False

    try:
        # Enable reading individual keypresses.
        # Ctrl+C remains an emergency interrupt.
        tty.setcbreak(fd)

        # Switch to an alternate terminal screen.
        sys.stdout.write("\033[?1049h")
        sys.stdout.flush()
        alternate_screen = True

        banner()

        if mode == "banner":
            wait_or_exit(min(duration, 2), deadline)
            return 0

        while time.monotonic() < deadline:
            if check_exit_key():
                break

            current_mode = mode

            if mode == "combined":
                current_mode = random.choice([
                    "warnings",
                    "matrix",
                    "diagnostics",
                ])

            if current_mode == "warnings":
                warnings()

            elif current_mode == "matrix":
                matrix()

            elif current_mode == "diagnostics":
                if fake_diagnostics(deadline):
                    break

            if wait_or_exit(0.4, deadline):
                break

    except KeyboardInterrupt:
        pass

    finally:
        try:
            termios.tcsetattr(
                fd,
                termios.TCSANOW,
                original_settings,
            )
        finally:
            if alternate_screen:
                restore_screen()

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Terminal Chaos Lab - Diagnostic Edition"
    )

    parser.add_argument(
        "--mode",
        choices=[
            "banner",
            "warnings",
            "matrix",
            "diagnostics",
            "combined",
        ],
        default="combined",
    )

    parser.add_argument(
        "--seconds",
        type=int,
        default=10,
        help="Duration in seconds (maximum 15)",
    )

    args = parser.parse_args()

    return run_demo(args.mode, args.seconds)


if __name__ == "__main__":
    raise SystemExit(main())
