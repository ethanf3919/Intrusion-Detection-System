
#!/usr/bin/env python3
"""
Terminal Chaos Lab - Ubuntu Server 24.04

Features:
- Fake system diagnostics
- Simulated Linux errors and warnings
- Matrix-style terminal output
- Progress bars and simulated retries
- Combined random effects
- Optional persistent Ctrl+X mapping for current user
- Automatic screen restoration
- Maximum 15-second runtime

All diagnostic results are simulated.
No actual services or system settings are modified
by the visual demonstration.
"""

import argparse
import random
import re
import shutil
import sys
import time
from pathlib import Path

RESET = "\033[0m"

CONFIG_START = "# BEGIN TERMINAL CHAOS LAB"
CONFIG_END = "# END TERMINAL CHAOS LAB"

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


def configure_interrupt_key():
    """
    Persist Ctrl+X as the interrupt key for
    the current user's interactive Bash sessions.
    """

    bashrc = Path.home() / ".bashrc"

    configuration = (
        f"\n{CONFIG_START}\n"
        "if [[ $- == *i* ]]; then\n"
        "    stty intr '^X' 2>/dev/null\n"
        "fi\n"
        f"{CONFIG_END}\n"
    )

    existing = bashrc.read_text() if bashrc.exists() else ""

    if CONFIG_START in existing:
        print("[LAB] Keymap configuration already installed.")
        return

    with bashrc.open("a") as file:
        file.write(configuration)

    print(f"[LAB] Updated {bashrc}")
    print("[LAB] New Bash sessions will use Ctrl+X.")
    print("[LAB] Run 'source ~/.bashrc' to apply it now.")


def remove_interrupt_configuration():
    """Remove the configuration added by this script."""

    bashrc = Path.home() / ".bashrc"

    if not bashrc.exists():
        print("[LAB] No Bash configuration found.")
        return

    existing = bashrc.read_text()

    pattern = (
        r"\n?"
        + re.escape(CONFIG_START)
        + r".*?"
        + re.escape(CONFIG_END)
        + r"\n?"
    )

    updated, count = re.subn(
        pattern,
        "\n",
        existing,
        flags=re.DOTALL,
    )

    if count:
        bashrc.write_text(updated)
        print("[LAB] Persistent keymap removed.")
        print("[LAB] Restore Ctrl+C using: stty intr '^C'")
    else:
        print("[LAB] No installed keymap found.")


def terminal_size():
    size = shutil.get_terminal_size((80, 24))
    return min(size.columns, 120), min(size.lines, 50)


def banner():
    print("=" * 55)
    print("                  TERMINAL CHAOS LAB")
    print("                  DIAGNOSTIC EDITION")
    print("=" * 55)
    print("[LAB] All messages and diagnostic results are simulated.")
    print("[LAB] Press Ctrl+C to stop.\n")


def warnings():
    """Display a simulated system warning."""

    print(random.choice(MESSAGES), flush=True)


def matrix():
    """Print a line of random characters."""

    width, _ = terminal_size()

    characters = "01abcdef"

    line = "".join(
        random.choice(characters)
        for _ in range(max(1, width - 2))
    )

    print(line, flush=True)


def fake_diagnostics(deadline):
    """
    Run one simulated diagnostic check with
    a progress bar and simulated result.
    """

    check = random.choice(CHECKS)

    print(f"\n[DIAGNOSTIC] {check}...")

    for progress in range(0, 101, 10):
        if time.monotonic() >= deadline:
            print()
            return

        filled = progress // 5

        bar = (
            "#" * filled
            + "-" * (20 - filled)
        )

        sys.stdout.write(
            f"\r[{bar}] {progress:3d}%"
        )
        sys.stdout.flush()

        time.sleep(
            min(
                0.12,
                max(0, deadline - time.monotonic())
            )
        )

    print()
    print("[SIMULATION] " + random.choice(RESULTS))
    print("[DIAGNOSTIC] Retrying verification...\n")


def restore_screen():
    """Restore the original terminal display."""

    sys.stdout.write(RESET)
    sys.stdout.write("\033[?25h")
    sys.stdout.write("\033[?1049l")
    sys.stdout.flush()

    print("[LAB] Demonstration ended. Terminal restored.")


def run_demo(mode, seconds):
    """Run effects in the current interactive terminal."""

    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print(
            "An interactive terminal is required.",
            file=sys.stderr,
        )
        return 2

    duration = max(1, min(seconds, 15))
    deadline = time.monotonic() + duration

    alternate_screen = False

    try:
        # Preserve the original terminal screen.
        sys.stdout.write("\033[?1049h")
        sys.stdout.flush()

        alternate_screen = True

        banner()

        if mode == "banner":
            time.sleep(min(duration, 2))
            return 0

        while time.monotonic() < deadline:
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
                fake_diagnostics(deadline)

            remaining = deadline - time.monotonic()

            if remaining > 0:
                time.sleep(min(0.4, remaining))

    except KeyboardInterrupt:
        pass

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

    group = parser.add_mutually_exclusive_group()

    group.add_argument(
        "--install-keymap",
        action="store_true",
        help="Persist Ctrl+X for the current lab user",
    )

    group.add_argument(
        "--remove-keymap",
        action="store_true",
        help="Remove the persistent Ctrl+X mapping",
    )

    args = parser.parse_args()

    if args.install_keymap:
        configure_interrupt_key()
        return 0

    if args.remove_keymap:
        remove_interrupt_configuration()
        return 0

    return run_demo(args.mode, args.seconds)


if __name__ == "__main__":
    raise SystemExit(main())
