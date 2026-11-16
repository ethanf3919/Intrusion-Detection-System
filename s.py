
#!/usr/bin/env python3
"""
Terminal Chaos Lab - Ubuntu Server 24.04

Features:
- Matrix-style terminal output
- Colored simulated warnings
- Combined random effects
- Temporary Ctrl+X interrupt mapping
- Optional persistent mapping for current lab user
- Automatic screen restoration
- Maximum 15-second demonstration
- Broadcast simulated warnings using wall

No flashing backgrounds or real system diagnostics.
"""

import argparse
import random
import re
import shutil
import subprocess
import sys
import termios
import time
from pathlib import Path

RESET = "\033[0m"
CLEAR = "\033[2J\033[H"

# Foreground text colors only.
COLORS = [
    "\033[37m",
    "\033[97m",
    "\033[36m",
    "\033[32m",
    "\033[35m",
    "\033[33m",
]

MESSAGES = [
    "[LAB] Simulated service warning",
    "[LAB] Example: connection delayed",
    "[LAB] Simulated authentication error",
    "[LAB] Example: resource usage warning",
    "[LAB] Terminal Chaos demonstration",
    "[LAB] No system configuration changed",
]

CONFIG_START = "# BEGIN TERMINAL CHAOS LAB"
CONFIG_END = "# END TERMINAL CHAOS LAB"


def configure_interrupt_key():
    """Persist Ctrl+X for the current lab user's Bash sessions."""

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
        print("[LAB] Configuration already installed.")
        return

    with bashrc.open("a") as file:
        file.write(configuration)

    print(f"[LAB] Updated {bashrc}")
    print("[LAB] New interactive Bash sessions will use Ctrl+X.")
    print("[LAB] Run 'source ~/.bashrc' to apply it now.")


def remove_interrupt_configuration():
    """Remove the persistent keymap installed by this script."""

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
    """Return terminal dimensions."""

    size = shutil.get_terminal_size((80, 24))

    return (
        min(size.columns, 120),
        min(size.lines, 50),
    )


def banner():
    """Display the simulation banner."""

    print("\033[1;35m")
    print("=" * 50)
    print("             TERMINAL CHAOS LAB")
    print("=" * 50)
    print(RESET)

    print("[LAB] Press Ctrl+X to stop the demonstration.")
    print()


def warnings():
    """Display a randomly colored simulated warning."""

    color = random.choice(COLORS)
    message = random.choice(MESSAGES)

    print(color + message + RESET, flush=True)


def matrix():
    """Display Matrix-style random characters."""

    width, _ = terminal_size()
    chars = "01abcdef"

    line = "".join(
        random.choice(chars)
        for _ in range(max(1, width - 2))
    )

    print("\033[32m" + line + RESET, flush=True)


def remap_interrupt():
    """Temporarily map Ctrl+X to SIGINT."""

    fd = sys.stdin.fileno()

    original = termios.tcgetattr(fd)
    modified = termios.tcgetattr(fd)

    # Ctrl+X is ASCII 24.
    modified[6][termios.VINTR] = 24

    termios.tcsetattr(
        fd,
        termios.TCSANOW,
        modified,
    )

    return original


def restore_interrupt(original):
    """Restore original terminal settings."""

    if original is not None:
        termios.tcsetattr(
            sys.stdin.fileno(),
            termios.TCSANOW,
            original,
        )


def restore_screen():
    """Restore the previous terminal display."""

    sys.stdout.write(RESET)
    sys.stdout.write("\033[?25h")
    sys.stdout.write(CLEAR)
    sys.stdout.write("\033[?1049l")
    sys.stdout.flush()

    print("[LAB] Demonstration ended. Screen restored.")


def broadcast_diagnostics():
    """
    Send one simulated diagnostic notification
    to terminals accepting wall broadcasts.

    Does not execute code in receiving terminals.
    """

    message = (
        "TERMINAL CHAOS LAB - SIMULATION\n"
        "========================================\n"
        "Simulated system diagnostic notification.\n"
        "Example warning: service response delayed.\n"
        "Example warning: connection retry required.\n"
        "\n"
        "These warnings are simulated.\n"
        "No actual system errors have been detected.\n"
        "No services or files have been modified.\n"
        "========================================\n"
    )

    try:
        subprocess.run(
            ["wall"],
            input=message,
            text=True,
            check=True,
            timeout=5,
        )

        print("[LAB] Broadcast submitted successfully.")
        return 0

    except FileNotFoundError:
        print(
            "[LAB] wall command not found.",
            file=sys.stderr,
        )

    except subprocess.TimeoutExpired:
        print(
            "[LAB] Broadcast timed out.",
            file=sys.stderr,
        )

    except subprocess.CalledProcessError as error:
        print(
            f"[LAB] Broadcast failed: {error}",
            file=sys.stderr,
        )

    return 1


def run_demo(mode, seconds):
    """Run visual effects in the current terminal."""

    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print(
            "An interactive terminal is required.",
            file=sys.stderr,
        )
        return 2

    duration = max(1, min(seconds, 15))
    end_time = time.monotonic() + duration

    original_terminal = None
    alternate_screen = False

    try:
        original_terminal = remap_interrupt()

        # Preserve the original terminal screen.
        sys.stdout.write("\033[?1049h")
        sys.stdout.flush()
        alternate_screen = True

        banner()

        if mode == "banner":
            time.sleep(min(duration, 2))
            return 0

        while time.monotonic() < end_time:

            current_mode = mode

            if mode == "combined":
                current_mode = random.choice([
                    "warnings",
                    "matrix",
                ])

            if current_mode == "warnings":
                warnings()

            elif current_mode == "matrix":
                matrix()

            time.sleep(
                min(
                    0.6,
                    max(0, end_time - time.monotonic()),
                )
            )

    except KeyboardInterrupt:
        pass

    finally:
        try:
            restore_interrupt(original_terminal)
        finally:
            if alternate_screen:
                restore_screen()

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Terminal Chaos Lab"
    )

    parser.add_argument(
        "--mode",
        choices=[
            "banner",
            "warnings",
            "matrix",
            "combined",
            "broadcast",
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
        help="Persist Ctrl+X for current lab user",
    )

    group.add_argument(
        "--remove-keymap",
        action="store_true",
        help="Remove persistent Ctrl+X mapping",
    )

    args = parser.parse_args()

    if args.install_keymap:
        configure_interrupt_key()
        return 0

    if args.remove_keymap:
        remove_interrupt_configuration()
        return 0

    if args.mode == "broadcast":
        return broadcast_diagnostics()

    return run_demo(args.mode, args.seconds)


if __name__ == "__main__":
    raise SystemExit(main())
