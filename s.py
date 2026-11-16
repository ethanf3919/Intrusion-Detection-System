
#!/usr/bin/env python3
"""
Terminal Chaos Lab - Ubuntu Server 24.04

Features:
- Matrix-style terminal output
- Colored simulated warnings
- Full-screen color effects
- Combined random effects
- Ctrl+X interrupt mapping
- Optional persistent mapping for current user
- Automatic screen restoration
- Maximum 15-second runtime

Use only in an authorized test terminal.
"""

import argparse
import random
import re
import shutil
import sys
import termios
import time
from pathlib import Path

RESET = "\033[0m"
CLEAR = "\033[2J\033[H"

COLORS = [
    "\033[47;30m",       # Light gray background, black text
    "\033[107;30m",      # White background, black text
    "\033[48;5;153;30m", # Pastel blue
    "\033[48;5;151;30m", # Pastel green
    "\033[48;5;225;30m", # Pastel pink
    "\033[48;5;230;30m", # Pale yellow
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
    """Persist Ctrl+X for the current user's Bash sessions."""

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
    """Remove the configuration installed by this script."""

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
        print("[LAB] Persistent interrupt mapping removed.")
        print("[LAB] Run: stty intr '^C'")
    else:
        print("[LAB] No installed mapping found.")


def terminal_size():
    size = shutil.get_terminal_size((80, 24))
    return min(size.columns, 120), min(size.lines, 50)


def banner():
    print("\033[1;35m")
    print("=" * 45)
    print("          TERMINAL CHAOS LAB")
    print("=" * 45)
    print(RESET)
    print("Press Ctrl+X to stop the demonstration.")
    print()


def warnings():
    color = random.choice(COLORS)
    message = random.choice(MESSAGES)

    print(color + message + RESET, flush=True)


def matrix():
    width, _ = terminal_size()

    chars = "01abcdef"

    line = "".join(
        random.choice(chars)
        for _ in range(max(1, width - 2))
    )

    print("\033[32m" + line + RESET, flush=True)


def color_screen():
    """Display a random full-screen background color."""

    width, height = terminal_size()
    color = random.choice(BACKGROUNDS)

    sys.stdout.write(CLEAR)
    sys.stdout.write(color)

    for row in range(height):
        sys.stdout.write(" " * max(1, width - 1))

        if row < height - 1:
            sys.stdout.write("\n")

    sys.stdout.write(RESET)
    sys.stdout.flush()


def remap_interrupt():
    """Temporarily map Ctrl+X to SIGINT."""

    fd = sys.stdin.fileno()

    original = termios.tcgetattr(fd)
    modified = termios.tcgetattr(fd)

    # ASCII 24 represents Ctrl+X.
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
    """Reset colors and restore the previous display."""

    sys.stdout.write(RESET)
    sys.stdout.write("\033[?25h")
    sys.stdout.write(CLEAR)
    sys.stdout.write("\033[?1049l")
    sys.stdout.flush()

    print("[LAB] Demonstration ended. Screen restored.")


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

        # Switch to an alternate screen.
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
                    "flash",
                ])

            if current_mode == "warnings":
                warnings()

            elif current_mode == "matrix":
                matrix()

            elif current_mode == "flash":
                color_screen()

            time.sleep(
                min(0.6, max(0, end_time - time.monotonic()))
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
            "flash",
            "combined",
        ],
        default="combined",
    )

    parser.add_argument(
        "--seconds",
        type=int,
        default=10,
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
        help="Remove the persistent mapping",
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
