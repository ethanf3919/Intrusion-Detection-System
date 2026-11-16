
#!/usr/bin/env python3
"""
Linux Terminal Chaos Lab
Ubuntu Server 24.04 LTS

Features:
- Colored simulated warnings
- Matrix-style terminal animation
- Full-screen background colors
- Combined random effects
- Temporary Ctrl+C to Ctrl+X remapping
- Automatic terminal restoration

Runs only in the current interactive terminal.
"""

import argparse
import random
import shutil
import sys
import termios
import time

RESET = "\033[0m"
BOLD = "\033[1m"
CLEAR = "\033[2J\033[H"

COLORS = [
    "\033[41;97m",
    "\033[42;30m",
    "\033[43;30m",
    "\033[44;97m",
    "\033[45;97m",
    "\033[46;30m",
]

BACKGROUNDS = [
    "\033[41m",
    "\033[42m",
    "\033[43m",
    "\033[44m",
    "\033[45m",
    "\033[46m",
]

MESSAGES = [
    "[LAB] Simulated service warning",
    "[LAB] Example: connection delayed",
    "[LAB] Simulated authentication error",
    "[LAB] Example: resource usage warning",
    "[LAB] Terminal Chaos demonstration",
    "[LAB] No system configuration changed",
]


def terminal_size():
    size = shutil.get_terminal_size((80, 24))
    return min(size.columns, 120), min(size.lines, 50)


def banner():
    print(BOLD + "\033[35m")
    print("=" * 45)
    print("         TERMINAL CHAOS LAB")
    print("=" * 45)
    print(RESET)
    print("Press Ctrl+X to exit.")
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
    """Fill the alternate screen with a random color."""
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
    """
    Temporarily change the current terminal's
    interrupt character from Ctrl+C to Ctrl+X.
    """
    fd = sys.stdin.fileno()
    original = termios.tcgetattr(fd)

    modified = termios.tcgetattr(fd)
    modified[6][termios.VINTR] = 24

    termios.tcsetattr(
        fd,
        termios.TCSANOW,
        modified
    )

    return original


def restore_interrupt(original):
    """Restore the original terminal input settings."""
    if original is not None:
        termios.tcsetattr(
            sys.stdin.fileno(),
            termios.TCSANOW,
            original
        )


def restore_screen():
    """Restore the original screen and formatting."""
    sys.stdout.write(RESET)
    sys.stdout.write("\033[?25h")
    sys.stdout.write("\033[?1049l")
    sys.stdout.flush()

    print("[LAB] Demo ended. Terminal restored.")


def main():
    parser = argparse.ArgumentParser(
        description="Linux Terminal Chaos Lab"
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
        help="Duration in seconds (maximum 15)",
    )

    args = parser.parse_args()

    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print(
            "An interactive terminal is required.",
            file=sys.stderr,
        )
        return 2

    duration = max(1, min(args.seconds, 15))
    end_time = time.monotonic() + duration

    original_terminal = None
    alternate_screen = False

    try:
        # Save and temporarily change interrupt key.
        original_terminal = remap_interrupt()

        # Preserve the existing terminal display.
        sys.stdout.write("\033[?1049h")
        sys.stdout.flush()
        alternate_screen = True

        banner()

        if args.mode == "banner":
            time.sleep(min(duration, 2))
            return 0

        while time.monotonic() < end_time:
            mode = args.mode

            if mode == "combined":
                mode = random.choice([
                    "warnings",
                    "matrix",
                    "flash",
                ])

            if mode == "warnings":
                warnings()

            elif mode == "matrix":
                matrix()

            elif mode == "flash":
                color_screen()

            time.sleep(0.6)

    except KeyboardInterrupt:
        pass

    finally:
        # Always restore terminal input configuration.
        try:
            restore_interrupt(original_terminal)
        finally:
            if alternate_screen:
                restore_screen()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
