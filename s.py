
#!/usr/bin/env python3
"""
Terminal Chaos Lab
Ubuntu Server 24.04 LTS

Visual terminal effects for an interactive lab session.
No changes to services, keyboard input, or other users.
"""

import argparse
import random
import shutil
import sys
import time

RESET = "\033[0m"
BOLD = "\033[1m"
CLEAR = "\033[2J\033[H"

COLORS = [
    "\033[41;97m",  # Red background, white text
    "\033[42;30m",  # Green background, black text
    "\033[43;30m",  # Yellow background, black text
    "\033[44;97m",  # Blue background, white text
    "\033[45;97m",  # Purple background, white text
    "\033[46;30m",  # Cyan background, black text
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
    print("       TERMINAL CHAOS LAB")
    print("=" * 45)
    print(RESET)


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
    """
    Fill the current terminal viewport with a
    randomly selected background color.
    """
    width, height = terminal_size()

    backgrounds = [
        "\033[41m",
        "\033[42m",
        "\033[43m",
        "\033[44m",
        "\033[45m",
        "\033[46m",
    ]

    color = random.choice(backgrounds)

    # Save the current screen when supported.
    # Move home and clear the demonstration viewport.
    sys.stdout.write(CLEAR)
    sys.stdout.write(color)

    for row in range(height):
        sys.stdout.write(" " * max(1, width - 1))
        if row < height - 1:
            sys.stdout.write("\n")

    sys.stdout.write(RESET)
    sys.stdout.flush()


def restore():
    """
    Restore the alternate screen and reset
    terminal formatting.
    """
    sys.stdout.write(RESET)
    sys.stdout.write("\033[?25h")
    sys.stdout.write("\033[?1049l")
    sys.stdout.flush()

    print("[LAB] Demo ended. Terminal restored.")


def main():
    parser = argparse.ArgumentParser(
        description="Terminal Chaos Lab visual simulator"
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
        default="banner",
    )

    parser.add_argument(
        "--seconds",
        type=int,
        default=5,
        help="Duration in seconds (maximum 15)",
    )

    args = parser.parse_args()

    if not sys.stdout.isatty():
        print(
            "An interactive terminal is required.",
            file=sys.stderr,
        )
        return 2

    duration = max(1, min(args.seconds, 15))
    end_time = time.monotonic() + duration

    # Use an alternate terminal screen to preserve
    # the original display where supported.
    sys.stdout.write("\033[?1049h")
    sys.stdout.flush()

    try:
        banner()

        if args.mode == "banner":
            print("[LAB] Terminal demonstration active.")
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
        print("\n[LAB] Interrupted.")

    finally:
        restore()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
