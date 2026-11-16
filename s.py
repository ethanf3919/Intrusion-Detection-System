
#!/usr/bin/env python3
"""
Terminal Chaos Lab - Non-Flashing Edition

Visual distraction simulator for the current terminal.
No flashing backgrounds, system changes, or input hijacking.
"""

import argparse
import random
import shutil
import sys
import time

RESET = "\033[0m"

WARNINGS = [
    "[SIMULATION] ERROR: Connection timed out",
    "[SIMULATION] WARNING: Unexpected process activity",
    "[SIMULATION] ERROR: Authentication failed",
    "[SIMULATION] WARNING: High CPU usage detected",
    "[SIMULATION] ERROR: Service response delayed",
    "[SIMULATION] WARNING: Network packet loss",
    "[SIMULATION] ERROR: Unable to establish connection",
]

TYPING_MESSAGES = [
    "[SIMULATION] Initializing diagnostic sequence...",
    "[SIMULATION] Checking running processes...",
    "[SIMULATION] Scanning active connections...",
    "[SIMULATION] Analyzing system logs...",
    "[SIMULATION] Unexpected response received...",
    "[SIMULATION] Retrying operation...",
]


def warnings():
    print(random.choice(WARNINGS), flush=True)


def matrix():
    width = shutil.get_terminal_size((80, 24)).columns
    width = min(width, 100)

    characters = "01abcdef"

    output = "".join(
        random.choice(characters)
        for _ in range(max(1, width - 2))
    )

    print(output, flush=True)


def typing_effect(deadline):
    message = random.choice(TYPING_MESSAGES)

    for character in message:
        if time.monotonic() >= deadline:
            break

        sys.stdout.write(character)
        sys.stdout.flush()
        time.sleep(0.025)

    print()


def main():
    parser = argparse.ArgumentParser(
        description="Non-flashing terminal distraction simulator"
    )

    parser.add_argument(
        "--mode",
        choices=["warnings", "matrix", "typing", "combined"],
        default="combined",
    )

    parser.add_argument(
        "--seconds",
        type=int,
        default=10,
    )

    args = parser.parse_args()

    if not sys.stdout.isatty():
        print("Interactive terminal required.", file=sys.stderr)
        return 2

    duration = max(1, min(args.seconds, 30))
    deadline = time.monotonic() + duration

    # Preserve the existing terminal display.
    sys.stdout.write("\033[?1049h")
    sys.stdout.flush()

    try:
        print("=" * 50)
        print("          TERMINAL CHAOS LAB")
        print("          NON-FLASHING EDITION")
        print("=" * 50)
        print("Press Ctrl+C to exit.\n")

        while time.monotonic() < deadline:
            mode = args.mode

            if mode == "combined":
                mode = random.choice(
                    ["warnings", "matrix", "typing"]
                )

            if mode == "warnings":
                warnings()

            elif mode == "matrix":
                matrix()

            elif mode == "typing":
                typing_effect(deadline)

            remaining = deadline - time.monotonic()

            if remaining > 0:
                time.sleep(min(0.5, remaining))

    except KeyboardInterrupt:
        pass

    finally:
        sys.stdout.write(RESET)
        sys.stdout.write("\033[?1049l")
        sys.stdout.flush()

        print("[LAB] Simulation ended. Terminal restored.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
