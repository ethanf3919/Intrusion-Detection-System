#!/usr/bin/env python3
"""Opt-in, time-limited terminal effects for the current lab session only."""
import argparse
import random
import shutil
import sys
import time

RESET = '\033[0m'
COLORS = ['\033[35m', '\033[36m', '\033[33m', '\033[32m']
MESSAGES = ['[LAB SIMULATION] Checking terminal...', '[LAB SIMULATION] Example warning: delayed response', '[LAB SIMULATION] No system changes performed']

def main():
    p = argparse.ArgumentParser(description='Reversible terminal effects in your own TTY')
    p.add_argument('--mode', choices=['banner', 'warnings', 'matrix', 'combined'], default='banner')
    p.add_argument('--seconds', type=int, default=5)
    a = p.parse_args()
    if not sys.stdout.isatty():
        print('Requires an interactive terminal.', file=sys.stderr)
        return 2
    duration = max(1, min(a.seconds, 15))
    width = min(shutil.get_terminal_size((80, 24)).columns, 100)
    end = time.monotonic() + duration
    print('\n\033[1;35m=== TERMINAL CHAOS LAB (SIMULATION) ===\033[0m')
    try:
        while time.monotonic() < end:
            mode = random.choice(['warnings', 'matrix']) if a.mode == 'combined' else a.mode
            if mode == 'banner':
                print('\033[36m[LAB] Terminal demo active (no changes to input or services)\033[0m')
                break
            elif mode == 'warnings':
                print(random.choice(COLORS) + random.choice(MESSAGES) + RESET)
            else:
                chars = '01abcdef'
                print('\033[32m' + ''.join(random.choice(chars) for _ in range(max(1, width - 2))) + RESET)
            time.sleep(0.35)
    except KeyboardInterrupt:
        pass
    finally:
        print(RESET + '[LAB] Demo ended. Terminal restored.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
