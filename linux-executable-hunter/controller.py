#!/usr/bin/env python3
"""SSH-based controller for predefined read-only scanner execution."""
import argparse
import csv
import datetime as dt
import json
import subprocess
from pathlib import Path

FIELDS = ['host', 'path', 'priority', 'type', 'owner', 'group', 'mode', 'size_bytes', 'modified_utc', 'sha256', 'package']

def main():
    ap = argparse.ArgumentParser(description='Run Linux Executable Hunter on authorized SSH hosts')
    ap.add_argument('--inventory', default='hosts.json')
    ap.add_argument('--host', action='append', help='Host name from inventory (repeatable); default all')
    ap.add_argument('--output', default='reports')
    ap.add_argument('--timeout', type=int, default=600)
    ap.add_argument('--max-files', type=int, default=250000)
    args = ap.parse_args()
    config = json.loads(Path(args.inventory).read_text(encoding='utf-8'))
    hosts = config['hosts']
    selected = args.host or sorted(hosts)
    for name in selected:
        if name not in hosts:
            ap.error('Unknown host: ' + name)
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    for name in selected:
        host = hosts[name]
        # Host values come from a trusted local inventory; no shell interpolation.
        target = f"{host['user']}@{host['address']}"
        remote = host.get('scanner_path', '/opt/linux-executable-hunter/scanner.py')
        cmd = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'ConnectTimeout=10', '-p', str(host.get('port', 22)), target,
               'python3', remote, '--max-files', str(args.max_files), '--same-filesystem']
        print(f'Scanning {name} ({target})...', flush=True)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout, check=False)
            if result.returncode != 0:
                print(f'  FAILED (ssh exit {result.returncode}): {result.stderr.strip()[:500]}')
                continue
            data = json.loads(result.stdout)
            stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
            base = out / f'{name}-{stamp}'
            base.with_suffix('.json').write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
            with base.with_suffix('.csv').open('w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=FIELDS, extrasaction='ignore')
                writer.writeheader()
                for item in data['findings']:
                    writer.writerow({'host': name, **item})
            counts = {level: sum(x['priority'] == level for x in data['findings']) for level in ('high', 'medium', 'low')}
            print(f"  OK: {len(data['findings'])} executables; priorities={counts}; truncated={data['truncated']}")
            print(f'  Reports: {base}.json / .csv')
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError, KeyError) as exc:
            print(f'  FAILED: {exc}')

if __name__ == '__main__':
    main()
