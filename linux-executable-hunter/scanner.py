#!/usr/bin/env python3
"""Read-only executable inventory for authorized Linux hosts."""
import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import pwd
import grp
import shutil
import stat
import subprocess
import sys
from pathlib import Path

PRIORITIES = [('/home/', 'high'), ('/tmp/', 'high'), ('/var/tmp/', 'high'), ('/opt/', 'medium'), ('/usr/local/', 'medium'), ('/srv/', 'medium')]

def command(args, timeout=3):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return -1, ''

def package_owner(path):
    if shutil.which('dpkg-query'):
        code, out = command(['dpkg-query', '-S', path])
        if code == 0:
            return out.split(':', 1)[0]
    if shutil.which('rpm'):
        code, out = command(['rpm', '-qf', path])
        if code == 0:
            return out.splitlines()[0]
    return None

def sha256(path, max_bytes):
    h = hashlib.sha256()
    size = 0
    with open(path, 'rb') as f:
        while True:
            data = f.read(1024 * 1024)
            if not data:
                break
            size += len(data)
            if size > max_bytes:
                return None
            h.update(data)
    return h.hexdigest()

def file_kind(path):
    with open(path, 'rb') as f:
        head = f.read(256)
    if head.startswith(b'\x7fELF'):
        return 'ELF'
    if head.startswith(b'#!'):
        return 'shebang-script'
    return 'other-executable'

def priority(path, managed):
    if managed:
        return 'low'
    for prefix, level in PRIORITIES:
        if path.startswith(prefix):
            return level
    return 'medium'

def scan(roots, max_files, max_hash_mb, same_fs):
    findings, errors = [], []
    scanned = 0
    def onerror(exc):
        if len(errors) < 100:
            errors.append(str(exc))
    for root in roots:
        if not os.path.isdir(root):
            errors.append('Not a directory: ' + root)
            continue
        root_dev = os.stat(root).st_dev
        for base, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(base, d)) and (not same_fs or os.stat(os.path.join(base, d)).st_dev == root_dev)]
            for name in files:
                path = os.path.join(base, name)
                try:
                    st = os.lstat(path)
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    scanned += 1
                    if scanned > max_files:
                        return findings, errors, scanned, True
                    if not (st.st_mode & 0o111):
                        continue
                    kind = file_kind(path)
                    managed = package_owner(path)
                    try:
                        owner = pwd.getpwuid(st.st_uid).pw_name
                    except KeyError:
                        owner = str(st.st_uid)
                    try:
                        group = grp.getgrgid(st.st_gid).gr_name
                    except KeyError:
                        group = str(st.st_gid)
                    findings.append({'path': path, 'type': kind, 'owner': owner, 'group': group,
                                     'mode': oct(stat.S_IMODE(st.st_mode)), 'size_bytes': st.st_size,
                                     'modified_utc': dt.datetime.fromtimestamp(st.st_mtime, dt.timezone.utc).isoformat(),
                                     'sha256': sha256(path, max_hash_mb * 1024 * 1024),
                                     'package': managed, 'priority': priority(path, managed)})
                except (OSError, PermissionError) as exc:
                    if len(errors) < 100:
                        errors.append(f'{path}: {exc}')
    return findings, errors, scanned, False

def main():
    ap = argparse.ArgumentParser(description='Read-only Linux executable inventory')
    ap.add_argument('--root', action='append', default=[], help='Scan root (repeatable); defaults to /')
    ap.add_argument('--max-files', type=int, default=250000)
    ap.add_argument('--max-hash-mb', type=int, default=64)
    ap.add_argument('--same-filesystem', action='store_true', help='Do not cross filesystem boundaries')
    ap.add_argument('--json-out', help='Optional local JSON output path')
    args = ap.parse_args()
    roots = args.root or ['/']
    findings, errors, scanned, truncated = scan(roots, args.max_files, args.max_hash_mb, args.same_filesystem)
    findings.sort(key=lambda x: ({'high': 0, 'medium': 1, 'low': 2}[x['priority']], x['path']))
    result = {'host': os.uname().nodename, 'timestamp_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
              'roots': roots, 'files_examined': scanned, 'executable_count': len(findings),
              'truncated': truncated, 'errors': errors, 'findings': findings}
    output = json.dumps(result, indent=2)
    if args.json_out:
        Path(args.json_out).write_text(output + '\n', encoding='utf-8')
    else:
        print(output)

if __name__ == '__main__':
    main()
