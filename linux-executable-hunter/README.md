# Linux Executable Hunter

A read-only, SSH-triggered executable inventory for **authorized** Linux systems. No persistent agent, arbitrary remote shell, stealth, or automatic file modification.

## Features
- Walks the local filesystem without following symbolic links.
- Detects regular files with executable permission bits, including ELF files and scripts with shebangs.
- Collects file metadata, SHA-256 hashes (up to a configurable size), and `dpkg`/`rpm` package ownership.
- Ranks unmanaged executables by directory heuristics; **high priority does not prove maliciousness**.
- Controller runs the predefined scanner through SSH and saves JSON and CSV per host.
- Limits scanned file count and SSH runtime; scan errors and truncation are included in reports.

## Requirements
- Linux target: Python 3, `dpkg-query` or `rpm` for package checks (optional).
- Controller: Python 3, OpenSSH client, SSH access to authorized targets.
- Deployment: Ansible on the controller, SSH credentials and sudo rights on targets.
- No pip dependencies.

## Deployment
1. Copy `ansible/inventory.example.ini` to `ansible/inventory.ini` and replace example addresses.
2. Establish SSH authentication and verify host keys beforehand (`ssh user@host`). Do not disable host-key checking.
3. From the project root run:

   ```bash
   ansible-playbook -i ansible/inventory.ini ansible/deploy.yml --ask-become-pass
   ```

4. Copy `hosts.example.json` to `hosts.json` and edit addresses and users.
5. Run the controller:

   ```bash
   python3 controller.py --inventory hosts.json
   python3 controller.py --inventory hosts.json --host linux-host-5
   ```

Reports are written to `reports/<host>-<UTC timestamp>.json` and `.csv`.

## Direct scanner usage

```bash
python3 scanner.py --root /home --root /opt
python3 scanner.py --root / --same-filesystem --max-files 100000 --json-out scan.json
```

The controller uses `--same-filesystem`, so it scans the root filesystem and does not cross into separately mounted filesystems. For a multi-filesystem host, run the scanner directly with additional `--root` paths, or extend the controller with an approved root allowlist. Scan completeness depends on permissions: a normal SSH user may be unable to inspect protected paths. Use explicitly authorized privileges if comprehensive scanning is needed.

## Limitations
- This is not a definitive determination of who deployed a file.
- Files without executable bits (including some scripts invoked through interpreters) are not included.
- No running-process or systemd-service correlation in this initial version.
- `dpkg-query -S` and `rpm -qf` are best-effort ownership checks, not a security verdict.
- File changes during scanning can produce partial metadata or read errors.
- Large files are not hashed beyond the configured limit.
- Full filesystem scans can be slow; limit scope on busy production systems.

## Suggested competition demonstration
Deploy to an authorized Linux VM, create a harmless executable in `/home/<user>/`, run the controller, and show the executable in JSON/CSV. Repeat after removing it to show the updated inventory.

## Source ownership
Add your own name/team to the source files and customize the implementation as required by your course's authorship rules. Review and understand all code before submission.
