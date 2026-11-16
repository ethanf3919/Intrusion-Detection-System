
#!/usr/bin/env python3
"""
Linux Executable Hunter
Read-only executable and script inventory for Linux.

Detects:
- Linux ELF executables and shared libraries
- Windows PE executables and DLLs
- Python, Bash, Perl, Ruby, PHP, PowerShell, and JS scripts
- Files with Linux executable permission bits
- Executable files without recognized extensions

Collects:
- File path and type
- Owner and group
- Permissions
- File size
- Modification time
- SHA-256 hash
- Package ownership
- Detection reason
- Priority classification

No files are executed, modified, or deleted.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
import pwd
import grp
import shutil
import stat
import subprocess
from pathlib import Path


# File extensions worth investigating
SCRIPT_EXTENSIONS = {
    ".py": "python-script",
    ".pyw": "python-script",
    ".sh": "shell-script",
    ".bash": "shell-script",
    ".zsh": "shell-script",
    ".pl": "perl-script",
    ".rb": "ruby-script",
    ".php": "php-script",
    ".js": "javascript",
    ".mjs": "javascript",
    ".ps1": "powershell-script",
    ".bat": "batch-script",
    ".cmd": "batch-script",
}

BINARY_EXTENSIONS = {
    ".exe": "windows-executable",
    ".dll": "windows-library",
    ".com": "windows-executable",
    ".scr": "windows-executable",
    ".bin": "binary-file",
    ".run": "installer-or-executable",
    ".so": "shared-library",
}

EXTENSIONS = {
    **SCRIPT_EXTENSIONS,
    **BINARY_EXTENSIONS,
}

PRIORITIES = [
    ("/home/", "high"),
    ("/tmp/", "high"),
    ("/var/tmp/", "high"),
    ("/opt/", "medium"),
    ("/usr/local/", "medium"),
    ("/srv/", "medium"),
]


def command(args, timeout=3):
    """Execute a predefined metadata lookup command."""

    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        return result.returncode, result.stdout.strip()

    except (OSError, subprocess.TimeoutExpired):
        return -1, ""


def package_owner(path):
    """Check whether a package manager owns the file."""

    if shutil.which("dpkg-query"):
        code, output = command(["dpkg-query", "-S", path])

        if code == 0:
            return output.split(":", 1)[0]

    if shutil.which("rpm"):
        code, output = command(["rpm", "-qf", path])

        if code == 0:
            return output.splitlines()[0]

    return None


def sha256(path, max_bytes):
    """Calculate SHA-256, skipping files above the size limit."""

    digest = hashlib.sha256()
    size = 0

    with open(path, "rb") as file:
        while True:
            data = file.read(1024 * 1024)

            if not data:
                break

            size += len(data)

            if size > max_bytes:
                return None

            digest.update(data)

    return digest.hexdigest()


def file_kind(path):
    """
    Identify file type using signatures, shebangs,
    and filename extensions.
    """

    extension = Path(path).suffix.lower()

    with open(path, "rb") as file:
        header = file.read(256)

    # Linux ELF binary
    if header.startswith(b"\x7fELF"):
        return "ELF"

    # Windows PE executable
    if header.startswith(b"MZ") and len(header) >= 64:
        pe_offset = int.from_bytes(header[60:64], "little")

        try:
            with open(path, "rb") as file:
                file.seek(pe_offset)
                if file.read(4) == b"PE\x00\x00":
                    return "PE-executable"
        except OSError:
            pass

    # Script with shebang
    if header.startswith(b"#!"):
        if extension in SCRIPT_EXTENSIONS:
            return SCRIPT_EXTENSIONS[extension]

        shebang = header.split(b"\n", 1)[0].lower()

        if b"python" in shebang:
            return "python-script"

        if b"bash" in shebang or b"/sh" in shebang:
            return "shell-script"

        if b"perl" in shebang:
            return "perl-script"

        if b"ruby" in shebang:
            return "ruby-script"

        return "shebang-script"

    # Extension-based classification
    if extension in EXTENSIONS:
        return EXTENSIONS[extension]

    return "other-executable"


def priority(path, managed):
    """Assign a heuristic investigation priority."""

    if managed:
        return "low"

    for prefix, level in PRIORITIES:
        if path.startswith(prefix):
            return level

    return "medium"


def scan(roots, max_files, max_hash_mb, same_fs):
    """Search directories for executable and script files."""

    findings = []
    errors = []
    scanned = 0

    def record_error(error):
        if len(errors) < 100:
            errors.append(str(error))

    def onerror(error):
        record_error(error)

    for root in roots:

        if not os.path.isdir(root):
            record_error("Not a directory: " + root)
            continue

        try:
            root_dev = os.stat(root).st_dev
        except OSError as error:
            record_error(error)
            continue

        for base, dirs, files in os.walk(
            root,
            followlinks=False,
            onerror=onerror,
        ):

            allowed_dirs = []

            for directory in dirs:
                directory_path = os.path.join(base, directory)

                try:
                    if os.path.islink(directory_path):
                        continue

                    if same_fs:
                        if os.stat(directory_path).st_dev != root_dev:
                            continue

                    allowed_dirs.append(directory)

                except OSError as error:
                    record_error(error)

            dirs[:] = allowed_dirs

            for name in files:
                path = os.path.join(base, name)

                try:
                    st = os.lstat(path)

                    # Only inspect regular files
                    if not stat.S_ISREG(st.st_mode):
                        continue

                    scanned += 1

                    if scanned > max_files:
                        return findings, errors, scanned, True

                    extension = Path(path).suffix.lower()

                    # Linux executable permission
                    is_executable = bool(st.st_mode & 0o111)

                    # Recognized script or binary extension
                    has_extension = extension in EXTENSIONS

                    # Include either condition
                    if not is_executable and not has_extension:
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

                    if is_executable and has_extension:
                        detection_reason = (
                            "executable-permission-and-extension"
                        )

                    elif is_executable:
                        detection_reason = "executable-permission"

                    else:
                        detection_reason = "file-extension"

                    file_hash = sha256(
                        path,
                        max_hash_mb * 1024 * 1024,
                    )

                    findings.append({
                        "path": path,
                        "type": kind,
                        "extension": extension,
                        "executable_permission": is_executable,
                        "detection_reason": detection_reason,
                        "owner": owner,
                        "group": group,
                        "mode": oct(stat.S_IMODE(st.st_mode)),
                        "size_bytes": st.st_size,
                        "modified_utc": dt.datetime.fromtimestamp(
                            st.st_mtime,
                            dt.timezone.utc,
                        ).isoformat(),
                        "sha256": file_hash,
                        "package": managed,
                        "priority": priority(path, managed),
                    })

                except (OSError, PermissionError) as error:
                    record_error(f"{path}: {error}")

    return findings, errors, scanned, False


def main():

    parser = argparse.ArgumentParser(
        description="Read-only Linux Executable Hunter"
    )

    parser.add_argument(
        "--root",
        action="append",
        default=[],
        help="Directory to scan (repeatable); default /",
    )

    parser.add_argument(
        "--max-files",
        type=int,
        default=250000,
        help="Maximum regular files to examine",
    )

    parser.add_argument(
        "--max-hash-mb",
        type=int,
        default=64,
        help="Maximum file size for SHA-256 hashing",
    )

    parser.add_argument(
        "--same-filesystem",
        action="store_true",
        help="Do not cross filesystem boundaries",
    )

    parser.add_argument(
        "--json-out",
        help="Save JSON report to a file",
    )

    args = parser.parse_args()

    roots = args.root or ["/"]

    findings, errors, scanned, truncated = scan(
        roots,
        args.max_files,
        args.max_hash_mb,
        args.same_filesystem,
    )

    # Sort high-priority findings first
    order = {
        "high": 0,
        "medium": 1,
        "low": 2,
    }

    findings.sort(
        key=lambda item: (
            order[item["priority"]],
            item["path"],
        )
    )

    result = {
        "host": os.uname().nodename,
        "timestamp_utc": dt.datetime.now(
            dt.timezone.utc
        ).isoformat(),
        "roots": roots,
        "files_examined": scanned,
        "executable_count": len(findings),
        "truncated": truncated,
        "errors": errors,
        "findings": findings,
    }

    output = json.dumps(result, indent=2)

    if args.json_out:
        Path(args.json_out).write_text(
            output + "\n",
            encoding="utf-8",
        )
        print(
            f"Scan complete: {len(findings)} findings. "
            f"Report saved to {args.json_out}"
        )
    else:
        print(output)


if __name__ == "__main__":
    main()
