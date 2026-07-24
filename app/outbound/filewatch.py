"""Pure filesystem scanning for the outbound file-drop poller
(app/poller.py). Deliberately has no DB/GPG/network dependencies -- it only
knows about directories, file mtimes, and moving files -- so it's testable
without any of the fixtures those require.

Layout under `settings.poller.base_dir`:

    <base_dir>/<duns>/                 -- drop a raw, unencrypted EDI file here
    <base_dir>/<duns>/processed/       -- moved here once handed to the delivery queue
    <base_dir>/<duns>/error/           -- moved here if pickup fails repeatedly
"""

from dataclasses import dataclass
from pathlib import Path

PROCESSED_DIRNAME = "processed"
ERROR_DIRNAME = "error"

_RESERVED_DIRNAMES = frozenset({PROCESSED_DIRNAME, ERROR_DIRNAME})

# Suffixes commonly left behind by editors/transfer tools while a file is
# still being written -- never picked up even once the quiet period elapses,
# since the final write (a rename to the real name) hasn't happened yet.
_IGNORED_SUFFIXES = (".tmp", ".part", ".swp", ".crdownload")


@dataclass(frozen=True)
class DunsDir:
    duns: str
    path: Path


def list_duns_dirs(base_dir: Path) -> list[DunsDir]:
    """Immediate subdirectories of base_dir, each named for a partner DUNS.
    Caller is responsible for resolving the name against the partner
    registry -- this module doesn't know about partners."""
    if not base_dir.is_dir():
        return []
    return sorted(
        (DunsDir(duns=entry.name, path=entry) for entry in base_dir.iterdir() if entry.is_dir()),
        key=lambda d: d.duns,
    )


def _is_ignorable(path: Path) -> bool:
    return path.name.startswith(".") or path.suffix in _IGNORED_SUFFIXES


def list_stable_files(duns_dir: Path, quiet_period_seconds: int, now: float) -> list[Path]:
    """Files directly inside duns_dir (never recursing into processed/error)
    that haven't been modified for at least quiet_period_seconds -- the
    signal that a writer has finished streaming the file to disk, per the
    NAESB gateway's own polling contract (not anything NAESB-specified)."""
    candidates = []
    for entry in duns_dir.iterdir():
        if entry.name in _RESERVED_DIRNAMES or not entry.is_file() or _is_ignorable(entry):
            continue
        age = now - entry.stat().st_mtime
        if age >= quiet_period_seconds:
            candidates.append(entry)
    return sorted(candidates)


def _unique_destination(dest_dir: Path, name: str) -> Path:
    """Appends -1, -2, ... before the extension if `name` already exists in
    dest_dir, so a same-named file dropped twice never silently overwrites
    an earlier processed/errored copy."""
    dest = dest_dir / name
    if not dest.exists():
        return dest
    stem, suffix = dest.stem, dest.suffix
    n = 1
    while True:
        candidate = dest_dir / f"{stem}-{n}{suffix}"
        if not candidate.exists():
            return candidate
        n += 1


def _move_into(file_path: Path, duns_dir: Path, dirname: str) -> Path:
    dest_dir = duns_dir / dirname
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = _unique_destination(dest_dir, file_path.name)
    file_path.rename(dest)
    return dest


def move_to_processed(file_path: Path, duns_dir: Path) -> Path:
    return _move_into(file_path, duns_dir, PROCESSED_DIRNAME)


def move_to_error(file_path: Path, duns_dir: Path) -> Path:
    return _move_into(file_path, duns_dir, ERROR_DIRNAME)
