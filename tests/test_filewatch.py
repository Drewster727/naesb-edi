import time

from app.outbound.filewatch import (
    ERROR_DIRNAME,
    PROCESSED_DIRNAME,
    list_duns_dirs,
    list_stable_files,
    move_to_error,
    move_to_processed,
)


def test_list_duns_dirs_only_lists_directories(tmp_path):
    (tmp_path / "987654321").mkdir()
    (tmp_path / "123456789").mkdir()
    (tmp_path / "not-a-duns-dir.txt").write_text("stray file")

    dirs = list_duns_dirs(tmp_path)

    assert [d.duns for d in dirs] == ["123456789", "987654321"]


def test_list_duns_dirs_missing_base_dir_returns_empty(tmp_path):
    assert list_duns_dirs(tmp_path / "does-not-exist") == []


def _touch(path, age_seconds: float):
    path.write_bytes(b"segment data")
    mtime = time.time() - age_seconds
    import os

    os.utime(path, (mtime, mtime))


def test_list_stable_files_excludes_recently_modified(tmp_path):
    duns_dir = tmp_path / "987654321"
    duns_dir.mkdir()
    fresh = duns_dir / "fresh.edi"
    stable = duns_dir / "stable.edi"
    _touch(fresh, age_seconds=5)
    _touch(stable, age_seconds=120)

    now = time.time()
    result = list_stable_files(duns_dir, quiet_period_seconds=60, now=now)

    assert result == [stable]


def test_list_stable_files_ignores_dotfiles_and_temp_suffixes(tmp_path):
    duns_dir = tmp_path / "987654321"
    duns_dir.mkdir()
    for name in (".hidden.edi", "upload.edi.tmp", "upload.edi.part", "upload.edi.swp"):
        _touch(duns_dir / name, age_seconds=120)
    real = duns_dir / "real.edi"
    _touch(real, age_seconds=120)

    result = list_stable_files(duns_dir, quiet_period_seconds=60, now=time.time())

    assert result == [real]


def test_list_stable_files_does_not_recurse_into_processed_or_error(tmp_path):
    duns_dir = tmp_path / "987654321"
    duns_dir.mkdir()
    (duns_dir / PROCESSED_DIRNAME).mkdir()
    (duns_dir / ERROR_DIRNAME).mkdir()
    _touch(duns_dir / PROCESSED_DIRNAME / "old.edi", age_seconds=120)
    _touch(duns_dir / ERROR_DIRNAME / "old.edi", age_seconds=120)

    result = list_stable_files(duns_dir, quiet_period_seconds=60, now=time.time())

    assert result == []


def test_move_to_processed_creates_dir_and_moves_file(tmp_path):
    duns_dir = tmp_path / "987654321"
    duns_dir.mkdir()
    src = duns_dir / "message.edi"
    src.write_bytes(b"segment data")

    dest = move_to_processed(src, duns_dir)

    assert not src.exists()
    assert dest == duns_dir / PROCESSED_DIRNAME / "message.edi"
    assert dest.read_bytes() == b"segment data"


def test_move_to_error_dedupes_colliding_names(tmp_path):
    duns_dir = tmp_path / "987654321"
    duns_dir.mkdir()
    (duns_dir / ERROR_DIRNAME).mkdir()
    (duns_dir / ERROR_DIRNAME / "message.edi").write_bytes(b"earlier failure")

    src = duns_dir / "message.edi"
    src.write_bytes(b"second failure")

    dest = move_to_error(src, duns_dir)

    assert dest == duns_dir / ERROR_DIRNAME / "message-1.edi"
    assert dest.read_bytes() == b"second failure"
    assert (duns_dir / ERROR_DIRNAME / "message.edi").read_bytes() == b"earlier failure"
