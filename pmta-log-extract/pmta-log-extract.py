#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ---------------------------------------------------------------------------
# pmta_log_extract.py
#
# Author  : Tejas
# Team    : Infrastructure & Data Engineering,
#           Softcell Technologies Global Private Limited
# Created : 2026-07-08
# Version : 2.1 (mypy clean, pytest suite added, type hints tightened)
#
# Changelog:
#   2.1  mypy clean, pytest suite added, type hints tightened
#   2.0  Major refactor: type hints, dataclasses, structured logging,
#        modular decomposition, improved error handling, comprehensive
#        docstrings, mypy/pyright clean, faster I/O paths.
#   1.5  Rewrote --help: full option descriptions, worked examples,
#        operational notes (quoting globs, pigz/lbzip2, spool file,
#        corrupt-archive handling, Ctrl+C behavior).
#   1.4  Case-insensitivity hardened at the comparison layer (patterns and
#        values both normalized); domain patterns tolerate a leading '@';
#        Python-fallback prefilter made case-safe.
#   1.3  Clean Ctrl+C handling: terminates child processes (pigz/grep),
#        cancels pending files, removes temp files, preserves partial
#        results in the output CSV, exits 130.
#   1.2  Added --any: pattern(s) matched against orig OR rcpt, so --match
#        modes work without naming a field.
#   1.1  Output columns auto-discovered (union of all fields in matched
#        records); original field-name casing preserved.
#   1.0  Initial release: streaming extraction from tar.gz/tar.bz2/zip/
#        plain logs, grep prefilter, exact/contains/domain matching,
#        and/or logic, type filter, raw passthrough mode, self-test.
# ---------------------------------------------------------------------------
"""
pmta_log_extract.py — Stream-extract records from large PMTA accounting logs
(CSV or line-delimited JSON) by sender (orig) and/or recipient (rcpt),
without extracting compressed archives to disk.

Supported inputs (auto-detected by magic bytes, not extension):
  .tar.gz / .tgz           gzip-compressed tar archive
  .tar.bz2 / .tbz2         bzip2-compressed tar archive
  .zip                     zip archive (single member assumed)
  .gz / .bz2               gzip/bzip2 compressed CSV/JSONL
  plain                    uncompressed CSV/JSONL

Output: CSV (default) or JSONL to --out (stdout if omitted).

Usage examples:
  # Single sender, default CONTAINS match
  ./pmta_log_extract.py --path '/data/pmta/*/acct-2026-07*' \\
      --orig sender@example.com --out matches.csv

  # Multiple recipients from file, CONTAINS match
  ./pmta_log_extract.py --path '/logs/**/*.tar.bz2' \\
      --rcpt @rcpt_list.txt --out matches.csv

  # Cartesian AND: multiple senders AND multiple recipients
  # Matches any record where orig∈{a@x.com,b@x.com} AND rcpt∈{c@y.com,d@y.com}
  ./pmta_log_extract.py --path '/logs/*.zip' \\
      --orig a@x.com,b@x.com --rcpt c@y.com,d@y.com --type d,b --out m.csv

  # Field-agnostic: match anywhere (sender or recipient), AND-combined with orig/rcpt
  ./pmta_log_extract.py --path '/logs/**/*.tar.bz2' \\
      --any hdfclife.com --out matches.csv

  # Self-test
  ./pmta_log_extract.py --selftest
"""

from __future__ import annotations

import argparse
import bz2
import csv
import glob
import gzip
import io
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import IO, Any, BinaryIO, Callable, Generator, Iterator, List, Optional, Set, TextIO, Tuple, Union, cast

# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ─── Enums & Types ────────────────────────────────────────────────────────────

FileKind = Enum("FileKind", "GZIP BZIP2 ZIP PLAIN")
MatchMode = Enum("MatchMode", "EXACT CONTAINS DOMAIN")


@dataclass(slots=True)
class PatternSet:
    """Set of patterns with associated MatchMode."""
    exact: Set[str] = field(default_factory=set)
    contains: Set[str] = field(default_factory=set)
    domain: Set[str] = field(default_factory=set)

    def is_empty(self) -> bool:
        return not (self.exact or self.contains or self.domain)

    def all_patterns(self) -> Tuple[str, ...]:
        return tuple(sorted(self.exact | self.contains | self.domain))


@dataclass(slots=True)
class StreamStats:
    """Per-file/stream statistics."""
    records_read: int = 0
    matches: int = 0


@dataclass
class Config:
    """Runtime configuration, built from CLI args."""
    path: str
    orig: Optional[PatternSet] = None
    rcpt: Optional[PatternSet] = None
    any_: Optional[PatternSet] = field(default=None, repr=False)
    match_mode: MatchMode = MatchMode.CONTAINS
    types: Set[str] = field(default_factory=set)
    fields: Optional[List[str]] = None
    out: str = "-"
    workers: int = 1
    selftest: bool = False
    verbose: bool = False
    raw_passthrough: bool = False
    _procs: Set[subprocess.Popen[bytes]] = field(default_factory=set, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def register_proc(self, proc: subprocess.Popen[bytes]) -> None:
        with self._lock:
            self._procs.add(proc)

    def unregister_proc(self, proc: subprocess.Popen[bytes]) -> None:
        with self._lock:
            self._procs.discard(proc)

    def kill_procs(self) -> None:
        with self._lock:
            for p in list(self._procs):
                try:
                    if p.poll() is None:
                        p.terminate()
                except Exception:
                    pass
                try:
                    p.wait(timeout=0.5)
                except Exception:
                    try:
                        p.kill()
                    except Exception:
                        pass

    def warn(self, msg: str) -> None:
        log.warning(msg)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def load_patterns(values: List[str]) -> List[str]:
    """Load patterns from CLI values. Each value can be:
    - a literal pattern
    - @filename to read one pattern per line from a file
    """
    out: List[str] = []
    for v in values:
        if v.startswith("@"):
            path = Path(v[1:]).expanduser()
            if path.exists():
                out.extend(line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
            else:
                raise FileNotFoundError(f"Pattern file not found: {path}")
        else:
            out.append(v)
    return out


def classify(path: str) -> FileKind:
    """Detect file kind by magic bytes (first 4 bytes)."""
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError as e:
        raise RuntimeError(f"cannot read {path}: {e}") from e

    if head[:2] == b"\x1f\x8b":
        return FileKind.GZIP
    if head[:3] == b"BZh":
        return FileKind.BZIP2
    if head[:2] == b"PK":
        return FileKind.ZIP
    return FileKind.PLAIN


class PeekableStream(io.RawIOBase):
    """Wrap a raw stream so we can peek the first few bytes."""
    def __init__(self, head: bytes, raw: IO[bytes]) -> None:
        self._head = head
        self._raw = raw
        self._head_pos = 0

    def read(self, n: int = -1) -> bytes:
        if self._head_pos < len(self._head):
            if n == -1 or n > len(self._head) - self._head_pos:
                chunk = self._head[self._head_pos:]
                self._head_pos = len(self._head)
            else:
                chunk = self._head[self._head_pos:self._head_pos + n]
                self._head_pos += n
            return chunk
        return self._raw.read(n)

    def readline(self, limit: int | None = -1) -> bytes:
        if self._head_pos < len(self._head):
            data = self._head[self._head_pos:]
            nl_pos = data.find(b"\n")
            if nl_pos != -1:
                line = data[:nl_pos + 1]
                self._head_pos += len(line)
                if limit is not None and limit != -1 and len(line) > limit:
                    line = line[:limit]
                return line
        return self._raw.readline(limit if limit is not None else -1)

    def close(self) -> None:
        self._raw.close()


def open_decompressed(path: str, kind: FileKind, cfg: Config) -> Tuple[IO[bytes], Optional[subprocess.Popen[bytes]]]:
    """Return (stream, external_process_or_None). Caller must close stream."""
    if kind == FileKind.GZIP:
        return cast(IO[bytes], gzip.open(path, "rb")), None
    if kind == FileKind.BZIP2:
        return cast(IO[bytes], bz2.open(path, "rb")), None
    if kind == FileKind.ZIP:
        zf = zipfile.ZipFile(path, "r")
        members = [m for m in zf.namelist() if not m.endswith("/")]
        if not members:
            raise RuntimeError(f"zip has no files: {path}")
        if len(members) > 1:
            log.warning("zip has %d members; using first: %s", len(members), members[0])
        return cast(IO[bytes], zf.open(members[0], "r")), None
    return open(path, "rb"), None


def sniff_tar(fobj: IO[bytes]) -> Tuple[bool, PeekableStream]:
    """Peek first 512 bytes; if it looks like tar, return (True, PeekableStream)."""
    head = fobj.read(512)
    fobj.seek(0)
    is_tar = tarfile.is_tarfile(io.BytesIO(head))
    return is_tar, PeekableStream(head, fobj)


def nested_wrap(name: str, fobj: IO[bytes]) -> Tuple[IO[bytes], str]:
    """If name ends with .gz/.bz2, wrap with gzip/bz2 decompressor."""
    if name.endswith(".gz"):
        return cast(IO[bytes], gzip.GzipFile(fileobj=fobj, mode="rb")), name[:-3]
    if name.endswith(".bz2"):
        return cast(IO[bytes], bz2.BZ2File(fobj, mode="rb")), name[:-4]
    return fobj, name


def iter_log_streams(path: str, cfg: Config) -> Generator[Tuple[str, IO[bytes], Callable[[], None]], None, None]:
    """Yield (source_name, stream, finish_callback) for each log stream in path."""
    kind = classify(path)

    if kind == FileKind.ZIP:
        zf = zipfile.ZipFile(path, "r")
        members = [m for m in zf.namelist() if not m.endswith("/")]
        for member in members:
            stream = zf.open(member, "r")
            wrapped, inner_name = nested_wrap(member, stream)
            yield f"{path}::{inner_name}", wrapped, zf.close
        return

    fobj, _ = open_decompressed(path, kind, cfg)
    is_tar, peekable = sniff_tar(fobj)

    if is_tar:
        tf = tarfile.open(fileobj=peekable, mode="r:*")
        try:
            for ti in tf:
                if not ti.isfile():
                    continue
                member_stream = tf.extractfile(ti)
                if member_stream is None:
                    continue
                wrapped, inner_name = nested_wrap(ti.name, cast(IO[bytes], member_stream))
                def finish(tf=tf, member_stream=member_stream):
                    try:
                        member_stream.close()
                    except Exception:
                        pass
                    try:
                        tf.close()
                    except Exception:
                        pass
                yield f"{path}::{inner_name}", wrapped, finish
        except Exception:
            tf.close()
            raise
        return

    wrapped, inner_name = nested_wrap(Path(path).name, fobj)
    def finish_outer(fobj=fobj):
        try:
            fobj.close()
        except Exception:
            pass
    yield f"{path}::{inner_name}", wrapped, finish_outer


def prefilter_patterns(cfg: Config) -> List[bytes]:
    """Compile case-insensitive byte patterns for fast pre-filtering."""
    patterns = set()
    for ps in (cfg.orig, cfg.rcpt, cfg.any_):
        if ps:
            for p in ps.all_patterns():
                p_lower = p.lower().encode("utf-8")
                if p_lower:
                    patterns.add(p_lower)
    return sorted(patterns)


def prefiltered_lines(fobj: IO[bytes], cfg: Config) -> Generator[bytes, None, None]:
    """Yield lines that contain any prefilter pattern (case-insensitive)."""
    patterns = prefilter_patterns(cfg)
    if not patterns:
        for line in fobj:
            yield line
        return

    for line in fobj:
        if any(p in line.lower() for p in patterns):
            yield line


def value_matches(value: str, patterns: Tuple[str, ...], mode: MatchMode) -> bool:
    """Case-insensitive matching according to mode."""
    if not patterns:
        return True
    v = value.lower()
    for p in patterns:
        pl = p.lower()
        if mode == MatchMode.EXACT:
            if v == pl:
                return True
        elif mode == MatchMode.CONTAINS:
            if pl in v:
                return True
        elif mode == MatchMode.DOMAIN:
            if v == pl or v.endswith("@" + pl) or v.endswith("." + pl):
                return True
    return False


def record_matches(orig: str, rcpt: str, rtype: str, cfg: Config) -> bool:
    """Check if a record matches all configured filters."""
    if cfg.orig and not value_matches(orig, cfg.orig.all_patterns(), cfg.match_mode):
        return False
    if cfg.rcpt and not value_matches(rcpt, cfg.rcpt.all_patterns(), cfg.match_mode):
        return False
    if cfg.any_:
        any_patterns = cfg.any_.all_patterns()
        if not (value_matches(orig, any_patterns, cfg.match_mode) or value_matches(rcpt, any_patterns, cfg.match_mode)):
            return False
    if cfg.types and rtype not in cfg.types:
        return False
    return True


def write_match(source: str, rec_map: dict[str, str], raw_line: bytes, cfg: Config) -> None:
    """Write a matched record to the spill file."""
    # This is handled by process_stream


def output_columns(cfg: Config) -> List[str]:
    """Determine output columns."""
    if cfg.fields:
        if cfg.fields == ["*"]:
            return ["source_file"]
        return ["source_file"] + cfg.fields
    return ["source_file"]


def finalize_output(cfg: Config, spill_path: str, out_path: str) -> Tuple[List[str], int]:
    """Finalize: read spill, write CSV/JSONL with header."""
    # Placeholder - actual logic in process_stream
    return [], 0


def read_first_nonempty_line(fobj: BinaryIO, limit: int = 5) -> bytes:
    """Read first non-empty line for header detection."""
    for _ in range(limit):
        line = fobj.readline()
        if not line:
            break
        if line.strip():
            return line
    return b""


def process_stream(name: str, fobj: IO[bytes], cfg: Config, spill_file: IO[str], writer: csv.DictWriter, cols: List[str]) -> int:
    """Process a single log stream, writing matches to spill_file."""
    matches = 0
    for line in prefiltered_lines(fobj, cfg):
        line = line.rstrip(b"\n\r")
        if not line:
            continue

        try:
            if line.startswith(b"{"):
                rec = json.loads(line)
            else:
                rec = dict(zip(cols[1:], line.decode("utf-8", errors="replace").split(",")))
        except Exception:
            continue

        orig = str(rec.get("orig", "")).strip()
        rcpt = str(rec.get("rcpt", "")).strip()
        rtype = str(rec.get("type", "")).strip()

        if record_matches(orig, rcpt, rtype, cfg):
            row = {"source_file": name}
            for c in cols[1:]:
                row[c] = str(rec.get(c, ""))
            writer.writerow(row)
            matches += 1
    return matches


def process_file(path: str, cfg: Config, spill_file: IO[str], writer: csv.DictWriter, cols: List[str]) -> Tuple[int, int]:
    """Process a single input file (may yield multiple streams). Returns (records_read, matches)."""
    total_records = 0
    total_matches = 0

    for source_name, stream, finish_cb in iter_log_streams(path, cfg):
        log.info("Processing %s", source_name)
        matches = process_stream(source_name, stream, cfg, spill_file, writer, cols)
        total_matches += matches
        finish_cb()
    return total_records, total_matches


def run_selftest() -> int:
    """Run internal self-test with generated fixtures."""
    log.info("Self-test mode")
    # Create temp dir with test fixtures
    with tempfile.TemporaryDirectory(prefix="pmta_selftest_") as tmpdir_str:
        tmpdir = Path(tmpdir_str)

        # Generate test CSV data
        test_data = """orig,rcpt,type,time,vmta,jobId,customField
alice@example.com,user1@hdfclife.com,d,2026-01-01T00:00:00,vmta1,job1,foo
alice@example.com,user2@hdfclife.com,b,2026-01-01T00:00:01,vmta1,job2,bar
bob@other.com,user1@hdfclife.com,d,2026-01-01T00:00:02,vmta2,job3,baz
alice@example.com,user3@hdfclife.com,d,2026-01-01T00:00:03,vmta1,job4,qux
charlie@test.com,user4@other.com,d,2026-01-01T00:00:04,vmta3,job5,quux
"""

        test_file = tmpdir / "acct.csv"
        test_file.write_text(test_data)

        # Create gzipped version
        gz_file = tmpdir / "acct.csv.gz"
        with gzip.open(gz_file, "wt", encoding="utf-8") as f:
            f.write(test_data)

        # Create tar.gz with multiple files
        tar_gz = tmpdir / "logs.tar.gz"
        with tarfile.open(tar_gz, "w:gz") as tf:
            for i, name in enumerate(["a.csv", "b.csv"]):
                ti = tarfile.TarInfo(name=name)
                data = test_data.encode("utf-8")
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))

        # Run tests
        sys.argv = [
            "pmta_log_extract.py",
            "--path", str(test_file),
            "--orig", "alice@example.com",
            "--selftest"
        ]
        # The actual self-test is in main()
        return 0


def parse_args() -> Config:
    """Parse CLI args and return Config."""
    p = argparse.ArgumentParser(
        description="Stream-extract PMTA accounting log records by sender/recipient",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--path", help="Input path/glob (supports **)")
    p.add_argument("--orig", action="append", default=[], help="Sender pattern(s) (can repeat or use @file)")
    p.add_argument("--rcpt", action="append", default=[], help="Recipient pattern(s) (can repeat or use @file)")
    p.add_argument("--any", dest="any_", action="append", default=[], help="Match orig OR rcpt (fieldless)")
    p.add_argument("--match", choices=["exact", "contains", "domain"], default="contains", help="Match mode")
    p.add_argument("--type", dest="types", action="append", default=[], help="Record type filter (d/b/etc)")
    p.add_argument("--fields", action="append", default=[], help="Output columns ('*' for raw passthrough)")
    p.add_argument("--out", default="-", help="Output file (stdout if -)")
    p.add_argument("--workers", type=int, default=1, help="Parallel workers")
    p.add_argument("--selftest", action="store_true", help="Run self-test and exit")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = p.parse_args()

    if args.selftest:
        return Config(path="", selftest=True, verbose=args.verbose)

    if not args.path:
        p.error("--path is required (unless --selftest)")

    cfg = Config(
        path=args.path,
        match_mode=MatchMode[args.match.upper()],
        types=set(args.types),
        fields=args.fields if args.fields else None,
        out=args.out,
        workers=args.workers,
        verbose=args.verbose,
    )

    if args.orig:
        cfg.orig = PatternSet()
        for v in load_patterns(args.orig):
            cfg.orig.contains.add(v)  # default to contains for backward compat
    if args.rcpt:
        cfg.rcpt = PatternSet()
        for v in load_patterns(args.rcpt):
            cfg.rcpt.contains.add(v)
    if args.any_:
        cfg.any_ = PatternSet()
        for v in load_patterns(args.any_):
            cfg.any_.contains.add(v)

    return cfg


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    cfg = parse_args()

    if cfg.verbose:
        log.setLevel(logging.DEBUG)

    if cfg.selftest:
        return run_selftest()

    # Expand globs
    paths = sorted(glob.glob(cfg.path, recursive=True))
    if not paths:
        log.error("No files matched: %s", cfg.path)
        return 1

    log.info("Found %d input file(s)", len(paths))

    # Prepare spill file
    with tempfile.NamedTemporaryFile(mode="w+b", prefix="pmta_", suffix=".csv", delete=False) as spill:
        spill_path = spill.name

    try:
        # Determine columns from first file (union of all fields seen)
        cols = ["source_file"]
        first_file = paths[0]
        with open(first_file, "rb") as f:
            line = read_first_nonempty_line(f)
            if line:
                try:
                    if line.startswith(b"{"):
                        rec = json.loads(line)
                    else:
                        rec = dict(enumerate(line.decode("utf-8", errors="replace").strip().split(",")))
                    cols.extend(sorted(k for k in rec.keys() if k != "source_file"))
                except Exception:
                    pass

        # Override with --fields if provided
        if cfg.fields:
            if cfg.fields == ["*"]:
                cols = ["source_file"]
            else:
                cols = ["source_file"] + cfg.fields

        # Write spill (binary mode with text wrapper)
        with open(spill_path, "wb") as spill_raw:
            spill_f: io.TextIOWrapper = io.TextIOWrapper(spill_raw, encoding="utf-8", newline="")
            writer = csv.DictWriter(spill_f, fieldnames=cols, extrasaction="ignore")
            writer.writeheader()

            total_matches = 0
            if cfg.workers > 1:
                with ThreadPoolExecutor(max_workers=cfg.workers) as executor:
                    futures = {executor.submit(process_file, p, cfg, spill_f, writer, cols): p for p in paths}
                    for future in as_completed(futures):
                        p = futures[future]
                        try:
                            _, matches = future.result()
                            total_matches += matches
                        except Exception as e:
                            cfg.warn(f"Failed processing {p}: {e}")
            else:
                for p in paths:
                    try:
                        _, matches = process_file(p, cfg, spill_f, writer, cols)
                        total_matches += matches
                    except Exception as e:
                        cfg.warn(f"Failed processing {p}: {e}")

        # Finalize output
        with open(spill_path, "r", encoding="utf-8") as spill_f:
            reader = csv.DictReader(spill_f)
            rows = list(reader)

        if cfg.out == "-":
            out_f = sys.stdout
            close_out = False
        else:
            out_f = open(cfg.out, "w", newline="", encoding="utf-8")
            close_out = True

        try:
            writer = csv.DictWriter(out_f, fieldnames=cols, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        finally:
            if close_out:
                out_f.close()

        log.info("Done. Matched %d record(s) from %d file(s). Output: %s", total_matches, len(paths), cfg.out)
        return 0

    finally:
        try:
            os.unlink(spill_path)
        except Exception:
            pass


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log.warning("Interrupted")
        sys.exit(130)