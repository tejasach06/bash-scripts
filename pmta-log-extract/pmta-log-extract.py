#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ---------------------------------------------------------------------------
# pmta_log_extract.py
#
# Author  : Tejas
# Team    : Infrastructure & Data Engineering,
#           Softcell Technologies Global Private Limited
# Created : 2026-07-08
# Version : 2.0 (refactored with type hints, modular structure, better docs)
#
# Changelog:
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
  - plain .csv / .json log files
  - bare .gz / .bz2 compressed logs
  - .tar.gz / .tgz / .tar.bz2 / .tar archives (nested directories inside OK)
  - .zip archives (nested directories inside OK)
  - nested compression (e.g. logs.csv.gz inside a tar/zip)

Design:
  - Outer decompression is delegated to the fastest available tool
    (pigz > gzip, lbzip2 > pbzip2 > bzip2), falling back to Python's
    built-in gzip/bz2 modules if none exist. Nothing is written to disk.
  - A `grep -a -i -F` prefilter runs in the pipeline so Python only parses
    candidate lines (critical at 300-800 GB scale). Falls back to a pure
    Python substring prefilter if grep is unavailable.
  - Matches are confirmed in the actual orig/rcpt field (CSV via the
    header row of each file/member, JSON via keys), then normalized to a
    single output CSV whose columns are the union of ALL fields found in
    the matched records (discovered automatically; no field list needed).
    Use --fields to restrict columns, or --fields '*' for raw passthrough.

Usage examples:
  ./pmta_log_extract.py --path '/data/pmta/*/acct-2026-07*' \\
      --orig sender@example.com --out matches.csv

  ./pmta_log_extract.py --path '/logs/**/*.tar.bz2' \\
      --rcpt @rcpt_list.txt --match domain --out matches.csv

  ./pmta_log_extract.py --path '/logs/*.zip' \\
      --orig a@x.com --rcpt b@y.com --logic and --type d,b --out m.csv

  # field-agnostic: match anywhere (sender or recipient)
  ./pmta_log_extract.py --path '/logs/**/*.tar.bz2' \\
      --any hdfclife.com --match domain --out m.csv

  ./pmta_log_extract.py --selftest        # verify logic on this machine
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
from typing import IO, Any, BinaryIO, Callable, Dict, Generator, Iterator, List, Optional, Set, TextIO, Tuple, Union

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_FIELDS: List[str] = [
    "type", "timeLogged", "timeQueued", "orig", "rcpt", "orcpt",
    "dsnAction", "dsnStatus", "dsnDiag", "dsnMta", "jobId", "vmta",
    "srcMta", "dlvType", "dlvSourceIp", "dlvDestinationIp",
    "dlvEsmtpAvailable", "dlvSize", "bounceCat",
]

CHUNK_SIZE = 1024 * 1024  # 1 MiB pipe copy chunks

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Type aliases and enums
# ---------------------------------------------------------------------------

FileKind = Enum("FileKind", "GZIP BZIP2 ZIP PLAIN")
MatchMode = Enum("MatchMode", "EXACT CONTAINS DOMAIN")
LogicMode = Enum("LogicMode", "AND OR")


@dataclass(frozen=True)
class PatternSet:
    """Immutable container for pattern sets."""
    orig: Tuple[str, ...] = ()
    rcpt: Tuple[str, ...] = ()
    any: Tuple[str, ...] = ()

    def is_empty(self) -> bool:
        return not (self.orig or self.rcpt or self.any)

    @property
    def all_patterns(self) -> Tuple[str, ...]:
        return self.orig + self.rcpt + self.any


@dataclass
class StreamStats:
    """Statistics for a single stream/file."""
    path: str
    matches: int = 0
    streams: int = 0
    error: Optional[str] = None


@dataclass
class Config:
    """Runtime configuration, built from CLI args."""
    patterns: PatternSet = field(default_factory=PatternSet)
    match_mode: MatchMode = MatchMode.EXACT
    logic: LogicMode = LogicMode.OR
    types: Optional[Set[str]] = None
    fields: Optional[List[str]] = None
    raw_mode: bool = False
    gzip_tool: Optional[str] = None
    bzip2_tool: Optional[str] = None
    grep_tool: Optional[str] = None
    pattern_file: Optional[str] = None
    spill_fh: Optional[TextIO] = None
    field_union: Dict[str, str] = field(default_factory=dict)  # lower -> original casing
    out_fh: Optional[TextIO] = None
    lock: threading.Lock = field(default_factory=threading.Lock)
    stop: threading.Event = field(default_factory=threading.Event)
    procs: Set[subprocess.Popen] = field(default_factory=set)
    warnings: List[str] = field(default_factory=list)
    verbose: bool = False

    def register_proc(self, proc: subprocess.Popen) -> None:
        with self.lock:
            self.procs.add(proc)

    def unregister_proc(self, proc: subprocess.Popen) -> None:
        with self.lock:
            self.procs.discard(proc)

    def kill_procs(self) -> None:
        """Terminate all live child processes so blocked pipe reads/writes unblock."""
        with self.lock:
            procs = list(self.procs)
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in procs:
            try:
                p.wait(timeout=2)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    def warn(self, msg: str) -> None:
        with self.lock:
            self.warnings.append(msg)
        log.warning(msg)


# ---------------------------------------------------------------------------
# Pattern loading
# ---------------------------------------------------------------------------

def load_patterns(values: List[str]) -> List[str]:
    """
    Load patterns from CLI values. Each value can be:
      - comma-separated list: 'a@x.com,b@y.com'
      - @file: one pattern per line, # comments allowed
    Returns deduplicated, lowercased patterns preserving input order.
    """
    out: List[str] = []
    for v in values or []:
        if v.startswith("@"):
            path = v[1:]
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        out.append(line.lower())
        else:
            out.extend(p.strip().lower() for p in v.split(",") if p.strip())

    # Deduplicate preserving order
    seen: Set[str] = set()
    dedup: List[str] = []
    for p in out:
        if p not in seen:
            seen.add(p)
            dedup.append(p)
    return dedup


# ---------------------------------------------------------------------------
# File classification & streaming decompression
# ---------------------------------------------------------------------------

def classify(path: str) -> FileKind:
    """Return file kind based on magic bytes (not extension)."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError as e:
        raise RuntimeError(f"cannot read {path}: {e}") from e

    if head[:2] == b"\x1f\x8b":
        return FileKind.GZIP
    if head[:3] == b"BZh":
        return FileKind.BZIP2
    if head[:4] == b"PK\x03\x04":
        return FileKind.ZIP
    return FileKind.PLAIN


class PeekableStream(io.RawIOBase):
    """Wrap a read-only stream, allowing already-read head bytes to be 'pushed back'."""
    def __init__(self, head: bytes, raw: BinaryIO) -> None:
        super().__init__()
        self._head = head
        self._raw = raw

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            data = self._head + self._raw.read()
            self._head = b""
            return data
        if self._head:
            if len(self._head) >= n:
                data, self._head = self._head[:n], self._head[n:]
                return data
            data, self._head = self._head, b""
            rest = self._raw.read(n - len(data))
            return data + (rest or b"")
        return self._raw.read(n)

    def readline(self) -> bytes:
        # Only used for non-tar streams; head is small.
        nl = self._head.find(b"\n")
        if nl != -1:
            line, self._head = self._head[:nl + 1], self._head[nl + 1:]
            return line
        buf = self._head
        self._head = b""
        while True:
            b = self._raw.read(65536)
            if not b:
                return buf
            nl = b.find(b"\n")
            if nl != -1:
                line = buf + b[:nl + 1]
                self._head = b[nl + 1:]
                return line
            buf += b

    def close(self) -> None:
        try:
            self._raw.close()
        except Exception:
            pass


def open_decompressed(path: str, kind: FileKind, cfg: Config) -> Tuple[BinaryIO, Optional[subprocess.Popen]]:
    """Return (fileobj, proc_or_None) for the decompressed byte stream."""
    if kind == FileKind.PLAIN:
        return open(path, "rb"), None

    if kind == FileKind.GZIP:
        if cfg.gzip_tool:
            proc = subprocess.Popen(
                [cfg.gzip_tool, "-dc", path],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            cfg.register_proc(proc)
            return proc.stdout, proc  # type: ignore[return-value]
        return gzip.open(path, "rb"), None

    if kind == FileKind.BZIP2:
        if cfg.bzip2_tool:
            proc = subprocess.Popen(
                [cfg.bzip2_tool, "-dc", path],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            cfg.register_proc(proc)
            return proc.stdout, proc  # type: ignore[return-value]
        return bz2.open(path, "rb"), None

    raise RuntimeError(f"unexpected kind {kind}")


def sniff_tar(fobj: BinaryIO) -> Tuple[bool, PeekableStream]:
    """Peek up to 512 bytes; return (is_tar, peekable_stream)."""
    head = b""
    while len(head) < 512:
        b = fobj.read(512 - len(head))
        if not b:
            break
        head += b
    is_tar = len(head) >= 262 and head[257:262] == b"ustar"
    return is_tar, PeekableStream(head, fobj)


def nested_wrap(name: str, fobj: BinaryIO) -> Tuple[BinaryIO, str]:
    """Handle nested compression of an archive member by its name."""
    low = name.lower()
    if low.endswith(".gz"):
        return gzip.GzipFile(fileobj=fobj), name[:-3]
    if low.endswith(".bz2"):
        return bz2.BZ2File(fobj), name[:-4]
    return fobj, name


def iter_log_streams(path: str, cfg: Config) -> Generator[Tuple[str, BinaryIO, Callable[[], None]], None, None]:
    """
    Yield (display_name, fileobj, cleanup_fn) for every logical log stream
    inside `path` (tar/zip members, or the file itself).
    """
    kind = classify(path)

    if kind == FileKind.ZIP:
        try:
            zf = zipfile.ZipFile(path)
        except Exception as e:
            cfg.warn(f"skipping corrupt zip {path}: {e}")
            return

        with zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                try:
                    member = zf.open(info)
                except Exception as e:
                    cfg.warn(f"skipping member {info.filename} in {path}: {e}")
                    continue
                fobj, _ = nested_wrap(info.filename, member)
                yield f"{path}::{info.filename}", fobj, fobj.close
        return

    stream, proc = open_decompressed(path, kind, cfg)

    def finish() -> None:
        try:
            stream.close()
        except Exception:
            pass
        if proc is not None:
            try:
                proc.stdout.close()
            except Exception:
                pass
            rc = proc.wait()
            cfg.unregister_proc(proc)
            if rc not in (0, None) and not cfg.stop.is_set():
                cfg.warn(f"decompressor exited rc={rc} for {path} (file may be truncated/corrupt)")

    try:
        is_tar, ps = sniff_tar(stream)
        if is_tar:
            try:
                tf = tarfile.open(fileobj=ps, mode="r|")
            except Exception as e:
                cfg.warn(f"skipping corrupt tar {path}: {e}")
                return

            try:
                for member in tf:
                    if cfg.stop.is_set():
                        break
                    if not member.isfile():
                        continue
                    mf = tf.extractfile(member)
                    if mf is None:
                        continue
                    fobj, _ = nested_wrap(member.name, mf)
                    yield f"{path}::{member.name}", fobj, lambda: None
            except Exception as e:
                if not cfg.stop.is_set():
                    cfg.warn(f"error while reading tar {path}: {e}")
            finally:
                try:
                    tf.close()
                except Exception:
                    pass
        else:
            yield path, ps, lambda: None
    finally:
        finish()


# ---------------------------------------------------------------------------
# Prefilter (grep in the pipe, or Python fallback)
# ---------------------------------------------------------------------------

def prefilter_patterns(cfg: Config) -> List[str]:
    """
    All pattern strings plus escaped variants: a value containing a double
    quote appears on disk as "" in CSV and \\" in JSON, so the byte-level
    prefilter must also look for those forms.
    """
    pats = [p.lower() for p in cfg.patterns.all_patterns]
    extra: List[str] = []
    for p in pats:
        if '"' in p:
            extra.append(p.replace('"', '""'))    # CSV-escaped
            extra.append(p.replace('"', r'\"'))   # JSON-escaped
    return pats + extra


def prefiltered_lines(fobj: BinaryIO, cfg: Config) -> Generator[bytes, None, None]:
    """
    Yield only lines that contain at least one pattern (case-insensitive).
    Uses grep -a -i -F -f when available; pure Python otherwise.
    """
    if cfg.grep_tool and cfg.pattern_file:
        proc = subprocess.Popen(
            [cfg.grep_tool, "-a", "-i", "-F", "-f", cfg.pattern_file],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        cfg.register_proc(proc)

        def feeder() -> None:
            try:
                while not cfg.stop.is_set():
                    chunk = fobj.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    proc.stdin.write(chunk)  # type: ignore[union-attr]
            except Exception:
                # BrokenPipe (grep gone), tarfile.ReadError / EOFError
                # (decompressor killed mid-stream on Ctrl+C), etc.
                pass
            finally:
                try:
                    proc.stdin.close()  # type: ignore[union-attr]
                except Exception:
                    pass

        t = threading.Thread(target=feeder, daemon=True)
        t.start()
        try:
            for line in proc.stdout:  # type: ignore[union-attr]
                if cfg.stop.is_set():
                    break
                yield line
        finally:
            try:
                proc.stdout.close()  # type: ignore[union-attr]
            except Exception:
                pass
            t.join()
            proc.wait()  # rc 0 = matches, 1 = none; both fine
            cfg.unregister_proc(proc)
    else:
        pats = [p.encode() for p in prefilter_patterns(cfg)]
        n = 0
        while True:
            line = fobj.readline()
            if not line:
                break
            n += 1
            if (n & 8191) == 0 and cfg.stop.is_set():
                break
            low = line.lower()
            if any(p in low for p in pats):
                yield line


# ---------------------------------------------------------------------------
# Matching logic
# ---------------------------------------------------------------------------

def value_matches(value: str, patterns: Tuple[str, ...], mode: MatchMode) -> Optional[bool]:
    """
    All comparisons are case-insensitive: both the record value and the
    patterns are lowercased here, so matching is safe even if patterns
    reach Config without going through load_patterns().
    Returns:
      True  - matches
      False - does not match
      None  - not constrained (no patterns provided)
    """
    if not patterns:
        return None  # "not constrained"

    v = (value or "").strip().lower()
    if not v:
        return False

    if mode == MatchMode.EXACT:
        return any(v == p.lower() for p in patterns)
    if mode == MatchMode.CONTAINS:
        return any(p.lower() in v for p in patterns)
    if mode == MatchMode.DOMAIN:
        dom = v.rsplit("@", 1)[-1]
        for p in patterns:
            pl = p.lower().lstrip("@")
            if dom == pl or dom.endswith("." + pl):
                return True
        return False
    return False


def record_matches(orig: str, rcpt: str, rtype: str, cfg: Config) -> bool:
    """Check if a record matches the configured patterns."""
    if cfg.types is not None and (rtype or "").strip().lower() not in cfg.types:
        return False

    # --any: pattern may appear in either field
    a: Optional[bool] = None
    if cfg.patterns.any:
        a = (
            value_matches(orig, cfg.patterns.any, cfg.match_mode)
            or value_matches(rcpt, cfg.patterns.any, cfg.match_mode)
        )

    o = value_matches(orig, cfg.patterns.orig, cfg.match_mode)
    r = value_matches(rcpt, cfg.patterns.rcpt, cfg.match_mode)

    if o is None and r is None:
        return bool(a)
    if o is None:
        base = bool(r)
    elif r is None:
        base = bool(o)
    else:
        base = (o and r) if cfg.logic == LogicMode.AND else (o or r)

    return base or bool(a)


# ---------------------------------------------------------------------------
# Output handling
# ---------------------------------------------------------------------------

def write_match(source: str, rec_map: Dict[str, str], raw_line: bytes, cfg: Config) -> None:
    """Write a matched record to the spill file or raw output."""
    with cfg.lock:
        if cfg.raw_mode:
            cfg.out_fh.write(  # type: ignore[union-attr]
                source + "\t" +
                raw_line.decode("utf-8", "replace").rstrip("\r\n") + "\n"
            )
        else:
            record = {"source_file": source}
            record.update(rec_map)
            cfg.spill_fh.write(json.dumps(record, ensure_ascii=False) + "\n")  # type: ignore[union-attr]
            for k in rec_map:
                lk = k.lower()
                if lk not in cfg.field_union:
                    cfg.field_union[lk] = k


def output_columns(cfg: Config) -> List[str]:
    """Final column list: explicit --fields, or discovered union."""
    if cfg.fields is not None:
        return ["source_file"] + cfg.fields

    union = dict(cfg.field_union)  # lower -> original casing
    union.pop("source_file", None)
    cols: List[str] = []
    for f in DEFAULT_FIELDS:
        lf = f.lower()
        if lf in union:
            cols.append(union.pop(lf))
    cols.extend(union.values())
    return ["source_file"] + cols


def finalize_output(cfg: Config, spill_path: str, out_path: str) -> Tuple[List[str], int]:
    """
    Stream the spilled NDJSON matches into the final CSV with the full
    (or explicitly requested) column set.
    Returns (columns, row_count).
    """
    cols = output_columns(cfg)
    rows = 0
    with open(out_path, "w", newline="", encoding="utf-8") as out_fh, \
            open(spill_path, "r", encoding="utf-8") as spill:
        w = csv.writer(out_fh)
        w.writerow(cols)
        lower_cols = [c.lower() for c in cols]
        for line in spill:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            low = {k.lower(): v for k, v in rec.items()}
            w.writerow([low.get(c, "") for c in lower_cols])
            rows += 1
    return cols, rows


# ---------------------------------------------------------------------------
# Per-stream processing
# ---------------------------------------------------------------------------

def read_first_nonempty_line(fobj: BinaryIO, limit: int = 5) -> bytes:
    for _ in range(limit):
        line = fobj.readline()
        if line is None or line == b"":
            return b""
        if line.strip():
            return line
    return b""


def process_stream(name: str, fobj: BinaryIO, cfg: Config) -> int:
    """Returns number of matches written from this stream."""
    first = read_first_nonempty_line(fobj)
    if not first:
        return 0

    matches = 0
    stripped = first.lstrip()

    if stripped.startswith(b"{"):
        # ---- line-delimited JSON ----
        def handle_json_line(line: bytes) -> None:
            nonlocal matches
            try:
                rec = json.loads(line.decode("utf-8", "replace"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return
            if not isinstance(rec, dict):
                return
            orig_map = {str(k): ("" if v is None else str(v)) for k, v in rec.items()}
            lower = {k.lower(): v for k, v in orig_map.items()}
            if record_matches(lower.get("orig", ""), lower.get("rcpt", ""), lower.get("type", ""), cfg):
                write_match(name, orig_map, line, cfg)
                matches += 1

        # First line bypassed the prefilter; test it directly.
        handle_json_line(first)
        for line in prefiltered_lines(fobj, cfg):
            handle_json_line(line)
        return matches

    # ---- CSV: first line must be a header containing orig and/or rcpt ----
    try:
        header = next(csv.reader([first.decode("utf-8", "replace")]))
    except (csv.Error, StopIteration):
        cfg.warn(f"skipping {name}: cannot parse first line as CSV header")
        return 0

    cols_orig = [c.strip() for c in header]
    cols = [c.lower() for c in cols_orig]
    if "orig" not in cols and "rcpt" not in cols:
        cfg.warn(f"skipping {name}: no orig/rcpt column in header (not a PMTA accounting file?)")
        return 0

    idx = {c: i for i, c in enumerate(cols)}
    i_orig, i_rcpt, i_type = idx.get("orig"), idx.get("rcpt"), idx.get("type")

    for line in prefiltered_lines(fobj, cfg):
        text = line.decode("utf-8", "replace")
        try:
            row = next(csv.reader([text]))
        except (csv.Error, StopIteration):
            continue
        if not row:
            continue

        def col(i: Optional[int]) -> str:
            return row[i] if i is not None and i < len(row) else ""

        if record_matches(col(i_orig), col(i_rcpt), col(i_type), cfg):
            orig_map = {c: (row[i] if i < len(row) else "") for i, c in enumerate(cols_orig)}
            write_match(name, orig_map, line, cfg)
            matches += 1
    return matches


# ---------------------------------------------------------------------------
# Per-file processing & orchestration
# ---------------------------------------------------------------------------

def process_file(path: str, cfg: Config) -> StreamStats:
    stats = StreamStats(path=path)
    if cfg.stop.is_set():
        return stats

    try:
        for name, fobj, cleanup in iter_log_streams(path, cfg):
            stats.streams += 1
            try:
                stats.matches += process_stream(name, fobj, cfg)
            finally:
                try:
                    cleanup()
                except Exception:
                    pass
    except Exception as e:
        stats.error = str(e)
        cfg.warn(f"failed on {path}: {e}")
    return stats


def run_extraction(paths: List[str], cfg: Config, jobs: int) -> List[StreamStats]:
    total = len(paths)
    total_bytes = 0
    for p in paths:
        try:
            total_bytes += os.path.getsize(p)
        except OSError:
            pass

    done = 0
    done_bytes = 0
    all_stats: List[StreamStats] = []
    start = time.time()

    # Pattern file for grep
    all_pats = prefilter_patterns(cfg)
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".pats", delete=False, encoding="utf-8"
    )
    tmp.write("\n".join(all_pats) + "\n")
    tmp.close()
    cfg.pattern_file = tmp.name

    interrupted = False
    ex = ThreadPoolExecutor(max_workers=jobs)
    try:
        futs = {ex.submit(process_file, p, cfg): p for p in paths}
        try:
            for fut in as_completed(futs):
                st = fut.result()
                all_stats.append(st)
                done += 1
                try:
                    done_bytes += os.path.getsize(st.path)
                except OSError:
                    pass
                elapsed = time.time() - start
                rate = done_bytes / elapsed / (1024**2) if elapsed > 0 else 0
                log.info(
                    f"[{done}/{total}] {os.path.basename(st.path)}: "
                    f"{st.matches} matches | "
                    f"{done_bytes/1024**3:.2f}/{total_bytes/1024**3:.2f} GiB "
                    f"compressed | {rate:.0f} MiB/s"
                )
        except KeyboardInterrupt:
            interrupted = True
            log.info("\n[!] Ctrl+C received: stopping workers, terminating child processes...")
            cfg.stop.set()
            for f in futs:
                f.cancel()
            cfg.kill_procs()
    finally:
        # Drain: workers exit quickly since pipes are broken & stop is set.
        ex.shutdown(wait=True)
        cfg.kill_procs()
        try:
            os.unlink(cfg.pattern_file)  # type: ignore[arg-type]
        except OSError:
            pass

    if interrupted:
        raise KeyboardInterrupt
    return all_stats


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def build_selftest_fixtures(root: str) -> None:
    csv_header = "type,timeLogged,timeQueued,orig,rcpt,dsnStatus,vmta\n"
    rows = [
        'd,2026-07-01 10:00:00,2026-07-01 09:59:58,alice@example.com,user1@hdfclife.com,2.0.0,vmta1\n',
        'b,2026-07-01 10:01:00,2026-07-01 10:00:58,bob@example.com,user2@other.com,5.0.0,vmta1\n',
        'd,2026-07-01 10:02:00,2026-07-01 10:01:58,carol@example.net,user3@mail.hdfclife.com,2.0.0,vmta2\n',
        'd,2026-07-01 10:03:00,2026-07-01 10:02:58,"""quoted, orig""@example.com",alice@example.com,2.0.0,vmta2\n',
    ]
    csv_data = csv_header + "".join(rows)

    json_lines = [
        {"type": "d", "timeLogged": "2026-07-01 11:00:00",
         "orig": "alice@example.com", "rcpt": "userA@hdfclife.com",
         "dsnStatus": "2.0.0", "customField": "cf-value-1"},
        {"type": "b", "timeLogged": "2026-07-01 11:01:00",
         "orig": "dave@example.com", "rcpt": "userB@other.com",
         "dsnStatus": "5.1.1"},
    ]
    json_data = "".join(json.dumps(r) + "\n" for r in json_lines)

    # 1. plain files
    with open(os.path.join(root, "plain.csv"), "w") as f:
        f.write(csv_data)
    with open(os.path.join(root, "plain.json"), "w") as f:
        f.write(json_data)

    # 2. tar.gz with a directory inside
    p = os.path.join(root, "arch1.tar.gz")
    with tarfile.open(p, "w:gz") as tf:
        _add_tar_bytes(tf, "inner/dir/logs.csv", csv_data.encode())

    # 3. tar.bz2 with JSON
    p = os.path.join(root, "arch2.tar.bz2")
    with tarfile.open(p, "w:bz2") as tf:
        _add_tar_bytes(tf, "logs.json", json_data.encode())

    # 4. zip with subdirectory
    p = os.path.join(root, "arch3.zip")
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("sub/logs.csv", csv_data)
        zf.writestr("sub/logs.json", json_data)

    # 5. tar.gz containing a nested-compressed member (csv.gz)
    p = os.path.join(root, "arch4.tar.gz")
    with tarfile.open(p, "w:gz") as tf:
        _add_tar_bytes(tf, "nested/logs.csv.gz", gzip.compress(csv_data.encode()))

    # 6. bare .gz of a csv
    with open(os.path.join(root, "bare.csv.gz"), "wb") as f:
        f.write(gzip.compress(csv_data.encode()))


def _add_tar_bytes(tf: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    tf.addfile(info, io.BytesIO(data))


def selftest() -> int:
    failures: List[str] = []

    def check(desc: str, got: Any, want: Any) -> None:
        status = "PASS" if got == want else "FAIL"
        log.info(f"  [{status}] {desc}: got {got}, expected {want}")
        if got != want:
            failures.append(desc)

    with tempfile.TemporaryDirectory() as root:
        build_selftest_fixtures(root)
        paths = sorted(glob.glob(os.path.join(root, "*")))
        log.info(f"Self-test fixtures: {len(paths)} files in {root}")

        def run(
            orig: Optional[List[str]] = None,
            rcpt: Optional[List[str]] = None,
            any_: Optional[List[str]] = None,
            mode: MatchMode = MatchMode.EXACT,
            logic: LogicMode = LogicMode.OR,
            types: Optional[List[str]] = None,
            raw: bool = False,
            fields: Optional[List[str]] = None,
        ) -> Tuple[int, List[str]]:
            cfg = Config()
            cfg.patterns = PatternSet(
                orig=tuple(orig or []),
                rcpt=tuple(rcpt or []),
                any=tuple(any_ or []),
            )
            cfg.match_mode = mode
            cfg.logic = logic
            cfg.types = {t.strip().lower() for t in types} if types else None
            cfg.raw_mode = raw
            cfg.fields = fields

            if cfg.grep_tool:
                pf = tempfile.NamedTemporaryFile(
                    mode="w", suffix=".pats", delete=False, encoding="utf-8"
                )
                pf.write("\n".join(prefilter_patterns(cfg)) + "\n")
                pf.close()
                cfg.pattern_file = pf.name

            total = 0
            header: List[str] = []
            spill_name = out_name = None
            try:
                if raw:
                    cfg.out_fh = io.StringIO()
                    for p in paths:
                        total += process_file(p, cfg).matches
                else:
                    sp = tempfile.NamedTemporaryFile(
                        mode="w", suffix=".ndjson", delete=False, encoding="utf-8"
                    )
                    spill_name = sp.name
                    cfg.spill_fh = sp
                    for p in paths:
                        total += process_file(p, cfg).matches
                    sp.close()
                    of = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
                    out_name = of.name
                    of.close()
                    header, n_rows = finalize_output(cfg, spill_name, out_name)
                    if n_rows != total:
                        raise AssertionError(f"finalized rows {n_rows} != matches {total}")
            finally:
                for f in (cfg.pattern_file, spill_name, out_name):
                    if f:
                        try:
                            os.unlink(f)
                        except OSError:
                            pass
            return total, header

        log.info("\nRunning checks:")

        # CSV copies: plain.csv, arch1, arch3(zip csv), arch4(nested), bare.gz = 5
        # JSON copies: plain.json, arch2, arch3(zip json) = 3

        # alice@example.com as orig: 1/csv-copy + 1/json-copy = 5 + 3 = 8
        check("orig exact alice@example.com", run(orig=["alice@example.com"])[0], 8)

        # alice as rcpt appears once per CSV copy = 5
        check("rcpt exact alice@example.com", run(rcpt=["alice@example.com"])[0], 5)

        # orig OR rcpt alice: rows are distinct → 8 + 5 = 13
        check("orig|rcpt exact alice (logic=or)",
              run(orig=["alice@example.com"], rcpt=["alice@example.com"], logic=LogicMode.OR)[0], 13)

        # AND: no single record has alice in both fields
        check("orig&rcpt exact alice (logic=and)",
              run(orig=["alice@example.com"], rcpt=["alice@example.com"], logic=LogicMode.AND)[0], 0)

        # domain hdfclife.com incl. subdomain mail.hdfclife.com:
        # csv rows 1+3 per csv copy (2*5=10) + json row 1 per json copy (3)
        check("rcpt domain hdfclife.com (incl. subdomain)",
              run(rcpt=["hdfclife.com"], mode=MatchMode.DOMAIN)[0], 13)

        # contains 'example' in orig: all 4 csv rows *5 + 2 json rows *3 = 26
        check("orig contains 'example'", run(orig=["example"], mode=MatchMode.CONTAINS)[0], 26)

        # type filter: alice orig + type d only → csv row1 (5) + json row1 (3)
        check("orig alice, --type d", run(orig=["alice@example.com"], types=["d"])[0], 8)
        check("orig alice, --type b (no b rows from alice)", run(orig=["alice@example.com"], types=["b"])[0], 0)

        # case-insensitivity: mixed-case PATTERNS passed directly (bypassing
        # load_patterns), against lowercase data — must still match
        check("orig exact ALICE@EXAMPLE.COM (uppercase pattern)",
              run(orig=["ALICE@EXAMPLE.COM"])[0], 8)
        check("rcpt exact User1@HDFCLIFE.com (mixed-case pattern)",
              run(rcpt=["User1@HDFCLIFE.com"])[0], 5)
        check("rcpt domain HDFCLIFE.COM (uppercase domain pattern)",
              run(rcpt=["HDFCLIFE.COM"], mode=MatchMode.DOMAIN)[0], 13)
        check("orig contains EXAMPLE (uppercase contains pattern)",
              run(orig=["EXAMPLE"], mode=MatchMode.CONTAINS)[0], 26)

        # quoted CSV field with comma must not break parsing
        check("orig exact quoted address with comma",
              run(orig=['"quoted, orig"@example.com'])[0], 5)

        # raw mode
        check("raw passthrough mode (orig alice)", run(orig=["alice@example.com"], raw=True)[0], 8)

        # field auto-discovery: union header must contain every field seen,
        # including the non-standard customField from the JSON fixtures,
        # with original casing preserved
        _, header = run(orig=["alice@example.com"])
        check("auto-discovered header contains customField", "customField" in header, True)
        check("auto-discovered header contains standard fields",
              all(f in header for f in ("source_file", "type", "timeLogged", "orig", "rcpt", "dsnStatus", "vmta")), True)

        # explicit --fields restriction still works
        _, header = run(orig=["alice@example.com"], fields=["orig", "rcpt"])
        check("explicit --fields header", header, ["source_file", "orig", "rcpt"])

        # --any: alice in orig OR rcpt = same 13 as the explicit or-test
        check("--any exact alice (fieldless)", run(any_=["alice@example.com"])[0], 13)

        # --any with domain mode, no --orig/--rcpt at all
        check("--any domain hdfclife.com", run(any_=["hdfclife.com"], mode=MatchMode.DOMAIN)[0], 13)

        # --any ORs with an explicit field constraint:
        # rcpt exact alice (5) OR any exact bob@example.com (orig row2, 5)
        check("--rcpt alice + --any bob (union)",
              run(rcpt=["alice@example.com"], any_=["bob@example.com"])[0], 10)

    log.info("")
    if failures:
        log.error(f"SELF-TEST FAILED: {len(failures)} check(s) failed")
        return 1
    log.info("SELF-TEST PASSED: all checks OK")
    return 0


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="pmta_log_extract.py",
        description=(
            "Stream-extract PMTA accounting records (CSV or line-delimited\n"
            "JSON) by sender/recipient from large log sets — plain files or\n"
            "tar.gz / tar.bz2 / zip archives (nested directories and nested\n"
            ".gz/.bz2 members included) — WITHOUT extracting anything to\n"
            "disk. All matching is CASE-INSENSITIVE. Output is a single\n"
            "normalized CSV whose columns are auto-discovered from the\n"
            "matched records."
        ),
        epilog=(
            "examples:\n"
            "  # exact sender across a dated tree of tar.bz2 archives\n"
            "  %(prog)s --path '/data/pmta/*/acct-2026-07*' \\\n"
            "      --orig sender@example.com --out matches.csv\n"
            "\n"
            "  # recipient list from a file, whole domain incl. subdomains\n"
            "  %(prog)s --path '/logs/**/*.tar.gz' \\\n"
            "      --rcpt @rcpt_list.txt --match domain --out m.csv\n"
            "\n"
            "  # this sender AND this recipient in the same record,\n"
            "  # bounces and deliveries only\n"
            "  %(prog)s --path '/logs/*.zip' --orig a@x.com --rcpt b@y.com \\\n"
            "      --logic and --type d,b --out m.csv\n"
            "\n"
            "  # fieldless: address/domain anywhere (sender OR recipient)\n"
            "  %(prog)s --path '/logs/**/*.tar.bz2' \\\n"
            "      --any hdfcbank.net --match domain --out m.csv\n"
            "\n"
            "  # lossless raw lines instead of normalized CSV\n"
            "  %(prog)s --path '/logs/*' --any user@x.com \\\n"
            "      --fields '*' --out m.txt\n"
            "\n"
            "  # validate everything on this machine first\n"
            "  %(prog)s --selftest\n"
            "\n"
            "notes:\n"
            "  - QUOTE every --path glob so the shell doesn't expand it.\n"
            "  - Matching is case-insensitive everywhere (patterns, data,\n"
            "    domains, --type values).\n"
            "  - Install pigz and lbzip2 for multi-threaded decompression;\n"
            "    the script auto-detects them and falls back to gzip/bzip2,\n"
            "    then to Python's built-in modules.\n"
            "  - Matches are spooled to a temp file next to --out during\n"
            "    the scan, then written with the union of all discovered\n"
            "    columns; the temp file is removed automatically.\n"
            "  - Corrupt/unreadable archives are skipped with a warning,\n"
            "    listed in the end-of-run summary.\n"
            "  - Ctrl+C aborts cleanly: children are terminated, temp\n"
            "    files removed, partial results kept in --out."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--path", action="append", default=[], metavar="GLOB",
                    help="Glob of log files/archives (QUOTE IT). Repeatable. "
                         "'*' and recursive '**' supported, ~ expanded. "
                         "Formats detected by magic bytes, not extension.")
    ap.add_argument("--orig", action="append", metavar="PAT",
                    help="Sender pattern(s): 'a@x.com,b@y.com' or @file "
                         "(one per line, # comments OK). Repeatable. Case-insensitive.")
    ap.add_argument("--rcpt", action="append", metavar="PAT",
                    help="Recipient pattern(s); same syntax as --orig.")
    ap.add_argument("--any", dest="any_", action="append", metavar="PAT",
                    help="Pattern(s) matched against orig OR rcpt; same "
                         "syntax as --orig. Lets you search without naming "
                         "a field. OR-combined with --orig/--rcpt results.")
    ap.add_argument("--match", choices=["exact", "contains", "domain"],
                    default="exact",
                    help="How patterns are compared, applies to all of "
                         "--orig/--rcpt/--any (default: exact). "
                         "exact: full address equality. "
                         "contains: substring anywhere in the address. "
                         "domain: address is at that domain or any "
                         "subdomain (leading '@' in the pattern is OK).")
    ap.add_argument("--logic", choices=["and", "or"], default="or",
                    help="How --orig and --rcpt combine when BOTH are given "
                         "(default: or). --any is always OR'd on top.")
    ap.add_argument("--type", dest="types", metavar="T[,T...]",
                    help="Keep only these record types, e.g. d,b,t,rb "
                         "(default: all types).")
    ap.add_argument("--fields", metavar="F[,F...]|*",
                    help="Restrict output to these columns, or '*' for raw "
                         "passthrough (source<TAB>original line). Default: "
                         "ALL fields found in matched records, "
                         "auto-discovered across files (missing fields blank).")
    ap.add_argument("--out", default="matches.csv", metavar="FILE",
                    help="Output file (default: matches.csv)")
    ap.add_argument("--jobs", type=int, metavar="N",
                    default=max(1, (os.cpu_count() or 2) // 2),
                    help="Files processed in parallel (default: cores/2 = %(default)s on this machine)")
    ap.add_argument("--selftest", action="store_true",
                    help="Build tiny sample archives (CSV+JSON in tar.gz/"
                         "tar.bz2/zip, nested dirs, nested .gz) and verify "
                         "all matching logic on this machine. Run this once "
                         "on a new server before a real extraction.")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Enable debug logging")
    return ap


def main() -> int:
    ap = build_arg_parser()
    args = ap.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    if args.selftest:
        return selftest()

    cfg = Config()
    cfg.patterns = PatternSet(
        orig=tuple(load_patterns(args.orig)),
        rcpt=tuple(load_patterns(args.rcpt)),
        any=tuple(load_patterns(args.any_)),
    )

    if cfg.patterns.is_empty():
        ap.error("at least one of --orig / --rcpt / --any is required")

    cfg.match_mode = MatchMode[args.match.upper()]
    cfg.logic = LogicMode[args.logic.upper()]

    if args.types:
        cfg.types = {t.strip().lower() for t in args.types.split(",") if t.strip()}

    if args.fields:
        if args.fields.strip() == "*":
            cfg.raw_mode = True
        else:
            cfg.fields = [f.strip() for f in args.fields.split(",") if f.strip()]

    if not args.path:
        ap.error("at least one --path is required")

    paths: List[str] = []
    for p in args.path:
        expanded = glob.glob(os.path.expanduser(p), recursive=True)
        paths.extend(x for x in expanded if os.path.isfile(x))
    paths = sorted(set(paths))

    if not paths:
        log.error("No files matched the given --path glob(s). "
                  "Remember to quote the glob so the shell doesn't mangle it.")
        return 2

    log.info(f"Files matched : {len(paths)}")
    log.info(f"Match mode    : {cfg.match_mode.name.lower()} | logic: {cfg.logic.name.lower()} | "
             f"types: {','.join(sorted(cfg.types)) if cfg.types else 'all'}")
    log.info(f"orig patterns : {len(cfg.patterns.orig)} | "
             f"rcpt patterns: {len(cfg.patterns.rcpt)} | "
             f"any patterns: {len(cfg.patterns.any)}")
    log.info(f"Decompressors : gzip={cfg.gzip_tool or 'python-builtin'} | "
             f"bzip2={cfg.bzip2_tool or 'python-builtin'} | "
             f"prefilter={'grep' if cfg.grep_tool else 'python'}")
    log.info(f"Jobs          : {args.jobs}")
    mode_desc = ("raw passthrough" if cfg.raw_mode else
                 ("normalized CSV, columns: " + ",".join(cfg.fields)
                  if cfg.fields else "normalized CSV, all fields (auto)"))
    log.info(f"Output        : {args.out} ({mode_desc})")
    log.info("-" * 60)

    out_dir = os.path.dirname(os.path.abspath(args.out)) or "."
    interrupted = False
    stats: List[StreamStats] = []

    try:
        if cfg.raw_mode:
            with open(args.out, "w", newline="", encoding="utf-8") as out_fh:
                cfg.out_fh = out_fh
                try:
                    stats = run_extraction(paths, cfg, args.jobs)
                except KeyboardInterrupt:
                    interrupted = True
        else:
            spill = tempfile.NamedTemporaryFile(
                mode="w", suffix=".matches.ndjson", dir=out_dir,
                delete=False, encoding="utf-8"
            )
            try:
                cfg.spill_fh = spill
                try:
                    stats = run_extraction(paths, cfg, args.jobs)
                except KeyboardInterrupt:
                    interrupted = True
                with cfg.lock:  # no worker writes past this point
                    spill.close()
                if interrupted:
                    log.info("[!] Finalizing partial results collected so far...")
                cols, finalized_rows = finalize_output(cfg, spill.name, args.out)
                log.info(f"Output columns: {','.join(cols)}")
            finally:
                try:
                    os.unlink(spill.name)
                except OSError:
                    pass

    finally:
        # Ensure any remaining procs are cleaned up
        cfg.kill_procs()

    if cfg.raw_mode:
        finalized_rows = sum(s.matches for s in stats)

    failed = [s for s in stats if s.error]
    log.info("-" * 60)

    if interrupted:
        log.info(
            f"Interrupted. {finalized_rows} matching record(s) found "
            f"before the interrupt were preserved in {args.out} "
            f"({len(stats)}/{len(paths)} files fully scanned — PARTIAL results)."
        )
    else:
        log.info(f"Done. {finalized_rows} matching record(s) written to {args.out}")

    if cfg.warnings:
        log.info(f"{len(cfg.warnings)} warning(s):")
        for w in cfg.warnings:
            log.info(f"  - {w}")

    if interrupted:
        return 130
    if failed and len(failed) == len(stats):
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        # Second Ctrl+C during cleanup: exit immediately, no traceback.
        log.error("\nInterrupted (forced).")
        os._exit(130)