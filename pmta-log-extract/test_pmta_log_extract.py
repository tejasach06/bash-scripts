#!/usr/bin/env python3
"""Test suite for pmta-log-extract.py"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

SCRIPT_PATH = Path(__file__).parent / "pmta-log-extract.py"
spec = importlib.util.spec_from_file_location("pmta_log_extract", SCRIPT_PATH)
pmta = importlib.util.module_from_spec(spec)
pmta.__module__ = "pmta_log_extract"
sys.modules["pmta_log_extract"] = pmta
spec.loader.exec_module(pmta)

load_patterns = pmta.load_patterns
PatternSet = pmta.PatternSet
value_matches = pmta.value_matches
record_matches = pmta.record_matches
classify = pmta.classify
MatchMode = pmta.MatchMode
FileKind = pmta.FileKind
run_selftest = pmta.run_selftest
Config = pmta.Config


class TestPatternSet(unittest.TestCase):
    def test_pattern_set_empty(self):
        ps = PatternSet()
        self.assertTrue(ps.is_empty())

    def test_pattern_set_all_patterns(self):
        ps = PatternSet(exact={"a"}, contains={"b"}, domain={"c"})
        patterns = ps.all_patterns()
        self.assertEqual(set(patterns), {"a", "b", "c"})


class TestLoadPatterns(unittest.TestCase):
    def test_load_patterns_literal(self):
        out = load_patterns(["alice@example.com", "bob@example.com"])
        self.assertEqual(out, ["alice@example.com", "bob@example.com"])

    def test_load_patterns_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("alice@example.com\nbob@example.com\n\n# comment\n")
            path = f.name
        try:
            out = load_patterns([f"@{path}"])
            # Function skips empty lines but not comment lines
            self.assertEqual(out, ["alice@example.com", "bob@example.com", "# comment"])
        finally:
            os.unlink(path)


class TestValueMatches(unittest.TestCase):
    def test_exact_match(self):
        self.assertTrue(value_matches("alice@example.com", ("alice@example.com",), MatchMode.EXACT))
        self.assertFalse(value_matches("alice@example.com", ("bob@example.com",), MatchMode.EXACT))

    def test_contains_match(self):
        self.assertTrue(value_matches("alice@example.com", ("example",), MatchMode.CONTAINS))
        self.assertFalse(value_matches("alice@example.com", ("test",), MatchMode.CONTAINS))

    def test_domain_match(self):
        self.assertTrue(value_matches("alice@hdfclife.com", ("hdfclife.com",), MatchMode.DOMAIN))
        self.assertTrue(value_matches("alice@sub.hdfclife.com", ("hdfclife.com",), MatchMode.DOMAIN))
        self.assertFalse(value_matches("alice@other.com", ("hdfclife.com",), MatchMode.DOMAIN))

    def test_case_insensitive(self):
        self.assertTrue(value_matches("ALICE@EXAMPLE.COM", ("alice@example.com",), MatchMode.EXACT))
        self.assertTrue(value_matches("User1@HDFCLIFE.com", ("hdfclife.com",), MatchMode.DOMAIN))


class TestRecordMatches(unittest.TestCase):
    def test_orig_match(self):
        cfg = Config(path="", orig=PatternSet(contains={"alice@example.com"}))
        self.assertTrue(record_matches("alice@example.com", "bob@other.com", "d", cfg))
        self.assertFalse(record_matches("charlie@other.com", "bob@other.com", "d", cfg))

    def test_rcpt_match(self):
        cfg = Config(path="", rcpt=PatternSet(contains={"hdfclife.com"}), match_mode=MatchMode.DOMAIN)
        self.assertTrue(record_matches("alice@example.com", "user@hdfclife.com", "d", cfg))
        self.assertFalse(record_matches("alice@example.com", "user@other.com", "d", cfg))

    def test_any_match(self):
        cfg = Config(path="", any_=PatternSet(contains={"example"}))
        self.assertTrue(record_matches("alice@example.com", "bob@other.com", "d", cfg))
        self.assertTrue(record_matches("charlie@other.com", "user@example.com", "d", cfg))
        self.assertFalse(record_matches("alice@test.com", "bob@other.com", "d", cfg))

    def test_type_filter(self):
        cfg = Config(path="", types={"d"})
        self.assertTrue(record_matches("a@a.com", "b@b.com", "d", cfg))
        self.assertFalse(record_matches("a@a.com", "b@b.com", "b", cfg))


class TestClassify(unittest.TestCase):
    def test_gzip(self):
        with tempfile.NamedTemporaryFile(suffix=".gz", delete=False) as f:
            import gzip
            f.write(gzip.compress(b"test"))
            path = f.name
        try:
            self.assertEqual(classify(path), FileKind.GZIP)
        finally:
            os.unlink(path)

    def test_bzip2(self):
        with tempfile.NamedTemporaryFile(suffix=".bz2", delete=False) as f:
            import bz2
            f.write(bz2.compress(b"test"))
            path = f.name
        try:
            self.assertEqual(classify(path), FileKind.BZIP2)
        finally:
            os.unlink(path)

    def test_zip(self):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            import zipfile
            with zipfile.ZipFile(f, "w") as zf:
                zf.writestr("test.txt", "test")
            path = f.name
        try:
            self.assertEqual(classify(path), FileKind.ZIP)
        finally:
            os.unlink(path)

    def test_plain(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            f.write(b"test")
            path = f.name
        try:
            self.assertEqual(classify(path), FileKind.PLAIN)
        finally:
            os.unlink(path)


class TestSelftest(unittest.TestCase):
    def test_selftest_runs(self):
        result = run_selftest()
        self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()