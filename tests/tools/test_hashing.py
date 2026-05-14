"""Tests for tools/hashing.py."""
import os
import csv
import hashlib
import pytest
from unittest.mock import patch
from tools.hashing import (
    hash_file,
    hash_directory,
    verify_evidence_hash,
    ssdeep_hash,
    ssdeep_compare,
    ssdeep_scan_directory,
    hashdeep_compute,
    hashdeep_audit,
    md5deep_scan,
)


KNOWN_CONTENT = b"TRUDI test content 12345"
KNOWN_MD5 = hashlib.md5(KNOWN_CONTENT).hexdigest()
KNOWN_SHA1 = hashlib.sha1(KNOWN_CONTENT).hexdigest()
KNOWN_SHA256 = hashlib.sha256(KNOWN_CONTENT).hexdigest()


@pytest.fixture
def test_file(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(KNOWN_CONTENT)
    return str(f)


class TestHashFile:
    def test_correct_md5(self, test_file):
        r = hash_file(test_file)
        assert r["success"] is True
        assert r["md5"] == KNOWN_MD5

    def test_correct_sha1(self, test_file):
        r = hash_file(test_file)
        assert r["sha1"] == KNOWN_SHA1

    def test_correct_sha256(self, test_file):
        r = hash_file(test_file)
        assert r["sha256"] == KNOWN_SHA256

    def test_correct_size(self, test_file):
        r = hash_file(test_file)
        assert r["size_bytes"] == len(KNOWN_CONTENT)

    def test_file_not_found(self):
        r = hash_file("/nonexistent/file.bin")
        assert r["success"] is False
        assert "error" in r

    def test_returns_file_path(self, test_file):
        r = hash_file(test_file)
        assert r["file"] == test_file


class TestHashDirectory:
    def test_hashes_all_files(self, tmp_path):
        for i in range(3):
            (tmp_path / f"file{i}.bin").write_bytes(f"content{i}".encode())
        r = hash_directory(str(tmp_path))
        assert r["success"] is True
        assert r["file_count"] == 3

    def test_sha256_algorithm(self, tmp_path):
        (tmp_path / "f.bin").write_bytes(b"data")
        r = hash_directory(str(tmp_path), algorithm="sha256")
        assert r["algorithm"] == "sha256"
        assert "sha256" in r["hashes"][0]

    def test_unknown_algorithm_fails(self, tmp_path):
        r = hash_directory(str(tmp_path), algorithm="blake3")
        assert r["success"] is False

    def test_output_manifest_written(self, tmp_path):
        (tmp_path / "f.bin").write_bytes(b"data")
        manifest = str(tmp_path / "manifest.csv")
        r = hash_directory(str(tmp_path), output_manifest=manifest)
        assert os.path.exists(manifest)
        with open(manifest) as f:
            rows = list(csv.reader(f))
        assert len(rows) == 2  # header + 1 file

    def test_output_manifest_evidence_path_blocked(self, tmp_path):
        with pytest.raises(ValueError, match="protected evidence"):
            hash_directory(str(tmp_path), output_manifest="/cases/srl/manifest.csv")

    def test_non_recursive(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (tmp_path / "top.bin").write_bytes(b"top")
        (sub / "nested.bin").write_bytes(b"nested")
        r = hash_directory(str(tmp_path), recursive=False)
        assert r["file_count"] == 1


class TestVerifyEvidenceHash:
    def test_no_expected_hashes(self, test_file):
        r = verify_evidence_hash(test_file)
        assert r["success"] is True
        assert r["md5_match"] is None
        assert r["sha1_match"] is None

    def test_correct_md5_match(self, test_file):
        r = verify_evidence_hash(test_file, expected_md5=KNOWN_MD5)
        assert r["md5_match"] is True
        assert r["integrity_verified"] is True

    def test_wrong_md5_mismatch(self, test_file):
        r = verify_evidence_hash(test_file, expected_md5="deadbeef" * 4)
        assert r["md5_match"] is False
        assert r["integrity_verified"] is False

    def test_correct_sha1_match(self, test_file):
        r = verify_evidence_hash(test_file, expected_sha1=KNOWN_SHA1)
        assert r["sha1_match"] is True

    def test_case_insensitive_comparison(self, test_file):
        r = verify_evidence_hash(test_file, expected_md5=KNOWN_MD5.upper())
        assert r["md5_match"] is True

    def test_file_not_found(self):
        r = verify_evidence_hash("/nonexistent.img")
        assert r["success"] is False


class TestSsdeepTools:
    @patch("tools.hashing.run")
    def test_ssdeep_hash(self, mock_run, run_ok, test_file):
        mock_run.return_value = run_ok
        r = ssdeep_hash(test_file)
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "ssdeep" in cmd

    @patch("tools.hashing.run")
    def test_ssdeep_compare(self, mock_run, run_ok, test_file):
        mock_run.return_value = run_ok
        ssdeep_compare(test_file, test_file)
        cmd = mock_run.call_args[0][0]
        assert "-d" in cmd

    @patch("tools.hashing.run")
    def test_ssdeep_scan_directory(self, mock_run, run_ok, tmp_path):
        mock_run.return_value = run_ok
        ssdeep_scan_directory(str(tmp_path), threshold=70)
        cmd = mock_run.call_args[0][0]
        assert "-r" in cmd
        assert "70" in cmd


class TestHashdeepTools:
    @patch("tools.hashing.run")
    def test_hashdeep_compute_basic(self, mock_run, run_ok, tmp_path):
        mock_run.return_value = run_ok
        hashdeep_compute(str(tmp_path))
        cmd = mock_run.call_args[0][0]
        assert "hashdeep" in cmd

    @patch("tools.hashing.run")
    def test_hashdeep_compute_recursive(self, mock_run, run_ok, tmp_path):
        (tmp_path / "sub").mkdir()
        mock_run.return_value = run_ok
        hashdeep_compute(str(tmp_path), recursive=True)
        cmd = mock_run.call_args[0][0]
        assert "-r" in cmd

    @patch("tools.hashing.run")
    def test_hashdeep_compute_writes_output(self, mock_run, run_ok, tmp_path):
        output = str(tmp_path / "manifest.txt")
        mock_run.return_value = {**run_ok, "stdout": "hashdeep output"}
        r = hashdeep_compute(str(tmp_path), output_path=output)
        assert os.path.exists(output)
        assert r["manifest_path"] == output

    @patch("tools.hashing.run")
    def test_hashdeep_audit(self, mock_run, run_ok, tmp_path):
        mock_run.return_value = run_ok
        hashdeep_audit("manifest.txt", str(tmp_path), mode="audit")
        cmd = mock_run.call_args[0][0]
        assert "-a" in cmd
        assert "-k" in cmd

    @patch("tools.hashing.run")
    def test_md5deep_scan(self, mock_run, run_ok, tmp_path):
        mock_run.return_value = run_ok
        md5deep_scan(str(tmp_path))
        cmd = mock_run.call_args[0][0]
        assert "md5deep" in cmd
        assert "-r" in cmd
