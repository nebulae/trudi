"""Tests for tools/_gates/_citation.py — the deterministic cite check.

Regression: the Windows-path regex allowed unbounded spaces, so a path followed
by prose ("C:\\Users\\Some User\\capture is the file") became a single uncitable
'claim'; it also stopped at '@', truncating paths with an '@' segment.
"""
import pytest

from tools._gates._citation import extract_claims, deterministic_cite_check


def _paths(text):
    return [v for k, v in extract_claims(text) if k == "path"]


def _keys(text):
    return [v for k, v in extract_claims(text) if k == "registry_key"]


class TestWindowsPathExtraction:
    def test_prose_after_path_is_not_swallowed(self):
        text = (r"The file C:\Documents and Settings\Some User\capture is a "
                r"173,372-byte libpcap capture.")
        assert _paths(text) == [r"C:\Documents and Settings\Some User\capture"]

    def test_at_sign_segment_kept_whole(self):
        text = r"C:\Program Files\App@Net\config.ini is the key artifact on disk."
        assert _paths(text) == [r"C:\Program Files\App@Net\config.ini"]

    def test_sentence_end_period_stripped(self):
        assert _paths(r"Staged at C:\Users\Some User\Downloads\wiper.zip.") == \
            [r"C:\Users\Some User\Downloads\wiper.zip"]

    def test_two_paths_in_one_sentence(self):
        text = (r"Copied C:\Users\Some User\Desktop\holiday photos.7z to "
                r"E:\backup\holiday photos.7z, then ran the wiper.")
        assert _paths(text) == [r"C:\Users\Some User\Desktop\holiday photos.7z",
                                r"E:\backup\holiday photos.7z"]

    def test_path_followed_by_comma_and_prose(self):
        text = r"the binary C:\Windows\Temp\svc.exe, a renamed copy of a tool, ran"
        assert _paths(text) == [r"C:\Windows\Temp\svc.exe"]

    def test_overlong_prose_segment_not_treated_as_directory(self):
        # No punctuation after the path: the 4-space / 64-char bounds stop it.
        text = (r"C:\Program Files\App\Data\config.ini holds the settings and the "
                r"server is mail.example.net on port 119")
        assert _paths(text) == [r"C:\Program Files\App\Data\config.ini"]

    def test_registry_key_bounded(self):
        text = r"HKLM\Software\Vendor value Owner was set to a name at install."
        assert _keys(text) == [r"HKLM\Software\Vendor"]


class TestDeterministicCiteCheck:
    def test_path_cited_when_evidence_quotes_it(self):
        finding = r"C:\Program Files\App@Net\config.ini records the registered owner."
        evidence = r"strings C:\Program Files\App@Net\config.ini -> RegOwner=A. Name"
        r = deterministic_cite_check(finding, evidence)
        assert r["verdict"] == "ALL_CITED", r

    def test_uncited_path_still_flagged(self):
        r = deterministic_cite_check(r"Dropped C:\Windows\Temp\x.exe", "nothing relevant")
        assert r["verdict"] == "UNCITED_CLAIMS_PRESENT"
        assert r["uncited_claims"] == [r"C:\Windows\Temp\x.exe"]

    def test_prose_only_finding_all_cited(self):
        assert deterministic_cite_check("The account was created interactively.", "")["verdict"] == "ALL_CITED"
