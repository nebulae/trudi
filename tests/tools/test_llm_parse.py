"""RESULT block: structured-first parsing of reviewer / DAIR output."""
import json

import tools._llm_parse as LP


class TestParseResultBlock:
    def test_plain(self):
        raw = 'analysis…\nRESULT:\n{"verdict": "SUPPORTED", "weaknesses": ["a"]}\n'
        obj, path = LP.parse_result_block(raw)
        assert obj == {"verdict": "SUPPORTED", "weaknesses": ["a"]} and path == "result_json"

    def test_bold_and_fence_and_comments(self):
        raw = ('prose\n**RESULT**:\n```json\n{\n  "verdict": "CHALLENGED", // why\n'
               '  "directives": {"priority_tools": ["ez.evtxecmd"]}\n}\n```\n')
        obj, _ = LP.parse_result_block(raw)
        assert obj["verdict"] == "CHALLENGED"
        assert obj["directives"]["priority_tools"] == ["ez.evtxecmd"]

    def test_nested_braces_and_strings(self):
        raw = 'RESULT:\n{"rationale": "has } brace and \\" quote", "d": {"x": {"y": 1}}}\nVERDICT: SUPPORTED'
        obj, _ = LP.parse_result_block(raw)
        assert obj["d"]["x"]["y"] == 1 and "}" in obj["rationale"]

    def test_last_block_wins(self):
        raw = 'RESULT:\n{"verdict": "UNCERTAIN"}\n…revised…\nRESULT:\n{"verdict": "SUPPORTED"}'
        assert LP.parse_result_block(raw)[0]["verdict"] == "SUPPORTED"

    def test_absent_or_malformed(self):
        assert LP.parse_result_block("no block here") == (None, "")

    # Regression (VANKO-2016-DEEPSEEK41, 2026-09-19): deepseek-v4.1 via Ollama
    # returns the requested object with no RESULT: header. DAIR read that as an
    # empty assessment and reason.* stored the raw JSON as the conclusion.
    def test_bare_object_without_header(self):
        raw = '{"schema_version": 1, "rationale": "r", "assessment": {"current_phase": "Triage"}}'
        obj, path = LP.parse_result_block(raw)
        assert obj["assessment"]["current_phase"] == "Triage" and path == "result_json"
        assert LP.strip_result_block(raw) == ""

    def test_bare_fenced_object_after_prose(self):
        raw = 'Some reasoning.\n```json\n{"schema_version": 1, "hypotheses": [{"id": "a"}]}\n```\n'
        obj, _ = LP.parse_result_block(raw)
        assert obj["hypotheses"] == [{"id": "a"}]
        assert LP.strip_result_block(raw) == "Some reasoning."

    def test_bare_object_needs_schema_version(self):
        assert LP.parse_result_block('prose {"a": 1} more') == (None, "")

    def test_header_wins_over_bare_object(self):
        raw = ('{"schema_version": 1, "verdict": "UNCERTAIN"}\n'
               'RESULT:\n{"schema_version": 1, "verdict": "SUPPORTED"}')
        assert LP.parse_result_block(raw)[0]["verdict"] == "SUPPORTED"
        assert LP.parse_result_block('RESULT:\n{"a": ') == (None, "")
        assert LP.parse_result_block("") == (None, "")

    def test_strip_is_surgical(self):
        raw = 'before\nRESULT:\n{"verdict": "SUPPORTED"}\nVERDICT: SUPPORTED — after'
        out = LP.strip_result_block(raw)
        assert "before" in out and "after" in out and "RESULT" not in out

    def test_str_list(self):
        assert LP.str_list(["a", 1, " ", None]) == ["a", "1", "None"] or LP.str_list(["a", 1, " "]) == ["a", "1"]
        assert LP.str_list("nope") == []

    def test_instruction_names_shape(self):
        t = LP.result_instruction('{"verdict": "X"}')
        assert "RESULT:" in t and '"verdict": "X"' in t and '"schema_version": 1' in t
