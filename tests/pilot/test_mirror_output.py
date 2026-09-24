"""The vera mirror carries retained tool output, not just the 600-char excerpt."""
import pilot.mirror as M


def test_reads_the_full_sidecar(tmp_path):
    side = tmp_path / "42.txt"
    side.write_text("row one\n" + "payload " * 500 + "\nrow last\n")
    entry = {"stdout_excerpt": "row one\n", "stdout_path": str(side),
             "stdout_chars": len(side.read_text())}
    out = M._action_output(entry)
    assert "row last" in out and len(out) > 600


def test_clip_is_stated_with_the_sidecar_path(tmp_path, monkeypatch):
    monkeypatch.setattr(M, "MIRROR_OUTPUT_CHARS", 100)
    side = tmp_path / "43.txt"
    side.write_text("x" * 5000)
    out = M._action_output({"stdout_excerpt": "x" * 600, "stdout_path": str(side),
                            "stdout_chars": 5000})
    assert "clipped at 100 chars of 5000" in out and str(side) in out
    assert len(out) < 400


def test_missing_sidecar_falls_back_to_the_excerpt(tmp_path):
    out = M._action_output({"stdout_excerpt": "only the excerpt",
                            "stdout_path": str(tmp_path / "gone.txt")})
    assert out == "only the excerpt"


def test_mcp_tool_names_the_action_shell_commands_left_to_vera():
    assert M._action_fields({"mcp_tool": "ez_recmd_hive"})["tool"] == "ez_recmd_hive"
    assert M._action_fields({"cmd": "<py>:reason_synthesize"})["tool"] == "reason_synthesize"
    assert M._action_fields({"cmd": 'P="/mnt/x"; ls $P'})["tool"] == ""


def test_produced_artifact_is_recorded():
    assert M._action_fields({"mcp_tool": "ez_mftecmd",
                             "output_path": "/case/exports/mft.csv"})["produced"] == "/case/exports/mft.csv"
