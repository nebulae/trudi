"""Attacker launcher boundaries; the Windows behavior is exercised on the demo VM."""
import os
from pathlib import Path
import subprocess
import shutil

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / 'demo/live-monitoring/victim/attacks/win-decoy.sh'


@pytest.mark.parametrize('account', ['DOMAIN\\linda', 'linda & whoami', 'linda;whoami', 'linda"', '-linda'])
def test_account_cannot_inject_the_desktop_command(tmp_path, account):
    result = subprocess.run(['bash', str(SCRIPT)], capture_output=True, text=True,
        env=dict(os.environ, WIN_HONEY_USER=account, WINDECOY_STATE_DIR=str(tmp_path)), timeout=5)
    assert result.returncode == 2
    assert 'Invalid local honey account' in result.stderr


def test_cleanup_does_not_signal_an_unrelated_process(tmp_path):
    (tmp_path / 'pid').write_text(str(os.getpid()))
    result = subprocess.run(['bash', str(SCRIPT), '--cleanup'], capture_output=True, text=True,
        env=dict(os.environ, WINDECOY_STATE_DIR=str(tmp_path)), timeout=5)
    assert result.returncode == 0
    os.kill(os.getpid(), 0)
    assert not (tmp_path / 'pid').exists()
    assert 'persistence remain evidence' in result.stdout


def test_honey_activity_collector_compiles_with_real_velociraptor():
    binary = shutil.which('velociraptor')
    if not binary:
        pytest.skip('installed Velociraptor required')
    root = SCRIPT.parents[4]
    result = subprocess.run([binary, '--definitions', str(root / 'monitoring/artifacts'),
        'artifacts', 'show', 'Custom.TRUDI.Win.HoneyActivity'],
        capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
