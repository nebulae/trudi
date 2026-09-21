import json
from pathlib import Path
import sqlite3
import subprocess
import pytest


def test_installed_hindsight_parses_synthetic_history(tmp_path):
    executable = Path('/usr/local/bin/hindsight.py')
    if not executable.is_file():
        pytest.skip('Optional Hindsight is not installed')
    profile = tmp_path / 'Default'
    profile.mkdir()
    output = tmp_path / 'parsed'
    output.mkdir()
    with sqlite3.connect(profile / 'History') as db:
        db.executescript('''
        CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,visit_count INTEGER,typed_count INTEGER,last_visit_time INTEGER,hidden INTEGER,favicon_id INTEGER);
        CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER,from_visit INTEGER,transition INTEGER,visit_duration INTEGER,is_indexed INTEGER);
        CREATE TABLE visit_source(id INTEGER PRIMARY KEY,source INTEGER);
        CREATE TABLE downloads(id INTEGER PRIMARY KEY,url TEXT,received_bytes INTEGER,total_bytes INTEGER,state INTEGER,full_path TEXT,start_time INTEGER,end_time INTEGER,opened INTEGER);
        INSERT INTO urls VALUES(1,'https://fixture.example.test/observed','Synthetic observation',1,1,13300000000000000,0,0);
        INSERT INTO visits VALUES(1,1,13300000000000000,0,1,0,0);
        INSERT INTO visit_source VALUES(1,0);
        ''')
    from tools.misc import hindsight_chrome
    result = hindsight_chrome(str(profile), str(output))
    assert result['success'], result
    records = [json.loads(line) for path in output.glob('*.jsonl') for line in path.read_text().splitlines() if line]
    assert any('https://fixture.example.test/observed' in json.dumps(row) for row in records), result
