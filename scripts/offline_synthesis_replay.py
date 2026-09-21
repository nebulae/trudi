"""Read-only packet/batch measurements. Never configure a trace or call a model."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def measure(trace):
    from core.execution_log import ExecutionLog
    from core.synthesis_evidence import build_synthesis_index, task_packet
    from core.synthesis_session import tasks_for, INSTRUCTION, TASK_SYSTEM
    from core.evidence_display import prompt_packet
    from tools.reasoning import _result_suffix
    data = json.loads(Path(trace).read_text())
    log = ExecutionLog()
    log._entries = data['entries']
    log._case_id = data['case_id']
    log._run_id = data.get('run_id') or 'offline-snapshot'
    log._path = str(Path(trace).resolve())
    index = build_synthesis_index(log)
    tasks = tasks_for(index)
    sizes = [len(TASK_SYSTEM + _result_suffix('reason_synthesize')) + len(INSTRUCTION) + len(json.dumps(prompt_packet(task_packet(index, t['finding_ids'])))) for t in tasks]
    return {'trace': str(trace), 'active_findings': len(index['findings']),
            'source_aliases': len(index['evidence']),
            'physical_sources': len({s['source_id'] for s in index['evidence']}),
            'index_characters': len(json.dumps(prompt_packet(index))),
            'tasks': len(tasks), 'maximum_initial_prompt_characters': max(sizes, default=0),
            'maximum_with_40000_fetch_headroom': max(sizes, default=0) + 40000,
            'initial_rows': 0, 'model_calls': 0}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace')
    args = parser.parse_args()
    print(json.dumps(measure(args.trace), indent=2))
