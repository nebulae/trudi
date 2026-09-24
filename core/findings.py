"""Finding lifecycle projections. History is preserved; invalid links never hide claims."""
from dataclasses import dataclass


@dataclass
class FindingView:
    active: list[dict]
    history: list[dict]
    anomalies: list[dict]


def incompatible_claim(old: dict, new: dict) -> list[str]:
    """Conservative typed compatibility, without guessing identity from prose."""
    a, b = old.get('claim') or {}, new.get('claim') or {}
    changed = [k for k in ('kind', 'category', 'act', 'channel', 'principal_norm')
               if a.get(k) and b.get(k) and a[k] != b[k]]
    ae = set(a.get('entities_norm') or a.get('entities') or [])
    be = set(b.get('entities_norm') or b.get('entities') or [])
    if ae and be and not ae.intersection(be):
        changed.append('entities')
    return changed


def finding_view(entries) -> FindingView:
    findings = [e for e in entries if e.get('type') == 'finding']
    by_id = {e['call_id']: e for e in findings if e.get('call_id') is not None}
    children: dict[int, list[dict]] = {}
    anomalies = []
    retracted = {e.get('finding_call_id') for e in entries if e.get('type') == 'finding_retracted'}
    for e in findings:
        parent = e.get('supersedes')
        if parent:
            children.setdefault(parent, []).append(e)
    retired = set()
    for parent, all_successors in children.items():
        old = by_id.get(parent)
        successors = [e for e in all_successors if e.get('call_id') not in retracted]
        if not successors:
            # Withdrawing a valid replacement must never resurrect the old claim.
            # Withdrawing an invalid legacy link, however, must not retire its target.
            if (old and len(all_successors) == 1
                    and all_successors[0]['call_id'] > parent
                    and not incompatible_claim(old, all_successors[0])):
                retired.add(parent)
            continue
        bad = ('missing_target' if old is None else
               'branching_revision' if len(successors) != 1 else
               'non_forward_revision' if successors[0]['call_id'] <= parent else
               'incompatible_claim' if incompatible_claim(old, successors[0]) else '')
        if bad:
            anomalies.append({'code': bad, 'target_call_id': parent,
                              'call_ids': [s['call_id'] for s in successors]})
        else:
            retired.add(parent)
    for e in findings:
        target = e.get('superseded_by')
        if target and target not in retracted and e['call_id'] not in retracted and not any(s.get('call_id') == target for s in children.get(e['call_id'], [])):
            anomalies.append({'code': 'orphan_superseded_by', 'target_call_id': e['call_id'],
                              'call_ids': [target]})
    # Retractions are explicit audit events and must reference a known finding.
    for e in entries:
        if e.get('type') == 'finding_retracted':
            target = e.get('finding_call_id')
            if target in by_id:
                retired.add(target)
            else:
                anomalies.append({'code': 'missing_retraction_target', 'target_call_id': target})
    return FindingView([e for e in findings if e.get('call_id') not in retired], findings, anomalies)


def active_findings(entries) -> list[dict]:
    return finding_view(entries).active


def current_entries(entries) -> list[dict]:
    """Current-state consumers use this; challenge/refusal history remains intact."""
    active = {e.get('call_id') for e in active_findings(entries)}
    return [e for e in entries if e.get('type') != 'finding' or e.get('call_id') in active]


def validate_revision(entries, supersedes: int, claim: dict | None = None) -> dict | None:
    if not supersedes:
        return None
    view = finding_view(entries)
    old = next((e for e in view.history if e['call_id'] == supersedes), None)
    if old is None:
        raise ValueError(f'Finding revision target {supersedes} does not exist in this case')
    retracted = {e.get('finding_call_id') for e in entries if e.get('type') == 'finding_retracted'}
    if any(e.get('supersedes') == supersedes and e.get('call_id') not in retracted
           for e in view.history) or old not in view.active:
        raise ValueError(f'Finding {supersedes} is not the current revision; select its active successor')
    if any(a.get('target_call_id') == supersedes or supersedes in a.get('call_ids', [])
           for a in view.anomalies):
        raise ValueError(f'Finding {supersedes} has ambiguous lifecycle links; adjudicate them first')
    changed = incompatible_claim(old, {'claim': claim or {}})
    if changed:
        raise ValueError(f'Revision changes proposition fields: {", ".join(changed)}. '
                         'Record a separate finding and explicitly retract the old claim if necessary')
    return old
