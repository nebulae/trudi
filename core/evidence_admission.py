"""Evidence admission is separate from execution success and scope completion."""


def evidence_usable(entry):
    if entry.get('success') is True:
        return True
    return (entry.get('result_status') in ('partial', 'cancelled') and
            any(item.get('validated') is True for item in
                (entry.get('output_manifest') or {}).get('files', [])))


def scope_complete(entry):
    return entry.get('success') is True and entry.get('scope_complete') is not False


def read_provenance(path):
    """Keep traced reads from laundering interrupted or modified job output."""
    import os
    from core.execution_log import log
    from core.evidence_packets import file_version
    resolved = os.path.realpath(path)
    for entry in reversed(log._entries):
        if not entry.get('job_completion'):
            continue
        manifest = entry.get('output_manifest') or {}
        files = manifest.get('files', [])
        for item in files:
            if os.path.realpath(item['path']) == resolved:
                if not item.get('validated') or file_version(resolved) != item.get('version'):
                    raise ValueError('Job output changed or has not been validated; collect or validate it before citing it')
                return {'producer_call_id': entry['call_id'],
                        'complete': bool(item.get('complete')) and scope_complete(entry)}
        unsafe = [f.get('derived_from') for f in files if f.get('derived_from')]
        unsafe += [f.get('path') for f in manifest.get('rejected_files', []) if isinstance(f, dict)]
        if any(p and os.path.realpath(p) == resolved for p in unsafe):
            raise ValueError('Interrupted output is not citable; read its validated output prefix from misc.job_status')
        if not scope_complete(entry) and os.path.isdir(resolved) and any(
                os.path.realpath(p).startswith(resolved + os.sep)
                for p in unsafe + [f['path'] for f in files] if p):
            raise ValueError('This directory contains incomplete job output; read an individually validated file')
    return {'complete': True}
