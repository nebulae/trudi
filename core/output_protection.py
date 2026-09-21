"""Preserve retained output paths when a wrapper publishes a fresh version."""
import os
from pathlib import Path
import uuid


def retained_paths(log):
    from core.evidence_admission import evidence_usable
    paths = set()
    for entry in log._entries:
        if entry.get('type') != 'tool_call' or not evidence_usable(entry):
            continue
        manifest = entry.get('output_manifest') or {}
        paths.update(os.path.realpath(f['path']) for f in manifest.get('files', []) if f.get('path'))
        for key in ('output_file', 'output_path', 'stdout_path'):
            value = entry.get(key)
            if isinstance(value, str) and os.path.isfile(value):
                paths.add(os.path.realpath(value))
    return paths


def version_destinations(arguments, names, log):
    owned = retained_paths(log)
    redirected = {}
    for name in names:
        value = arguments.get(name)
        if not isinstance(value, str) or not value:
            continue
        path = os.path.realpath(os.path.expanduser(value))
        if any(p == path or p.startswith(path + os.sep) for p in owned):
            target = Path(path)
            suffix = '.v-' + uuid.uuid4().hex[:12]
            fresh = str(target.with_name(target.stem + suffix + target.suffix)) if target.is_file() else path + suffix
            arguments[name] = fresh
            redirected[name] = {'requested': value, 'published': fresh}
    return redirected
