"""Capture exact output ownership at completion, never by a later directory scan."""
from contextvars import ContextVar
from functools import wraps
import asyncio
import fcntl
import hashlib
import inspect
import os
from pathlib import Path
import shlex
import tempfile

from core.evidence_packets import file_version

_invocation = ContextVar('output_invocation', default=None)


def targets(cmd, output_path=None, cwd=None, produced_paths=()):
    tokens = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
    pairs = dict(zip(tokens, tokens[1:]))
    paths = list(produced_paths or ())
    if output_path:
        paths.append(output_path)
    # EZ tools use a directory PLUS a filename; neither flag alone certifies
    # ownership of every file found in the directory.
    for directory, filename in (('--csv', '--csvf'), ('--json', '--jsonf')):
        if pairs.get(directory) and pairs.get(filename):
            paths.append(os.path.join(pairs[directory], pairs[filename]))
    for flag in ('--output', '--output-file', '--output_file', '--dumpfile'):
        if pairs.get(flag):
            paths.append(pairs[flag])
    resolved = sorted({os.path.abspath(os.path.join(cwd or os.getcwd(), os.path.expanduser(p)))
                       for p in paths})
    return [p for p in resolved if not os.path.isdir(p)]


class Invocation:
    def __init__(self, paths):
        self.paths, self.locks, self.before = paths, [], {}

    def acquire(self):
        root = Path(tempfile.gettempdir()) / f'trudi-output-locks-{os.getuid()}'
        root.mkdir(mode=0o700, exist_ok=True)
        try:
            for path in self.paths:
                lock = open(root / hashlib.sha256(path.encode()).hexdigest(), 'a')
                self.locks.append(lock)
                fcntl.flock(lock, fcntl.LOCK_EX)
                self.before[path] = file_version(path)
                from core.execution_log import log
                from core.output_protection import retained_paths
                if os.path.realpath(path) in retained_paths(log) and self.before[path]:
                    raise ValueError('Retained evidence output is protected: ' + path +
                                     '. Publish a new output path; the previous version must remain readable.')
        except BaseException:
            self.release()
            raise

    def release(self):
        for lock in reversed(self.locks):
            lock.close()
        self.locks.clear()

    def finish(self, success):
        files, unavailable = [], []
        for path in self.paths:
            version = file_version(path)
            if success and version and version != self.before[path] and os.path.isfile(path):
                files.append({'path': path, 'version': version, 'role': 'produced_output',
                              'complete': True})
            else:
                unavailable.append(path)
        return {'schema_version': 1, 'files': files, 'unavailable_targets': unavailable,
                'attribution': 'declared_targets_at_completion',
                'discovery_complete': False,
                'limitation': 'Only declared output files are registered; directory siblings are not attributed.'}


def output_manifested(fn):
    """Serialize cooperating writers to the SAME file, including across processes.

    Different filenames in a shared directory remain independent. Directory-only
    tools must register paths explicitly or expose a traced read of their output.
    """
    signature = inspect.signature(fn)
    def prepare(args, kwargs):
        bound = signature.bind(*args, **kwargs).arguments
        return Invocation(targets(bound['cmd'], bound.get('output_path'),
                                  bound.get('cwd'), bound.get('produced_paths')))
    if inspect.iscoroutinefunction(fn):
        @wraps(fn)
        async def wrapped(*args, **kwargs):
            inv = prepare(args, kwargs)
            # Shield acquisition so cancellation cannot leak a held file lock.
            task = asyncio.create_task(asyncio.to_thread(inv.acquire))
            try:
                await asyncio.shield(task)
            except BaseException:
                await task
                inv.release()
                raise
            token = _invocation.set(inv)
            try:
                return await fn(*args, **kwargs)
            finally:
                _invocation.reset(token)
                inv.release()
    else:
        @wraps(fn)
        def wrapped(*args, **kwargs):
            inv = prepare(args, kwargs)
            inv.acquire()
            token = _invocation.set(inv)
            try:
                return fn(*args, **kwargs)
            finally:
                _invocation.reset(token)
                inv.release()
    return wrapped


def completed_manifest(success):
    inv = _invocation.get()
    return inv.finish(success) if inv else None


def read_manifest(path, version, selector):
    from core.evidence_admission import read_provenance
    return {'schema_version': 1, 'attribution': 'observed_read', 'discovery_complete': True,
            'files': [{'path': os.path.abspath(path), 'version': version,
                       'role': 'read_source', 'selector': selector, **read_provenance(path)}]}
