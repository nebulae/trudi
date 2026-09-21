"""One registry for job selection, worker adapters and generated guidance."""
from functools import wraps
import inspect
import os

# adapter: input arguments whose resolved directories make the call unbounded.
# None means always background; mail stores use a byte threshold.
ADAPTERS = {
    'tools.carving:bulk_extractor_scan': None,
    'tools.carving:bulk_extractor_unallocated': None,
    'tools.carving:foremost_carve': None,
    'tools.carving:scalpel_carve': None,
    'tools.imaging:photorec_carve': None,
    'tools.plaso:plaso_create_timeline': None,
    'tools.plaso:plaso_create_targeted': None,
    'tools.eztools:ez_lecmd': ('lnk_path',),
    'tools.eztools:ez_jlecmd': ('jump_list_path',),
    'tools.eztools:ez_pecmd': ('prefetch_path',),
    'tools.eztools:ez_mftecmd_dir': ('volume_dir',),
    'tools.eztools:ez_recmd_dir': ('hives_dir', 'directory'),
    'tools.eztools:ez_recmd_batch': ('hives_dir',),
    'tools.eztools:ez_sqlecmd': ('db_path', 'source_path'),
    'tools.eztools:ez_evtxecmd': ('evtx_path',),
    'tools.yara_tools:yara_scan_directory': ('directory', 'target_dir'),
    'tools.misc:readpst_extract': ('large_store',),
    'tools.misc:pff_export': ('large_store',),
    'tools.sleuthkit:tsk_recover': None,
}


def job_backed(fn):
    key = fn.__module__ + ':' + fn.__name__
    if key not in ADAPTERS:
        raise ValueError('Missing job adapter policy: ' + key)
    signature = inspect.signature(fn)
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if os.environ.get('TRUDI_JOB_WORKER') == '1' or os.environ.get('TRUDI_BACKGROUND_JOBS', '1') == '0':
            return fn(*args, **kwargs)
        bound = signature.bind(*args, **kwargs)
        bound.apply_defaults()
        arguments = bound.arguments
        policy = ADAPTERS[key]
        selected = policy is None
        if policy == ('large_store',):
            path = os.path.expanduser(arguments.get('pst_path', ''))
            selected = os.path.isfile(path) and os.path.getsize(path) >= 64 * 1024 * 1024
        elif policy:
            selected = any(os.path.isdir(os.path.expanduser(arguments.get(arg, ''))) for arg in policy)
        if not selected:
            return fn(*args, **kwargs)
        from core.jobs import start_job
        return start_job([], fn.__name__, 0, arguments.get('output_dir', ''),
                         adapter=key, arguments=dict(arguments),
                         needs_sudo=fn.__module__ in ('tools.carving', 'tools.sleuthkit', 'tools.imaging'))
    return wrapped


def guidance():
    return [{'adapter': key, 'mode': 'always' if value is None else 'large_store' if value == ('large_store',) else 'directory',
             'input_arguments': list(value or ())} for key, value in sorted(ADAPTERS.items())]
