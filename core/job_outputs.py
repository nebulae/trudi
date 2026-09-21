"""Production-time manifests and conservative admission of interrupted output."""
import csv
import hashlib
import json
import os
from pathlib import Path
from core.evidence_packets import file_version


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def snapshot(roots):
    result = {}
    for root in roots:
        path = Path(root)
        for item in path.rglob('*') if path.is_dir() else [path]:
            if item.is_file() and not item.is_symlink():
                result[str(item.resolve())] = file_version(item)
    return result


def _partial_records(path, job_id):
    """Produce a separate valid prefix; the original interrupted file is retained."""
    suffix = Path(path).suffix.lower()
    if suffix not in ('.csv', '.tsv', '.jsonl', '.txt', '.log'):
        return None
    output = path + '.' + job_id + '.validated' + suffix
    count = 0
    try:
        with open(path, encoding='utf-8', errors='strict', newline='') as source, open(output, 'w', encoding='utf-8', newline='') as dest:
            if suffix in ('.csv', '.tsv'):
                delimiter = '\t' if suffix == '.tsv' else ','
                def terminated_lines():
                    for line in source:
                        if not line.endswith(('\n', '\r')):
                            break
                        yield line
                reader = csv.reader(terminated_lines(), delimiter=delimiter, strict=True)
                header = next(reader, None)
                if not header or len(set(header)) != len(header):
                    return None
                writer = csv.writer(dest, delimiter=delimiter)
                writer.writerow(header)
                try:
                    for row in reader:
                        if len(row) != len(header):
                            break
                        writer.writerow(row)
                        count += 1
                except csv.Error:
                    pass
            else:
                for line in source:
                    if not line.endswith('\n'):
                        break
                    if suffix == '.jsonl':
                        try:
                            json.loads(line)
                        except ValueError:
                            break
                    dest.write(line)
                    count += 1
            dest.flush()
            os.fsync(dest.fileno())
    except (OSError, UnicodeError, csv.Error):
        return None
    return {'path': output, 'row_count': count, 'derived_from': path,
            'selection_description': 'validated complete record prefix'} if count else None


def validate_complete(path):
    """Validate known record/container formats without interpreting their facts."""
    suffix = Path(path).suffix.lower()
    if suffix in ('.csv', '.tsv'):
        with open(path, encoding='utf-8-sig', newline='') as stream:
            rows = csv.reader(stream, delimiter='\t' if suffix == '.tsv' else ',', strict=True)
            header = next(rows, None)
            if not header or len(set(header)) != len(header):
                raise ValueError('Missing or ambiguous record header')
            count = 0
            for row in rows:
                if len(row) != len(header):
                    raise ValueError('Incomplete record')
                count += 1
        return {'validation': 'csv_strict', 'row_count': count}
    if suffix in ('.json', '.jsonl'):
        with open(path, encoding='utf-8-sig') as stream:
            if suffix == '.json':
                json.load(stream)
            else:
                for line in stream:
                    json.loads(line)
        return {'validation': 'json_parse'}
    if suffix == '.zip':
        import zipfile
        with zipfile.ZipFile(path) as archive:
            if archive.testzip() is not None:
                raise ValueError('Unreadable archive member')
        return {'validation': 'zip_crc'}
    # Opaque artifacts (carved images, mail, plaso stores) retain the wrapper's
    # completion assertion. Interrupted opaque formats never use this branch.
    return {'validation': 'completed_adapter_output'}


def finalize(roots, before, *, complete, job_id):
    after = snapshot(roots)
    files, rejected = [], []
    for path, version in after.items():
        if before.get(path) == version:
            continue
        item = {'path': path}
        file_complete = complete
        if file_complete:
            try:
                item.update(validate_complete(path))
            except (OSError, ValueError, UnicodeError, csv.Error) as exc:
                rejected.append({'path': path, 'reason': 'format validation failed: ' + str(exc)})
                file_complete = False
            except Exception as exc:
                rejected.append({'path': path, 'reason': 'container validation failed: ' + str(exc)})
                file_complete = False
        if not file_complete:
            selected = _partial_records(path, job_id)
            if not selected:
                rejected.append({'path': path, 'reason': 'partial output requires format validation'})
                continue
            item.update(selected)
            item['validation'] = 'complete_record_prefix'
        chosen = item['path']
        before_hash = file_version(chosen)
        try:
            hashed = sha256(chosen)
        except OSError:
            rejected.append({'path': chosen, 'reason': 'output unavailable'})
            continue
        if before_hash != file_version(chosen):
            rejected.append({'path': chosen, 'reason': 'output changed during finalization'})
            continue
        files.append({**item, 'version': before_hash, 'sha256': hashed,
            'byte_size': os.path.getsize(chosen), 'role': 'produced_output',
            'validated': True, 'complete': file_complete, 'scope_complete': file_complete})
    return {'schema_version': 2, 'files': files, 'rejected_files': rejected,
            'attribution': 'worker_finalization', 'discovery_complete': complete}


def verify_manifest(manifest, *, hashes=True):
    errors = []
    for item in manifest.get('files', []):
        try:
            if file_version(item['path']) != item['version'] or (hashes and sha256(item['path']) != item['sha256']):
                errors.append(item['path'])
        except (OSError, KeyError):
            errors.append(item.get('path'))
    return errors
