"""One selector contract for initial, continued and legacy independent reviews."""
import re


def normalize_requests(items):
    if not isinstance(items, list):
        raise ValueError('evidence_request must be a list')
    requests = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError('Each evidence request must be an object')
        cid = item.get('call_id')
        if isinstance(cid, str) and cid.isdecimal():
            cid = int(cid)
        if type(cid) is not int or cid <= 0:
            raise ValueError('Evidence request needs a positive call_id')
        query = item.get('query')
        if not isinstance(query, str) or not query.strip():
            raise ValueError('Evidence request needs a nonempty query')
        columns = item.get('columns') or []
        if isinstance(columns, str):
            columns = re.split(r'[,|]', columns)
        if not isinstance(columns, list) or any(not isinstance(c, str) for c in columns):
            raise ValueError('columns must name fields, not individual characters or objects')
        request = {'call_id': cid, 'query': query.strip()[:200],
                   'columns': list(dict.fromkeys(c.strip() for c in columns if c.strip()))[:8]}
        for key in ('path', 'replaces_request_id', 'request_id'):
            value = item.get(key)
            if value is not None and not isinstance(value, str):
                raise ValueError(key + ' must be a string or null')
            if value:
                request[key] = value
        if item.get('finding_call_id') is not None:
            if type(item['finding_call_id']) is not int:
                raise ValueError('finding_call_id must be an integer')
            request['finding_call_id'] = item['finding_call_id']
        requests.append(request)
    return requests
