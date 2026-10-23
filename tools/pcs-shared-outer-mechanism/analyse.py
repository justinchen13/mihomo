"""Bounded offline analysis only; all runtime inputs must already be frozen."""
import argparse
import hashlib
import json
import os
from pathlib import Path
from contract import analyse


def load(path):
    with Path(path).open('rb') as f:
        b = f.read(1048577)
    if len(b) > 1048576:
        raise ValueError('one_MiB_input_cap')
    return json.loads(b), hashlib.sha256(b).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--client', required=True)
    p.add_argument('--origin-result', required=True)
    p.add_argument('--resources', required=True)
    p.add_argument('--output', required=True)
    a = p.parse_args()
    c, cs = load(a.client)
    o, osum = load(a.origin_result)
    r, rs = load(a.resources)
    result = analyse(c, o, r)
    result['input_sha256'] = {'client': cs, 'origin_result': osum, 'resources': rs}
    data = json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()+b'\n'
    if len(data) > 262144:
        raise ValueError('summary_cap')
    fd = os.open(a.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)


if __name__ == '__main__':
    main()
