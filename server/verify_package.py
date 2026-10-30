"""Verify release contents before installation; this is a checksum, not a signature."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
manifest = json.loads((root / 'release-manifest.json').read_text(encoding='utf-8'))
failures = []
for filename, expected in manifest['files'].items():
    path = root / filename
    # Git may check out these text sources with CRLF on Windows. Hash their
    # canonical LF bytes so the same manifest verifies on every supported OS.
    actual = path.read_bytes().replace(b'\r\n', b'\n') if path.is_file() else None
    if actual is None or hashlib.sha256(actual).hexdigest() != expected:
        failures.append(filename)
if failures:
    raise SystemExit('Release differs: ' + ', '.join(failures))
print('Verified ' + str(len(manifest['files'])) + ' release files. LOCAL ONLY, production disabled.')
