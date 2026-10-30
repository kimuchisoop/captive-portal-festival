"""Verify release contents before installation; this is a checksum, not a signature."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
manifest = json.loads((root / 'release-manifest.json').read_text(encoding='utf-8'))
failures = []
for filename, expected in manifest['files'].items():
    path = root / filename
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        failures.append(filename)
if failures:
    raise SystemExit('Release differs: ' + ', '.join(failures))
print('Verified ' + str(len(manifest['files'])) + ' release files. LOCAL ONLY, production disabled.')
