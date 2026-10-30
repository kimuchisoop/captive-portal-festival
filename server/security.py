"""Restrict newly-created service directories before writing any secrets."""
import csv
import io
import os
import subprocess
import re
from functools import lru_cache


@lru_cache(maxsize=1)
def windows_sid():
    result = subprocess.run(['whoami', '/user', '/fo', 'csv', '/nh'], check=True, capture_output=True)
    # Only the ASCII SID is needed; the account name and diagnostics use the OS code page.
    match = re.search(rb',"(S-1-(?:[0-9]+-)*[0-9]+)"\s*$',result.stdout)
    if match is None:
        raise ValueError('Cannot determine Windows security identity')
    return match[1].decode('ascii')


def protect_directory(path):
    if os.name == 'nt':
        subprocess.run(['icacls', str(path), '/inheritance:r', '/grant:r',
                        '*' + windows_sid() + ':(OI)(CI)F', '*S-1-5-18:(OI)(CI)F'],
                       check=True, capture_output=True)
    else:
        os.chmod(path, 0o700)
