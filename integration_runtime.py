"""User-owned coordination for the pinned teammate parser, without changing it."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import csv
import io
import os
from pathlib import Path
import re
import subprocess
import tempfile

from parser_adapter import preview_capture

TEAM_COMMIT='843b6898c29b27714e97da1010900496b7c7a88c'
PARSER_LIMITATIONS=[
    'DNS extraction covers A/AAAA/CNAME/MX/NS/PTR/TXT fields; other resource types are not extracted.',
    'Ambiguous HTTP groupings and multi-string TXT resources are rejected explicitly.',
    'Frame-coverage and record validation are enforced by the integration adapter.',
    'SQLite metadata is not encrypted; database encryption is deferred by project decision.',
]


def _restrict_directory(directory):
    if os.name!='nt':
        directory.chmod(0o700)
        return
    identity=subprocess.run(['whoami.exe','/user','/fo','csv','/nh'],capture_output=True,text=True,check=True)
    rows=list(csv.reader(io.StringIO(identity.stdout.strip())))
    sid=rows[0][-1] if rows else ''
    if not re.fullmatch(r'S-1-\d+(?:-\d+)+',sid):
        raise PermissionError('Could not identify the analyst for temporary-file permissions')
    result=subprocess.run(['icacls.exe',str(directory),'/inheritance:r','/grant:r',
        f'*{sid}:(OI)(CI)F','*S-1-5-18:(OI)(CI)F'],capture_output=True,text=True)
    if result.returncode:
        raise PermissionError('Could not restrict parser temporary-directory access')


def _parse_worker(content,tshark_path,pcapng):
    try:
        from parser import parse_pcap
    except ImportError as error:
        raise RuntimeError('Full parsing needs PyShark. Launch through launch_dashboard.py or use .venv-parser.') from error
    loop=asyncio.ProactorEventLoop() if os.name=='nt' else asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        with tempfile.TemporaryDirectory(prefix='pcap-parser-') as temporary:
            folder=Path(temporary)
            _restrict_directory(folder)  # Set permissions before writing any plaintext.
            source=folder/('capture.pcapng' if pcapng else 'capture.pcap')
            with source.open('xb') as stream:stream.write(content)
            source.chmod(0o600)
            return preview_capture(source,parser_fn=parse_pcap,tshark_path=tshark_path)
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.run_until_complete(asyncio.sleep(0))
        finally:
            asyncio.set_event_loop(None)
            loop.close()


def parse_content(content, *, tshark_path=None):
    # A dedicated thread owns its asyncio loop; Streamlit's caller state is untouched.
    with ThreadPoolExecutor(max_workers=1,thread_name_prefix='pcap-parser') as worker:
        return worker.submit(_parse_worker,content,tshark_path,content[:4]==b'\x0a\x0d\x0d\x0a').result()
