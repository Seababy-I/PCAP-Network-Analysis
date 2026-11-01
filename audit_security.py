"""Read-only audit verification and independently signed checkpoints."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
from uuid import uuid4

from crypto_utils import sign_report, verify_report
from confidentiality import prompt_password,set_session_password


def _rows(db_name):
    conn = sqlite3.connect(Path(db_name).resolve().as_uri() + '?mode=ro', uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute('SELECT * FROM audit_log ORDER BY id')]
    finally:
        conn.close()


def verify_audit(db_name, *, checkpoint=None, signature=None, key_dir='keys'):
    rows = _rows(db_name)
    previous = 'GENESIS'
    for row in rows:
        if row['prev_hash'] != previous:
            return False, f'Previous hash mismatch at entry {row["id"]}'
        version = row.get('hash_version', 1)
        if version == 1:
            payload = row['operation'] + row['status'] + row['timestamp'] + row['prev_hash']
        elif version == 2:
            payload = json.dumps({k:row[k] for k in ('id','evidence_id','operation','status','timestamp',
                'prev_hash','details','hash_version')}, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        else:
            return False, f'Unsupported audit version at entry {row["id"]}'
        if hashlib.sha256(payload.encode()).hexdigest() != row['entry_hash']:
            return False, f'Digest mismatch at entry {row["id"]}'
        previous = row['entry_hash']
    if checkpoint is not None:
        if signature is None:
            raise ValueError('Checkpoint signature is required')
        if not verify_report(checkpoint, signature, key_dir=key_dir):
            return False, 'Checkpoint signature is invalid'
        trusted = json.loads(Path(checkpoint).read_text(encoding='utf-8'))
        if trusted.get('version') != 1:
            raise ValueError('Unsupported checkpoint version')
        prefix = [row for row in rows if row['id'] <= trusted['last_id']]
        head = prefix[-1]['entry_hash'] if prefix else 'GENESIS'
        if len(prefix) != trusted['entry_count'] or head != trusted['entry_hash']:
            return False, 'Audit history does not match the trusted checkpoint'
    legacy = sum(row.get('hash_version', 1) == 1 for row in rows)
    return True, f'{len(rows)} entries valid; {legacy} legacy entries have limited field coverage'


def create_checkpoint(db_name, output_dir, *, key_dir='keys'):
    valid, reason = verify_audit(db_name)
    if not valid:
        raise ValueError(reason)
    rows = _rows(db_name)
    # Verify the same snapshot that is committed into the checkpoint below.
    # Appends during this read are harmless; existing entries must remain intact.
    payload = dict(version=1, entry_count=len(rows), last_id=rows[-1]['id'] if rows else 0,
                   entry_hash=rows[-1]['entry_hash'] if rows else 'GENESIS')
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (uuid4().hex + '.checkpoint.json')
    with path.open('x', encoding='utf-8') as stream:
        json.dump(payload, stream, sort_keys=True)
    signature = sign_report(path, signature_dir=directory, key_dir=key_dir)
    # Detect changes between the two snapshot reads before returning a trusted result.
    valid, reason = verify_audit(db_name, checkpoint=path, signature=signature, key_dir=key_dir)
    if not valid:
        raise ValueError(reason)
    return str(path), signature


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', required=True)
    parser.add_argument('--keys', default='keys')
    parser.add_argument('--create', metavar='OUTPUT_DIRECTORY')
    parser.add_argument('--checkpoint')
    parser.add_argument('--signature')
    args = parser.parse_args(argv)
    try:
        if args.create:
            set_session_password(prompt_password())
            print(json.dumps(create_checkpoint(args.db, args.create, key_dir=args.keys)))
            return 0
        valid, message = verify_audit(args.db, checkpoint=args.checkpoint, signature=args.signature, key_dir=args.keys)
    except (ValueError, OSError, sqlite3.Error, KeyError, TypeError) as error:
        parser.exit(2, f'Audit verification unavailable: {error}\n')
    print(message)
    return 0 if valid else 1


if __name__ == '__main__':
    raise SystemExit(main())
