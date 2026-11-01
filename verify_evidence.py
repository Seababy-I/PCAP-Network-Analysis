import argparse
import sqlite3
from analysis_service import DEFAULT_DB, DEFAULT_KEYS, verify_evidence
from confidentiality import prompt_password,set_session_password


def main(argv=None):
    parser = argparse.ArgumentParser(description='Verify existing evidence; never sign or replace keys.')
    parser.add_argument('--evidence-id', type=int, required=True)
    parser.add_argument('--db', default=str(DEFAULT_DB))
    parser.add_argument('--keys', default=str(DEFAULT_KEYS))
    parser.add_argument('--file', help='Optional candidate/tampered copy to compare with original evidence')
    args = parser.parse_args(argv)
    try:
        set_session_password(prompt_password())
        valid = verify_evidence(args.evidence_id, db_name=args.db, candidate_path=args.file, key_dir=args.keys)
    except (ValueError, OSError, sqlite3.Error) as error:
        parser.exit(2, f'Verification could not complete: {error}\n')
    print('VALID' if valid else 'INVALID: digest or signature mismatch')
    return 0 if valid else 1


if __name__ == '__main__':
    raise SystemExit(main())
