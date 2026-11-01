"""Sign saved evidence and run network heuristics without synthetic TLS findings."""
import argparse
import json
import sqlite3
from analysis_service import DEFAULT_DB, DEFAULT_KEYS, DEFAULT_STORAGE, process_capture
from confidentiality import prompt_password,set_session_password


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcap', required=True)
    parser.add_argument('--db', default=str(DEFAULT_DB))
    parser.add_argument('--storage', default=str(DEFAULT_STORAGE))
    parser.add_argument('--keys', default=str(DEFAULT_KEYS))
    parser.add_argument('--mode',choices=['network','full'],default='full')
    parser.add_argument('--allow-plaintext-metadata',action='store_true',help='Acknowledge that SQLite packet/protocol metadata is not encrypted yet')
    parser.add_argument('--tshark')
    args = parser.parse_args(argv)
    try:
        set_session_password(prompt_password())
        result = process_capture(args.pcap, db_name=args.db, storage_dir=args.storage, key_dir=args.keys,
            mode=args.mode,allow_plaintext_metadata=args.allow_plaintext_metadata,tshark_path=args.tshark)
    except (ValueError, OSError, sqlite3.Error,RuntimeError) as error:
        parser.exit(1, f'Analysis failed: {error}\n')
    print(json.dumps(result, indent=2))
    print('Network-only analysis: packet/flow storage was not requested.' if args.mode=='network' else
          'Functional parser/storage integration; parser coverage limitations and unencrypted SQLite metadata remain.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
