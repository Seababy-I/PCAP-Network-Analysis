"""Import Jahnnavi's structured parser output; TLS extraction is excluded."""
import argparse
import asyncio
import sys
from pathlib import Path
from contextlib import closing
import database as db
from parser_db_bridge import store_parsed_capture


def import_capture(path, db_name=db.DB_NAME, tshark_path=None, sha256=None, signature=None):
    # Lazy import: database/demo/tests require neither PyShark nor TShark.
    from parser import parse_pcap
    path = Path(path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f'Capture not found: {path}')
    # PyShark's published parser expects a current event loop, including on 3.14.
    # Use a subprocess-capable Windows loop for the synchronous CLI workflow.
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        raise RuntimeError('Run this synchronous importer outside a running asyncio loop')
    loop = asyncio.ProactorEventLoop() if sys.platform == 'win32' else asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        packets = parse_pcap(path, tshark_path=tshark_path)
        with closing(packets):
            result = store_parsed_capture(str(path), packets, sha256=sha256,
                                          signature=signature, db_name=db_name)
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
            # Let closed subprocess pipe callbacks complete before closing the loop.
            loop.run_until_complete(asyncio.sleep(0))
        finally:
            asyncio.set_event_loop(None)
            loop.close()
    result['flow_count'] = db.reconstruct_flows(db_name, result['evidence_id'])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pcap')
    parser.add_argument('--db', default=db.DB_NAME)
    parser.add_argument('--tshark-path')
    args = parser.parse_args()
    result = import_capture(args.pcap, args.db, args.tshark_path)
    print('Database:', Path(args.db).resolve())
    print('Evidence ID:', result['evidence_id'])
    print('Packets stored:', len(result['packet_ids']))
    print('Flows:', result['flow_count'])
    print('This import does not sign evidence. Priyali supplies sha256/signature through import_capture().')


if __name__ == '__main__':
    main()
