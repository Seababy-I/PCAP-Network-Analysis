"""Explicit parser acceptance preview. Never changes production storage or activates parsing."""
import argparse
import importlib.util
import json
from pathlib import Path

from parser_adapter import preview_capture


def load_parser(path):
    file = Path(path).resolve()
    if not file.is_file():
        raise FileNotFoundError(f'Parser module not found: {file}')
    spec = importlib.util.spec_from_file_location('pcap_teammate_parser_preview',file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    function = getattr(module,'parse_pcap',None)
    if not callable(function):
        raise ValueError('Parser module must expose parse_pcap(path, tshark_path=None)')
    return function


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parser', required=True, help='Explicit path to the reviewed teammate parser')
    parser.add_argument('--pcap', required=True)
    parser.add_argument('--tshark')
    parser.add_argument('--records',action='store_true',help='Include full records in stdout JSON')
    args = parser.parse_args(argv)
    try:
        result = preview_capture(args.pcap,parser_fn=load_parser(args.parser),tshark_path=args.tshark)
    except Exception as error:
        parser.exit(2,f'Parser preview failed: {error}\n')
    if not args.records:
        result.pop('records')
    print(json.dumps(result,indent=2,allow_nan=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
