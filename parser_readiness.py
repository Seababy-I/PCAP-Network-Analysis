"""Read-only environment check; does not accept, import or activate a teammate parser."""
import argparse
import ast
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def locate_tshark(explicit=None):
    candidates = [explicit] if explicit else [os.environ.get('TSHARK_PATH'), shutil.which('tshark'),
        r'C:\Program Files\Wireshark\tshark.exe',r'C:\Program Files (x86)\Wireshark\tshark.exe',
        '/usr/bin/tshark','/usr/local/bin/tshark','/opt/homebrew/bin/tshark']
    return next((str(Path(path).resolve()) for path in candidates if path and Path(path).is_file()), None)


def check_readiness(parser_path=None, tshark_path=None):
    path = Path(parser_path) if parser_path else Path(__file__).with_name('parser.py')
    package = importlib.util.find_spec('pyshark') is not None
    try:
        version = importlib.metadata.version('pyshark') if package else None
    except importlib.metadata.PackageNotFoundError:
        version = 'unknown'
    interface = False
    parser_error = None
    if path.is_file():
        try:
            tree = ast.parse(path.read_text(encoding='utf-8-sig'))
            for node in tree.body:
                if isinstance(node,ast.FunctionDef) and node.name == 'parse_pcap':
                    arguments = [arg.arg for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]
                    interface = 'path' in arguments and 'tshark_path' in arguments
        except (SyntaxError, OSError) as error:
            parser_error = str(error)
    executable = locate_tshark(tshark_path)
    executable_version = None
    executable_error = None
    if executable:
        try:
            result = subprocess.run([executable,'--version'],capture_output=True,text=True,timeout=5)
            if result.returncode == 0:
                executable_version = result.stdout.splitlines()[0] if result.stdout else None
                if not executable_version or 'tshark' not in executable_version.lower():
                    executable_error = 'Configured executable does not identify itself as TShark'
            else:
                executable_error = f'TShark version check exited {result.returncode}'
        except (OSError,subprocess.TimeoutExpired) as error:
            executable_error = str(error)
    return dict(python=sys.version.split()[0], parser_path=str(path.resolve()),parser_file_present=path.is_file(),
                parser_interface_present=interface,parser_error=parser_error,
                pyshark_present=package,pyshark_version=version,tshark_path=executable,
                tshark_version=executable_version,tshark_error=executable_error,
                preview_environment_ready=bool(package and interface and executable_version and not executable_error),
                parser_acceptance='NOT_AUTOMATIC: owner fixes and real-capture tests still required',
                active_workflow='NETWORK_ONLY',database_integration='PENDING_AANYA')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parser')
    parser.add_argument('--tshark')
    args = parser.parse_args(argv)
    result = check_readiness(args.parser,args.tshark)
    print(json.dumps(result,indent=2))
    return 0 if result['preview_environment_ready'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
