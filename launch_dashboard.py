"""Launch the analyst dashboard on loopback, independently of the working directory."""
from pathlib import Path
import subprocess
import sys


def main():
    project=Path(__file__).resolve().parent
    candidate=project/'.venv-parser'/('Scripts/python.exe' if sys.platform=='win32' else 'bin/python')
    executable=str(candidate) if candidate.is_file() else sys.executable
    args=[executable,'-m','streamlit','run',str(project/'dashboard.py'),
          '--server.address=127.0.0.1','--server.headless=true','--browser.gatherUsageStats=false']
    # shell=False list arguments preserve executable paths containing spaces on Windows.
    try:
        return subprocess.run(args,cwd=project,check=False).returncode
    except KeyboardInterrupt:
        return 130


if __name__=='__main__':raise SystemExit(main())
