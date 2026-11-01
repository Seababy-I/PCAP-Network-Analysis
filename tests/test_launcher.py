from pathlib import Path
from types import SimpleNamespace
import launch_dashboard


def test_windows_interpreter_is_one_argument_and_exit_code_propagates(monkeypatch):
    calls=[]
    executable=r'C:\Program Files\Python311\python.exe'
    monkeypatch.setattr(launch_dashboard.Path,'is_file',lambda _:False)
    monkeypatch.setattr(launch_dashboard.sys,'executable',executable)
    def run(args,**kwargs):
        calls.append((args,kwargs))
        return SimpleNamespace(returncode=7)
    monkeypatch.setattr(launch_dashboard.subprocess,'run',run)
    assert launch_dashboard.main()==7
    args,kwargs=calls[0]
    assert args[0]==executable
    assert args[1:4]==['-m','streamlit','run']
    assert Path(args[4]).name=='dashboard.py'
    assert '--server.address=127.0.0.1' in args
    assert kwargs['cwd']==Path(launch_dashboard.__file__).resolve().parent
    assert 'shell' not in kwargs  # subprocess default is shell=False.


def test_launcher_prefers_project_parser_environment(monkeypatch):
    calls=[]
    monkeypatch.setattr(launch_dashboard.Path,'is_file',lambda _:True)
    monkeypatch.setattr(launch_dashboard.subprocess,'run',lambda args,**kwargs:(calls.append(args) or SimpleNamespace(returncode=0)))
    assert launch_dashboard.main()==0
    assert '.venv-parser' in Path(calls[0][0]).parts
