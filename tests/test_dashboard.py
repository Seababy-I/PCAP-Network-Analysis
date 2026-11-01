import os
from pathlib import Path

from scapy.all import wrpcap
from test_security_workflow import frames
from analysis_service import process_capture
from dashboard_auth import create_account
from conftest import TEST_PASSPHRASE


def test_dashboard_selection_verification_and_reports(tmp_path, monkeypatch):
    from streamlit import config
    config.set_option('server.address','127.0.0.1')
    monkeypatch.setenv('STREAMLIT_BROWSER_GATHER_USAGE_STATS', 'false')
    monkeypatch.setenv('STREAMLIT_SERVER_FILE_WATCHER_TYPE', 'none')
    monkeypatch.setenv('PCAP_DB', str(tmp_path/'demo.db'))
    monkeypatch.setenv('PCAP_KEYS', str(tmp_path/'keys'))
    monkeypatch.setenv('PCAP_STORAGE', str(tmp_path/'evidence'))
    from streamlit.testing.v1 import AppTest
    source=Path(__file__).resolve().parents[1]
    create_account(TEST_PASSPHRASE)
    app=AppTest.from_file(str(source/'dashboard.py')).run(timeout=15)
    assert not app.exception
    assert not (tmp_path/'demo.db').exists()
    app.text_input(key='unlock_password').input(TEST_PASSPHRASE)
    app.button(key='unlock_vault').click().run(timeout=15)
    assert not app.exception
    assert app.button(key='analyze_capture').disabled
    scan,normal=tmp_path/'scan.pcap',tmp_path/'normal.pcap'
    wrpcap(str(scan),frames())
    wrpcap(str(normal),frames(2))
    args=dict(db_name=tmp_path/'demo.db',key_dir=tmp_path/'keys',storage_dir=tmp_path/'evidence')
    first=process_capture(scan,**args)
    process_capture(normal,**args)
    app.run(timeout=15)
    assert app.metric[0].value=='0'
    app.selectbox(key='selected_evidence_id').select(first['evidence_id']).run(timeout=15)
    assert app.metric[0].value=='1'
    app.button(key='nav_Alerts').click().run(timeout=15)
    assert not app.exception
    app.button(key='nav_Evidence Security').click().run(timeout=15)
    app.button(key='verify_evidence').click().run(timeout=15)
    assert any('VALID' in x.value for x in app.success)
    app.button(key='nav_Reports').click().run(timeout=15)
    app.button(key='generate_report').click().run(timeout=15)
    assert not app.exception
    assert not app.error
    app.button(key='verify_report').click().run(timeout=15)
    assert any('VALID' in x.value for x in app.success)
    app.button(key='nav_Audit Log').click().run(timeout=15)
    app.button(key='create_checkpoint').click().run(timeout=15)
    assert any('checkpoint saved' in x.value for x in app.success)
    app.button(key='verify_audit_chain').click().run(timeout=15)
    assert any('VALID' in x.value for x in app.success)
    assert not app.exception
    app.text_input(key='db_path').set_value(str(tmp_path)).run(timeout=15)
    assert not app.exception
    assert any('Database unavailable' in error.value for error in app.error)


def test_first_setup_wrong_password_and_lock_hide_evidence(tmp_path,monkeypatch):
    from streamlit import config
    config.set_option('server.address','127.0.0.1')
    monkeypatch.setenv('PCAP_DB',str(tmp_path/'private.db'))
    monkeypatch.setenv('PCAP_KEYS',str(tmp_path/'keys'))
    monkeypatch.setenv('PCAP_STORAGE',str(tmp_path/'evidence'))
    from streamlit.testing.v1 import AppTest
    app=AppTest.from_file(str(Path(__file__).resolve().parents[1]/'dashboard.py')).run(timeout=15)
    assert not app.exception and not app.metric and not (tmp_path/'private.db').exists()
    app.text_input(key='new_vault_password').input(TEST_PASSPHRASE)
    app.text_input(key='confirm_vault_password').input('not matching')
    app.button(key='create_vault').click().run(timeout=15)
    assert app.error and not (tmp_path/'auth.json').exists()
    app.text_input(key='confirm_vault_password').input(TEST_PASSPHRASE)
    app.button(key='create_vault').click().run(timeout=15)
    assert not app.exception and (tmp_path/'auth.json').exists()
    assert not (tmp_path/'private.db').exists()
    app.text_input(key='unlock_password').input('Wrong passphrase for testing')
    app.button(key='unlock_vault').click().run(timeout=15)
    assert app.error and not (tmp_path/'private.db').exists()
    app.text_input(key='unlock_password').input(TEST_PASSPHRASE)
    app.button(key='unlock_vault').click().run(timeout=15)
    assert not app.exception and (tmp_path/'private.db').exists()
    from test_security_workflow import capture
    process_capture(capture(tmp_path,1),db_name=tmp_path/'private.db',storage_dir=tmp_path/'evidence',key_dir=tmp_path/'keys')
    app.run(timeout=15)
    assert app.metric
    app.button(key='lock_vault').click().run(timeout=15)
    assert not app.exception and not app.metric
    assert app.text_input(key='unlock_password') is not None


def test_nonlocal_configuration_is_blocked_before_setup(tmp_path,monkeypatch):
    from streamlit import config
    from streamlit.testing.v1 import AppTest
    monkeypatch.setenv('PCAP_DB',str(tmp_path/'must-not-exist.db'))
    previous=config.get_option('server.address')
    try:
        config.set_option('server.address','0.0.0.0')
        app=AppTest.from_file(str(Path(__file__).resolve().parents[1]/'dashboard.py')).run(timeout=15)
        assert not app.exception and any('local access only' in item.value for item in app.error)
        assert not (tmp_path/'auth.json').exists() and not (tmp_path/'must-not-exist.db').exists()
    finally:
        config.set_option('server.address',previous)


def test_full_parser_investigation_views_are_scoped(tmp_path,monkeypatch):
    import importlib.util
    from parser_readiness import locate_tshark
    import pytest
    if not locate_tshark() or not importlib.util.find_spec('pyshark'):
        pytest.skip('Full investigation UI requires TShark/PyShark')
    from streamlit import config
    from streamlit.testing.v1 import AppTest
    config.set_option('server.address','127.0.0.1')
    monkeypatch.setenv('PCAP_DB',str(tmp_path/'full.db'))
    monkeypatch.setenv('PCAP_KEYS',str(tmp_path/'keys'))
    monkeypatch.setenv('PCAP_STORAGE',str(tmp_path/'evidence'))
    create_account(TEST_PASSPHRASE)
    root=Path(__file__).resolve().parents[1]
    item=process_capture(root/'team_tests'/'fixtures'/'dns_valid.pcap',db_name=tmp_path/'full.db',
        key_dir=tmp_path/'keys',storage_dir=tmp_path/'evidence',mode='full',allow_plaintext_metadata=True)
    app=AppTest.from_file(str(root/'dashboard.py')).run(timeout=15)
    app.text_input(key='unlock_password').input(TEST_PASSPHRASE)
    app.button(key='unlock_vault').click().run(timeout=15)
    app.button(key='nav_Investigation').click().run(timeout=15)
    assert not app.exception and not app.error
    assert [metric.value for metric in app.metric[:4]]==['2','1','2','0']
    app.selectbox(key='packet_protocol').select('UDP').run(timeout=15)
    assert not app.exception and not app.error
    app.text_input(key='packet_ip').input('192.0.2.80').run(timeout=15)
    assert not app.exception and not app.error
