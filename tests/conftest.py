import pytest
from confidentiality import set_session_password

# This public, test-only value is never a production default.
TEST_PASSPHRASE='Test-only vault passphrase 2026!'


@pytest.fixture(autouse=True)
def isolated_vault_context(tmp_path,monkeypatch):
    set_session_password(None)
    monkeypatch.setenv('PCAP_VAULT_PASSWORD',TEST_PASSPHRASE)
    monkeypatch.setenv('PCAP_AUTH_CONFIG',str(tmp_path/'auth.json'))
    yield
    set_session_password(None)
