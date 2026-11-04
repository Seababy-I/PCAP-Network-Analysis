"""Single-analyst local dashboard gate. No password is stored in plaintext."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import time

from confidentiality import derive_key,resolve_password,set_session_password


def auth_path():
    return Path(os.environ.get('PCAP_AUTH_CONFIG',str(Path(__file__).parent/'.secrets'/'dashboard_auth.json')))


def create_account(password,path=None):
    password=resolve_password(password)
    salt=os.urandom(16)
    data=dict(version=1,salt=salt.hex(),verifier=derive_key(password,salt).hex())
    path=Path(path) if path else auth_path()
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x',encoding='utf-8') as stream:json.dump(data,stream)
    path.chmod(0o600)


def check_password(password,path=None):
    path=Path(path) if path else auth_path()
    data=json.loads(path.read_text(encoding='utf-8'))
    if data.get('version')!=1:
        raise ValueError('Unsupported authentication configuration')
    try:
        salt=bytes.fromhex(data['salt']); expected=bytes.fromhex(data['verifier'])
        if len(salt)!=16 or len(expected)!=32:raise ValueError('Invalid authentication configuration')
        actual=derive_key(password,salt)
        return hmac.compare_digest(expected,actual)
    except PermissionError:
        return False


def require_unlock():
    import streamlit as st
    set_session_password(None)
    if st.get_option('server.address') not in ('127.0.0.1','localhost','::1'):
        st.error('This dashboard supports local access only. Start it with python launch_dashboard.py.')
        st.stop()
    path=auth_path()
    if not path.exists():
        st.title('Set up your local evidence vault')
        st.info('Choose a strong passphrase of at least 12 characters. Keep it safe: it decrypts new evidence and reports and cannot be recovered from this application.')
        with st.form('vault_setup'):
            password=st.text_input('New vault passphrase',type='password',key='new_vault_password')
            confirm=st.text_input('Confirm passphrase',type='password',key='confirm_vault_password')
            submitted=st.form_submit_button('Create local vault',key='create_vault')
        if submitted:
            try:
                if password!=confirm:raise ValueError('Passphrases do not match')
                create_account(password,path)
                st.session_state.pop('new_vault_password',None)
                st.session_state.pop('confirm_vault_password',None)
                st.rerun()
            except (OSError,ValueError,PermissionError) as error:st.error(str(error))
        st.stop()
    fingerprint=hashlib.sha256(path.read_bytes()).hexdigest()
    session=st.session_state.get('_vault_session')
    if session and (session['config']!=fingerprint or time.monotonic()-session['last_seen']>900):
        st.session_state.clear();session=None
    if not session:
        st.title('Unlock evidence vault')
        with st.form('vault_login'):
            password=st.text_input('Vault passphrase',type='password',key='unlock_password')
            submitted=st.form_submit_button('Unlock',key='unlock_vault')
        if submitted:
            blocked_until=st.session_state.get('_blocked_until',0)
            if time.monotonic()<blocked_until:
                st.error('Please wait before retrying this session.')
            elif check_password(password,path):
                st.session_state['_vault_session']=dict(password=password,config=fingerprint,last_seen=time.monotonic())
                st.session_state.pop('unlock_password',None)
                st.rerun()
            else:
                attempts=st.session_state.get('_failed_logins',0)+1
                st.session_state['_failed_logins']=attempts
                if attempts>=5:st.session_state['_blocked_until']=time.monotonic()+30
                st.error('Incorrect passphrase')
        st.stop()
    with st.sidebar:
        if st.button('Lock vault',key='lock_vault'):
            st.session_state.clear();st.rerun()
        st.caption('Local analyst session. Lock when leaving; inactive sessions require unlock on the next interaction after 15 minutes.')
    session['last_seen']=time.monotonic()
    set_session_password(session['password'])
    return session['password']
