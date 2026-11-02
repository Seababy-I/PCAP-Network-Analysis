"""Password-derived authenticated encryption for managed evidence and exports."""
from contextlib import contextmanager
from contextvars import ContextVar
import getpass
import os
from pathlib import Path
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b'PCAPVAULT\x01'
MAX_BYTES = 64 * 1024 * 1024
PURPOSES = {'evidence':1,'report':2,'report-export':3,'generic':4}
_password = ContextVar('pcap_vault_password', default=None)


class VaultIntegrityError(ValueError):
    pass


def resolve_password(password=None):
    value = password if password is not None else _password.get()
    if value is None:
        value = os.environ.get('PCAP_VAULT_PASSWORD')
    if not isinstance(value,str) or len(value)<12:
        raise PermissionError('Unlock the vault with a passphrase of at least 12 characters')
    return value


def prompt_password():
    try:
        return resolve_password()
    except PermissionError:
        if not sys.stdin.isatty():
            raise PermissionError('Vault passphrase required; use an interactive terminal or PCAP_VAULT_PASSWORD')
        try:
            return resolve_password(getpass.getpass('Vault passphrase (not echoed): '))
        except (EOFError,KeyboardInterrupt) as error:
            raise PermissionError('No vault passphrase supplied') from error


@contextmanager
def vault_session(password):
    token = _password.set(resolve_password(password))
    try:
        yield
    finally:
        _password.reset(token)


def set_session_password(password):
    _password.set(password)


def derive_key(password,salt):
    return Scrypt(salt=salt,length=32,n=2**15,r=8,p=1).derive(resolve_password(password).encode('utf-8'))


def encrypt_bytes(data, *, password=None, purpose='generic'):
    if not isinstance(data,bytes) or len(data)>MAX_BYTES:
        raise ValueError('Vault payload exceeds the supported 64 MiB limit')
    salt,nonce = os.urandom(16),os.urandom(12)
    header = MAGIC + bytes([PURPOSES[purpose]]) + salt + nonce
    return header + AESGCM(derive_key(password,salt)).encrypt(nonce,data,header)


def decrypt_bytes(envelope, *, password=None):
    header_length = len(MAGIC)+1+16+12
    if len(envelope)<header_length+16 or len(envelope)>MAX_BYTES+header_length+16 or not envelope.startswith(MAGIC):
        raise VaultIntegrityError('Invalid or truncated encrypted artifact')
    if envelope[len(MAGIC)] not in PURPOSES.values():
        raise VaultIntegrityError('Unsupported encrypted artifact type')
    offset=len(MAGIC)+1
    salt,nonce=envelope[offset:offset+16],envelope[offset+16:header_length]
    try:
        return AESGCM(derive_key(password,salt)).decrypt(nonce,envelope[header_length:],envelope[:header_length])
    except InvalidTag as error:
        raise VaultIntegrityError('Wrong passphrase or modified encrypted artifact') from error


def is_encrypted(path):
    with Path(path).open('rb') as stream:
        return stream.read(len(MAGIC))==MAGIC


def read_artifact(path, *, password=None):
    path=Path(path)
    if path.stat().st_size>MAX_BYTES+128:
        raise ValueError('Artifact exceeds supported read limit')
    content=path.read_bytes()
    if content.startswith(MAGIC):
        return decrypt_bytes(content,password=password)
    if path.suffix=='.vault':
        raise VaultIntegrityError('Encrypted artifact header is missing or modified')
    return content  # Explicit legacy support; historical files are not migrated.


def write_encrypted(path,data, *, password=None,purpose='generic'):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    envelope=encrypt_bytes(data,password=password,purpose=purpose)
    with path.open('xb') as stream:
        stream.write(envelope)
    path.chmod(0o600)
    return str(path.resolve())
