"""Persistent RSA-PSS signing with independent, versioned artifacts."""
import hashlib
import json
import os
import time
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from confidentiality import is_encrypted,read_artifact,resolve_password,VaultIntegrityError


def calculate_sha256(file_path, *, password=None):
    if str(file_path).endswith('.vault') or is_encrypted(file_path):
        return hashlib.sha256(read_artifact(file_path,password=password)).hexdigest()
    digest = hashlib.sha256()
    with open(file_path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def generate_rsa_keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, private.public_key()


def public_bytes(key):
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def key_fingerprint(key):
    return hashlib.sha256(key.public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def load_private_key(key_dir='keys'):
    data=(Path(key_dir) / 'private_key.pem').read_bytes()
    try:
        return serialization.load_pem_private_key(data,password=None)
    except TypeError:
        return serialization.load_pem_private_key(data,password=resolve_password().encode('utf-8'))


def load_public_key(key_dir='keys'):
    return serialization.load_pem_public_key((Path(key_dir) / 'public_key.pem').read_bytes())


def save_keys(private_key, public_key, key_dir='keys'):
    """Initialize a pair; never replace existing evidence keys."""
    directory = Path(key_dir)
    directory.mkdir(parents=True, exist_ok=True)
    if key_fingerprint(private_key.public_key()) != key_fingerprint(public_key):
        raise ValueError('Private and public keys do not match')
    private_path, public_path = directory / 'private_key.pem', directory / 'public_key.pem'
    if private_path.exists() or public_path.exists():
        if not (private_path.exists() and public_path.exists()):
            raise ValueError('Incomplete key pair; restore the missing key before signing')
        if (key_fingerprint(load_private_key(directory).public_key()) != key_fingerprint(public_key)
                or key_fingerprint(load_public_key(directory)) != key_fingerprint(public_key)):
            raise ValueError('Refusing to replace existing keys')
        return
    with private_path.open('xb') as stream:
        stream.write(private_key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(resolve_password().encode('utf-8'))))
    private_path.chmod(0o600)
    with public_path.open('xb') as stream:
        stream.write(public_bytes(public_key))


@contextmanager
def _key_lock(directory):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / '.key-init.lock'
    deadline = time.monotonic() + 5
    while True:
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
            break
        except FileExistsError:
            if time.monotonic() >= deadline:
                raise TimeoutError('Signing keys are busy; check for another signing process before retrying')
            time.sleep(0.02)
    try:
        yield
    finally:
        path.unlink()


def get_or_create_keys(key_dir='keys'):
    resolve_password()  # Signing requires an unlocked analyst context, even for legacy keys.
    directory = Path(key_dir)
    with _key_lock(directory):
        if not ((directory / 'private_key.pem').exists() or (directory / 'public_key.pem').exists()):
            save_keys(*generate_rsa_keys(), key_dir=directory)
        private, public = load_private_key(directory), load_public_key(directory)
        if key_fingerprint(private.public_key()) != key_fingerprint(public):
            raise ValueError('Existing private and public keys do not match')
        archive = directory / 'public' / (key_fingerprint(public) + '.pem')
        archive.parent.mkdir(parents=True, exist_ok=True)
        if archive.exists():
            if archive.read_bytes() != public_bytes(public):
                raise ValueError('Archived signing key differs from its fingerprint')
        else:
            with archive.open('xb') as stream:
                stream.write(public_bytes(public))
    return private, public


def _pss():
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def sign_file(file_path, private_key):
    return private_key.sign(bytes.fromhex(calculate_sha256(file_path)), _pss(), utils.Prehashed(hashes.SHA256()))


def verify_signature(file_path, signature, public_key):
    try:
        public_key.verify(signature, bytes.fromhex(calculate_sha256(file_path)), _pss(),
                          utils.Prehashed(hashes.SHA256()))
        return True
    except (InvalidSignature,VaultIntegrityError):
        return False


def load_signature(signature_path):
    return Path(signature_path).read_bytes()


def save_signature(signature, signature_path):
    path = Path(signature_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Legacy callers must also opt into a new path instead of replacing an artifact.
    with path.open('xb') as stream:
        stream.write(signature)


def signature_metadata(signature_path):
    path = Path(str(signature_path) + '.json')
    if not path.exists():
        return None
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict) or value.get('version') != 1 or value.get('algorithm') != 'RSA-PSS-SHA256':
        raise ValueError('Invalid or unsupported signature manifest')
    for field in ('key_id', 'sha256'):
        text = value.get(field)
        if not isinstance(text, str) or len(text) != 64 or any(c not in '0123456789abcdef' for c in text):
            raise ValueError(f'Invalid manifest {field}')
    return value


def signing_public_key_path(signature_path, key_dir='keys'):
    metadata = signature_metadata(signature_path)
    if metadata:
        # Resolve only within the explicitly configured local public-key archive.
        key_id = metadata['key_id']
        if len(key_id) != 64 or any(c not in '0123456789abcdef' for c in key_id):
            raise ValueError('Invalid signing key fingerprint')
        return Path(key_dir) / 'public' / (key_id + '.pem')
    return Path(key_dir) / 'public_key.pem'  # Historical signatures have no sidecar.


def _secure(file_path, signature_dir='signatures', key_dir='keys'):
    private, public = get_or_create_keys(key_dir)
    key_id = key_fingerprint(public)
    digest = calculate_sha256(file_path)
    signature = private.sign(bytes.fromhex(digest), _pss(), utils.Prehashed(hashes.SHA256()))
    path = Path(signature_dir) / (uuid4().hex + '.sig')
    save_signature(signature, path)
    metadata = dict(version=1, algorithm='RSA-PSS-SHA256', key_id=key_id, sha256=digest)
    with Path(str(path) + '.json').open('x', encoding='utf-8') as stream:
        json.dump(metadata, stream, sort_keys=True)
    return digest, str(path)


def secure_evidence(file_path, *, signature_dir='signatures', key_dir='keys'):
    return _secure(file_path, signature_dir, key_dir)


def verify_evidence_file(file_path, signature_path, *, expected_sha256=None, key_dir='keys'):
    try:
        content=read_artifact(file_path)
    except VaultIntegrityError:
        return False
    return verify_evidence_bytes(content,signature_path,expected_sha256=expected_sha256,key_dir=key_dir)


def verify_evidence_bytes(content,signature_path, *, expected_sha256=None,key_dir='keys'):
    metadata = signature_metadata(signature_path)
    digest = hashlib.sha256(content).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        return False
    if metadata and digest != metadata['sha256']:
        return False
    public = serialization.load_pem_public_key(signing_public_key_path(signature_path, key_dir).read_bytes())
    if metadata and key_fingerprint(public) != metadata['key_id']:
        raise ValueError('Signing key fingerprint does not match the manifest')
    try:
        public.verify(load_signature(signature_path),bytes.fromhex(digest),_pss(),utils.Prehashed(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def sign_report(report_path, *, signature_dir='signatures', key_dir='keys'):
    return _secure(report_path, signature_dir, key_dir)[1]


def verify_report(report_path, signature_path, *, key_dir='keys'):
    return verify_evidence_file(report_path, signature_path, key_dir=key_dir)
