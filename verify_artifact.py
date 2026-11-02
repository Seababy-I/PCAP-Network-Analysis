"""Verify an exported artifact with an explicit public key; no database/private key needed."""
import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from crypto_utils import calculate_sha256, key_fingerprint, load_signature, verify_signature


def verify_artifact(file_path, signature_path, public_key_path, manifest_path=None):
    public = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
    if manifest_path is not None:
        metadata = json.loads(Path(manifest_path).read_text(encoding='utf-8'))
        if metadata.get('version') != 1 or metadata.get('algorithm') != 'RSA-PSS-SHA256':
            raise ValueError('Unsupported signature manifest')
        if metadata.get('key_id') != key_fingerprint(public):
            return False
        if metadata.get('sha256') != calculate_sha256(file_path):
            return False
    return verify_signature(file_path, load_signature(signature_path), public)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--file', required=True)
    parser.add_argument('--signature', required=True)
    parser.add_argument('--public-key', required=True)
    parser.add_argument('--manifest')
    args = parser.parse_args(argv)
    try:
        valid = verify_artifact(args.file, args.signature, args.public_key, args.manifest)
    except (ValueError, OSError, TypeError, AttributeError) as error:
        parser.exit(2, f'Verification unavailable: {error}\n')
    print('VALID' if valid else 'INVALID')
    return 0 if valid else 1


if __name__ == '__main__':
    raise SystemExit(main())
