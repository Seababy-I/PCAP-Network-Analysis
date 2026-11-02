"""Explicit file encryption/decryption. Never overwrites an existing output."""
import argparse
from pathlib import Path
from confidentiality import decrypt_bytes,encrypt_bytes,prompt_password


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=['encrypt','decrypt'])
    parser.add_argument('--input',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args(argv)
    try:
        password=prompt_password()
        source=Path(args.input)
        if source.stat().st_size>64*1024*1024+128:raise ValueError('Input exceeds vault limit')
        data=source.read_bytes()
        output=encrypt_bytes(data,password=password) if args.operation=='encrypt' else decrypt_bytes(data,password=password)
        path=Path(args.output)
        with path.open('xb') as stream:stream.write(output)
        path.chmod(0o600)
    except (OSError,ValueError) as error:parser.exit(2,f'Vault operation failed: {error}\n')
    print('Encrypted output saved' if args.operation=='encrypt' else 'Decrypted output saved; protect this authorized plaintext copy')
    return 0


if __name__=='__main__':raise SystemExit(main())
