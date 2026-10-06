import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def calculate_sha256(file_path):
    with open(file_path, "rb") as file:
        file_data = file.read()

    return hashlib.sha256(file_data).hexdigest()


def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    return private_key, public_key

def sign_file(file_path, private_key):
    with open(file_path, "rb") as file:
        file_data = file.read()

    signature = private_key.sign(
        file_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature

def save_keys(private_key, public_key):
    with open("keys/private_key.pem", "wb") as file:
        file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open("keys/public_key.pem", "wb") as file:
        file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

def load_private_key():
    with open("keys/private_key.pem", "rb") as file:
        return serialization.load_pem_private_key(
            file.read(),
            password=None
        )


def load_public_key():
    with open("keys/public_key.pem", "rb") as file:
        return serialization.load_pem_public_key(
            file.read()
        )

def load_signature(signature_path):
    with open(signature_path, "rb") as file:
        return file.read()

def verify_signature(file_path, signature, public_key):
    with open(file_path, "rb") as file:
        file_data = file.read()

    try:
        public_key.verify(
            signature,
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True

    except Exception:
        return False

def save_signature(signature, signature_path):
    with open(signature_path, "wb") as file:
        file.write(signature)


def secure_evidence(file_path):
    # Calculate SHA-256
    hash_value = calculate_sha256(file_path)

    # Generate RSA key pair
    private_key, public_key = generate_rsa_keys()

    # Save RSA keys
    save_keys(private_key, public_key)

    # Create digital signature
    signature = sign_file(file_path, private_key)

    # Save signature
    signature_path = "signatures/sample.pcap.sig"
    save_signature(signature, signature_path)

    return hash_value, signature_path

def verify_evidence_file(file_path, signature_path):
    # Load saved public key
    public_key = load_public_key()

    # Load saved signature
    signature = load_signature(signature_path)

    # Verify
    return verify_signature(
        file_path,
        signature,
        public_key
    )

def sign_report(report_path):
    """
    Sign a forensic report using the existing RSA private key.
    Returns the signature path.
    """

    private_key = load_private_key()

    signature = sign_file(
        report_path,
        private_key
    )

    signature_path = "signatures/forensic_report.html.sig"

    save_signature(
        signature,
        signature_path
    )

    return signature_path


def verify_report(report_path, signature_path):
    """
    Verify a signed forensic report using the RSA public key.
    """

    public_key = load_public_key()

    signature = load_signature(
        signature_path
    )

    return verify_signature(
        report_path,
        signature,
        public_key
    )