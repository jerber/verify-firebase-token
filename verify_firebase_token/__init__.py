import typing as T
import requests
import jwt
import threading
from datetime import datetime, UTC, timedelta
from email.utils import parsedate_to_datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

KEY_ID_TO_CERT: dict[str, str] = {}
EXPIRES_AT: float = (datetime.now(UTC) - timedelta(hours=1)).timestamp()
PUBLIC_KEYS_LOCK = threading.Lock()


def is_expired() -> bool:
    return EXPIRES_AT < datetime.now(UTC).timestamp() - 10


def public_key_from_cert(cert: str) -> str:
    """
    Extract the public key from an X.509 certificate.

    Args:
    - cert (str): The X.509 certificate in PEM format.

    Returns:
    - str: The public key in PEM format.
    """
    certificate = x509.load_pem_x509_certificate(cert.encode(), default_backend())
    public_key = certificate.public_key()

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return pem_public_key.decode()


def fetch_public_keys() -> None:
    """
    Asynchronously fetch CERTS from Google's servers, extract the public keys, and update the cache.
    """
    global KEY_ID_TO_CERT
    global EXPIRES_AT

    response = requests.get(
        "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com",
        timeout=5,
        verify=True,
    )

    EXPIRES_AT = parsedate_to_datetime(response.headers["expires"]).timestamp()
    for kid, cert in response.json().items():
        KEY_ID_TO_CERT[kid] = public_key_from_cert(cert)


def verify_token(token: str, project_id: str) -> dict[str, T.Any]:
    """
    Asynchronously verify the Firebase token.

    possible errors:
    jwt.exceptions.InvalidIssuerError: Invalid issuer
    jwt.exceptions.ExpiredSignatureError: Signature has expired
    jwt.exceptions.DecodeError: Invalid payload padding
    ValueError("Key ID not found in public keys.")
    """

    if is_expired():
        with PUBLIC_KEYS_LOCK:  # Locking mechanism to ensure fetch_public_keys is not concurrently executed
            if is_expired():  # Double check expiration after acquiring the lock
                fetch_public_keys()

    header = jwt.get_unverified_header(token)
    kid = header.get("kid")

    if kid not in KEY_ID_TO_CERT:
        raise ValueError("Key ID not found in public keys.")

    public_key = KEY_ID_TO_CERT[kid]

    # Decode and verify the token
    decoded = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience=project_id,
        issuer=f"https://securetoken.google.com/{project_id}",
    )

    # Other constraints
    if "sub" not in decoded or not decoded["sub"]:
        raise ValueError("Token 'sub' claim is invalid.")

    return decoded


__all__ = ['verify_token']
