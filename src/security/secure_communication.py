"""Mutual TLS channel management."""

import datetime
import ssl
from pathlib import Path
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class SecureChannel:
    """Generates and manages mutual TLS certificates for the dashboard."""

    def __init__(self, cert_dir: str = "certs"):
        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(exist_ok=True)
        self._ca_cert, self._ca_key = self._ensure_ca()
        self._ensure_cert("server")

    def _ensure_ca(self) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        ca_crt = self.cert_dir / "ca.crt"
        ca_key = self.cert_dir / "ca.key"

        if ca_crt.exists() and ca_key.exists():
            key = serialization.load_pem_private_key(ca_key.read_bytes(), password=None)
            cert = x509.load_pem_x509_certificate(ca_crt.read_bytes())
            return cert, key

        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TIGRESS"),
            x509.NameAttribute(NameOID.COMMON_NAME, "TIGRESS CA"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA512())
        )
        ca_key.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ))
        ca_key.chmod(0o600)
        ca_crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return cert, key

    def _ensure_cert(self, name: str) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        crt_file = self.cert_dir / f"{name}.crt"
        key_file = self.cert_dir / f"{name}.key"

        if crt_file.exists() and key_file.exists():
            key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
            cert = x509.load_pem_x509_certificate(crt_file.read_bytes())
            return cert, key

        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TIGRESS"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"TIGRESS {name}"),
        ])
        eku = ExtendedKeyUsageOID.SERVER_AUTH if name == "server" else ExtendedKeyUsageOID.CLIENT_AUTH
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=True)
            .sign(self._ca_key, hashes.SHA512())
        )
        key_file.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ))
        key_file.chmod(0o600)
        crt_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return cert, key

    def get_ssl_context(self, role: str = "server") -> ssl.SSLContext:
        """Build a hardened mutual-TLS SSLContext for the given role."""
        purpose = ssl.Purpose.CLIENT_AUTH if role == "server" else ssl.Purpose.SERVER_AUTH
        ctx = ssl.create_default_context(purpose)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.options |= ssl.OP_NO_TICKET | ssl.OP_NO_COMPRESSION
        ctx.load_cert_chain(self.cert_dir / f"{role}.crt", self.cert_dir / f"{role}.key")
        ctx.load_verify_locations(self.cert_dir / "ca.crt")
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx
