import json
import ssl

import pytest

# These modules require the cryptography package; skip cleanly if unavailable.
pytest.importorskip("cryptography")

from src.security.audit_log import AuditLog
from src.security.secure_communication import SecureChannel
from src.security.secure_config import SecureConfig, SecurityError

# --------------------------------------------------------------------------- #
# AuditLog: tamper-evident, ECDSA-signed, hash-chained log
# --------------------------------------------------------------------------- #

def test_audit_log_verifies_untampered_chain(tmp_path):
    audit = AuditLog(log_path=str(tmp_path / "audit"))
    audit.log("boot", {"stage": "init"})
    audit.log("detection", {"id": "x1", "severity": 4})
    assert audit.verify_integrity() is True


def test_audit_log_detects_modified_entry(tmp_path):
    audit = AuditLog(log_path=str(tmp_path / "audit"))
    audit.log("detection", {"id": "x1", "severity": 4})
    audit.log("detection", {"id": "x2", "severity": 2})

    log_file = next((tmp_path / "audit").glob("audit_*.log"))
    lines = log_file.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["data"]["severity"] = 1  # tamper with a signed field
    lines[0] = json.dumps(entry)
    log_file.write_text("\n".join(lines) + "\n")

    # A fresh instance loads the same persisted signing key, so a clean log
    # would still verify — but the tampered entry must be rejected.
    assert AuditLog(log_path=str(tmp_path / "audit")).verify_integrity() is False


def test_audit_log_detects_chain_break(tmp_path):
    audit = AuditLog(log_path=str(tmp_path / "audit"))
    audit.log("a", {"n": 1})
    audit.log("b", {"n": 2})

    log_file = next((tmp_path / "audit").glob("audit_*.log"))
    lines = log_file.read_text().splitlines()
    # Drop the first entry so the second's prev_hash no longer chains.
    log_file.write_text(lines[1] + "\n")

    assert AuditLog(log_path=str(tmp_path / "audit")).verify_integrity() is False


# --------------------------------------------------------------------------- #
# SecureConfig: encrypted store with HMAC integrity
# --------------------------------------------------------------------------- #

def test_secure_config_round_trip(tmp_path):
    store = SecureConfig(config_path=str(tmp_path / "secure"))
    payload = {"api_key": "s3cr3t", "nested": {"threshold": 0.9}}
    config_id = store.save("prod", payload)
    assert store.load(config_id) == payload


def test_secure_config_missing_id_raises(tmp_path):
    store = SecureConfig(config_path=str(tmp_path / "secure"))
    with pytest.raises(ValueError):
        store.load("does-not-exist")


def test_secure_config_detects_ciphertext_tamper(tmp_path):
    store = SecureConfig(config_path=str(tmp_path / "secure"))
    config_id = store.save("prod", {"k": "v"})

    enc_file = tmp_path / "secure" / f"{config_id}.enc"
    blob = bytearray(enc_file.read_bytes())
    blob[-1] ^= 0x01  # flip a bit in the ciphertext
    enc_file.write_bytes(bytes(blob))

    with pytest.raises(SecurityError):
        store.load(config_id)


# --------------------------------------------------------------------------- #
# SecureChannel: mutual TLS certificate management
# --------------------------------------------------------------------------- #

def test_secure_channel_generates_ca_and_server_certs(tmp_path):
    cert_dir = tmp_path / "certs"
    SecureChannel(cert_dir=str(cert_dir))
    for name in ("ca.crt", "server.crt", "server.key"):
        assert (cert_dir / name).exists()


def test_secure_channel_context_requires_client_cert(tmp_path):
    channel = SecureChannel(cert_dir=str(tmp_path / "certs"))
    ctx = channel.get_ssl_context("server")
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3


def test_secure_channel_reuses_existing_ca(tmp_path):
    cert_dir = tmp_path / "certs"
    first = (SecureChannel(cert_dir=str(cert_dir)).cert_dir / "ca.crt").read_bytes()
    second = (SecureChannel(cert_dir=str(cert_dir)).cert_dir / "ca.crt").read_bytes()
    assert first == second  # a second run must not regenerate the CA
