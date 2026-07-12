import json

import pytest

from src.core.evidence import (
    EvidenceExporter,
    provenance,
    sha256_file,
    verify_bundle,
)


def _write_log(path, records):
    path.write_text("".join(json.dumps(r) + "\n" for r in records))


def test_export_writes_bundle_with_separated_hash(tmp_path):
    log = tmp_path / "forensic.jsonl"
    _write_log(log, [
        {"type": "detection", "data": {"id": "a", "severity": 4, "timestamp": "2026-05-01T00:00:00+00:00"}},
        {"type": "detection", "data": {"id": "b", "severity": 2, "timestamp": "2026-05-02T00:00:00+00:00"}},
    ])
    out = tmp_path / "bundle"
    manifest = EvidenceExporter(str(log)).export(str(out))

    assert manifest["record_count"] == 2
    assert (out / "evidence.jsonl").exists()
    assert (out / "manifest.json").exists()
    assert (out / "CHAIN_OF_CUSTODY.txt").exists()
    assert not (out / "manifest.sig").exists()  # no signer -> unsigned

    # The hash lives in the manifest, separately from evidence.jsonl, and matches.
    assert manifest["sha256"] == sha256_file(out / "evidence.jsonl")
    on_disk = json.loads((out / "manifest.json").read_text())
    assert on_disk["sha256"] == manifest["sha256"]


def test_export_filters_by_time_window_and_type(tmp_path):
    log = tmp_path / "forensic.jsonl"
    _write_log(log, [
        {"type": "detection", "data": {"id": "old", "timestamp": "2026-01-01T00:00:00+00:00"}},
        {"type": "detection", "data": {"id": "mid", "timestamp": "2026-06-01T00:00:00+00:00"}},
        {"type": "boot", "data": {"id": "boot", "timestamp": "2026-06-01T00:00:00+00:00"}},
    ])
    out = tmp_path / "bundle"
    manifest = EvidenceExporter(str(log)).export(
        str(out), since="2026-05-01T00:00:00+00:00", event_types=["detection"],
    )
    assert manifest["record_count"] == 1
    lines = (out / "evidence.jsonl").read_text().splitlines()
    assert json.loads(lines[0])["data"]["id"] == "mid"


def test_export_signs_manifest_when_signer_given(tmp_path):
    pytest.importorskip("cryptography")
    from src.security.audit_log import AuditLog

    log = tmp_path / "forensic.jsonl"
    _write_log(log, [{"type": "detection", "data": {"id": "a"}}])
    out = tmp_path / "bundle"

    signer = AuditLog(log_path=str(tmp_path / "audit"))
    manifest = EvidenceExporter(str(log), signer=signer).export(str(out))
    assert manifest["signed"] is True

    sig = json.loads((out / "manifest.sig").read_text())
    manifest_bytes = (out / "manifest.json").read_bytes()
    assert AuditLog.verify_bytes(manifest_bytes, sig["signature"], sig["public_key"]) is True
    # Any edit to the manifest breaks the signature.
    assert AuditLog.verify_bytes(manifest_bytes + b" ", sig["signature"], sig["public_key"]) is False


def test_export_fails_closed_on_missing_log(tmp_path):
    out = tmp_path / "bundle"
    with pytest.raises(FileNotFoundError):
        EvidenceExporter(str(tmp_path / "nope.jsonl")).export(str(out))


def test_export_fails_closed_on_malformed_line(tmp_path):
    log = tmp_path / "forensic.jsonl"
    log.write_text('{"type": "detection", "data": {}}\nnot json\n')
    out = tmp_path / "bundle"
    with pytest.raises(ValueError, match=":2"):  # reports the bad line number
        EvidenceExporter(str(log)).export(str(out))


def test_provenance_has_tool_version_and_timestamp():
    prov = provenance({"case_id": "CASE-1"})
    assert prov["tool"] == "TIGRESS"
    assert prov["version"]
    assert prov["case_id"] == "CASE-1"
    assert prov["generated_at"].endswith("+00:00")


# --------------------------------------------------------------------------- #
# verify_bundle
# --------------------------------------------------------------------------- #

def _make_bundle(tmp_path, signed):
    log = tmp_path / "forensic.jsonl"
    _write_log(log, [
        {"type": "detection", "data": {"id": "a", "severity": 4}},
        {"type": "detection", "data": {"id": "b", "severity": 2}},
    ])
    out = tmp_path / "bundle"
    signer = None
    if signed:
        pytest.importorskip("cryptography")
        from src.security.audit_log import AuditLog
        signer = AuditLog(log_path=str(tmp_path / "audit"))
    EvidenceExporter(str(log), signer=signer).export(str(out))
    return out


def test_verify_bundle_accepts_intact_signed_bundle(tmp_path):
    out = _make_bundle(tmp_path, signed=True)
    report = verify_bundle(str(out))
    assert report["ok"] is True
    names = {c["name"] for c in report["checks"]}
    assert {"evidence_sha256", "record_count", "manifest_signature"} <= names


def test_verify_bundle_accepts_unsigned_bundle(tmp_path):
    out = _make_bundle(tmp_path, signed=False)
    report = verify_bundle(str(out))
    assert report["ok"] is True
    sig_check = next(c for c in report["checks"] if c["name"] == "manifest_signature")
    assert "unsigned" in sig_check["detail"]


def test_verify_bundle_detects_tampered_evidence(tmp_path):
    out = _make_bundle(tmp_path, signed=False)
    (out / "evidence.jsonl").write_text('{"type": "detection", "data": {"id": "z"}}\n')
    report = verify_bundle(str(out))
    assert report["ok"] is False
    assert any(c["name"] == "evidence_sha256" and not c["passed"] for c in report["checks"])


def test_verify_bundle_detects_tampered_signed_manifest(tmp_path):
    out = _make_bundle(tmp_path, signed=True)
    manifest = json.loads((out / "manifest.json").read_text())
    manifest["record_count"] = 99  # edit after signing
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    report = verify_bundle(str(out))
    assert report["ok"] is False
    assert any(c["name"] == "manifest_signature" and not c["passed"] for c in report["checks"])


def test_verify_bundle_missing_manifest(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    report = verify_bundle(str(empty))
    assert report["ok"] is False


def test_verify_bundle_pins_expected_public_key(tmp_path):
    pytest.importorskip("cryptography")
    from src.security.audit_log import AuditLog

    log = tmp_path / "forensic.jsonl"
    _write_log(log, [{"type": "detection", "data": {"id": "a"}}])
    out = tmp_path / "bundle"
    signer = AuditLog(log_path=str(tmp_path / "audit"))
    EvidenceExporter(str(log), signer=signer).export(str(out))

    # Correct key -> pinned check passes.
    ok = verify_bundle(str(out), expected_public_key=signer.public_key_b64)
    assert ok["ok"] is True
    assert any(c["name"] == "public_key_pinned" and c["passed"] for c in ok["checks"])

    # A different (attacker) key -> pin fails even though the signature is valid.
    other = AuditLog(log_path=str(tmp_path / "audit2"))
    bad = verify_bundle(str(out), expected_public_key=other.public_key_b64)
    assert bad["ok"] is False
    assert any(c["name"] == "public_key_pinned" and not c["passed"] for c in bad["checks"])


def test_verify_bundle_requires_signature_when_key_expected(tmp_path):
    out = _make_bundle(tmp_path, signed=False)  # unsigned bundle
    report = verify_bundle(str(out), expected_public_key="c29tZS1rZXk=")
    assert report["ok"] is False
    assert any(c["name"] == "manifest_signature" and not c["passed"] for c in report["checks"])


def test_verify_bundle_detects_tampered_custody_note(tmp_path):
    out = _make_bundle(tmp_path, signed=True)
    # The custody note is covered by the signed manifest, so editing it fails.
    (out / "CHAIN_OF_CUSTODY.txt").write_text("Case ID: forged\n")
    report = verify_bundle(str(out))
    assert report["ok"] is False
    assert any(c["name"] == "custody_sha256" and not c["passed"] for c in report["checks"])


def test_verify_bundle_rejects_evidence_file_outside_bundle(tmp_path):
    out = _make_bundle(tmp_path, signed=False)
    # Point evidence_file outside the bundle (path traversal).
    secret = tmp_path / "secret.txt"
    secret.write_text("top secret")
    manifest = json.loads((out / "manifest.json").read_text())
    manifest["evidence_file"] = "../secret.txt"
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    report = verify_bundle(str(out))
    assert report["ok"] is False
    assert any(c["name"] == "evidence_present" and not c["passed"] for c in report["checks"])
