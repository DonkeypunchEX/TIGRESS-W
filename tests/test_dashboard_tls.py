import os
import ssl

import pytest

# The dashboard imports fastapi/uvicorn at module load; TLS needs cryptography.
pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")
pytest.importorskip("cryptography")

from src.dashboard import app


def test_ssl_options_empty_when_insecure():
    assert app._ssl_options(False, {}) == {}


def test_ssl_options_provides_hardened_mtls_context(tmp_path):
    opts = app._ssl_options(True, {"cert_dir": str(tmp_path / "certs")})
    assert set(opts) == {"ssl_context_factory"}

    # uvicorn calls the factory as factory(config, default_factory); the returned
    # context must preserve SecureChannel's hardening, not uvicorn's defaults.
    ctx = opts["ssl_context_factory"](None, None)
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
    assert ctx.options & ssl.OP_NO_TICKET, "OP_NO_TICKET not set"
    assert ctx.options & ssl.OP_NO_COMPRESSION, "OP_NO_COMPRESSION not set"

    for name in ("ca.crt", "server.crt", "server.key"):
        assert os.path.exists(tmp_path / "certs" / name), f"{name} was not generated"
