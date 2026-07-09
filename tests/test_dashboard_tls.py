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


def test_ssl_options_enables_mtls(tmp_path):
    opts = app._ssl_options(True, {"cert_dir": str(tmp_path / "certs")})
    assert opts["ssl_cert_reqs"] == ssl.CERT_REQUIRED
    for key in ("ssl_certfile", "ssl_keyfile", "ssl_ca_certs"):
        assert os.path.exists(opts[key]), f"{key} was not generated"
