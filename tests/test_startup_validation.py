import logging

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")

from src.core.selftest import run_selftest
from src.dashboard.app import _warn_if_revalidation_needed


def test_warns_when_no_validation_record(tmp_path, caplog):
    config = {"app": {"validation_dir": str(tmp_path)}}
    with caplog.at_level(logging.WARNING):
        _warn_if_revalidation_needed(config)
    assert any("self-validation" in r.message for r in caplog.records)


def test_no_warning_after_passing_validation(tmp_path, caplog):
    run_selftest(record_dir=str(tmp_path))  # records a passing validation
    config = {"app": {"validation_dir": str(tmp_path)}}
    with caplog.at_level(logging.WARNING):
        _warn_if_revalidation_needed(config)
    assert not any("self-validation" in r.message for r in caplog.records)
