import csv
import os
import sys
import zipfile

import numpy as np
import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(REPO_ROOT, "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

import phyphox_harmonics as ph


def _write_export(dirpath, peaks, binw=1.0, fmax=1000.0, noise=0.001):
    """Write a synthetic 'FFT Spectrum.csv' with single-bin peaks at given freqs."""
    freqs = np.arange(0.0, fmax + binw, binw)
    amps = np.full(len(freqs), noise)
    for f0, a in peaks.items():
        amps[int(round(f0 / binw))] = a
    csv_path = os.path.join(dirpath, "FFT Spectrum.csv")
    with open(csv_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["Frequency (Hz)", "Amplitude"])
        for f, a in zip(freqs, amps):
            w.writerow([f"{f:.3f}", f"{a:.6e}"])
    return csv_path


def test_find_fft_csv_in_folder(tmp_path):
    _write_export(str(tmp_path), {100.0: 1.0})
    found = ph.find_fft_csv(str(tmp_path))
    assert os.path.basename(found) == "FFT Spectrum.csv"


def test_find_fft_csv_in_zip(tmp_path):
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    csv_path = _write_export(str(export_dir), {100.0: 1.0})
    zip_path = tmp_path / "Audio_Spectrum_2026-07-14.zip"
    with zipfile.ZipFile(zip_path, "w") as z:
        z.write(csv_path, "FFT Spectrum.csv")
    found = ph.find_fft_csv(str(zip_path))
    assert os.path.basename(found) == "FFT Spectrum.csv"
    assert os.path.exists(found)


def test_find_fft_csv_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        ph.find_fft_csv(str(tmp_path))


def test_load_fft_skips_header_and_bad_rows(tmp_path):
    csv_path = tmp_path / "FFT Spectrum.csv"
    csv_path.write_text(
        "Frequency (Hz),Amplitude\n"
        "0.0,0.001\n"
        "not,a-number\n"
        "short-row\n"
        "1.0,0.5\n"
    )
    freq, amp = ph.load_fft(str(csv_path))
    assert freq.tolist() == [0.0, 1.0]
    assert amp.tolist() == [0.001, 0.5]


def test_local_peaks_finds_spikes_amplitude_ranked():
    freq = np.arange(0.0, 500.0, 1.0)
    amp = np.full(len(freq), 0.001)
    amp[120] = 0.8
    amp[240] = 1.0
    peaks = ph.local_peaks(freq, amp)
    assert [freq[i] for i in peaks] == [240.0, 120.0]


def test_local_peaks_respects_fmax_and_floor():
    freq = np.arange(0.0, 4000.0, 1.0)
    amp = np.full(len(freq), 0.001)
    amp[100] = 1.0
    amp[200] = 0.01   # below the 5% prominence floor
    amp[3000] = 1.0   # beyond fmax
    peaks = ph.local_peaks(freq, amp)
    assert [freq[i] for i in peaks] == [100.0]


def test_score_fundamental_counts_harmonics_within_tolerance():
    hits, explained = ph.score_fundamental(
        50.0, [50.0, 100.0, 151.5, 60.0], tol=2.0)
    assert hits == 3
    assert explained == {50.0, 100.0, 151.5}


def test_main_separates_harmonic_stack_from_residual(tmp_path, monkeypatch, capsys):
    # Harmonic stack at 120/240/360 Hz plus one unrelated tone at 517 Hz.
    _write_export(
        str(tmp_path),
        {120.0: 1.0, 240.0: 0.8, 360.0: 0.6, 517.0: 0.5},
    )
    monkeypatch.setattr(sys, "argv", ["phyphox_harmonics.py", str(tmp_path)])
    ph.main()
    out = capsys.readouterr().out
    assert "Best-fit fundamental" in out
    harmonic, residual = out.split("--- NON-HARMONIC residual")
    assert "✓ present" in harmonic
    assert "517.00" in residual
    for f in ("120.00", "240.00", "360.00"):
        assert f not in residual


def test_main_flat_spectrum_reports_no_peaks(tmp_path, monkeypatch, capsys):
    _write_export(str(tmp_path), {})
    monkeypatch.setattr(sys, "argv", ["phyphox_harmonics.py", str(tmp_path)])
    ph.main()
    out = capsys.readouterr().out
    assert "No peaks above threshold" in out
