#!/usr/bin/env python3
"""phyphox_harmonics.py — analyze a Phyphox "Audio Spectrum" export.

Point it at either the unzipped folder or the .zip directly:
    python3 scripts/phyphox_harmonics.py /path/to/Audio_Spectrum_....zip
    python3 scripts/phyphox_harmonics.py /path/to/unzipped_folder

What it does:
  - Loads FFT Spectrum.csv (freq, amplitude)
  - Finds spectral peaks
  - Searches for the best-fit fundamental f0 and its harmonic stack
  - Reports which peaks are explained as harmonics (mechanical signature)
  - Flags NON-harmonic peaks — the residual is the only "interesting" part
  - Notes when the harmonic spacing == FFT bin width (quantization artifact risk)

Only dependency: numpy.
"""

import csv
import os
import sys
import tempfile
import zipfile

import numpy as np


def find_fft_csv(path):
    """Locate FFT Spectrum.csv under a folder or inside a Phyphox .zip export."""
    if path.lower().endswith(".zip"):
        tmp = tempfile.mkdtemp()
        with zipfile.ZipFile(path) as z:
            z.extractall(tmp)
        path = tmp
    for root, _, files in os.walk(path):
        for f in files:
            if f.lower() == "fft spectrum.csv":
                return os.path.join(root, f)
    raise FileNotFoundError("FFT Spectrum.csv not found under: " + path)


def load_fft(csv_path):
    """Parse the export CSV into (freq, amplitude) numpy arrays, skipping bad rows."""
    freq, amp = [], []
    with open(csv_path, newline="") as fh:
        r = csv.reader(fh)
        next(r, None)  # header
        for row in r:
            if len(row) < 2:
                continue
            try:
                freq.append(float(row[0]))
                amp.append(float(row[1]))
            except ValueError:
                continue
    return np.array(freq), np.array(amp)


def local_peaks(freq, amp, prominence_ratio=0.05, fmax=2000.0):
    """Simple peak picker: local maxima above a prominence floor, within fmax."""
    peaks = []
    floor = amp.max() * prominence_ratio
    for i in range(1, len(amp) - 1):
        if freq[i] > fmax:
            break
        if amp[i] > amp[i - 1] and amp[i] >= amp[i + 1] and amp[i] >= floor:
            peaks.append(i)
    # sort by amplitude desc
    peaks.sort(key=lambda i: amp[i], reverse=True)
    return peaks


def score_fundamental(f0, peak_freqs, tol):
    """How many peaks fall on integer multiples of f0, and total weight."""
    hits = 0
    explained = set()
    for pf in peak_freqs:
        n = round(pf / f0)
        if n >= 1 and abs(pf - n * f0) <= tol:
            hits += 1
            explained.add(round(pf, 2))
    return hits, explained


def main():
    """Run the harmonic analysis on the export named on the command line."""
    if len(sys.argv) < 2:
        print("usage: python3 phyphox_harmonics.py <export.zip | folder>")
        sys.exit(1)

    fft_csv = find_fft_csv(sys.argv[1])
    freq, amp = load_fft(fft_csv)
    binw = float(np.median(np.diff(freq)))
    print(f"Loaded {len(freq)} FFT bins | bin width = {binw:.3f} Hz | "
          f"range 0–{freq[-1]:.0f} Hz\n")

    pk = local_peaks(freq, amp)
    if not pk:
        print("No peaks above threshold. Signal is broadband/flat — "
              "that itself is atypical for machinery. Inspect manually.")
        return
    peak_freqs = [float(freq[i]) for i in pk]
    peak_amps = [float(amp[i]) for i in pk]

    print("Detected peaks (amplitude-ranked):")
    for f_, a_ in zip(peak_freqs, peak_amps):
        print(f"   {f_:9.2f} Hz   {a_:.4e}")
    print()

    # Candidate fundamentals: each low peak, plus sub-harmonic guesses.
    tol = max(binw * 0.6, 2.0)  # tolerance for "on a harmonic"
    candidates = set()
    for f_ in peak_freqs:
        if f_ <= 400:
            candidates.add(round(f_, 3))
            for d in (2, 3):           # allow the true f0 to be a sub-multiple
                candidates.add(round(f_ / d, 3))
    candidates = [c for c in candidates if c >= 8.0]  # ignore DC-ish junk

    best = None
    for f0 in sorted(candidates):
        hits, explained = score_fundamental(f0, peak_freqs, tol)
        # weight by amplitude of explained peaks, prefer more hits then lower f0
        weight = sum(a for f_, a in zip(peak_freqs, peak_amps)
                     if round(f_, 2) in explained)
        key = (hits, weight)
        if best is None or key > best[0]:
            best = (key, f0, explained)

    (hits, weight), f0, explained = best
    print(f"Best-fit fundamental f0 ≈ {f0:.2f} Hz  "
          f"({hits}/{len(peak_freqs)} peaks explained as harmonics)")
    rpm = f0 * 60
    print(f"   → if rotational: ~{rpm:.0f} RPM (1st order) "
          f"or ~{rpm/2:.0f} RPM if f0 is 2× line/blade order")

    # Artifact warning
    if abs(f0 - binw) < 0.05 * binw or abs((f0 % binw)) < 0.05 * binw:
        print("   ⚠  f0 ≈ FFT bin width (or a multiple). The harmonic spacing may be\n"
              "      a QUANTIZATION artifact. Re-record with a larger FFT size / "
              "longer window\n      (target bin width ≤ 1 Hz) before trusting the stack.")

    # Residual = non-harmonic peaks
    residual = [(f_, a_) for f_, a_ in zip(peak_freqs, peak_amps)
                if round(f_, 2) not in explained]
    print("\n--- HARMONIC (mechanical) content ---")
    for n in range(1, 12):
        h = n * f0
        if h > freq[-1]:
            break
        near = [f_ for f_ in explained if abs(f_ - h) <= tol]
        if near:
            print(f"   n={n:<2} {h:8.2f} Hz  ✓ present")

    print("\n--- NON-HARMONIC residual (the only potentially interesting part) ---")
    if not residual:
        print("   none — spectrum is fully explained by a single harmonic source.")
        print("   Verdict: consistent with ordinary rotating machinery. Not anomalous.")
    else:
        residual.sort(key=lambda t: t[1], reverse=True)
        for f_, a_ in residual:
            frac = a_ / max(peak_amps)
            tag = "strong" if frac > 0.3 else ("moderate" if frac > 0.1 else "weak")
            print(f"   {f_:9.2f} Hz   {a_:.4e}   ({tag}, {frac*100:.0f}% of max)")
        print("\n   These don't fit the harmonic stack. Usually = a 2nd machine, "
              "mains\n   hum (50/60/120 Hz), or measurement noise. Only escalate if a "
              "strong,\n   stable, non-harmonic tone persists after killing local power.")

    print("\nNote: analysis is only as good as the export resolution. For a real "
          "verdict,\nrecord ≥60 s at the highest FFT size Phyphox offers.")


if __name__ == "__main__":
    main()
