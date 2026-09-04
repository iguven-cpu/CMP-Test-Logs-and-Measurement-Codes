# Empirical Input-Security Validation (Fuzzing Artifacts)

This directory accompanies the paper's *Empirical Input-Security Validation*
section. It contains the black-box fuzzing harness, the malformed-input corpus
generators, and the anonymized findings summary needed to reproduce the
security evaluation of the firmware CMP client's web-driven input pipeline.

> **Anonymization / responsible disclosure.** All device identifiers (address,
> hostname, session tokens, vendor/product names) have been removed. No real
> private key is included; the key corpus is regenerated at run time from a
> throwaway key. The one defect found (a logging-layer format-string issue,
> CWE-134) was fixed at the source before release.

## Contents

All artifacts share a `fuzzing_` prefix so they group together even when added
individually (not as a folder):

```
fuzzing_README.md              # this file
fuzzing_cmp_fuzz.py            # black-box fuzzer for the 7 CMP text parameter fields
fuzzing_generate_corpus.ps1   # regenerates all 51 malformed credential files
fuzzing_findings_summary.json # anonymized methodology + results
```

## Methodology (summary)

Two attack surfaces of the web-driven pipeline were fuzzed on a running device,
using device **liveness (ICMP ping + dashboard/clock) as a crash oracle**:

1. **Text parameter fields (7 fields, ~130 malformed inputs).**
   Requests are issued directly to the firmware's configuration endpoints,
   bypassing the browser-side JavaScript checks so that the firmware's own
   server-side validation is exercised. Payload classes: command-injection
   metacharacters, path traversal, format strings, oversized strings, embedded
   NUL bytes, and non-UTF-8/Unicode input. Each field is restored to its
   baseline after every request. Only the validate-stage (`bufferwrite`) is
   used, so malformed values are validated but never committed.

2. **Credential-file upload path (51 malformed files, 4 corpora).**
   Malformed PEM, binary DER/ASN.1, wrong-object-type, and non-key file-type
   inputs are uploaded through the authenticated key-upload widget; the firmware
   verdict is recorded and device liveness is confirmed after each upload.

Across both surfaces, **no input caused a crash, hang, or reboot**. Empirical
testing corroborated the server-side length bounds and the by-construction
elimination of shell injection, and surfaced a logging-layer format-string
defect (CWE-134) that the design-based analysis had missed; the credential-file
path proved robust (layered validation, bounded ASN.1 parsing, private-key type
enforcement, strict PEM-marker matching).

## Prerequisites

- **Text fuzzer:** Python 3.9+, `pip install requests`.
- **Corpus generator:** PowerShell 5.1+ and `openssl` on `PATH` (used only to
  mint a throwaway RSA key as the "valid" base for the corpus).

## Running

### 1. Text-field fuzzer

Set the target and an authenticated session via environment variables (obtain
the session cookie and the anti-replay nonce from the browser DevTools of a
logged-in session), then run:

```powershell
$env:CMP_DEVICE   = "192.0.2.10"          # device address (example)
$env:CMP_COOKIE   = "SID=<session-cookie>"  # from DevTools > Application > Cookies
$env:CMP_NONCE    = "<anti-replay-nonce>"   # from DevTools console
python fuzzing_cmp_fuzz.py
```

Results are written to `fuzzing_results/fuzz_<timestamp>.jsonl` and `.csv`. Run only
against a test unit or with configuration-saving disabled (so a reboot restores
state), with a serial console/syslog open to observe the native trace.

### 2. Credential-file corpus

```powershell
./fuzzing_generate_corpus.ps1    # creates 51 files under ./fuzzing_corpus/
```

Upload the generated files through the device's key-upload page and record each
verdict; confirm device liveness between uploads.

## Safety

These procedures mutate live device state. Use a **test unit**, keep
**configuration-saving disabled** (reboot restores), rate-limit requests
(>= 450 ms apart), and watch the liveness oracle. The harness restores each
text field to its baseline after every request.
