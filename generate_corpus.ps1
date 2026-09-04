# =============================================================================
# generate_corpus.ps1 - Regenerate the 51-file malformed credential corpus.
#
# No real private key is committed. A throwaway RSA key is minted at run time
# with openssl and used as the "valid" base for the corpus (including the
# positive-control and lenient-preamble cases). Output: ./corpus/
#
# Requires: openssl on PATH, PowerShell 5.1+.
# =============================================================================
$ErrorActionPreference = "Stop"
$dir = Join-Path $PSScriptRoot "corpus"
New-Item -ItemType Directory -Force -Path $dir | Out-Null

if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
    Write-Error "openssl not found on PATH. Install OpenSSL and retry."
}

# --- Throwaway 'valid' RSA private key (never a real credential) ------------
$keyPath = Join-Path $dir "_throwaway_key.pem"
& openssl genrsa -out $keyPath 2048 2>$null
$valid = Get-Content -Raw $keyPath
$b64stub = "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA1234567890abcdef"

function Write-Ascii([string]$name, [string]$text) {
    [System.IO.File]::WriteAllText((Join-Path $dir $name), $text, [System.Text.Encoding]::ASCII)
}
function Write-Bytes([string]$name, [byte[]]$bytes) {
    [System.IO.File]::WriteAllBytes((Join-Path $dir $name), $bytes)
}
$bodyLines = ($valid -split "`n" | Where-Object { $_ -notmatch 'BEGIN|END' -and $_.Trim() -ne '' })
$body = $bodyLines -join "`n"

# --- Corpus 1: PEM text -----------------------------------------------------
Write-Ascii "empty.pem" ""
Write-Ascii "onlyheader.pem" "-----BEGIN RSA PRIVATE KEY-----`n-----END RSA PRIVATE KEY-----"
Write-Ascii "truncated.pem" ("-----BEGIN RSA PRIVATE KEY-----`n" + ($bodyLines | Select-Object -First 6) -join "`n")
Write-Ascii "corrupted_b64.pem" ("-----BEGIN RSA PRIVATE KEY-----`n" + ("!@#$%^&*()_+" * 130) + "`n-----END RSA PRIVATE KEY-----")
Write-Ascii "wrongheader.pem" ("-----BEGN RSA PRIVATE KEY-----`n" + $body + "`n-----END RSA PRIVATE KEY-----")
Write-Ascii "notkey.pem" "-----BEGIN CERTIFICATE-----`nTm90QUtleUp1c3RTb21lUEVNT2JqZWN0RGF0YQ==`n-----END CERTIFICATE-----"
Write-Bytes "binary.bin" ((1..4096 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }))
Write-Ascii "metachars.pem" ("-----BEGIN RSA PRIVATE KEY-----`n" + '%x%x%n;reboot`id`../../etc/passwd' + "`n-----END RSA PRIVATE KEY-----")
Write-Bytes "nul.pem" ([byte[]](0x00,0x00))
# Oversized ~2.6 MB PEM
$sbHuge = New-Object System.Text.StringBuilder
[void]$sbHuge.Append("-----BEGIN RSA PRIVATE KEY-----`n")
1..40000 | ForEach-Object { [void]$sbHuge.Append("MIIEpAIBAAKCAQEA1234567890abcdefABCDEF1234567890abcdefABCDEF12`n") }
[void]$sbHuge.Append("-----END RSA PRIVATE KEY-----")
Write-Ascii "huge.pem" $sbHuge.ToString()

# --- Corpus 1b: structural PEM variants ------------------------------------
Write-Ascii "pkcs8_garbage.pem" "-----BEGIN PRIVATE KEY-----`nTm90QVZhbGlkUEtDUzhLZXlKdXN0R2FyYmFnZURhdGE=`n-----END PRIVATE KEY-----"
Write-Ascii "ec_invalid.pem" "-----BEGIN EC PRIVATE KEY-----`nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`n-----END EC PRIVATE KEY-----"
Write-Ascii "doublekey.pem" ($valid.TrimEnd() + "`n" + $valid.TrimEnd() + "`n")
$begin = "-----BEGIN RSA PRIVATE KEY-----`n"; $end = "-----END RSA PRIVATE KEY-----`n"
Write-Ascii "nested_begin.pem" (($begin * 50) + "QUFBQQ==`n" + ($end * 50))
Write-Ascii "overlong_line.pem" ("-----BEGIN RSA PRIVATE KEY-----`n" + ("A" * 200000) + "`n-----END RSA PRIVATE KEY-----")
Write-Ascii "crlf_inject.pem" "-----BEGIN RSA PRIVATE KEY-----`r`nQUFBQQ==`r`n[CRITICAL] injected log line`r`nreboot now`r`n-----END RSA PRIVATE KEY-----"
Write-Bytes "bom_header.pem" ([byte[]](0xEF,0xBB,0xBF) + [System.Text.Encoding]::ASCII.GetBytes("-----BEGIN RSA PRIVATE KEY-----`nQUFBQQ==`n-----END RSA PRIVATE KEY-----"))
$pemBytes = [System.Text.Encoding]::ASCII.GetBytes($valid)
$withNul = New-Object System.Collections.Generic.List[byte]
for ($i = 0; $i -lt $pemBytes.Length; $i++) { $withNul.Add($pemBytes[$i]); if ($i -gt 40 -and $i % 60 -eq 0) { $withNul.Add(0) } }
Write-Bytes "nul_scattered.pem" ($withNul.ToArray())
Write-Ascii "encrypted_bad.pem" "-----BEGIN RSA PRIVATE KEY-----`nProc-Type: 4,ENCRYPTED`nDEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF`n`nU2FsdGVkX1invalidbase64bodythatwontdecrypt==`n-----END RSA PRIVATE KEY-----"
Write-Ascii "fmt_body.pem" ("-----BEGIN RSA PRIVATE KEY-----`n" + ("%n%s%x%p" * 200) + "`n-----END RSA PRIVATE KEY-----")

# --- Corpus 2: binary DER / ASN.1 ------------------------------------------
& openssl rsa -in $keyPath -outform DER -out (Join-Path $dir "der_valid.der") 2>$null
$der = [System.IO.File]::ReadAllBytes((Join-Path $dir "der_valid.der"))
Write-Bytes "der_truncated.der" ($der[0..([Math]::Min(120,$der.Length)-1)])
Write-Bytes "der_lenoverflow.der" ([byte[]](0x30,0x84,0xFF,0xFF,0xFF,0xFF,0x02,0x01,0x00))
$deep = New-Object System.Collections.Generic.List[byte]
for ($i=0;$i -lt 2000;$i++){ $deep.Add(0x30); $deep.Add(0x80) }
for ($i=0;$i -lt 2000;$i++){ $deep.Add(0x00); $deep.Add(0x00) }
Write-Bytes "der_deepnest.der" $deep.ToArray()

# --- Corpus 3: wrong object type -------------------------------------------
Write-Ascii "cert_in_keyslot.pem" "-----BEGIN CERTIFICATE-----`nMIIBfakeCertData1234567890abcdefABCDEF==`n-----END CERTIFICATE-----"
Write-Ascii "csr_in_keyslot.pem" "-----BEGIN CERTIFICATE REQUEST-----`nMIIBADCBmwIBADBZMQswCQYDVQQGEwJYWDELMAkGA1UECAwCWFgxDzANBgNV==`n-----END CERTIFICATE REQUEST-----"
Write-Ascii "pubkey.pem" "-----BEGIN PUBLIC KEY-----`n$b64stub`n-----END PUBLIC KEY-----"
Write-Ascii "rsa_pubkey.pem" "-----BEGIN RSA PUBLIC KEY-----`n$b64stub`n-----END RSA PUBLIC KEY-----"
Write-Ascii "dsa_key.pem" "-----BEGIN DSA PRIVATE KEY-----`n$b64stub`n-----END DSA PRIVATE KEY-----"
Write-Ascii "openssh_key.pem" "-----BEGIN OPENSSH PRIVATE KEY-----`nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB`n-----END OPENSSH PRIVATE KEY-----"
Write-Ascii "pgp_key.asc" "-----BEGIN PGP PRIVATE KEY BLOCK-----`nVersion: GnuPG v2`n`nlQOYBF$b64stub`n-----END PGP PRIVATE KEY BLOCK-----"
Write-Ascii "dh_params.pem" "-----BEGIN DH PARAMETERS-----`nMIGHAoGBAP//////`n-----END DH PARAMETERS-----"
Write-Ascii "cert_then_key.pem" ("-----BEGIN CERTIFICATE-----`nMIIBfakeCertData1234567890abcdefABCDEF==`n-----END CERTIFICATE-----`n" + $valid.TrimEnd())

# --- Corpus 4: marker syntax + non-key file types --------------------------
Write-Ascii "whitespace_markers.pem" "----- BEGIN RSA PRIVATE KEY -----`n$body`n----- END RSA PRIVATE KEY -----"
Write-Ascii "lowercase_markers.pem" "-----begin rsa private key-----`n$body`n-----end rsa private key-----"
Write-Ascii "extra_dashes.pem" "--------BEGIN RSA PRIVATE KEY--------`n$body`n--------END RSA PRIVATE KEY--------"
Write-Ascii "missing_end.pem" "-----BEGIN RSA PRIVATE KEY-----`n$body"
Write-Ascii "missing_begin.pem" "$body`n-----END RSA PRIVATE KEY-----"
Write-Ascii "tabs_in_body.pem" ("-----BEGIN RSA PRIVATE KEY-----`n" + (($bodyLines | ForEach-Object { "`t" + $_ + "  " }) -join "`n") + "`n-----END RSA PRIVATE KEY-----")
Write-Ascii "mismatched_markers.pem" ("-----BEGIN RSA PRIVATE KEY-----`n$body`n-----END EC PRIVATE KEY-----")
Write-Ascii "bad_padding.pem" "-----BEGIN RSA PRIVATE KEY-----`nQUFB====`nBBBB=`n=====`n-----END RSA PRIVATE KEY-----"
Write-Ascii "b64_illegalchars.pem" "-----BEGIN RSA PRIVATE KEY-----`nQUF@#!*()<>{}[]QUFB`n-----END RSA PRIVATE KEY-----"
Write-Ascii "trailing_garbage.pem" ($valid.TrimEnd() + "`n%n%n;reboot`0GARBAGE" + ("Z" * 500))
Write-Ascii "leading_garbage.pem" (("Q" * 500) + "leading junk %s%n`n" + $valid.TrimEnd() + "`n")
Write-Ascii "shebang.pem" ("#!/bin/sh`nreboot`nrm -rf /`n" + $valid.TrimEnd())
Write-Ascii "json_file.json" '{"privateKey":"not a real key","alg":"RSA","d":"%n%n%n","bits":2048}'
Write-Ascii "xml_xxe.xml" '<?xml version="1.0"?><!DOCTYPE key [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><key>&xxe;</key>'
[System.IO.File]::WriteAllText((Join-Path $dir "utf16.pem"), $valid, [System.Text.Encoding]::Unicode)
$sbBlank = New-Object System.Text.StringBuilder
[void]$sbBlank.Append("-----BEGIN RSA PRIVATE KEY-----`n"); [void]$sbBlank.Append(("`n" * 400000)); [void]$sbBlank.Append("QUFBQQ==`n-----END RSA PRIVATE KEY-----")
Write-Ascii "manyblanklines.pem" $sbBlank.ToString()
Write-Bytes "allnull.bin" (New-Object byte[] 4096)
$ff = New-Object byte[] 4096; for ($i=0;$i -lt 4096;$i++){ $ff[$i]=0xFF }
Write-Bytes "allff.bin" $ff

$count = (Get-ChildItem $dir -File | Where-Object { $_.Name -ne "_throwaway_key.pem" }).Count
Write-Host "Generated $count malformed corpus files under: $dir"
