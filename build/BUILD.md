# Building PILA Suite — Community (Host)

The product is a self-contained Windows `.exe` that serves the freescore GUI
locally and opens it in the browser. It has **no third-party runtime
dependencies** — the app is pure Python standard library, so the packaged `.exe`
embeds only this code plus CPython (PSF license). Build-time only: PyInstaller
(its bootloader exception permits distributing the frozen app commercially).

## 1. Build (on Bryant-PC, Windows)

From the repo root:

```
.\build\build.ps1
```

This creates a throwaway venv, installs PyInstaller, and runs `build/pila-suite.spec`.
Output: `dist\pila-suite-<version>.exe` (name and Windows version metadata are read
from `freescore/__init__.py`, so a version bump needs no spec edit).

Run `python -m freescore` first if you want to smoke-test the app unpackaged.

## 2. Sign (Certum SimplySign, same as the scanner releases)

Make sure SimplySign Desktop is running and logged in, then:

```
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | ? { $_.Subject -like "*ByTE X Bit*" } | Select-Object -First 1
Set-AuthenticodeSignature -FilePath .\dist\pila-suite-<version>.exe -Certificate $cert -TimestampServer "http://time.certum.pl" -HashAlgorithm SHA256
Get-AuthenticodeSignature .\dist\pila-suite-<version>.exe | Format-List Path, Status, SignerCertificate
```

`Status` must be `Valid` with the ByTE X Bit certificate (thumbprint `DB81E8…`).

## 3. Checksum

```
Get-FileHash .\dist\pila-suite-<version>.exe -Algorithm SHA256 | % Hash > .\dist\pila-suite-<version>.exe.sha256
```

## 4. Publish

Deploy discipline (site): copy the **signed** exe to the CT 111 webroot `/downloads/`,
hash-gate it against the local file, bump `version.json` (the in-app update manifest),
update the download-page link (2.0.0 → the new version), then Cloudflare **Purge
Everything** (the download URL caches hard). Then cut a GitHub Release tagged
`v<version>` with the signed exe and its `.sha256` attached.
