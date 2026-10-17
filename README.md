# My SOC Sentinel Project

Sentinel includes a private, browser-based project scanner and an offline
command-line scanner for common security risks in source code and configuration
files.

## Web app

Run the local Windows service from PowerShell at the project root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\sentinel_server.ps1
```

Then open <http://127.0.0.1:8765/>. The service listens on the loopback
interface only; press `Ctrl+C` in PowerShell to stop it. Keep the terminal open
while using the local tools. Windows PowerShell may restrict locally-created
scripts, so `-ExecutionPolicy Bypass` applies only to this server process and
does not change the saved machine or user policy. Opening `index.html` directly
still supports browser-only source and log analysis, but the system tools
require the local service.

### Security operations tools

- **Source-code scan:** Choose files or a project folder, or drag source files
  onto the dropzone. The browser checks for exposed credentials, risky
  execution/deserialization, and other common risks. Findings do not reveal
  source lines or secret values.
- **Host discovery:** View the Windows IPv4 neighbor cache. This is a passive
  lookup, not an active network scan; it only shows private-network devices the
  computer has already seen.
- **Virus scan:** Submit a file to the local service for a Microsoft Defender
  custom scan. Files are limited to 50 MB and are not executed. Sentinel only
  sends the file to this computer and removes the temporary copy after the
  scan. Defender cloud protection or sample-submission settings may still
  submit samples according to your Windows security settings. Results may be
  indeterminate; review Windows Security's Protection history.
- **Web security check:** Make a single read-only `HEAD` request to the root
  path on an RFC1918 or loopback IPv4 address. The check reviews common response
  headers and cookie flags; it does not authenticate, follow redirects, send
  test payloads, or access public hosts. Use only on services you own or are
  authorized to assess. HTTPS certificate validation stays enabled.
- **Traffic and threat hunting:** Analyze Apache-style, CSV, or JSON Lines
  access logs and authentication logs locally in the browser. Access-log burst detection groups requests by
  source and minute, and also checks for distributed request bursts; the
  default alert threshold is 100 requests per minute and can be changed.
  Hunting checks identify a few suspicious patterns and repeated login
  failures without displaying raw log lines. Rate analysis requires an
  identifiable source IPv4 address and timestamp. Up to 20 MB across 20 files
  and the first 20,000 lines per file are analyzed. This is defensive log
  analysis only: it does not generate traffic or perform DDoS testing.

System tools are limited to this computer; do not expose the local service to a
network or the internet. The source-code scanner supports files up to 1 MB and
skips common generated and dependency directories. The log analyzer supports
up to 20 MB across 20 files, and scans up to 20,000 lines per file. The
antivirus upload is restricted to 50 MB.

All checks are heuristic or limited-scope defensive checks. They do not replace
endpoint detection, full malware analysis, continuous DDoS protection,
dependency scanning, authorized penetration testing, or incident-response
review. Review results rather than treating an empty report as proof that a
system is safe.

## Command-line scanner

Python 3.10 or newer is required to run `Sentinel.PY`.

```powershell
python Sentinel.PY .
python Sentinel.PY .\src --format json
```

Use `--exclude PATTERN` one or more times to exclude additional paths, or
`--max-file-size BYTES` to change the per-file size limit. JSON output includes
findings and scan warnings for automation.

Exit status is `0` when no finding reaches the selected threshold, `1` when at
least one does, and `2` when the scan encountered unreadable or skipped files.
The threshold defaults to `low`; `--severity high` only fails for high or
critical findings.

Both scanners use heuristic static checks; they do not execute scanned code or
identify vulnerable dependency versions. They are not a substitute for code
review, a language-aware analyzer, a dependency vulnerability database, or a
penetration test. Results can include false positives and should be reviewed
before taking action.

## Tests

Run the command-line tests with:

```powershell
python -m unittest discover -s tests
```
