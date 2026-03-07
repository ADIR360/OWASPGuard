# OWASPGuard
## Offline Static Application Security Analyzer for OWASP Top 10 Compliance

A local-first, CLI-driven security analysis tool that performs SAST + SCA + Configuration scanning with strict OWASP Top 10 mapping.

## Features

- **Static Code Analysis (SAST)**: Detects vulnerabilities in Python, JavaScript, and Java code
- **Software Composition Analysis (SCA)**: Identifies vulnerable dependencies using local CVE database
- **Configuration Scanning**: Detects secrets, misconfigurations, and security issues
- **OWASP Top 10 Mapping**: All findings mapped to OWASP Top 10 categories
- **Rule-Based Detection**: Transparent, explainable, deterministic logic
- **Offline Operation**: No internet connection required
- **Professional Reports**: JSON and PDF output formats
- **CLI + GUI**: Command-line and graphical interfaces

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### CLI (planned)

The `OWASPGuard/cli` package contains `ScanCommand` and `ReportCommand` building blocks for a future CLI, but the final entrypoint is not wired yet.  
For now, prefer the **GUI** or **programmatic usage**.

### GUI

To launch the modern GUI from the project root:

```bash
python -m OWASPGuard.gui.modern_app
```

### Programmatic (Python)

You can run a scan directly from Python:

```python
from OWASPGuard.core.orchestrator import ScanOrchestrator

orchestrator = ScanOrchestrator(
    project_path=".",
    languages=["python", "javascript"],
    max_workers=4,
)

results = orchestrator.scan()
print("Files scanned:", results["stats"]["files_scanned"])
print("Total findings:", len(results["findings"]))
```

## Architecture

- **Core**: Orchestration, rule engine, OWASP mapping, risk assessment
- **Scanners**: SAST (Python/JS/Java), SCA (dependency analysis), Config (secrets/misconfig)
- **Rules**: JSON-based rule definitions for OWASP Top 10
- **Reporting**: JSON and PDF report generators
- **CLI/GUI**: User interfaces

## OWASP Top 10 Coverage

✅ A01: Broken Access Control  
✅ A02: Cryptographic Failures  
✅ A03: Injection  
✅ A04: Insecure Design  
✅ A05: Security Misconfiguration  
✅ A06: Vulnerable Components (SCA)  
✅ A07: Authentication Failures  
✅ A08: Software & Data Integrity Failures  
✅ A09: Security Logging & Monitoring Failures  
✅ A10: Server-Side Request Forgery (SSRF)  

## License

Educational Use Only

