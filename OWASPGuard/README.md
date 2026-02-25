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

### CLI

```bash
# Scan a project
python -m cli.main scan ./project

# Scan with specific language
python -m cli.main scan --lang python ./repo

# Generate PDF report
python -m cli.main report --pdf

# Generate JSON report
python -m cli.main report --json
```

### GUI

```bash
python -m gui.app
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

