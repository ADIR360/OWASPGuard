# OWASPGuard Architecture

## Overview

OWASPGuard is an offline static application security analyzer that performs SAST (Static Application Security Testing), SCA (Software Composition Analysis), and configuration scanning with strict OWASP Top 10 mapping.

## Core Components

### 1. File Loader (`core/file_loader.py`)
- Secure file traversal
- Memory-efficient line-by-line reading
- Binary file filtering
- Extension-based language detection

### 2. Rule Engine (`core/rule_engine.py`)
- Loads JSON-based security rules
- Pattern matching (regex, AST, file patterns)
- Language-specific rule filtering
- This is the core IP of the tool

### 3. OWASP Mapper (`core/owasp_mapper.py`)
- Maps findings to OWASP Top 10 categories
- Categorizes findings by OWASP code
- Groups findings for reporting

### 4. Risk Engine (`core/risk_engine.py`)
- Calculates risk scores
- Assigns risk levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Considers severity, exploitability, and confidence

### 5. Scan Orchestrator (`core/orchestrator.py`)
- Coordinates all scanners
- Manages scan workflow
- Multi-threaded file processing
- Aggregates results

## Scanners

### SAST Scanners

#### Python Scanner (`scanners/sast/python_scanner.py`)
- Regex-based rule matching
- AST-based injection detection
- Detects SQL injection, command injection

#### JavaScript Scanner (`scanners/sast/js_scanner.py`)
- Pattern-based vulnerability detection
- XSS detection (innerHTML)
- Code injection (eval)

### SCA Scanner

#### Dependency Parser (`scanners/sca/dependency_parser.py`)
- Parses requirements.txt, package.json, pom.xml
- Extracts package names and versions

#### CVE Matcher (`scanners/sca/cve_matcher.py`)
- Matches dependencies against local CVE database
- Version vulnerability checking
- Offline operation

### Configuration Scanners

#### Secrets Scanner (`scanners/config_scan/secrets_scanner.py`)
- Detects hardcoded API keys, passwords, tokens
- Pattern-based detection
- Maps to A02 (Cryptographic Failures)

#### Environment Scanner (`scanners/config_scan/env_scanner.py`)
- Scans .env and config files
- Detects misconfigurations
- Maps to A05 (Security Misconfiguration)

## Rules

Rules are defined in JSON files in the `rules/` directory:

- `injection.json` - A03: Injection vulnerabilities
- `crypto_failures.json` - A02: Cryptographic failures
- `access_control.json` - A01: Broken access control
- `misconfiguration.json` - A05: Security misconfiguration
- `ssrf.json` - A10: Server-Side Request Forgery
- `auth_failures.json` - A07: Authentication failures
- `logging_failures.json` - A09: Logging failures
- `insecure_design.json` - A04: Insecure design
- `data_integrity.json` - A08: Data integrity failures

## Reporting

### JSON Report (`reporting/json_report.py`)
- Machine-readable format
- Complete finding details
- Categorized by OWASP

### PDF Report (`reporting/pdf_report.py`)
- Human-readable format
- Professional layout
- Executive summary
- Detailed findings

## User Interfaces

### CLI (`cli/main.py`, `cli/commands.py`)
- Command-line interface
- Scan and report commands
- Configurable options

### GUI (`gui/app.py`)
- Professional tkinter-based interface
- Real-time scan progress
- Interactive findings browser
- Summary statistics

## Workflow

1. **File Loading**: Traverse project, filter files
2. **SAST Scanning**: Apply rules to source code
3. **SCA Scanning**: Check dependencies against CVE database
4. **Config Scanning**: Scan for secrets and misconfigurations
5. **OWASP Mapping**: Map all findings to OWASP categories
6. **Risk Assessment**: Calculate risk scores
7. **Report Generation**: Generate JSON and PDF reports

## Memory Optimization

- Line-by-line file reading
- Thread pool for parallel processing
- Binary file filtering
- File size limits
- Cached rule compilation

## Extensibility

- Add new rules by creating JSON files
- Add new scanners by implementing scanner interface
- Add new languages by creating language-specific scanners
- Extend CVE database for more dependency coverage

