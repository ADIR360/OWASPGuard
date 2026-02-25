# OWASPGuard Quick Start Guide

## Installation

1. Install dependencies:
```bash
cd OWASPGuard
pip install -r requirements.txt
```

## Usage

### CLI Usage

**Scan a project:**
```bash
python -m cli.main scan ./my_project
```

**Scan specific languages:**
```bash
python -m cli.main scan --lang python,javascript ./my_project
```

**Generate reports:**
```bash
python -m cli.main report --pdf
python -m cli.main report --json
```

### GUI Usage

**Launch GUI:**
```bash
python run_gui.py
```

Or:
```bash
python -m gui.app
```

**GUI Workflow:**
1. Click "Browse" to select project directory
2. Select languages to scan
3. Click "Start Scan"
4. View findings in the Findings tab
5. Click "Export Reports" to generate PDF/JSON

## Example Project Structure

```
my_project/
├── app.py
├── utils.py
├── requirements.txt
└── config.py
```

## What Gets Scanned

- **Source Code**: Python (.py), JavaScript (.js, .jsx, .ts)
- **Dependencies**: requirements.txt, package.json, pom.xml
- **Configuration**: .env files, config files

## OWASP Top 10 Coverage

✅ A01: Broken Access Control  
✅ A02: Cryptographic Failures  
✅ A03: Injection  
✅ A04: Insecure Design  
✅ A05: Security Misconfiguration  
✅ A06: Vulnerable Components  
✅ A07: Authentication Failures  
✅ A08: Data Integrity Failures  
✅ A09: Logging Failures  
✅ A10: SSRF  

## Report Formats

- **JSON**: Machine-readable, complete data
- **PDF**: Human-readable, submission-ready

## Customization

### Adding Rules

Edit JSON files in `rules/` directory:
```json
{
  "id": "CUSTOM-001",
  "language": "python",
  "pattern": "your_pattern_here",
  "severity": "HIGH",
  "owasp": "A03",
  "description": "Your description",
  "recommendation": "Your recommendation"
}
```

### Extending CVE Database

Edit `scanners/sca/local_cve_db.json`:
```json
{
  "package_name": [
    {
      "cve_id": "CVE-YYYY-XXXXX",
      "severity": "HIGH",
      "description": "Vulnerability description",
      "affected_versions": ["<1.2.3"],
      "fixed_version": "1.2.3"
    }
  ]
}
```

## Troubleshooting

**Import errors:**
- Ensure you're running from the OWASPGuard directory
- Check that all dependencies are installed

**No findings:**
- Verify project path is correct
- Check that files match selected languages
- Review log output for errors

**Performance:**
- Adjust worker threads (default: 4)
- Large projects may take time
- Check file size limits (10MB default)

