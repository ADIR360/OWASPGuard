# Mini-ZAP: OWASP Top 10 Automated Vulnerability Scanner

A lightweight automated web vulnerability scanner focused on identifying high-impact OWASP Top 10 vulnerabilities.

## Features

- **Web Crawling**: Discovers accessible endpoints and input points
- **Vulnerability Detection**: Identifies SQL Injection, XSS, Broken Access Control, Security Misconfiguration, and SSRF
- **Custom Detection Logic**: Transparent and explainable vulnerability detection
- **Risk Classification**: Categorizes vulnerabilities according to OWASP standards
- **Report Generation**: Generates structured JSON and PDF reports

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Graphical User Interface (GUI) - Recommended

Launch the GUI application:

```bash
python gui.py
```

The GUI provides:
- Easy-to-use interface for configuring scans
- Real-time scan progress and logging
- Interactive vulnerability browser with details
- Summary statistics
- Export reports (JSON and PDF)

### Command Line Interface

```bash
python main.py --url https://example.com
```

Options:
- `--url`: Target URL to scan (required)
- `--depth`: Crawl depth (default: 2)
- `--delay`: Delay between requests in seconds (default: 0.5)
- `--output-dir`: Output directory for reports (default: current directory)
- `--scanners`: Scanners to run (sql, xss, access, misconfig, ssrf, all)

Example:
```bash
python main.py --url https://example.com --depth 3 --scanners sql xss
```

### Web API Interface

Start the FastAPI server:

```bash
python app.py
```

Or using uvicorn:

```bash
uvicorn app:app --reload
```

Then visit `http://localhost:8000` in your browser for API documentation.

#### API Usage Examples

Start a scan:
```bash
curl -X POST "http://localhost:8000/scan" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "depth": 2, "scanners": ["sql", "xss"]}'
```

Check scan status:
```bash
curl "http://localhost:8000/scan/{scan_id}"
```

Download reports:
```bash
curl "http://localhost:8000/scan/{scan_id}/report/json" -o report.json
curl "http://localhost:8000/scan/{scan_id}/report/pdf" -o report.pdf
```

## Project Structure

```
.
├── app.py                 # FastAPI web interface
├── main.py                # CLI entry point
├── crawler.py             # Web crawler module
├── scanners/              # Vulnerability scanners
│   ├── __init__.py
│   ├── sql_injection.py
│   ├── xss.py
│   ├── access_control.py
│   ├── misconfiguration.py
│   └── ssrf.py
├── reports/               # Report generators
│   ├── __init__.py
│   ├── json_report.py
│   └── pdf_report.py
├── utils/                 # Utility modules
│   ├── __init__.py
│   ├── vulnerability.py
│   └── payloads.py
└── requirements.txt
```

## OWASP Top 10 Coverage

1. **A01:2021 – Broken Access Control** ✓
2. **A02:2021 – Cryptographic Failures** (Partial)
3. **A03:2021 – Injection** ✓ (SQL Injection)
4. **A04:2021 – Insecure Design** (Partial)
5. **A05:2021 – Security Misconfiguration** ✓
6. **A06:2021 – Vulnerable Components** (Partial)
7. **A07:2021 – Authentication Failures** (Partial)
8. **A08:2021 – Software and Data Integrity Failures** (Partial)
9. **A09:2021 – Security Logging Failures** (Partial)
10. **A10:2021 – Server-Side Request Forgery** ✓

## Disclaimer

This tool is for authorized security testing and educational purposes only. Always obtain proper authorization before scanning any web application.

## License

Educational Use Only

