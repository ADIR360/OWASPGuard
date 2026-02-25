# OSV Database Setup Guide

## Quick Start

The OSV database enables offline CVE scanning and is **100x faster** than API calls.

### Initial Setup (One-time)

```bash
cd OWASPGuard
python3 scanners/sca/osv_database.py update
```

This will:
- Download CVE data for PyPI, npm, and Maven
- Create SQLite database (~50MB)
- Take 5-10 minutes (one-time download)

### Verify Installation

```bash
# Check database statistics
python3 scanners/sca/osv_database.py stats
```

Expected output:
```
Total vulnerabilities: ~50,000+
By ecosystem: {'PyPI': 15000+, 'npm': 20000+, 'Maven': 15000+}
By severity: {'CRITICAL': 5000+, 'HIGH': 15000+, ...}
```

### Query Example

```bash
# Check if a specific package version is vulnerable
python3 scanners/sca/osv_database.py query PyPI requests 2.25.0
```

### Automatic Updates

The database automatically checks if updates are needed (weekly). To force update:

```bash
python3 scanners/sca/osv_database.py update --force
```

---

## Integration

The OSV database is **automatically used** by the CVE matcher if available. No code changes needed!

**Priority Order:**
1. OSV Database (fastest, offline)
2. Local JSON database (if exists)
3. Online APIs (NVD, GitHub Advisory) - fallback

---

## Benefits

- ✅ **100x faster** than API calls
- ✅ **Works offline** after initial download
- ✅ **No rate limiting**
- ✅ **Comprehensive coverage** (50,000+ CVEs)
- ✅ **Automatic updates** (weekly check)

---

## Troubleshooting

### Database not found
If you see "OSV database not available", run:
```bash
python3 scanners/sca/osv_database.py update
```

### Download fails
- Check internet connection
- OSV servers may be temporarily unavailable
- Try again later or use `--force` flag

### Database too large
The database is ~50MB. If space is an issue, you can:
- Only download specific ecosystems
- Use online APIs instead (slower but no disk space)

---

## Manual Database Management

```bash
# Update specific ecosystem only
python3 -c "
from scanners.sca.osv_database import OSVDatabase
db = OSVDatabase()
db.update_from_osv(['PyPI'])  # Only PyPI
"

# Check if update needed
python3 -c "
from scanners.sca.osv_database import OSVDatabase
db = OSVDatabase()
print('PyPI needs update:', db.needs_update('PyPI'))
"
```

