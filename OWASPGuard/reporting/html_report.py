"""
HTML Report Generator for OWASPGuard
"""
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
import json

class HTMLReportGenerator:
    """
    Generate beautiful, comprehensive HTML security reports
    
    Features:
    - Interactive filtering
    - Color-coded severity
    - Code snippets
    - Detailed remediation
    """
    
    def __init__(self, findings: List[Dict], metadata: Dict[str, Any]):
        self.findings = findings
        self.metadata = metadata
        self.stats = self._calculate_statistics()
    
    def _calculate_statistics(self) -> Dict[str, Any]:
        """Calculate scan statistics"""
        stats = {
            'total_findings': len(self.findings),
            'by_severity': {},
            'by_type': {},
            'by_file': {},
            'by_owasp': {},
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
        }
        
        for finding in self.findings:
            # By severity
            severity = finding.get('severity', 'UNKNOWN')
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            
            # Counts
            if severity == 'CRITICAL':
                stats['critical_count'] += 1
            elif severity == 'HIGH':
                stats['high_count'] += 1
            elif severity == 'MEDIUM':
                stats['medium_count'] += 1
            elif severity == 'LOW':
                stats['low_count'] += 1
            
            # By type
            vuln_type = finding.get('type', 'unknown')
            stats['by_type'][vuln_type] = stats['by_type'].get(vuln_type, 0) + 1
            
            # By file
            file_path = finding.get('file_path', 'unknown')
            stats['by_file'][file_path] = stats['by_file'].get(file_path, 0) + 1
            
            # By OWASP category
            owasp = finding.get('owasp_category', 'UNKNOWN')
            stats['by_owasp'][owasp] = stats['by_owasp'].get(owasp, 0) + 1
        
        return stats
    
    def generate(self, output_file: str):
        """Generate HTML report"""
        html = self._generate_html()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"HTML report generated: {output_file}")
    
    def _generate_html(self) -> str:
        """Generate complete HTML document"""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OWASPGuard Security Scan Report</title>
    <style>
        {self._get_css()}
    </style>
</head>
<body>
    <div class="container">
        {self._generate_header()}
        {self._generate_summary()}
        {self._generate_statistics()}
        {self._generate_findings()}
    </div>
    <script>
        {self._get_javascript()}
    </script>
</body>
</html>"""
    
    def _get_css(self) -> str:
        """Get CSS styles"""
        return """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        h1 { font-size: 2.5em; margin-bottom: 10px; }
        h2 { font-size: 1.8em; margin: 30px 0 15px; color: #667eea; }
        h3 { font-size: 1.3em; margin: 20px 0 10px; }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .stat-card .number {
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .stat-card .label {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .critical { color: #d32f2f; }
        .high { color: #f57c00; }
        .medium { color: #fbc02d; }
        .low { color: #388e3c; }
        
        .finding {
            background: white;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .finding.critical { border-left-color: #d32f2f; }
        .finding.high { border-left-color: #f57c00; }
        .finding.medium { border-left-color: #fbc02d; }
        .finding.low { border-left-color: #388e3c; }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .severity-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            color: white;
        }
        
        .severity-badge.critical { background: #d32f2f; }
        .severity-badge.high { background: #f57c00; }
        .severity-badge.medium { background: #fbc02d; color: #333; }
        .severity-badge.low { background: #388e3c; }
        
        .finding-details {
            margin: 10px 0;
            padding: 10px;
            background: #f9f9f9;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        
        .code-snippet {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
        }
        
        .filter-buttons {
            margin: 20px 0;
        }
        
        .filter-btn {
            padding: 10px 20px;
            margin: 5px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9em;
            transition: all 0.3s;
        }
        
        .filter-btn:hover { transform: translateY(-2px); box-shadow: 0 4px 6px rgba(0,0,0,0.2); }
        .filter-btn.active { font-weight: bold; box-shadow: 0 4px 6px rgba(0,0,0,0.2); }
        .filter-btn.all { background: #667eea; color: white; }
        .filter-btn.critical { background: #d32f2f; color: white; }
        .filter-btn.high { background: #f57c00; color: white; }
        .filter-btn.medium { background: #fbc02d; }
        .filter-btn.low { background: #388e3c; color: white; }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        th {
            background: #667eea;
            color: white;
            font-weight: bold;
        }
        
        tr:hover { background: #f5f5f5; }
    """
    
    def _generate_header(self) -> str:
        """Generate report header"""
        return f"""
        <header>
            <h1>🛡️ OWASPGuard Security Report</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Project: {self.metadata.get('project_path', 'Unknown')}</p>
        </header>
        """
    
    def _generate_summary(self) -> str:
        """Generate summary cards"""
        return f"""
        <div class="summary">
            <div class="stat-card">
                <div class="label">Total Findings</div>
                <div class="number">{self.stats['total_findings']}</div>
            </div>
            <div class="stat-card">
                <div class="label">Critical</div>
                <div class="number critical">{self.stats['critical_count']}</div>
            </div>
            <div class="stat-card">
                <div class="label">High</div>
                <div class="number high">{self.stats['high_count']}</div>
            </div>
            <div class="stat-card">
                <div class="label">Medium</div>
                <div class="number medium">{self.stats['medium_count']}</div>
            </div>
            <div class="stat-card">
                <div class="label">Low</div>
                <div class="number low">{self.stats['low_count']}</div>
            </div>
        </div>
        """
    
    def _generate_statistics(self) -> str:
        """Generate statistics table"""
        return f"""
        <div style="background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <h2>Scan Information</h2>
            <table>
                <tr>
                    <th>Metric</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>Files Scanned</td>
                    <td>{self.metadata.get('files_scanned', 0):,}</td>
                </tr>
                <tr>
                    <td>Lines Scanned</td>
                    <td>{self.metadata.get('lines_scanned', 0):,}</td>
                </tr>
                <tr>
                    <td>Scan Duration</td>
                    <td>{self.metadata.get('duration', 0):.2f} seconds</td>
                </tr>
                <tr>
                    <td>Scanners Used</td>
                    <td>{', '.join(self.metadata.get('scanners', []))}</td>
                </tr>
            </table>
        </div>
        """
    
    def _generate_findings(self) -> str:
        """Generate findings section"""
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_findings = sorted(
            self.findings,
            key=lambda x: severity_order.get(x.get('severity', 'LOW'), 999)
        )
        
        findings_html = '<div class="filter-buttons">'
        findings_html += '<button class="filter-btn all active" onclick="filterFindings(\'all\')">All</button>'
        findings_html += '<button class="filter-btn critical" onclick="filterFindings(\'CRITICAL\')">Critical</button>'
        findings_html += '<button class="filter-btn high" onclick="filterFindings(\'HIGH\')">High</button>'
        findings_html += '<button class="filter-btn medium" onclick="filterFindings(\'MEDIUM\')">Medium</button>'
        findings_html += '<button class="filter-btn low" onclick="filterFindings(\'LOW\')">Low</button>'
        findings_html += '</div>'
        
        findings_html += '<h2>Findings</h2>'
        findings_html += '<div id="findings-container">'
        
        for finding in sorted_findings:
            findings_html += self._generate_finding_html(finding)
        
        findings_html += '</div>'
        
        return findings_html
    
    def _generate_finding_html(self, finding: Dict) -> str:
        """Generate HTML for a single finding"""
        severity = finding.get('severity', 'LOW').lower()
        vuln_type = finding.get('type', 'unknown').replace('_', ' ').title()
        description = finding.get('description', 'No description')
        file_path = finding.get('file_path', 'unknown')
        line = finding.get('line_number', '?')
        confidence = finding.get('confidence', 0)
        if isinstance(confidence, str):
            confidence = 0.8 if confidence == 'high' else 0.5 if confidence == 'medium' else 0.3
        confidence_pct = int(confidence * 100) if isinstance(confidence, (int, float)) else 80
        
        code_snippet = finding.get('line_content', '')
        code_html = f'<div class="code-snippet">{code_snippet}</div>' if code_snippet else ''
        
        remediation = finding.get('remediation', finding.get('recommendation', ''))
        remediation_html = f'<p><strong>Remediation:</strong> {remediation}</p>' if remediation else ''
        
        owasp = finding.get('owasp_category_full', finding.get('owasp_category', 'Unknown'))
        
        return f"""
        <div class="finding {severity}" data-severity="{finding.get('severity', 'LOW')}">
            <div class="finding-header">
                <h3>{vuln_type}</h3>
                <span class="severity-badge {severity}">{finding.get('severity', 'LOW')}</span>
            </div>
            <p><strong>OWASP Category:</strong> {owasp}</p>
            <p><strong>Description:</strong> {description}</p>
            <div class="finding-details">
                <p><strong>File:</strong> {file_path}:{line}</p>
                <p><strong>Confidence:</strong> {confidence_pct}%</p>
            </div>
            {code_html}
            {remediation_html}
        </div>
        """
    
    def _get_javascript(self) -> str:
        """Get JavaScript for interactivity"""
        return """
        function filterFindings(severity) {
            const findings = document.querySelectorAll('.finding');
            const buttons = document.querySelectorAll('.filter-btn');
            
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            findings.forEach(finding => {
                if (severity === 'all' || finding.dataset.severity === severity) {
                    finding.style.display = 'block';
                } else {
                    finding.style.display = 'none';
                }
            });
        }
        """

