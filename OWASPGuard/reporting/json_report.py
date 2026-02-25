"""
JSON report generator.
"""
import json
from pathlib import Path
from datetime import datetime
from typing import Dict


class JSONReportGenerator:
    """Generates JSON vulnerability reports."""
    
    def generate(self, results: Dict, output_dir: str = ".") -> str:
        """
        Generate JSON report from scan results.
        
        Args:
            results: Scan results dictionary
            output_dir: Output directory
        
        Returns:
            Path to generated report
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        report = {
            "metadata": {
                "tool": "OWASPGuard",
                "version": "1.0.0",
                "scan_date": datetime.now().isoformat(),
                "scan_duration": results.get('stats', {}).get('scan_duration', 0)
            },
            "summary": {
                "total_findings": len(results.get('findings', [])),
                "files_scanned": results.get('stats', {}).get('files_scanned', 0),
                "scan_duration": results.get('stats', {}).get('scan_duration', 0),
                "severity_breakdown": self._calculate_severity_breakdown(results.get('findings', [])),
                "owasp_breakdown": self._calculate_owasp_breakdown(results.get('categorized', {})),
                "scan_type_breakdown": self._calculate_scan_type_breakdown(results.get('findings', [])),
                "top_vulnerabilities": self._get_top_vulnerabilities(results.get('findings', []), 10)
            },
            "findings": results.get('findings', []),
            "categorized_findings": results.get('categorized', {})
        }
        
        report_path = output_path / f"owaspguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return str(report_path)
    
    def _calculate_severity_breakdown(self, findings: list) -> dict:
        """Calculate severity breakdown."""
        breakdown = {}
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN')
            breakdown[severity] = breakdown.get(severity, 0) + 1
        return breakdown
    
    def _calculate_owasp_breakdown(self, categorized: dict) -> dict:
        """Calculate OWASP category breakdown."""
        return {cat: len(findings) for cat, findings in categorized.items()}
    
    def _calculate_scan_type_breakdown(self, findings: list) -> dict:
        """Calculate scan type breakdown."""
        breakdown = {}
        for finding in findings:
            scan_type = finding.get('scan_type', 'SAST')
            breakdown[scan_type] = breakdown.get(scan_type, 0) + 1
        return breakdown
    
    def _get_top_vulnerabilities(self, findings: list, top_n: int = 10) -> list:
        """Get top N vulnerabilities by severity score."""
        sorted_findings = sorted(findings, key=lambda x: x.get('severity_score', 0), reverse=True)
        top = []
        for finding in sorted_findings[:top_n]:
            top.append({
                'rule_id': finding.get('rule_id'),
                'description': finding.get('description'),
                'severity': finding.get('severity'),
                'severity_score': finding.get('severity_score', 0),
                'file_path': finding.get('file_path'),
                'line_number': finding.get('line_number'),
                'owasp_category': finding.get('owasp_category')
            })
        return top

