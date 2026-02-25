"""
FastAPI web interface for Mini-ZAP.
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Dict, Any
import time
import os
import uuid
from crawler import WebCrawler
from scanners.sql_injection import SQLInjectionScanner
from scanners.xss import XSSScanner
from scanners.access_control import AccessControlScanner
from scanners.misconfiguration import MisconfigurationScanner
from scanners.ssrf import SSRFScanner
from reports.json_report import JSONReportGenerator
from reports.pdf_report import PDFReportGenerator
from utils.vulnerability import Vulnerability, RiskLevel, OWASPCategory


app = FastAPI(title="Mini-ZAP API", description="OWASP Top 10 Automated Vulnerability Scanner")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for scan results (use database in production)
scan_results: Dict[str, Dict[str, Any]] = {}


class ScanRequest(BaseModel):
    """Scan request model."""
    url: str
    depth: int = 2
    delay: float = 0.5
    scanners: List[str] = ["sql", "xss", "access", "misconfig", "ssrf"]


class ScanResponse(BaseModel):
    """Scan response model."""
    scan_id: str
    status: str
    message: str


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "Mini-ZAP API",
        "version": "1.0.0",
        "description": "OWASP Top 10 Automated Vulnerability Scanner"
    }


@app.post("/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start a vulnerability scan.
    
    Args:
        request: Scan configuration
        background_tasks: FastAPI background tasks
    
    Returns:
        Scan ID and status
    """
    scan_id = str(uuid.uuid4())
    
    # Validate URL
    if not request.url.startswith(('http://', 'https://')):
        request.url = 'https://' + request.url
    
    # Initialize scan result
    scan_results[scan_id] = {
        "status": "running",
        "url": request.url,
        "vulnerabilities": [],
        "scan_info": {},
        "start_time": time.time()
    }
    
    # Run scan in background
    background_tasks.add_task(
        run_scan_task,
        scan_id,
        request.url,
        request.depth,
        request.delay,
        request.scanners
    )
    
    return ScanResponse(
        scan_id=scan_id,
        status="running",
        message="Scan started successfully"
    )


def run_scan_task(scan_id: str, url: str, depth: int, delay: float, scanners: List[str]):
    """Run the vulnerability scan task."""
    try:
        all_vulnerabilities = []
        
        # Crawl
        crawler = WebCrawler(url, max_depth=depth, delay=delay)
        crawl_result = crawler.crawl()
        
        # Run scanners
        scanners_to_run = []
        if "sql" in scanners:
            scanners_to_run.append(('SQL Injection', SQLInjectionScanner(delay=delay)))
        if "xss" in scanners:
            scanners_to_run.append(('XSS', XSSScanner(delay=delay)))
        if "access" in scanners:
            scanners_to_run.append(('Access Control', AccessControlScanner(delay=delay)))
        if "misconfig" in scanners:
            scanners_to_run.append(('Misconfiguration', MisconfigurationScanner(delay=delay)))
        if "ssrf" in scanners:
            scanners_to_run.append(('SSRF', SSRFScanner(delay=delay)))
        
        for scanner_name, scanner in scanners_to_run:
            if scanner_name == 'Access Control':
                vulns = scanner.scan(crawl_result['endpoints'], crawl_result['base_url'])
            elif scanner_name == 'Misconfiguration':
                vulns = scanner.scan(crawl_result['endpoints'])
            else:
                vulns = scanner.scan(crawl_result['input_points'])
            
            all_vulnerabilities.extend(vulns)
        
        scan_duration = time.time() - scan_results[scan_id]["start_time"]
        
        # Update scan results
        scan_results[scan_id]["status"] = "completed"
        scan_results[scan_id]["vulnerabilities"] = [v.to_dict() for v in all_vulnerabilities]
        scan_results[scan_id]["scan_info"] = {
            "target_url": url,
            "duration": scan_duration,
            "total_vulnerabilities": len(all_vulnerabilities)
        }
        
    except Exception as e:
        scan_results[scan_id]["status"] = "error"
        scan_results[scan_id]["error"] = str(e)


@app.get("/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """
    Get scan status and results.
    
    Args:
        scan_id: Scan ID
    
    Returns:
        Scan status and results
    """
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    result = scan_results[scan_id]
    
    if result["status"] == "completed":
        return {
            "status": "completed",
            "scan_info": result["scan_info"],
            "vulnerabilities": result["vulnerabilities"],
            "summary": {
                "total": len(result["vulnerabilities"]),
                "critical": len([v for v in result["vulnerabilities"] if v["risk_level"] == "Critical"]),
                "high": len([v for v in result["vulnerabilities"] if v["risk_level"] == "High"]),
                "medium": len([v for v in result["vulnerabilities"] if v["risk_level"] == "Medium"]),
                "low": len([v for v in result["vulnerabilities"] if v["risk_level"] == "Low"]),
                "info": len([v for v in result["vulnerabilities"] if v["risk_level"] == "Informational"]),
            }
        }
    elif result["status"] == "error":
        return {
            "status": "error",
            "error": result.get("error", "Unknown error")
        }
    else:
        return {
            "status": "running",
            "message": "Scan in progress"
        }


@app.get("/scan/{scan_id}/report/json")
async def get_json_report(scan_id: str):
    """
    Get JSON report for a scan.
    
    Args:
        scan_id: Scan ID
    
    Returns:
        JSON report file
    """
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    result = scan_results[scan_id]
    
    if result["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed yet")
    
    # Generate JSON report
    report_path = f"report_{scan_id}.json"
    json_gen = JSONReportGenerator()
    
    # Reconstruct Vulnerability objects from dictionaries
    vulns = []
    for v_dict in result["vulnerabilities"]:
        v_dict_copy = v_dict.copy()
        v_dict_copy["category"] = OWASPCategory(v_dict["category"])
        v_dict_copy["risk_level"] = RiskLevel(v_dict["risk_level"])
        vulns.append(Vulnerability(**v_dict_copy))
    
    json_gen.generate(vulns, result["scan_info"], report_path)
    
    return FileResponse(
        report_path,
        media_type="application/json",
        filename=f"report_{scan_id}.json"
    )


@app.get("/scan/{scan_id}/report/pdf")
async def get_pdf_report(scan_id: str):
    """
    Get PDF report for a scan.
    
    Args:
        scan_id: Scan ID
    
    Returns:
        PDF report file
    """
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    result = scan_results[scan_id]
    
    if result["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed yet")
    
    # Generate PDF report
    report_path = f"report_{scan_id}.pdf"
    pdf_gen = PDFReportGenerator()
    
    # Reconstruct Vulnerability objects from dictionaries
    vulns = []
    for v_dict in result["vulnerabilities"]:
        v_dict_copy = v_dict.copy()
        v_dict_copy["category"] = OWASPCategory(v_dict["category"])
        v_dict_copy["risk_level"] = RiskLevel(v_dict["risk_level"])
        vulns.append(Vulnerability(**v_dict_copy))
    
    pdf_gen.generate(vulns, result["scan_info"], report_path)
    
    return FileResponse(
        report_path,
        media_type="application/pdf",
        filename=f"report_{scan_id}.pdf"
    )


@app.get("/scans")
async def list_scans():
    """List all scans."""
    return {
        "scans": [
            {
                "scan_id": scan_id,
                "url": result["url"],
                "status": result["status"],
                "vulnerability_count": len(result.get("vulnerabilities", []))
            }
            for scan_id, result in scan_results.items()
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

