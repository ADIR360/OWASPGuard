"""
Performance monitoring and metrics for OWASPGuard
"""
import time
import os
from typing import Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

@dataclass
class PerformanceMetrics:
    """Performance metrics for a scan"""
    start_time: float = field(default_factory=time.time)
    end_time: float = 0
    duration: float = 0
    
    files_scanned: int = 0
    lines_scanned: int = 0
    findings_count: int = 0
    
    memory_start_mb: float = 0
    memory_peak_mb: float = 0
    memory_end_mb: float = 0
    
    cpu_percent: float = 0
    
    scanner_times: Dict[str, float] = field(default_factory=dict)
    
    def __post_init__(self):
        if PSUTIL_AVAILABLE:
            try:
                self.memory_start_mb = psutil.Process().memory_info().rss / 1024 / 1024
            except:
                pass


class PerformanceMonitor:
    """
    Monitor and report performance metrics
    
    Features:
    - Execution time tracking
    - Memory usage monitoring
    - CPU usage tracking
    - Per-scanner performance
    - Performance optimization suggestions
    """
    
    def __init__(self):
        self.metrics = PerformanceMetrics()
        if PSUTIL_AVAILABLE:
            try:
                self.process = psutil.Process()
            except:
                self.process = None
        else:
            self.process = None
    
    def start_scan(self):
        """Start monitoring"""
        self.metrics.start_time = time.time()
        if PSUTIL_AVAILABLE and self.process:
            try:
                self.metrics.memory_start_mb = self.process.memory_info().rss / 1024 / 1024
            except:
                pass
    
    def end_scan(self):
        """End monitoring and calculate final metrics"""
        self.metrics.end_time = time.time()
        self.metrics.duration = self.metrics.end_time - self.metrics.start_time
        if PSUTIL_AVAILABLE and self.process:
            try:
                self.metrics.memory_end_mb = self.process.memory_info().rss / 1024 / 1024
                self.metrics.cpu_percent = self.process.cpu_percent()
            except:
                pass
    
    def track_scanner(self, scanner_name: str, duration: float):
        """Track individual scanner performance"""
        self.metrics.scanner_times[scanner_name] = duration
    
    def update_stats(self, files: int = 0, lines: int = 0, findings: int = 0):
        """Update scan statistics"""
        self.metrics.files_scanned += files
        self.metrics.lines_scanned += lines
        self.metrics.findings_count += findings
        
        # Update peak memory
        if PSUTIL_AVAILABLE and self.process:
            try:
                current_mem = self.process.memory_info().rss / 1024 / 1024
                self.metrics.memory_peak_mb = max(self.metrics.memory_peak_mb, current_mem)
            except:
                pass
    
    def get_report(self) -> Dict[str, Any]:
        """Get performance report"""
        return {
            'duration_seconds': round(self.metrics.duration, 2),
            'files_scanned': self.metrics.files_scanned,
            'lines_scanned': self.metrics.lines_scanned,
            'findings': self.metrics.findings_count,
            'files_per_second': round(
                self.metrics.files_scanned / self.metrics.duration 
                if self.metrics.duration > 0 else 0,
                2
            ),
            'memory_usage': {
                'start_mb': round(self.metrics.memory_start_mb, 2),
                'peak_mb': round(self.metrics.memory_peak_mb, 2),
                'end_mb': round(self.metrics.memory_end_mb, 2),
                'increase_mb': round(
                    self.metrics.memory_end_mb - self.metrics.memory_start_mb,
                    2
                )
            },
            'cpu_percent': round(self.metrics.cpu_percent, 2),
            'scanner_performance': {
                name: round(duration, 2)
                for name, duration in self.metrics.scanner_times.items()
            },
            'recommendations': self._get_recommendations()
        }
    
    def _get_recommendations(self) -> List[str]:
        """Get performance optimization recommendations"""
        recommendations = []
        
        # Memory recommendations
        if self.metrics.memory_peak_mb > 500:
            recommendations.append(
                "High memory usage detected. Consider scanning smaller directories "
                "or using incremental scanning."
            )
        
        # Speed recommendations
        if self.metrics.duration > 60 and self.metrics.files_scanned > 100:
            files_per_sec = self.metrics.files_scanned / self.metrics.duration
            if files_per_sec < 5:
                recommendations.append(
                    "Slow scan detected. Enable parallel processing to improve speed."
                )
        
        # Scanner recommendations
        if self.metrics.scanner_times:
            slowest_scanner = max(
                self.metrics.scanner_times.items(),
                key=lambda x: x[1],
                default=(None, 0)
            )
            
            if slowest_scanner[1] > 10:
                recommendations.append(
                    f"Scanner '{slowest_scanner[0]}' is slow. "
                    "Consider optimizing or disabling if not needed."
                )
        
        return recommendations
    
    def print_summary(self):
        """Print performance summary to console"""
        report = self.get_report()
        
        print("\n" + "="*60)
        print("PERFORMANCE SUMMARY")
        print("="*60)
        print(f"Duration: {report['duration_seconds']}s")
        print(f"Files scanned: {report['files_scanned']}")
        print(f"Lines scanned: {report['lines_scanned']:,}")
        print(f"Findings: {report['findings']}")
        print(f"Speed: {report['files_per_second']} files/sec")
        print(f"\nMemory:")
        print(f"  Start: {report['memory_usage']['start_mb']} MB")
        print(f"  Peak: {report['memory_usage']['peak_mb']} MB")
        print(f"  Increase: {report['memory_usage']['increase_mb']} MB")
        print(f"\nCPU: {report['cpu_percent']}%")
        
        if report['scanner_performance']:
            print(f"\nScanner Performance:")
            for scanner, duration in sorted(
                report['scanner_performance'].items(),
                key=lambda x: x[1],
                reverse=True
            ):
                print(f"  {scanner}: {duration}s")
        
        if report['recommendations']:
            print(f"\n💡 Recommendations:")
            for rec in report['recommendations']:
                print(f"  - {rec}")
        
        print("="*60 + "\n")

