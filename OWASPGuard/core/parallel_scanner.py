"""
Parallel file scanning for faster analysis.
Uses threads for I/O-bound tasks and processes for CPU-bound tasks.
"""
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Callable
import multiprocessing


class ParallelScanner:
    """
    Parallel file scanning for faster analysis
    
    Uses threads for I/O-bound tasks (file reading)
    Uses processes for CPU-bound tasks (AST parsing, ML inference)
    """
    
    def __init__(self, max_workers: int = None):
        """
        Args:
            max_workers: Number of workers (default: CPU count - 1)
        """
        if max_workers is None:
            max_workers = max(2, multiprocessing.cpu_count() - 1)
        
        self.max_workers = max_workers
    
    def scan_files_parallel(self, file_paths: List[Path], 
                          scan_function: Callable) -> List[Dict]:
        """
        Scan files in parallel using thread pool
        
        Args:
            file_paths: List of files to scan
            scan_function: Function to call for each file (file_path) -> List[Dict]
        
        Returns:
            Aggregated results from all files
        """
        all_findings = []
        
        # Use ThreadPoolExecutor for I/O-bound file operations
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(scan_function, file_path): file_path 
                for file_path in file_paths
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    findings = future.result(timeout=60)  # 60s timeout per file
                    if findings:
                        all_findings.extend(findings)
                except Exception as e:
                    print(f"[!] Error scanning {file_path}: {e}")
        
        return all_findings
    
    def analyze_batch_parallel(self, items: List, 
                              analyze_function: Callable) -> List:
        """
        Analyze items in parallel using process pool
        
        Use for CPU-intensive tasks like ML inference
        
        Args:
            items: List of items to analyze
            analyze_function: Function to call for each item
        
        Returns:
            List of analysis results
        """
        results = []
        
        # Use ProcessPoolExecutor for CPU-bound analysis
        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(analyze_function, item) for item in items]
            
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=30)
                    results.append(result)
                except Exception as e:
                    print(f"[!] Error in parallel analysis: {e}")
        
        return results

