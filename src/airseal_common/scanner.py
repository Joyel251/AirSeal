"""
AirSeal File Scanner

Integrates with antivirus engines to scan files:
- Windows Defender (built-in)
- ClamAV (optional)
- Demo scanner (for testing)
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class ScanResult:
    """Result of a file scan."""
    status: str  # "CLEAN", "INFECTED", "ERROR", "UNKNOWN"
    engine: str
    details: str
    threats_found: list[str]
    scan_time: float
    
    def is_clean(self) -> bool:
        """Check if file is clean."""
        return self.status.upper() == "CLEAN"


class FileScanner:
    """Base class for file scanners."""
    
    def scan(self, file_path: Path) -> ScanResult:
        """Scan a file. Must be implemented by subclasses."""
        raise NotImplementedError


class WindowsDefenderScanner(FileScanner):
    """Scanner using Windows Defender."""
    
    def __init__(self):
        """Initialize Windows Defender scanner."""
        self.engine_name = "Windows Defender"
        self._check_available()
    
    def _check_available(self) -> bool:
        """Check if Windows Defender is available."""
        try:
            # Try to run MpCmdRun.exe with -h flag
            result = subprocess.run(
                ["C:\\Program Files\\Windows Defender\\MpCmdRun.exe", "-h"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def scan(self, file_path: Path) -> ScanResult:
        """Scan a file with Windows Defender."""
        start_time = time.time()
        
        try:
            # Run Windows Defender scan
            # MpCmdRun.exe -Scan -ScanType 3 -File "path"
            result = subprocess.run(
                [
                    "C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
                    "-Scan",
                    "-ScanType", "3",  # Custom scan
                    "-File", str(file_path.absolute()),
                ],
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )
            
            scan_time = time.time() - start_time
            
            # Parse result
            # Return code 0 = no threats found
            # Return code 2 = threats found
            if result.returncode == 0:
                return ScanResult(
                    status="CLEAN",
                    engine=self.engine_name,
                    details="No threats detected",
                    threats_found=[],
                    scan_time=scan_time,
                )
            elif result.returncode == 2:
                # Extract threat names from output
                threats = self._parse_threats(result.stdout)
                return ScanResult(
                    status="INFECTED",
                    engine=self.engine_name,
                    details=f"Threats detected: {', '.join(threats)}",
                    threats_found=threats,
                    scan_time=scan_time,
                )
            else:
                return ScanResult(
                    status="ERROR",
                    engine=self.engine_name,
                    details=f"Scan error (code {result.returncode}): {result.stderr}",
                    threats_found=[],
                    scan_time=scan_time,
                )
        
        except subprocess.TimeoutExpired:
            return ScanResult(
                status="ERROR",
                engine=self.engine_name,
                details="Scan timeout (>5 minutes)",
                threats_found=[],
                scan_time=300.0,
            )
        except FileNotFoundError:
            return ScanResult(
                status="ERROR",
                engine=self.engine_name,
                details="Windows Defender not found. Ensure Windows Defender is installed.",
                threats_found=[],
                scan_time=0.0,
            )
        except Exception as e:
            return ScanResult(
                status="ERROR",
                engine=self.engine_name,
                details=f"Scan error: {str(e)}",
                threats_found=[],
                scan_time=time.time() - start_time,
            )
    
    def _parse_threats(self, output: str) -> list[str]:
        """Parse threat names from Windows Defender output."""
        threats = []
        for line in output.split('\n'):
            if "Threat" in line or "threat" in line:
                # Extract threat name (simple parsing)
                parts = line.split(':')
                if len(parts) > 1:
                    threat_name = parts[1].strip()
                    if threat_name:
                        threats.append(threat_name)
        return threats


class ClamAVScanner(FileScanner):
    """Scanner using ClamAV (if installed)."""
    
    def __init__(self, clamscan_path: str = "clamscan"):
        """Initialize ClamAV scanner."""
        self.engine_name = "ClamAV"
        self.clamscan_path = clamscan_path
    
    def scan(self, file_path: Path) -> ScanResult:
        """Scan a file with ClamAV."""
        start_time = time.time()
        
        try:
            result = subprocess.run(
                [self.clamscan_path, str(file_path.absolute())],
                capture_output=True,
                text=True,
                timeout=300,
            )
            
            scan_time = time.time() - start_time
            
            # ClamAV exit codes:
            # 0 = no virus found
            # 1 = virus found
            # 2+ = error
            
            if result.returncode == 0:
                return ScanResult(
                    status="CLEAN",
                    engine=self.engine_name,
                    details="No threats detected",
                    threats_found=[],
                    scan_time=scan_time,
                )
            elif result.returncode == 1:
                threats = self._parse_threats(result.stdout)
                return ScanResult(
                    status="INFECTED",
                    engine=self.engine_name,
                    details=f"Threats detected: {', '.join(threats)}",
                    threats_found=threats,
                    scan_time=scan_time,
                )
            else:
                return ScanResult(
                    status="ERROR",
                    engine=self.engine_name,
                    details=f"Scan error: {result.stderr}",
                    threats_found=[],
                    scan_time=scan_time,
                )
        
        except FileNotFoundError:
            return ScanResult(
                status="ERROR",
                engine=self.engine_name,
                details="ClamAV not found. Install ClamAV or use Windows Defender.",
                threats_found=[],
                scan_time=0.0,
            )
        except Exception as e:
            return ScanResult(
                status="ERROR",
                engine=self.engine_name,
                details=f"Scan error: {str(e)}",
                threats_found=[],
                scan_time=time.time() - start_time,
            )
    
    def _parse_threats(self, output: str) -> list[str]:
        """Parse threat names from ClamAV output."""
        threats = []
        for line in output.split('\n'):
            if "FOUND" in line:
                # Format: filename: ThreatName FOUND
                parts = line.split(':')
                if len(parts) >= 2:
                    threat_part = parts[-1].replace("FOUND", "").strip()
                    if threat_part:
                        threats.append(threat_part)
        return threats


class DemoScanner(FileScanner):
    """Demo scanner for testing (always returns CLEAN)."""
    
    def __init__(self):
        """Initialize demo scanner."""
        self.engine_name = "Demo Scanner"
    
    def scan(self, file_path: Path) -> ScanResult:
        """
        Demo scan - simulates scanning with a delay.
        
        For testing, you can create files with specific names to simulate threats:
        - Files containing "virus" or "malware" in name → INFECTED
        - Files containing "error" in name → ERROR
        - All others → CLEAN
        """
        import time
        start_time = time.time()
        
        # Simulate scan time
        time.sleep(0.5)
        
        filename_lower = file_path.name.lower()
        
        if "virus" in filename_lower or "malware" in filename_lower:
            return ScanResult(
                status="INFECTED",
                engine=self.engine_name,
                details="Demo threat detected",
                threats_found=["Demo.TestVirus"],
                scan_time=time.time() - start_time,
            )
        elif "error" in filename_lower:
            return ScanResult(
                status="ERROR",
                engine=self.engine_name,
                details="Demo scan error",
                threats_found=[],
                scan_time=time.time() - start_time,
            )
        else:
            return ScanResult(
                status="CLEAN",
                engine=self.engine_name,
                details="No threats detected (demo)",
                threats_found=[],
                scan_time=time.time() - start_time,
            )


class ScannerFactory:
    """Factory for creating file scanners."""
    
    @staticmethod
    def get_scanner(engine: str = "auto") -> FileScanner:
        """
        Get a file scanner.
        
        Args:
            engine: "auto", "defender", "clamav", or "demo"
        
        Returns:
            FileScanner instance
        """
        if engine == "demo":
            return DemoScanner()
        elif engine == "defender":
            return WindowsDefenderScanner()
        elif engine == "clamav":
            return ClamAVScanner()
        elif engine == "auto":
            # Try Windows Defender first
            try:
                scanner = WindowsDefenderScanner()
                if scanner._check_available():
                    return scanner
            except Exception:
                pass
            
            # Fall back to demo scanner
            return DemoScanner()
        else:
            raise ValueError(f"Unknown scanner engine: {engine}")
    
    @staticmethod
    def list_available() -> list[str]:
        """List available scanner engines."""
        available = ["demo"]
        
        # Check Windows Defender
        try:
            scanner = WindowsDefenderScanner()
            if scanner._check_available():
                available.append("defender")
        except Exception:
            pass
        
        # Check ClamAV
        try:
            scanner = ClamAVScanner()
            test_result = subprocess.run(
                ["clamscan", "--version"],
                capture_output=True,
                timeout=5,
            )
            if test_result.returncode == 0:
                available.append("clamav")
        except Exception:
            pass
        
        return available
