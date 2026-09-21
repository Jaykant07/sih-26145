"""DDoS detector package for PS-26145."""

from detectors.ddos.config import DDoSConfig
from detectors.ddos.detector import DDoSDetector

__all__ = ["DDoSDetector", "DDoSConfig"]
