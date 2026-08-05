"""Abstract base class for all detectors."""

from __future__ import annotations
from abc import ABC, abstractmethod
from pathlib import Path
from ..models import CryptoFinding


class BaseDetector(ABC):
    """
    A detector reads one file and returns zero or more CryptoFindings.

    Subclass contract:
      - supported_extensions: set of lowercase extensions this detector handles
        (e.g. {".py", ".pyw"}).  Empty set = accepts every file.
      - detect(path) → list[CryptoFinding]
    """

    supported_extensions: set[str] = set()

    def can_handle(self, path: Path) -> bool:
        if not self.supported_extensions:
            return True
        return path.suffix.lower() in self.supported_extensions

    @abstractmethod
    def detect(self, path: Path) -> list[CryptoFinding]:
        ...
