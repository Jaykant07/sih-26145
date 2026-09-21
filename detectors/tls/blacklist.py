"""
Static Offline JA3/JA3S Blacklist Lookup Layer for PS-26145.

Loads local curated suspicious TLS fingerprint snapshots and performs
deterministic, zero-network lookups. No outbound or live threat-intel queries
are ever made at runtime.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("tls_blacklist")

DEFAULT_BLACKLIST_PATH = Path("data/intel/ja3_blacklist.json")
MD5_HEX_REGEX = re.compile(r"^[0-9a-fA-F]{32}$")


class JA3Blacklist:
    """
    Offline JA3 and JA3S fingerprint repository.
    Validates MD5 syntax, indexes fingerprints, and provides fast local matching.
    """

    def __init__(self, blacklist_path: Optional[str | Path] = None) -> None:
        self.blacklist_path = Path(blacklist_path or DEFAULT_BLACKLIST_PATH)
        self.metadata: dict[str, Any] = {}
        self._ja3_db: dict[str, dict[str, Any]] = {}
        self._ja3s_db: dict[str, dict[str, Any]] = {}
        self.load()

    def load(self) -> None:
        """Load and validate the static blacklist snapshot from disk."""
        if not self.blacklist_path.exists():
            logger.warning(
                "JA3 blacklist file not found at %s. Operating with empty snapshot.",
                self.blacklist_path,
            )
            return

        try:
            with open(self.blacklist_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.error("Failed to read JA3 blacklist JSON from %s: %s", self.blacklist_path, e)
            return

        self.metadata = data.get("snapshot_metadata", {})

        # Ingest JA3 entries
        raw_ja3 = data.get("ja3", {})
        self._ja3_db.clear()
        for h, info in raw_ja3.items():
            h_clean = str(h).strip().lower()
            if self._is_valid_hash(h_clean):
                self._ja3_db[h_clean] = info if isinstance(info, dict) else {"info": str(info)}
            else:
                logger.warning("Skipping invalid JA3 hash format in snapshot: %s", h)

        # Ingest JA3S entries
        raw_ja3s = data.get("ja3s", {})
        self._ja3s_db.clear()
        for h, info in raw_ja3s.items():
            h_clean = str(h).strip().lower()
            if self._is_valid_hash(h_clean):
                self._ja3s_db[h_clean] = info if isinstance(info, dict) else {"info": str(info)}
            else:
                logger.warning("Skipping invalid JA3S hash format in snapshot: %s", h)

        logger.info(
            "Loaded offline JA3 blacklist (%d JA3, %d JA3S fingerprints, version: %s)",
            len(self._ja3_db),
            len(self._ja3s_db),
            self.metadata.get("version", "unknown"),
        )

    @staticmethod
    def _is_valid_hash(h: str) -> bool:
        """Validate that a string is exactly a 32-character hexadecimal MD5 hash."""
        return bool(MD5_HEX_REGEX.match(h))

    def lookup_ja3(self, ja3_hash: Optional[str]) -> Optional[dict[str, Any]]:
        """Look up client JA3 fingerprint. Returns threat metadata if matched, else None."""
        if not ja3_hash or not isinstance(ja3_hash, str):
            return None
        h = ja3_hash.strip().lower()
        if not self._is_valid_hash(h):
            return None
        return self._ja3_db.get(h)

    def lookup_ja3s(self, ja3s_hash: Optional[str]) -> Optional[dict[str, Any]]:
        """Look up server JA3S fingerprint. Returns threat metadata if matched, else None."""
        if not ja3s_hash or not isinstance(ja3s_hash, str):
            return None
        h = ja3s_hash.strip().lower()
        if not self._is_valid_hash(h):
            return None
        return self._ja3s_db.get(h)

    def match(
        self,
        ja3_hash: Optional[str],
        ja3s_hash: Optional[str],
    ) -> tuple[bool, bool, Optional[dict[str, Any]], Optional[dict[str, Any]]]:
        """
        Check both client JA3 and server JA3S against the static snapshot.

        Returns:
            (ja3_match, ja3s_match, ja3_info, ja3s_info)
        """
        info_ja3 = self.lookup_ja3(ja3_hash)
        info_ja3s = self.lookup_ja3s(ja3s_hash)
        return (info_ja3 is not None, info_ja3s is not None, info_ja3, info_ja3s)

    @property
    def ja3_count(self) -> int:
        return len(self._ja3_db)

    @property
    def ja3s_count(self) -> int:
        return len(self._ja3s_db)
