"""
FANCI-Inspired DGA Domain Feature Extractor for PS-26145.

Research Attribution:
    Inspired by:
    Schüppen, Teubert, Herrmann, Meyer,
    "FANCI: Feature-based Automated NXDomain Classification and Intelligence",
    27th USENIX Security Symposium, 2018.

    PS-26145 implements an independent FANCI-inspired DGA classifier using
    a Random Forest and a selected subset of published domain-name features.
    It does not use FANCI source code or FANCI's original dataset.

Feature Vector:
    1. domain_length: Length of candidate generated label.
    2. shannon_entropy: Shannon entropy over label characters.
    3. digit_ratio: Ratio of digits to label length.
    4. vowel_to_consonant_ratio: Ratio of vowels to consonants (with safe zero-handling).
    5. longest_meaningful_substring: Ratio of longest English word substring to length.
    6. ngram_frequency_distance: Mean negative log-likelihood of bigrams against benign reference.
"""

from __future__ import annotations

import json
import math
from collections import Counter
from pathlib import Path
from typing import Any, Optional

FEATURE_NAMES: list[str] = [
    "domain_length",
    "shannon_entropy",
    "digit_ratio",
    "vowel_to_consonant_ratio",
    "longest_meaningful_substring",
    "ngram_frequency_distance",
]

VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")

# Default paths
DEFAULT_WORDLIST_PATH = Path("artifacts/dga/datasets/wordlist.txt")
DEFAULT_NGRAM_PATH = Path("artifacts/dga/models/ngram_reference.json")


def extract_candidate_label(domain: str) -> str:
    """
    Extract the candidate generated label from a domain query string.

    Convention:
        - Strips trailing dots and whitespace.
        - Converts to lowercase.
        - For FQDNs with multiple labels (e.g., 'randomlabel.lab.local' or 'sub.example.com'),
          extracts the leftmost label ('randomlabel' or 'sub').
        - For 2-level domains (e.g., 'example.com'), extracts the second-level domain ('example').
        - For single labels without dots, returns the label directly.

    This ensures identical preprocessing across training, validation, and inference.
    """
    if not isinstance(domain, str):
        return ""
    clean = domain.strip().rstrip(".").lower()
    if not clean:
        return ""
    parts = clean.split(".")
    # Leftmost label represents candidate generated portion in synthetic and standard DGA
    return parts[0] if parts else clean


def compute_domain_length(label: str) -> float:
    """Feature 1: Length of candidate domain label."""
    return float(len(label))


def compute_shannon_entropy(label: str) -> float:
    """
    Feature 2: Shannon entropy over character distribution.

    H(X) = - sum(p * log2(p))
    Handles empty string and 1-character strings safely by returning 0.0.
    """
    if len(label) <= 1:
        return 0.0
    counts = Counter(label)
    n = len(label)
    entropy = 0.0
    for count in counts.values():
        p = count / n
        if p > 0.0:
            entropy -= p * math.log2(p)
    return round(entropy, 6)


def compute_digit_ratio(label: str) -> float:
    """
    Feature 3: Number of digits / label length.

    Handles zero-length input safely by returning 0.0.
    """
    if not label:
        return 0.0
    digits = sum(1 for c in label if c.isdigit())
    return round(digits / len(label), 6)


def compute_vowel_to_consonant_ratio(label: str) -> float:
    """
    Feature 4: Ratio of vowels to consonants.

    Documented behavior:
      - If consonants > 0: return vowels / consonants.
      - If consonants == 0 and vowels > 0: return float(vowels) (avoids division by zero).
      - If consonants == 0 and vowels == 0: return 0.0.
    """
    if not label:
        return 0.0
    num_vowels = sum(1 for c in label if c in VOWELS)
    num_consonants = sum(1 for c in label if c in CONSONANTS)

    if num_consonants > 0:
        return round(num_vowels / num_consonants, 6)
    if num_vowels > 0:
        return float(num_vowels)
    return 0.0


class DGAFeatureExtractor:
    """
    Stateful feature extractor that manages wordlist lookups and
    persisted n-gram reference models.
    """

    def __init__(
        self,
        wordlist_path: Optional[str | Path] = None,
        ngram_path: Optional[str | Path] = None,
    ) -> None:
        self.wordlist_path = Path(wordlist_path or DEFAULT_WORDLIST_PATH)
        self.ngram_path = Path(ngram_path or DEFAULT_NGRAM_PATH)
        self._words: set[str] = set()
        self._ngram_data: dict[str, Any] = {}
        self._default_log_prob: float = -4.5
        self._load_resources()

    def _load_resources(self) -> None:
        # Load English wordlist
        if self.wordlist_path.exists():
            try:
                with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                    self._words = {line.strip().lower() for line in f if len(line.strip()) >= 3}
            except OSError:
                self._words = set()

        # Fallback minimal wordlist if file unavailable
        if not self._words:
            self._words = {
                "google", "service", "system", "network", "server", "cloud", "portal",
                "secure", "online", "connect", "access", "apple", "amazon", "microsoft",
                "direct", "office", "market", "media", "stream", "packet", "engine"
            }

        # Load N-Gram reference model
        if self.ngram_path.exists():
            try:
                with open(self.ngram_path, "r", encoding="utf-8") as f:
                    self._ngram_data = json.load(f)
                    self._default_log_prob = float(self._ngram_data.get("default_log10_prob", -4.5))
            except (OSError, json.JSONDecodeError):
                self._ngram_data = {}

    compute_domain_length = staticmethod(compute_domain_length)
    compute_shannon_entropy = staticmethod(compute_shannon_entropy)
    compute_digit_ratio = staticmethod(compute_digit_ratio)
    compute_vowel_to_consonant_ratio = staticmethod(compute_vowel_to_consonant_ratio)

    def compute_longest_meaningful_substring(self, label: str) -> float:
        """
        Feature 5: Ratio of longest English word substring (min length 3) to label length.

        Returns 0.0 if label length is 0 or no dictionary substring is found.
        """
        if not label:
            return 0.0
        n = len(label)
        longest = 0
        # Check all substrings of length >= 3
        for length in range(n, 2, -1):
            if longest >= length:
                break
            for start in range(n - length + 1):
                sub = label[start:start + length]
                if sub in self._words:
                    longest = length
                    break
        return round(longest / n, 6)

    def compute_ngram_frequency_distance(self, label: str) -> float:
        """
        Feature 6: Cross-entropy / mean negative log-likelihood of character bigrams.

        For label c_1 c_2 ... c_k, computes:
            - 1/(k-1) * sum(log10(P(c_i c_{i+1})))
        Higher score indicates anomalous, unnatural character transitions typical of DGAs.
        Handles labels with length <= 1 by returning 0.0.
        """
        clean = "".join(c for c in label if c.isalnum() or c in "-_")
        if len(clean) <= 1:
            return 0.0

        bigram_probs = self._ngram_data.get("bigrams", {})
        total_neg_log = 0.0
        bigram_count = len(clean) - 1

        for i in range(bigram_count):
            bg = clean[i:i + 2]
            log_prob = bigram_probs.get(bg, self._default_log_prob)
            total_neg_log -= log_prob

        return round(total_neg_log / bigram_count, 6)

    def extract_features(self, domain: str) -> dict[str, float]:
        """
        Extract all 6 FANCI-inspired features for a domain.

        Returns:
            Dictionary mapping feature names to numerical values.
        """
        label = extract_candidate_label(domain)
        return {
            "domain_length": compute_domain_length(label),
            "shannon_entropy": compute_shannon_entropy(label),
            "digit_ratio": compute_digit_ratio(label),
            "vowel_to_consonant_ratio": compute_vowel_to_consonant_ratio(label),
            "longest_meaningful_substring": self.compute_longest_meaningful_substring(label),
            "ngram_frequency_distance": self.compute_ngram_frequency_distance(label),
        }

    def extract_vector(self, domain: str) -> list[float]:
        """
        Extract feature vector in strict deterministic FEATURE_NAMES order.

        Returns:
            List of 6 float values.
        """
        feats = self.extract_features(domain)
        return [feats[name] for name in FEATURE_NAMES]


# Global singleton instance for easy import
_global_extractor: Optional[DGAFeatureExtractor] = None


def get_feature_extractor() -> DGAFeatureExtractor:
    global _global_extractor
    if _global_extractor is None:
        _global_extractor = DGAFeatureExtractor()
    return _global_extractor


def extract_features(domain: str) -> dict[str, float]:
    """Convenience functional interface for feature extraction."""
    return get_feature_extractor().extract_features(domain)


def extract_feature_vector(domain: str) -> list[float]:
    """Convenience functional interface for feature vector."""
    return get_feature_extractor().extract_vector(domain)
