"""
DNS Query Feature Extraction Layer for PS-26145.

Per-query DNS feature extraction. Computes lexical, information-theoretic,
and n-gram frequency distance features against a pre-built local reference
model. Operates without external lookups or payload inspection.

Re-exports core algorithms from detectors/dga/features.py to maintain 100%
backward compatibility while providing a unified per-query DNS feature API.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from detectors.dga.features import (
    CONSONANTS,
    DEFAULT_NGRAM_PATH,
    DEFAULT_WORDLIST_PATH,
    DGAFeatureExtractor,
    FEATURE_NAMES,
    VOWELS,
    compute_digit_ratio,
    compute_domain_length,
    compute_shannon_entropy,
    compute_vowel_to_consonant_ratio,
    extract_candidate_label,
    extract_feature_vector,
    extract_features,
    get_feature_extractor,
)

logger = logging.getLogger("dns_features")


def normalize_domain_name(domain: str) -> str:
    """
    Deterministically preprocess and normalize a DNS query name.

    Normalization steps:
      1. Converts to string, strips surrounding whitespace.
      2. Removes trailing dot(s) (e.g. 'example.com.' -> 'example.com').
      3. Converts to lowercase.
      4. Returns empty string for empty strings or root query ('.').
    """
    if not isinstance(domain, str):
        return ""
    clean = domain.strip().rstrip(".").lower()
    return clean


@dataclass(frozen=True)
class DNSFeatureRecord:
    """
    Per-query DNS feature record. Emitted for individual DNS query names.
    Does not perform detection, classification, or thresholding.
    """

    query_name: str
    normalized_name: str
    candidate_label: str
    domain_length: float
    shannon_entropy: float
    digit_ratio: float
    vowel_to_consonant_ratio: float
    longest_meaningful_substring: float
    ngram_frequency_distance: float

    def to_dict(self) -> dict[str, Any]:
        """Convert DNS feature record to dictionary."""
        return {
            "query_name": self.query_name,
            "normalized_name": self.normalized_name,
            "candidate_label": self.candidate_label,
            "domain_length": self.domain_length,
            "shannon_entropy": self.shannon_entropy,
            "digit_ratio": self.digit_ratio,
            "vowel_to_consonant_ratio": self.vowel_to_consonant_ratio,
            "longest_meaningful_substring": self.longest_meaningful_substring,
            "ngram_frequency_distance": self.ngram_frequency_distance,
        }


def extract_dns_query_features(
    query_name: str,
    extractor: Optional[DGAFeatureExtractor] = None,
    wordlist_path: Optional[str | Path] = None,
    ngram_path: Optional[str | Path] = None,
) -> DNSFeatureRecord:
    """
    Extract per-query DNS features from a domain string.

    Args:
        query_name: The raw DNS query name from Zeek dns.log.
        extractor: Optional cached DGAFeatureExtractor instance.
        wordlist_path: Optional path to English wordlist for substring lookup.
        ngram_path: Optional path to local pre-built ngram_reference.json.

    Returns:
        DNSFeatureRecord containing all 6 required lexical and statistical features.
    """
    normalized = normalize_domain_name(query_name)
    label = extract_candidate_label(query_name)

    if extractor is not None:
        ext = extractor
    elif wordlist_path is not None or ngram_path is not None:
        ext = DGAFeatureExtractor(wordlist_path=wordlist_path, ngram_reference_path=ngram_path)
    else:
        ext = get_feature_extractor()

    feat_dict = ext.extract_features(query_name)

    return DNSFeatureRecord(
        query_name=str(query_name),
        normalized_name=normalized,
        candidate_label=label,
        domain_length=feat_dict["domain_length"],
        shannon_entropy=feat_dict["shannon_entropy"],
        digit_ratio=feat_dict["digit_ratio"],
        vowel_to_consonant_ratio=feat_dict["vowel_to_consonant_ratio"],
        longest_meaningful_substring=feat_dict["longest_meaningful_substring"],
        ngram_frequency_distance=feat_dict["ngram_frequency_distance"],
    )


__all__ = [
    # Feature constants & names
    "FEATURE_NAMES",
    "VOWELS",
    "CONSONANTS",
    "DEFAULT_WORDLIST_PATH",
    "DEFAULT_NGRAM_PATH",
    # Normalization & record
    "normalize_domain_name",
    "DNSFeatureRecord",
    "extract_dns_query_features",
    # Underlying extractors & functions
    "extract_candidate_label",
    "compute_domain_length",
    "compute_shannon_entropy",
    "compute_digit_ratio",
    "compute_vowel_to_consonant_ratio",
    "extract_features",
    "extract_feature_vector",
    "DGAFeatureExtractor",
    "get_feature_extractor",
]
