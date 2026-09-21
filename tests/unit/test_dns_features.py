"""
Unit tests for features.dns_features — shared per-query DNS feature extraction.
"""

import math
import pytest

from features.dns_features import (
    DNSFeatureRecord,
    compute_digit_ratio,
    compute_domain_length,
    compute_shannon_entropy,
    compute_vowel_to_consonant_ratio,
    extract_candidate_label,
    extract_dns_query_features,
    normalize_domain_name,
)


class TestDNSNormalization:
    def test_normalize_trailing_dot(self):
        assert normalize_domain_name("example.com.") == "example.com"
        assert normalize_domain_name("sub.domain.org...") == "sub.domain.org"

    def test_normalize_case_and_whitespace(self):
        assert normalize_domain_name("   EXAMPLE.Local.   ") == "example.local"

    def test_normalize_empty_and_root(self):
        assert normalize_domain_name("") == ""
        assert normalize_domain_name(".") == ""
        assert normalize_domain_name(None) == ""


class TestHandComputedDNSFeatures:
    def test_hand_computed_domain_length(self):
        assert compute_domain_length("google") == 6.0
        assert compute_domain_length("") == 0.0
        assert compute_domain_length("a") == 1.0

    def test_hand_computed_shannon_entropy(self):
        # Monotonous characters -> 0 bits
        assert compute_shannon_entropy("aaaa") == 0.0
        assert compute_shannon_entropy("") == 0.0
        assert compute_shannon_entropy("x") == 0.0

        # Two distinct characters equally distributed: p(a)=0.5, p(b)=0.5 -> 1.0 bit
        assert compute_shannon_entropy("ab") == pytest.approx(1.0)
        assert compute_shannon_entropy("abab") == pytest.approx(1.0)

        # Hand computed: "abc" -> 3 equal chars -> log2(3) = 1.5849625 bits
        assert compute_shannon_entropy("abc") == pytest.approx(math.log2(3), abs=1e-4)

    def test_hand_computed_digit_ratio(self):
        assert compute_digit_ratio("abc123") == pytest.approx(0.5)
        assert compute_digit_ratio("12345") == pytest.approx(1.0)
        assert compute_digit_ratio("nodigits") == pytest.approx(0.0)
        assert compute_digit_ratio("") == 0.0

    def test_hand_computed_vowel_to_consonant_ratio(self):
        # "cat" -> vowels: 'a' (1), consonants: 'c', 't' (2) -> 1/2 = 0.5
        assert compute_vowel_to_consonant_ratio("cat") == pytest.approx(0.5)

        # "rhythm" -> 0 vowels, 6 consonants -> 0 / 6 = 0.0
        assert compute_vowel_to_consonant_ratio("rhythm") == pytest.approx(0.0)

        # "aeiou" -> 5 vowels, 0 consonants -> safe zero handling: 5 / max(0, 1) = 5.0
        assert compute_vowel_to_consonant_ratio("aeiou") == pytest.approx(5.0)

        # Punctuation/digits do not count as consonants or vowels
        # "a-1-b" -> 1 vowel ('a'), 1 consonant ('b') -> 1/1 = 1.0
        assert compute_vowel_to_consonant_ratio("a-1-b") == pytest.approx(1.0)


class TestDNSQueryFeatureExtraction:
    def test_per_query_feature_record(self):
        query = "vn0xg58vzlubb.lab.local."
        record = extract_dns_query_features(query)

        assert isinstance(record, DNSFeatureRecord)
        assert record.query_name == query
        assert record.normalized_name == "vn0xg58vzlubb.lab.local"
        assert record.candidate_label == "vn0xg58vzlubb"
        assert record.domain_length == 13.0
        assert record.digit_ratio == pytest.approx(3 / 13, abs=1e-5)
        assert record.shannon_entropy > 3.0
        assert record.ngram_frequency_distance > 0.0

        d = record.to_dict()
        assert d["candidate_label"] == "vn0xg58vzlubb"
        assert d["domain_length"] == 13.0
        assert "ngram_frequency_distance" in d

    def test_independence_and_no_leakage(self):
        rec1 = extract_dns_query_features("alpha.example.com")
        rec2 = extract_dns_query_features("beta.example.com")
        assert rec1.candidate_label == "alpha"
        assert rec2.candidate_label == "beta"
        assert rec1.candidate_label != rec2.candidate_label
