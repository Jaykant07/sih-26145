"""Unit tests for DGA feature extraction (FANCI-inspired features)."""

import math
import pytest
from pathlib import Path

from detectors.dga.features import (
    FEATURE_NAMES,
    DEFAULT_WORDLIST_PATH,
    DEFAULT_NGRAM_PATH,
    DGAFeatureExtractor,
    extract_candidate_label,
)


@pytest.fixture
def extractor() -> DGAFeatureExtractor:
    return DGAFeatureExtractor(
        wordlist_path=DEFAULT_WORDLIST_PATH,
        ngram_path=DEFAULT_NGRAM_PATH,
    )


class TestCandidateLabelExtraction:
    def test_extract_candidate_label_fqdn(self):
        # 3+ levels: leftmost label
        assert extract_candidate_label("vn0xg58vzlubb.lab.local") == "vn0xg58vzlubb"
        assert extract_candidate_label("sub.example.com") == "sub"

    def test_extract_candidate_label_2_levels(self):
        # 2 levels: SLD
        assert extract_candidate_label("google.com") == "google"
        assert extract_candidate_label("github.com.") == "github"

    def test_extract_candidate_label_single_or_empty(self):
        assert extract_candidate_label("localhost") == "localhost"
        assert extract_candidate_label("") == ""


class TestIndividualFeatureComputations:
    def test_domain_length(self, extractor: DGAFeatureExtractor):
        assert extractor.compute_domain_length("google") == 6
        assert extractor.compute_domain_length("") == 0
        assert extractor.compute_domain_length("a" * 25) == 25

    def test_shannon_entropy(self, extractor: DGAFeatureExtractor):
        # Monotonous string has zero entropy
        assert extractor.compute_shannon_entropy("aaaaaa") == 0.0
        assert extractor.compute_shannon_entropy("") == 0.0

        # Uniform 2-char string has entropy 1.0 bit
        assert extractor.compute_shannon_entropy("abab") == 1.0

        # Random high-diversity string has higher entropy
        ent_random = extractor.compute_shannon_entropy("abcdefghij")
        ent_words = extractor.compute_shannon_entropy("hellohello")
        assert ent_random > ent_words

    def test_digit_ratio(self, extractor: DGAFeatureExtractor):
        assert extractor.compute_digit_ratio("abc") == 0.0
        assert extractor.compute_digit_ratio("123") == 1.0
        assert extractor.compute_digit_ratio("a1b2") == 0.5
        assert extractor.compute_digit_ratio("") == 0.0

    def test_vowel_to_consonant_ratio(self, extractor: DGAFeatureExtractor):
        # "apple": 2 vowels (a, e), 3 consonants (p, p, l) -> 2 / 3 = 0.666667
        assert extractor.compute_vowel_to_consonant_ratio("apple") == pytest.approx(2 / 3, abs=1e-5)
        # all consonants: 0 / k = 0.0
        assert extractor.compute_vowel_to_consonant_ratio("bcdfgh") == 0.0
        # all vowels: 3 consonants = 0 -> returns float(vowels) = 3.0
        assert extractor.compute_vowel_to_consonant_ratio("aei") == 3.0
        # empty string
        assert extractor.compute_vowel_to_consonant_ratio("") == 0.0

    def test_longest_meaningful_substring(self, extractor: DGAFeatureExtractor):
        # Legitimate domain with dictionary word
        ratio = extractor.compute_longest_meaningful_substring("facebook")
        assert ratio > 0.5

        # Pure random gibberish
        gibberish_ratio = extractor.compute_longest_meaningful_substring("xzqjkwpt")
        assert gibberish_ratio == 0.0

        assert extractor.compute_longest_meaningful_substring("") == 0.0

    def test_ngram_frequency_distance(self, extractor: DGAFeatureExtractor):
        # Common English/domain transitions should have lower negative log-likelihood
        eng_score = extractor.compute_ngram_frequency_distance("facebook")
        # Rare/anomalous transitions should have higher negative log-likelihood
        rare_score = extractor.compute_ngram_frequency_distance("xzqjkwpt")
        assert rare_score > eng_score

        # Short or empty labels
        assert extractor.compute_ngram_frequency_distance("a") == 0.0
        assert extractor.compute_ngram_frequency_distance("") == 0.0


class TestExtractFeaturesVector:
    def test_feature_vector_keys_and_ordering(self, extractor: DGAFeatureExtractor):
        feats = extractor.extract_features("vn0xg58vzlubb.lab.local")
        assert list(feats.keys()) == FEATURE_NAMES
        for k in FEATURE_NAMES:
            assert isinstance(feats[k], (int, float))
            assert not math.isnan(feats[k])
            assert not math.isinf(feats[k])
