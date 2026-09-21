"""Unit tests for DGAModel container, persistence, and thresholding."""

import tempfile
from pathlib import Path
import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from detectors.dga.features import FEATURE_NAMES
from detectors.dga.model import DGAModel, DEFAULT_MODEL_VERSION, DEFAULT_THRESHOLD


@pytest.fixture
def trained_toy_model() -> DGAModel:
    clf = RandomForestClassifier(n_estimators=10, random_state=42)
    # 2 features, 4 samples (2 benign [0], 2 malicious [1])
    X = np.array([
        [5.0, 1.2, 0.0, 0.5, 0.8, 1.5],
        [6.0, 1.4, 0.0, 0.4, 0.9, 1.2],
        [15.0, 3.8, 0.3, 0.1, 0.0, 4.5],
        [18.0, 4.0, 0.4, 0.0, 0.0, 5.0],
    ])
    y = np.array([0, 0, 1, 1])
    clf.fit(X, y)
    return DGAModel(
        classifier=clf,
        model_version="1.0.0-test",
        threshold=0.45,
        feature_names=FEATURE_NAMES,
    )


class TestDGAModel:
    def test_predict_proba_1d_and_2d(self, trained_toy_model: DGAModel):
        # 1D vector
        sample_1d = [5.0, 1.2, 0.0, 0.5, 0.8, 1.5]
        prob_1d = trained_toy_model.predict_proba(sample_1d)
        assert isinstance(prob_1d, np.ndarray)
        assert prob_1d.shape == (1,)
        assert 0.0 <= prob_1d[0] <= 1.0

        # 2D batch
        sample_2d = [
            [5.0, 1.2, 0.0, 0.5, 0.8, 1.5],
            [18.0, 4.0, 0.4, 0.0, 0.0, 5.0],
        ]
        prob_2d = trained_toy_model.predict_proba(sample_2d)
        assert prob_2d.shape == (2,)
        assert prob_2d[0] < prob_2d[1]

    def test_predict_thresholding(self, trained_toy_model: DGAModel):
        sample_2d = [
            [5.0, 1.2, 0.0, 0.5, 0.8, 1.5],
            [18.0, 4.0, 0.4, 0.0, 0.0, 5.0],
        ]
        preds = trained_toy_model.predict(sample_2d)
        assert preds[0] == 0
        assert preds[1] == 1

        # Override threshold to very high value
        preds_high = trained_toy_model.predict(sample_2d, threshold=0.99)
        assert np.all(preds_high == 0)

    def test_save_and_load(self, trained_toy_model: DGAModel):
        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "test_model.joblib"
            trained_toy_model.save(model_path)
            assert model_path.exists()

            loaded = DGAModel.load(model_path)
            assert loaded.model_version == trained_toy_model.model_version
            assert loaded.threshold == trained_toy_model.threshold
            assert loaded.feature_names == trained_toy_model.feature_names

            sample = [15.0, 3.8, 0.3, 0.1, 0.0, 4.5]
            orig_prob = trained_toy_model.predict_proba(sample)[0]
            loaded_prob = loaded.predict_proba(sample)[0]
            assert np.isclose(orig_prob, loaded_prob)

    def test_unfitted_model_raises_error(self):
        empty_model = DGAModel()
        with pytest.raises(RuntimeError, match="not been fitted"):
            empty_model.predict_proba([1.0, 2.0, 3.0, 4.0, 5.0, 6.0])
