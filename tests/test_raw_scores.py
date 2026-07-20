from __future__ import annotations

from types import SimpleNamespace
import unittest

from api.raw_scores import RawScoreCapture, complete_raw_score, raw_score_from_capture


class FakeVector:
    def __init__(self, similarity: float) -> None:
        self.similarity = similarity
        self.T = self

    def dot(self, other: object) -> float:
        return self.similarity


class FakeLogits:
    def __init__(self, probabilities: list[float]) -> None:
        self.probabilities = probabilities

    def softmax(self, dimension: int) -> FakeLogits:
        return self

    def tolist(self) -> list[float]:
        return self.probabilities


class FakeAnalyzer:
    def __init__(self) -> None:
        self.thresholds: list[float] = []

    def analyze(self, **kwargs: object) -> list[SimpleNamespace]:
        threshold = float(kwargs["score_threshold"])
        self.thresholds.append(threshold)
        return [
            SimpleNamespace(score=score)
            for score in (0.2, 0.83)
            if score >= threshold
        ]


class RawScoreTests(unittest.TestCase):
    def score(
        self,
        scanner_type: str,
        results: list,
        scanner: object | None = None,
        text: str = "text",
        sanitized: str = "text",
    ) -> float | None:
        return raw_score_from_capture(
            scanner_type,
            scanner or SimpleNamespace(),
            results,
            text,
            sanitized,
        )

    def test_capture_wraps_and_restores_private_callable(self) -> None:
        pipeline = lambda value: [{"label": "INJECTION", "score": value}]
        scanner = SimpleNamespace(_pipeline=pipeline)
        capture = RawScoreCapture("PromptInjection", scanner)

        capture.install()
        result = scanner._pipeline(0.73)
        capture.uninstall()

        self.assertIs(scanner._pipeline, pipeline)
        self.assertEqual(capture.results, [result])

    def test_probability_scanners_use_their_decision_labels(self) -> None:
        results = [
            [
                {"label": "safe", "score": 0.8},
                {"label": "INJECTION", "score": 0.65},
            ]
        ]
        self.assertEqual(self.score("PromptInjection", results), 0.65)
        self.assertEqual(self.score("Gibberish", [[{"label": "clean", "score": 0.8}]]), 0.2)
        self.assertEqual(self.score("Bias", [[{"label": "UNBIASED", "score": 0.76}]]), 0.24)

    def test_toxicity_and_malicious_urls_take_max_relevant_score(self) -> None:
        self.assertEqual(
            self.score(
                "Toxicity",
                [
                    [[{"label": "insult", "score": 0.44}]],
                    [{"label": "toxicity", "score": 0.81}],
                ],
            ),
            0.81,
        )
        self.assertEqual(
            self.score(
                "MaliciousURLs",
                [
                    [
                        [
                            {"label": "benign", "score": 0.9},
                            {"label": "phishing", "score": 0.72},
                        ]
                    ]
                ],
            ),
            0.72,
        )

    def test_configured_language_metrics_ignore_other_labels(self) -> None:
        code = SimpleNamespace(_languages=["Python"])
        language = SimpleNamespace(_valid_languages=["en"])
        competitors = SimpleNamespace(_competitors=["Exact Corp"])

        self.assertEqual(
            self.score(
                "Code",
                [[[{"label": "Java", "score": 0.99}, {"label": "Python", "score": 0.678}]]],
                code,
            ),
            0.68,
        )
        self.assertEqual(
            self.score(
                "Language",
                [[[{"label": "en", "score": 0.8}, {"label": "fr", "score": 0.19}]]],
                language,
            ),
            0.19,
        )
        self.assertEqual(
            self.score(
                "BanCompetitors",
                [
                    [
                        {"word": " Exact Corp ", "score": 0.87},
                        {"word": "Other", "score": 0.99},
                    ]
                ],
                competitors,
            ),
            0.87,
        )

    def test_presidio_sentiment_relevance_and_entailment_scores(self) -> None:
        entities = [SimpleNamespace(score=0.61), SimpleNamespace(score=0.934)]
        self.assertEqual(self.score("Anonymize", [entities]), 0.93)
        self.assertEqual(self.score("Sensitive", [entities]), 0.93)
        self.assertEqual(self.score("Sentiment", [{"compound": -0.42}]), -0.42)
        self.assertEqual(self.score("Relevance", [FakeVector(0.37), FakeVector(0.0)]), 0.37)
        self.assertEqual(
            self.score("FactualConsistency", [{"logits": [FakeLogits([0.83, 0.17])]}]),
            0.83,
        )

    def test_non_threshold_scanners_are_deterministic(self) -> None:
        self.assertEqual(self.score("InvisibleText", [], text="a\u200bb"), 1.0)
        self.assertEqual(self.score("TokenLimit", [(["chunk"], 23)]), 23.0)
        self.assertEqual(self.score("Secrets", [], text="secret", sanitized="******"), 1.0)
        self.assertEqual(self.score("Secrets", [], text="safe", sanitized="safe"), 0.0)
        self.assertIsNone(self.score("Deanonymize", []))

    def test_supported_scanner_without_inference_has_zero_score(self) -> None:
        self.assertEqual(self.score("MaliciousURLs", []), 0.0)
        self.assertEqual(self.score("Relevance", []), 0.0)

    def test_complete_score_reuses_all_canonical_classifier_results(self) -> None:
        scanner = SimpleNamespace()
        canonical_results = [
            {"label": "BIASED", "score": 0.8},
            {"label": "BIASED", "score": 0.95},
        ]

        raw_score = complete_raw_score(
            "Bias",
            scanner,
            canonical_results,
            "output",
            "output",
        )

        self.assertEqual(raw_score, 0.95)

    def test_presidio_pass_uses_zero_without_changing_scanner_threshold(self) -> None:
        analyzer = FakeAnalyzer()
        scanner = SimpleNamespace(
            _analyzer=analyzer,
            _threshold=0.5,
            _language="en",
            _entity_types=["PERSON"],
            _allowed_names=None,
        )

        raw_score = complete_raw_score(
            "Anonymize",
            scanner,
            [[SimpleNamespace(score=0.83)]],
            "text",
            "[REDACTED]",
        )

        self.assertEqual(raw_score, 0.83)
        self.assertEqual(analyzer.thresholds, [0.0])
        self.assertEqual(scanner._threshold, 0.5)


if __name__ == "__main__":
    unittest.main()
