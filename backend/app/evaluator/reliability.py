from dataclasses import dataclass


@dataclass
class ReliabilityInputs:
    detection_success_rate: float
    telemetry_reliability: float
    latency_score: float
    rule_specificity: float
    evidence_quality: float
    reproducibility: float


@dataclass
class ReliabilityWeights:
    detection_success: float = 0.30
    telemetry: float = 0.20
    latency: float = 0.15
    specificity: float = 0.15
    evidence: float = 0.10
    reproducibility: float = 0.10


def compute_reliability(
    inputs: ReliabilityInputs, weights: ReliabilityWeights | None = None
) -> float:
    weights = weights or ReliabilityWeights()
    score = (
        inputs.detection_success_rate * weights.detection_success
        + inputs.telemetry_reliability * weights.telemetry
        + inputs.latency_score * weights.latency
        + inputs.rule_specificity * weights.specificity
        + inputs.evidence_quality * weights.evidence
        + inputs.reproducibility * weights.reproducibility
    )
    return max(0.0, min(1.0, score))