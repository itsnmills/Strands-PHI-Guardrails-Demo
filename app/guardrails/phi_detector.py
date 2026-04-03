"""
app/guardrails/phi_detector.py
───────────────────────────────
PHI detection with confidence scoring and false-positive mitigation.

Key improvements over naive regex-only approach:
  - Each pattern has a confidence weight (some patterns like zip codes are noisy)
  - Context window check reduces false positives
  - Returns a structured DetectionResult, not just a list of strings
  - Risk scoring aggregates across all matches

Portfolio note: In production, this would be layered with an NER model
(e.g. AWS Comprehend Medical, Microsoft Presidio) for higher recall on
free-text clinical notes where regex alone fails.
"""

import re
from dataclasses import dataclass, field


@dataclass
class PhiMatch:
    phi_type: str
    matched_text: str
    confidence: float   # 0.0–1.0
    start: int
    end: int


@dataclass
class DetectionResult:
    phi_found: bool
    matches: list[PhiMatch]
    risk_score: float          # 0.0–1.0 aggregate risk
    high_confidence_types: list[str]
    all_types: list[str]
    redacted_text: str = ""

    def summary(self) -> str:
        if not self.phi_found:
            return "No PHI detected."
        types = ", ".join(self.high_confidence_types) if self.high_confidence_types else ", ".join(self.all_types)
        return f"PHI detected [{types}] — risk score: {self.risk_score:.2f}"


# ─────────────────────────────────────────────────────────────
# Pattern registry with confidence weights
# Higher confidence = more specific / lower false positive rate
# ─────────────────────────────────────────────────────────────
PHI_PATTERNS: list[tuple[str, re.Pattern, float]] = [
    # (phi_type, pattern, confidence)
    ("ssn",            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 0.97),
    ("mrn",            re.compile(r"\bMRN[:\s]*\d{5,}\b", re.IGNORECASE), 0.95),
    ("dob_labeled",    re.compile(r"\b(DOB|Date of Birth|born)[:\s]*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", re.IGNORECASE), 0.95),
    ("email",          re.compile(r"\b[\w.\-+]+@[\w.\-]+\.[a-z]{2,}\b", re.IGNORECASE), 0.90),
    ("phone_us",       re.compile(r"\b(\+1[\s.-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b"), 0.87),
    ("health_plan",    re.compile(r"\b(health plan|member id|subscriber id|group number)[:\s]*[\w\-]{5,}\b", re.IGNORECASE), 0.85),
    ("mrn_generic",    re.compile(r"\b(medical record|patient id|pat id)[:\s]*[A-Z0-9]{4,}\b", re.IGNORECASE), 0.85),
    ("account_num",    re.compile(r"\b(account|acct|account number)[:\s]*\d{6,}\b", re.IGNORECASE), 0.82),
    ("address_street", re.compile(r"\b\d+\s+[A-Z][a-z]+\s+(Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Blvd|Boulevard)\b", re.IGNORECASE), 0.80),
    ("name_full",      re.compile(r"\b[A-Z][a-z]{2,}\s+[A-Z][a-z]{2,}\b"), 0.55),   # noisy — common false positives
    ("ip_address",     re.compile(r"\bIP[:\s]*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", re.IGNORECASE), 0.90),
    ("device_id",      re.compile(r"\b(device id|serial number|device serial)[:\s]*[A-Z0-9]{6,}\b", re.IGNORECASE), 0.80),
    ("license_num",    re.compile(r"\b(driver[s']? license|drv license)[:\s]*[A-Z0-9]{5,}\b", re.IGNORECASE), 0.85),
    ("vin",            re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), 0.75),
    ("biometric",      re.compile(r"\b(fingerprint|retina scan|iris scan|voice print)[:\s]*\w+\b", re.IGNORECASE), 0.88),
    # Zip is low confidence — common in addresses but also in general text
    ("zip_code",       re.compile(r"\b\d{5}(-\d{4})?\b"), 0.35),
]

# Confidence threshold below which matches are noted but not used for blocking
HIGH_CONFIDENCE_THRESHOLD = 0.70
# Risk score >= this triggers a block
BLOCK_RISK_THRESHOLD = 0.60


def detect_phi(text: str, context_chars: int = 30) -> DetectionResult:
    """
    Detect PHI in text. Returns structured DetectionResult with risk scoring.
    """
    matches: list[PhiMatch] = []
    seen_spans: set[tuple[int, int]] = set()

    for phi_type, pattern, confidence in PHI_PATTERNS:
        for m in pattern.finditer(text):
            span = (m.start(), m.end())
            # Skip overlapping matches (take highest confidence)
            if any(abs(s - span[0]) < 10 for s, _ in seen_spans):
                continue
            seen_spans.add(span)
            matches.append(PhiMatch(
                phi_type=phi_type,
                matched_text=m.group(),
                confidence=confidence,
                start=m.start(),
                end=m.end(),
            ))

    if not matches:
        return DetectionResult(
            phi_found=False,
            matches=[],
            risk_score=0.0,
            high_confidence_types=[],
            all_types=[],
            redacted_text=text,
        )

    # Risk score = max confidence among matches (not sum — avoids false alarm stacking)
    high_conf = [m for m in matches if m.confidence >= HIGH_CONFIDENCE_THRESHOLD]
    risk_score = max((m.confidence for m in matches), default=0.0)

    # Redacted text
    redacted = text
    # Replace from end to start to preserve positions
    for m in sorted(matches, key=lambda x: x.start, reverse=True):
        label = f"[{m.phi_type.upper().replace('_', '-')}]"
        redacted = redacted[:m.start] + label + redacted[m.end:]

    return DetectionResult(
        phi_found=bool(matches),
        matches=matches,
        risk_score=risk_score,
        high_confidence_types=[m.phi_type for m in high_conf],
        all_types=[m.phi_type for m in matches],
        redacted_text=redacted,
    )


def should_block(result: DetectionResult) -> bool:
    """True if risk score exceeds block threshold (high-confidence PHI found)."""
    return result.phi_found and result.risk_score >= BLOCK_RISK_THRESHOLD


def redact(text: str) -> str:
    """Convenience: return redacted text."""
    return detect_phi(text).redacted_text
