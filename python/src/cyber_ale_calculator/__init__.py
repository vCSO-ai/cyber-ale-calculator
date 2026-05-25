"""Cyber ALE Calculator - cybersecurity risk quantification using FAIR methodology."""

from .calculator import (
    THREAT_SCENARIOS,
    calculate_ale,
    calculate_aro,
    calculate_risk_reduction,
    calculate_sle,
    risk_rating,
)

__all__ = [
    "calculate_ale",
    "calculate_sle",
    "calculate_aro",
    "calculate_risk_reduction",
    "risk_rating",
    "THREAT_SCENARIOS",
]

__version__ = "1.0.0"
