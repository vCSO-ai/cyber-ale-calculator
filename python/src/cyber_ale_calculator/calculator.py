"""
Cyber ALE Calculator - Annual Loss Expectancy calculations for cybersecurity risk quantification.

Implements standard FAIR (Factor Analysis of Information Risk) formulas:
  ALE = SLE x ARO
  SLE = Asset Value x Exposure Factor
  ARO = Incidents / Period (years)
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Threat-scenario lookup table
# ---------------------------------------------------------------------------

THREAT_SCENARIOS: dict[str, dict] = {
    "ransomware": {
        "name": "Ransomware Attack",
        "aro_low": 0.25,
        "aro_mid": 0.75,
        "aro_high": 2.0,
        "typical_exposure_factor": 0.6,
        "description": "Encryption of critical systems with ransom demand; includes recovery costs, downtime, and potential data loss.",
    },
    "phishing": {
        "name": "Phishing / Business Email Compromise",
        "aro_low": 1.0,
        "aro_mid": 5.0,
        "aro_high": 20.0,
        "typical_exposure_factor": 0.15,
        "description": "Credential theft or fraudulent wire transfers initiated via deceptive email.",
    },
    "insider_threat": {
        "name": "Insider Threat (Malicious or Negligent)",
        "aro_low": 0.1,
        "aro_mid": 0.5,
        "aro_high": 2.0,
        "typical_exposure_factor": 0.35,
        "description": "Data exfiltration, sabotage, or accidental exposure by employees or contractors.",
    },
    "ddos": {
        "name": "Distributed Denial of Service (DDoS)",
        "aro_low": 0.5,
        "aro_mid": 3.0,
        "aro_high": 12.0,
        "typical_exposure_factor": 0.1,
        "description": "Service disruption from volumetric or application-layer flooding.",
    },
    "data_breach": {
        "name": "Data Breach (External Actor)",
        "aro_low": 0.05,
        "aro_mid": 0.2,
        "aro_high": 1.0,
        "typical_exposure_factor": 0.5,
        "description": "Unauthorized access to sensitive data (PII, PHI, financial records) with regulatory and reputational impact.",
    },
}


# ---------------------------------------------------------------------------
# Risk-rating thresholds (annual loss in USD)
# ---------------------------------------------------------------------------

_RISK_THRESHOLDS: list[tuple[float, str]] = [
    (10_000_000, "critical"),    # >= $10 M
    (1_000_000, "high"),         # >= $1 M
    (100_000, "medium"),         # >= $100 K
    (10_000, "low"),             # >= $10 K
    (0, "negligible"),           # < $10 K
]


# ---------------------------------------------------------------------------
# Core calculation functions
# ---------------------------------------------------------------------------

def calculate_sle(asset_value: float, exposure_factor: float) -> float:
    """Calculate Single Loss Expectancy.

    Parameters
    ----------
    asset_value : float
        Total value of the asset at risk (USD).
    exposure_factor : float
        Fraction of asset value lost per incident (0.0 - 1.0).

    Returns
    -------
    float
        SLE = asset_value * exposure_factor
    """
    if asset_value < 0:
        raise ValueError("asset_value must be non-negative")
    if not 0.0 <= exposure_factor <= 1.0:
        raise ValueError("exposure_factor must be between 0.0 and 1.0")
    return asset_value * exposure_factor


def calculate_aro(incidents_over_period: float, period_years: float) -> float:
    """Calculate Annual Rate of Occurrence.

    Parameters
    ----------
    incidents_over_period : float
        Number of incidents observed during the measurement period.
    period_years : float
        Length of the measurement period in years (must be > 0).

    Returns
    -------
    float
        ARO = incidents_over_period / period_years
    """
    if incidents_over_period < 0:
        raise ValueError("incidents_over_period must be non-negative")
    if period_years <= 0:
        raise ValueError("period_years must be positive")
    return incidents_over_period / period_years


def calculate_ale(asset_value: float, exposure_factor: float, aro: float) -> float:
    """Calculate Annual Loss Expectancy.

    Parameters
    ----------
    asset_value : float
        Total value of the asset at risk (USD).
    exposure_factor : float
        Fraction of asset value lost per incident (0.0 - 1.0).
    aro : float
        Annual Rate of Occurrence.

    Returns
    -------
    float
        ALE = SLE * ARO = (asset_value * exposure_factor) * aro
    """
    if aro < 0:
        raise ValueError("aro must be non-negative")
    sle = calculate_sle(asset_value, exposure_factor)
    return sle * aro


def calculate_risk_reduction(
    ale_before: float,
    ale_after: float,
    control_cost: float,
) -> dict[str, float]:
    """Evaluate the financial benefit of a security control.

    Parameters
    ----------
    ale_before : float
        ALE before implementing the control.
    ale_after : float
        ALE after implementing the control.
    control_cost : float
        Annual cost of the control (USD).

    Returns
    -------
    dict
        {
            "net_benefit": float,     # annual savings minus control cost
            "roi_percent": float,     # (net_benefit / control_cost) * 100
            "payback_months": float,  # months to recoup the control cost
        }
    """
    if ale_before < 0 or ale_after < 0:
        raise ValueError("ALE values must be non-negative")
    if control_cost < 0:
        raise ValueError("control_cost must be non-negative")

    risk_reduction = ale_before - ale_after
    net_benefit = risk_reduction - control_cost

    if control_cost == 0:
        roi_percent = float("inf") if risk_reduction > 0 else 0.0
        payback_months = 0.0
    else:
        roi_percent = (net_benefit / control_cost) * 100.0
        if risk_reduction > 0:
            payback_months = (control_cost / risk_reduction) * 12.0
        else:
            payback_months = float("inf")

    return {
        "net_benefit": net_benefit,
        "roi_percent": roi_percent,
        "payback_months": payback_months,
    }


def risk_rating(ale: float) -> str:
    """Classify ALE into a qualitative risk tier.

    Thresholds (USD):
        >= 10,000,000  -> 'critical'
        >=  1,000,000  -> 'high'
        >=    100,000  -> 'medium'
        >=     10,000  -> 'low'
        <      10,000  -> 'negligible'

    Parameters
    ----------
    ale : float
        Annual Loss Expectancy (USD).

    Returns
    -------
    str
        One of 'critical', 'high', 'medium', 'low', 'negligible'.
    """
    if ale < 0:
        raise ValueError("ale must be non-negative")
    for threshold, rating in _RISK_THRESHOLDS:
        if ale >= threshold:
            return rating
    return "negligible"  # fallback (shouldn't reach here)
