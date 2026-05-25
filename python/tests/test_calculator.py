"""Tests for cyber_ale_calculator — 30+ cases covering all functions and edge cases."""

import math

import pytest

from cyber_ale_calculator import (
    THREAT_SCENARIOS,
    calculate_ale,
    calculate_aro,
    calculate_risk_reduction,
    calculate_sle,
    risk_rating,
)


# ──────────────────────────────────────────────────────────────────────────────
# calculate_sle
# ──────────────────────────────────────────────────────────────────────────────

class TestCalculateSLE:
    def test_basic(self):
        assert calculate_sle(1_000_000, 0.5) == 500_000

    def test_full_exposure(self):
        assert calculate_sle(250_000, 1.0) == 250_000

    def test_zero_exposure(self):
        assert calculate_sle(1_000_000, 0.0) == 0.0

    def test_zero_asset_value(self):
        assert calculate_sle(0, 0.75) == 0.0

    def test_small_exposure(self):
        assert calculate_sle(10_000_000, 0.01) == pytest.approx(100_000)

    def test_negative_asset_raises(self):
        with pytest.raises(ValueError, match="asset_value"):
            calculate_sle(-100, 0.5)

    def test_exposure_out_of_range_raises(self):
        with pytest.raises(ValueError, match="exposure_factor"):
            calculate_sle(100_000, 1.5)


# ──────────────────────────────────────────────────────────────────────────────
# calculate_aro
# ──────────────────────────────────────────────────────────────────────────────

class TestCalculateARO:
    def test_basic(self):
        assert calculate_aro(6, 3) == 2.0

    def test_fractional(self):
        assert calculate_aro(1, 4) == 0.25

    def test_zero_incidents(self):
        assert calculate_aro(0, 5) == 0.0

    def test_zero_period_raises(self):
        with pytest.raises(ValueError, match="period_years"):
            calculate_aro(5, 0)

    def test_negative_period_raises(self):
        with pytest.raises(ValueError, match="period_years"):
            calculate_aro(5, -1)

    def test_negative_incidents_raises(self):
        with pytest.raises(ValueError, match="incidents_over_period"):
            calculate_aro(-1, 5)


# ──────────────────────────────────────────────────────────────────────────────
# calculate_ale
# ──────────────────────────────────────────────────────────────────────────────

class TestCalculateALE:
    def test_basic(self):
        # SLE = 1M * 0.5 = 500K, ALE = 500K * 2 = 1M
        assert calculate_ale(1_000_000, 0.5, 2.0) == 1_000_000

    def test_low_frequency(self):
        # SLE = 5M * 0.3 = 1.5M, ALE = 1.5M * 0.1 = 150K
        assert calculate_ale(5_000_000, 0.3, 0.1) == pytest.approx(150_000)

    def test_zero_aro(self):
        assert calculate_ale(1_000_000, 0.5, 0) == 0.0

    def test_very_large_numbers(self):
        # $1B asset, 80% EF, 5x/year = $4B ALE
        result = calculate_ale(1_000_000_000, 0.8, 5.0)
        assert result == pytest.approx(4_000_000_000)

    def test_negative_aro_raises(self):
        with pytest.raises(ValueError, match="aro"):
            calculate_ale(1_000_000, 0.5, -1)


# ──────────────────────────────────────────────────────────────────────────────
# calculate_risk_reduction
# ──────────────────────────────────────────────────────────────────────────────

class TestCalculateRiskReduction:
    def test_positive_roi(self):
        result = calculate_risk_reduction(500_000, 100_000, 50_000)
        assert result["net_benefit"] == 350_000
        assert result["roi_percent"] == pytest.approx(700.0)
        assert result["payback_months"] == pytest.approx(1.5)

    def test_break_even(self):
        result = calculate_risk_reduction(500_000, 100_000, 400_000)
        assert result["net_benefit"] == 0.0
        assert result["roi_percent"] == pytest.approx(0.0)

    def test_negative_roi(self):
        result = calculate_risk_reduction(500_000, 400_000, 200_000)
        assert result["net_benefit"] == -100_000
        assert result["roi_percent"] == pytest.approx(-50.0)

    def test_zero_control_cost(self):
        result = calculate_risk_reduction(500_000, 100_000, 0)
        assert result["roi_percent"] == float("inf")
        assert result["payback_months"] == 0.0

    def test_no_risk_reduction(self):
        result = calculate_risk_reduction(500_000, 500_000, 100_000)
        assert result["net_benefit"] == -100_000
        assert result["payback_months"] == float("inf")

    def test_zero_control_cost_no_reduction(self):
        result = calculate_risk_reduction(500_000, 500_000, 0)
        assert result["roi_percent"] == 0.0
        assert result["payback_months"] == 0.0

    def test_negative_ale_raises(self):
        with pytest.raises(ValueError, match="ALE"):
            calculate_risk_reduction(-1, 100_000, 50_000)

    def test_negative_cost_raises(self):
        with pytest.raises(ValueError, match="control_cost"):
            calculate_risk_reduction(500_000, 100_000, -50_000)


# ──────────────────────────────────────────────────────────────────────────────
# risk_rating
# ──────────────────────────────────────────────────────────────────────────────

class TestRiskRating:
    def test_critical(self):
        assert risk_rating(10_000_000) == "critical"
        assert risk_rating(50_000_000) == "critical"

    def test_high(self):
        assert risk_rating(1_000_000) == "high"
        assert risk_rating(9_999_999) == "high"

    def test_medium(self):
        assert risk_rating(100_000) == "medium"
        assert risk_rating(999_999) == "medium"

    def test_low(self):
        assert risk_rating(10_000) == "low"
        assert risk_rating(99_999) == "low"

    def test_negligible(self):
        assert risk_rating(0) == "negligible"
        assert risk_rating(9_999) == "negligible"

    def test_negative_raises(self):
        with pytest.raises(ValueError, match="ale"):
            risk_rating(-1)


# ──────────────────────────────────────────────────────────────────────────────
# THREAT_SCENARIOS lookup table
# ──────────────────────────────────────────────────────────────────────────────

class TestThreatScenarios:
    def test_all_five_present(self):
        expected = {"ransomware", "phishing", "insider_threat", "ddos", "data_breach"}
        assert set(THREAT_SCENARIOS.keys()) == expected

    def test_required_fields(self):
        required = {"name", "aro_low", "aro_mid", "aro_high", "typical_exposure_factor", "description"}
        for key, scenario in THREAT_SCENARIOS.items():
            assert required.issubset(scenario.keys()), f"{key} missing fields"

    def test_aro_ordering(self):
        for key, scenario in THREAT_SCENARIOS.items():
            assert scenario["aro_low"] <= scenario["aro_mid"] <= scenario["aro_high"], (
                f"{key}: ARO values not in ascending order"
            )

    def test_exposure_factor_valid(self):
        for key, scenario in THREAT_SCENARIOS.items():
            ef = scenario["typical_exposure_factor"]
            assert 0.0 < ef <= 1.0, f"{key}: exposure factor out of range"
