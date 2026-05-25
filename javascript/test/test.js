/**
 * Tests for cyber-ale-calculator — 30+ cases covering all functions and edge cases.
 * Uses Node.js built-in assert module (no external dependencies).
 */

"use strict";

const assert = require("node:assert/strict");
const { describe, it } = require("node:test");

const {
  calculateAle,
  calculateSle,
  calculateAro,
  calculateRiskReduction,
  riskRating,
  THREAT_SCENARIOS,
} = require("../index");

// Helper: check approximate equality for floating point
function approx(actual, expected, tolerance = 1e-6) {
  assert.ok(
    Math.abs(actual - expected) <= tolerance * Math.max(1, Math.abs(expected)),
    `Expected ~${expected}, got ${actual}`
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// calculateSle
// ──────────────────────────────────────────────────────────────────────────────

describe("calculateSle", () => {
  it("basic calculation", () => {
    assert.equal(calculateSle(1_000_000, 0.5), 500_000);
  });

  it("full exposure", () => {
    assert.equal(calculateSle(250_000, 1.0), 250_000);
  });

  it("zero exposure", () => {
    assert.equal(calculateSle(1_000_000, 0.0), 0);
  });

  it("zero asset value", () => {
    assert.equal(calculateSle(0, 0.75), 0);
  });

  it("small exposure factor", () => {
    approx(calculateSle(10_000_000, 0.01), 100_000);
  });

  it("throws on negative asset value", () => {
    assert.throws(() => calculateSle(-100, 0.5), RangeError);
  });

  it("throws on exposure factor > 1", () => {
    assert.throws(() => calculateSle(100_000, 1.5), RangeError);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// calculateAro
// ──────────────────────────────────────────────────────────────────────────────

describe("calculateAro", () => {
  it("basic calculation", () => {
    assert.equal(calculateAro(6, 3), 2.0);
  });

  it("fractional result", () => {
    assert.equal(calculateAro(1, 4), 0.25);
  });

  it("zero incidents", () => {
    assert.equal(calculateAro(0, 5), 0);
  });

  it("throws on zero period", () => {
    assert.throws(() => calculateAro(5, 0), RangeError);
  });

  it("throws on negative period", () => {
    assert.throws(() => calculateAro(5, -1), RangeError);
  });

  it("throws on negative incidents", () => {
    assert.throws(() => calculateAro(-1, 5), RangeError);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// calculateAle
// ──────────────────────────────────────────────────────────────────────────────

describe("calculateAle", () => {
  it("basic calculation", () => {
    // SLE = 1M * 0.5 = 500K, ALE = 500K * 2 = 1M
    assert.equal(calculateAle(1_000_000, 0.5, 2.0), 1_000_000);
  });

  it("low frequency", () => {
    // SLE = 5M * 0.3 = 1.5M, ALE = 1.5M * 0.1 = 150K
    approx(calculateAle(5_000_000, 0.3, 0.1), 150_000);
  });

  it("zero ARO returns zero", () => {
    assert.equal(calculateAle(1_000_000, 0.5, 0), 0);
  });

  it("very large numbers", () => {
    // $1B asset, 80% EF, 5x/year = $4B ALE
    approx(calculateAle(1_000_000_000, 0.8, 5.0), 4_000_000_000);
  });

  it("throws on negative ARO", () => {
    assert.throws(() => calculateAle(1_000_000, 0.5, -1), RangeError);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// calculateRiskReduction
// ──────────────────────────────────────────────────────────────────────────────

describe("calculateRiskReduction", () => {
  it("positive ROI", () => {
    const result = calculateRiskReduction(500_000, 100_000, 50_000);
    assert.equal(result.netBenefit, 350_000);
    approx(result.roiPercent, 700.0);
    approx(result.paybackMonths, 1.5);
  });

  it("break even", () => {
    const result = calculateRiskReduction(500_000, 100_000, 400_000);
    assert.equal(result.netBenefit, 0);
    approx(result.roiPercent, 0);
  });

  it("negative ROI", () => {
    const result = calculateRiskReduction(500_000, 400_000, 200_000);
    assert.equal(result.netBenefit, -100_000);
    approx(result.roiPercent, -50.0);
  });

  it("zero control cost with reduction", () => {
    const result = calculateRiskReduction(500_000, 100_000, 0);
    assert.equal(result.roiPercent, Infinity);
    assert.equal(result.paybackMonths, 0);
  });

  it("no risk reduction", () => {
    const result = calculateRiskReduction(500_000, 500_000, 100_000);
    assert.equal(result.netBenefit, -100_000);
    assert.equal(result.paybackMonths, Infinity);
  });

  it("zero control cost with no reduction", () => {
    const result = calculateRiskReduction(500_000, 500_000, 0);
    assert.equal(result.roiPercent, 0);
    assert.equal(result.paybackMonths, 0);
  });

  it("throws on negative ALE", () => {
    assert.throws(
      () => calculateRiskReduction(-1, 100_000, 50_000),
      RangeError
    );
  });

  it("throws on negative control cost", () => {
    assert.throws(
      () => calculateRiskReduction(500_000, 100_000, -50_000),
      RangeError
    );
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// riskRating
// ──────────────────────────────────────────────────────────────────────────────

describe("riskRating", () => {
  it("critical at threshold", () => {
    assert.equal(riskRating(10_000_000), "critical");
  });

  it("critical above threshold", () => {
    assert.equal(riskRating(50_000_000), "critical");
  });

  it("high at threshold", () => {
    assert.equal(riskRating(1_000_000), "high");
  });

  it("high just below critical", () => {
    assert.equal(riskRating(9_999_999), "high");
  });

  it("medium at threshold", () => {
    assert.equal(riskRating(100_000), "medium");
  });

  it("medium just below high", () => {
    assert.equal(riskRating(999_999), "medium");
  });

  it("low at threshold", () => {
    assert.equal(riskRating(10_000), "low");
  });

  it("low just below medium", () => {
    assert.equal(riskRating(99_999), "low");
  });

  it("negligible at zero", () => {
    assert.equal(riskRating(0), "negligible");
  });

  it("negligible just below low", () => {
    assert.equal(riskRating(9_999), "negligible");
  });

  it("throws on negative ALE", () => {
    assert.throws(() => riskRating(-1), RangeError);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// THREAT_SCENARIOS lookup table
// ──────────────────────────────────────────────────────────────────────────────

describe("THREAT_SCENARIOS", () => {
  it("contains all five scenarios", () => {
    const expected = new Set([
      "ransomware",
      "phishing",
      "insiderThreat",
      "ddos",
      "dataBreach",
    ]);
    assert.deepEqual(new Set(Object.keys(THREAT_SCENARIOS)), expected);
  });

  it("each scenario has required fields", () => {
    const required = [
      "name",
      "aroLow",
      "aroMid",
      "aroHigh",
      "typicalExposureFactor",
      "description",
    ];
    for (const [key, scenario] of Object.entries(THREAT_SCENARIOS)) {
      for (const field of required) {
        assert.ok(
          field in scenario,
          `${key} missing field: ${field}`
        );
      }
    }
  });

  it("ARO values are in ascending order", () => {
    for (const [key, scenario] of Object.entries(THREAT_SCENARIOS)) {
      assert.ok(
        scenario.aroLow <= scenario.aroMid &&
          scenario.aroMid <= scenario.aroHigh,
        `${key}: ARO values not in ascending order`
      );
    }
  });

  it("exposure factors are valid (0, 1]", () => {
    for (const [key, scenario] of Object.entries(THREAT_SCENARIOS)) {
      const ef = scenario.typicalExposureFactor;
      assert.ok(
        ef > 0 && ef <= 1,
        `${key}: exposure factor ${ef} out of range`
      );
    }
  });

  it("table is frozen (immutable)", () => {
    assert.ok(Object.isFrozen(THREAT_SCENARIOS));
    for (const scenario of Object.values(THREAT_SCENARIOS)) {
      assert.ok(Object.isFrozen(scenario));
    }
  });
});
