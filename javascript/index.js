/**
 * Cyber ALE Calculator
 *
 * Annual Loss Expectancy calculations for cybersecurity risk quantification.
 * Implements standard FAIR (Factor Analysis of Information Risk) formulas.
 *
 * @module cyber-ale-calculator
 * @license MIT
 * @author vCSO.ai <contact@vcso.ai>
 */

"use strict";

// ---------------------------------------------------------------------------
// Threat-scenario lookup table
// ---------------------------------------------------------------------------

const THREAT_SCENARIOS = Object.freeze({
  ransomware: Object.freeze({
    name: "Ransomware Attack",
    aroLow: 0.25,
    aroMid: 0.75,
    aroHigh: 2.0,
    typicalExposureFactor: 0.6,
    description:
      "Encryption of critical systems with ransom demand; includes recovery costs, downtime, and potential data loss.",
  }),
  phishing: Object.freeze({
    name: "Phishing / Business Email Compromise",
    aroLow: 1.0,
    aroMid: 5.0,
    aroHigh: 20.0,
    typicalExposureFactor: 0.15,
    description:
      "Credential theft or fraudulent wire transfers initiated via deceptive email.",
  }),
  insiderThreat: Object.freeze({
    name: "Insider Threat (Malicious or Negligent)",
    aroLow: 0.1,
    aroMid: 0.5,
    aroHigh: 2.0,
    typicalExposureFactor: 0.35,
    description:
      "Data exfiltration, sabotage, or accidental exposure by employees or contractors.",
  }),
  ddos: Object.freeze({
    name: "Distributed Denial of Service (DDoS)",
    aroLow: 0.5,
    aroMid: 3.0,
    aroHigh: 12.0,
    typicalExposureFactor: 0.1,
    description:
      "Service disruption from volumetric or application-layer flooding.",
  }),
  dataBreach: Object.freeze({
    name: "Data Breach (External Actor)",
    aroLow: 0.05,
    aroMid: 0.2,
    aroHigh: 1.0,
    typicalExposureFactor: 0.5,
    description:
      "Unauthorized access to sensitive data (PII, PHI, financial records) with regulatory and reputational impact.",
  }),
});

// ---------------------------------------------------------------------------
// Risk-rating thresholds (annual loss in USD)
// ---------------------------------------------------------------------------

const RISK_THRESHOLDS = [
  [10_000_000, "critical"], // >= $10 M
  [1_000_000, "high"], // >= $1 M
  [100_000, "medium"], // >= $100 K
  [10_000, "low"], // >= $10 K
  [0, "negligible"], // < $10 K
];

// ---------------------------------------------------------------------------
// Core calculation functions
// ---------------------------------------------------------------------------

/**
 * Calculate Single Loss Expectancy.
 *
 * @param {number} assetValue - Total value of the asset at risk (USD).
 * @param {number} exposureFactor - Fraction of asset value lost per incident (0.0 - 1.0).
 * @returns {number} SLE = assetValue * exposureFactor
 * @throws {RangeError} If assetValue is negative or exposureFactor is outside [0, 1].
 */
function calculateSle(assetValue, exposureFactor) {
  if (assetValue < 0) {
    throw new RangeError("assetValue must be non-negative");
  }
  if (exposureFactor < 0 || exposureFactor > 1) {
    throw new RangeError("exposureFactor must be between 0.0 and 1.0");
  }
  return assetValue * exposureFactor;
}

/**
 * Calculate Annual Rate of Occurrence.
 *
 * @param {number} incidentsOverPeriod - Number of incidents observed during the measurement period.
 * @param {number} periodYears - Length of the measurement period in years (must be > 0).
 * @returns {number} ARO = incidentsOverPeriod / periodYears
 * @throws {RangeError} If incidentsOverPeriod is negative or periodYears is <= 0.
 */
function calculateAro(incidentsOverPeriod, periodYears) {
  if (incidentsOverPeriod < 0) {
    throw new RangeError("incidentsOverPeriod must be non-negative");
  }
  if (periodYears <= 0) {
    throw new RangeError("periodYears must be positive");
  }
  return incidentsOverPeriod / periodYears;
}

/**
 * Calculate Annual Loss Expectancy.
 *
 * @param {number} assetValue - Total value of the asset at risk (USD).
 * @param {number} exposureFactor - Fraction of asset value lost per incident (0.0 - 1.0).
 * @param {number} aro - Annual Rate of Occurrence.
 * @returns {number} ALE = (assetValue * exposureFactor) * aro
 * @throws {RangeError} If aro is negative (other params validated by calculateSle).
 */
function calculateAle(assetValue, exposureFactor, aro) {
  if (aro < 0) {
    throw new RangeError("aro must be non-negative");
  }
  const sle = calculateSle(assetValue, exposureFactor);
  return sle * aro;
}

/**
 * Evaluate the financial benefit of a security control.
 *
 * @param {number} aleBefore - ALE before implementing the control.
 * @param {number} aleAfter - ALE after implementing the control.
 * @param {number} controlCost - Annual cost of the control (USD).
 * @returns {{ netBenefit: number, roiPercent: number, paybackMonths: number }}
 * @throws {RangeError} If any parameter is negative.
 */
function calculateRiskReduction(aleBefore, aleAfter, controlCost) {
  if (aleBefore < 0 || aleAfter < 0) {
    throw new RangeError("ALE values must be non-negative");
  }
  if (controlCost < 0) {
    throw new RangeError("controlCost must be non-negative");
  }

  const riskReduction = aleBefore - aleAfter;
  const netBenefit = riskReduction - controlCost;

  let roiPercent;
  let paybackMonths;

  if (controlCost === 0) {
    roiPercent = riskReduction > 0 ? Infinity : 0;
    paybackMonths = 0;
  } else {
    roiPercent = (netBenefit / controlCost) * 100;
    paybackMonths =
      riskReduction > 0 ? (controlCost / riskReduction) * 12 : Infinity;
  }

  return { netBenefit, roiPercent, paybackMonths };
}

/**
 * Classify ALE into a qualitative risk tier.
 *
 * Thresholds (USD):
 *   >= 10,000,000  -> 'critical'
 *   >=  1,000,000  -> 'high'
 *   >=    100,000  -> 'medium'
 *   >=     10,000  -> 'low'
 *   <      10,000  -> 'negligible'
 *
 * @param {number} ale - Annual Loss Expectancy (USD).
 * @returns {string} One of 'critical', 'high', 'medium', 'low', 'negligible'.
 * @throws {RangeError} If ale is negative.
 */
function riskRating(ale) {
  if (ale < 0) {
    throw new RangeError("ale must be non-negative");
  }
  for (const [threshold, rating] of RISK_THRESHOLDS) {
    if (ale >= threshold) {
      return rating;
    }
  }
  return "negligible";
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  calculateAle,
  calculateSle,
  calculateAro,
  calculateRiskReduction,
  riskRating,
  THREAT_SCENARIOS,
};
