"""Explainable Risk-Scoring Engine for Intelligent URL and Domain Analyzer (Component C1).

This engine combines available evidence across 8 distinct intelligence channels:
1. URL lexical and structural analysis
2. Entropy and obfuscation analysis
3. Homoglyph and lookalike-domain indicators
4. Domain registration age and registrar metadata
5. DNS and reputation intelligence
6. DGA (Domain Generation Algorithm) classification
7. Shortened URL destinations and redirect-chain indicators
8. Machine-learning predictions

Key architectural capabilities:
- Normalized risk score from 0.0 to 100.0.
- Configurable scoring weights with explicit documented rationale.
- Dynamic weight renormalization for missing features and unavailable external services.
- Collinearity dampening to avoid double-counting correlated signals (e.g. entropy vs DGA,
  homoglyphs vs keywords, ML probabilities vs lexical features, Punycode vs homoglyphs).
- Strict epistemological tier separation (Observed Facts vs Heuristic Indicators vs Model Predictions).
- Main contributing indicators with impact deltas and empirical evidence strings.
- Explicit documentation of analysis limitations and service fallbacks.
- Mitigating factors for established domains (>2 years, DNSSEC) to prevent false positives.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.config import Settings, get_settings
from app.schemas.url_schema import (
    ContributingRiskFactor,
    DgaAnalysisFeatures,
    DnsIntelligenceFeatures,
    DomainIntelligenceReport,
    DomainRegistrationFeatures,
    DomainReputationFeatures,
    EpistemicEvidenceBreakdown,
    ExplainableRiskAssessment,
    MlPredictionResult,
    RedirectChainFeatures,
    ThreatInfrastructureReport,
    UrlLexicalFeatures,
)


class ExplainableRiskScoringEngine:
    """Multi-channel explainable risk-scoring engine with dynamic weight renormalization

    and collinearity dampening.
    """

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()

    def evaluate(
        self,
        raw_url: str,
        lexical_features: UrlLexicalFeatures,
        domain_report: DomainIntelligenceReport,
        infra_report: ThreatInfrastructureReport,
        ml_res: Optional[MlPredictionResult] = None,
    ) -> ExplainableRiskAssessment:
        """Execute full explainable risk evaluation across all available intelligence channels."""
        timestamp_utc = datetime.now(timezone.utc).isoformat()
        analysis_limitations: List[str] = []

        # ---------------------------------------------------------------------
        # 1. Epistemological Evidence Collection
        # ---------------------------------------------------------------------
        observed_facts: List[str] = []
        heuristic_indicators: List[str] = []
        model_predictions: List[str] = []
        contributing_factors: List[ContributingRiskFactor] = []

        self._collect_epistemic_evidence(
            raw_url=raw_url,
            lexical_features=lexical_features,
            domain_report=domain_report,
            infra_report=infra_report,
            ml_res=ml_res,
            observed_facts=observed_facts,
            heuristic_indicators=heuristic_indicators,
            model_predictions=model_predictions,
            limitations=analysis_limitations,
        )

        # ---------------------------------------------------------------------
        # 2. Compute Individual Channel Sub-Scores (0.0 to 100.0)
        # ---------------------------------------------------------------------
        channel_scores: Dict[str, float] = {}
        channel_active: Dict[str, bool] = {}

        # Channel 1: Lexical & Structural
        score_lex, lex_factors = self._evaluate_lexical_structural(lexical_features)
        channel_scores["lexical_structural"] = score_lex
        channel_active["lexical_structural"] = True
        contributing_factors.extend(lex_factors)

        # Channel 2: Entropy & Obfuscation
        score_ent, ent_factors = self._evaluate_entropy_obfuscation(
            lexical_features, infra_report.dga
        )
        channel_scores["entropy_obfuscation"] = score_ent
        channel_active["entropy_obfuscation"] = True
        contributing_factors.extend(ent_factors)

        # Channel 3: Homoglyph & Lookalike
        score_homo, homo_factors = self._evaluate_homoglyph_lookalike(lexical_features)
        channel_scores["homoglyph_lookalike"] = score_homo
        channel_active["homoglyph_lookalike"] = True
        contributing_factors.extend(homo_factors)

        # Channel 4: Domain Registration
        score_reg, reg_factors, reg_active, reg_limitation = self._evaluate_domain_registration(
            lexical_features, domain_report.registration
        )
        channel_scores["domain_registration"] = score_reg
        channel_active["domain_registration"] = reg_active
        if reg_limitation:
            analysis_limitations.append(reg_limitation)
        contributing_factors.extend(reg_factors)

        # Channel 5: DNS & Reputation
        score_dns, dns_factors, dns_active, dns_limitation = self._evaluate_dns_reputation(
            lexical_features, domain_report.dns, domain_report.reputation
        )
        channel_scores["dns_reputation"] = score_dns
        channel_active["dns_reputation"] = dns_active
        if dns_limitation:
            analysis_limitations.append(dns_limitation)
        contributing_factors.extend(dns_factors)

        # Channel 6: DGA Classification
        score_dga, dga_factors, dga_active, dga_limitation = self._evaluate_dga(
            lexical_features, infra_report.dga
        )
        channel_scores["dga"] = score_dga
        channel_active["dga"] = dga_active
        if dga_limitation:
            analysis_limitations.append(dga_limitation)
        contributing_factors.extend(dga_factors)

        # Channel 7: Shorteners & Redirect Chains
        score_redir, redir_factors, redir_active = self._evaluate_shortener_redirect(
            infra_report.redirect_chain
        )
        channel_scores["shortener_redirect"] = score_redir
        channel_active["shortener_redirect"] = redir_active
        contributing_factors.extend(redir_factors)

        # Channel 8: Machine Learning Classifier
        score_ml, ml_factors, ml_active, ml_limitation = self._evaluate_machine_learning(ml_res)
        channel_scores["machine_learning"] = score_ml
        channel_active["machine_learning"] = ml_active
        if ml_limitation:
            analysis_limitations.append(ml_limitation)
        contributing_factors.extend(ml_factors)

        # ---------------------------------------------------------------------
        # 3. Dynamic Weight Renormalization & Collinearity Dampening
        # ---------------------------------------------------------------------
        active_weights = self._calculate_renormalized_weights(channel_active, ml_active)

        # Compute base composite score
        composite_score = sum(
            active_weights[ch] * channel_scores[ch]
            for ch in active_weights
            if channel_active.get(ch, False)
        )

        # ---------------------------------------------------------------------
        # 4. Contextual Synergy Boosts and Mitigating Factor Sanity Caps
        # ---------------------------------------------------------------------
        composite_score, contextual_factors = self._apply_contextual_rules(
            composite_score=composite_score,
            lexical_features=lexical_features,
            domain_report=domain_report,
            infra_report=infra_report,
            ml_res=ml_res,
        )
        contributing_factors.extend(contextual_factors)

        # ---------------------------------------------------------------------
        # 4b. Effective Risk Score & ML Alignment
        # ---------------------------------------------------------------------
        ml_prob_pct = (ml_res.malicious_probability * 100.0) if (ml_res and ml_res.is_model_loaded) else None
        
        # If ML probability exceeds 80%, ensure effective risk score reflects high-risk threshold
        if ml_prob_pct is not None and ml_prob_pct >= 80.0:
            effective_score = max(composite_score, ml_prob_pct)
        else:
            effective_score = composite_score if composite_score > 0 else (ml_prob_pct if ml_prob_pct is not None else 0.0)

        # Bound final score strictly between 0.0 and 100.0
        final_risk_score = round(min(max(effective_score, 0.0), 100.0), 1)

        # ---------------------------------------------------------------------
        # 5. Final Verdict Determination (>80%, =80%, <80% Rules)
        # ---------------------------------------------------------------------
        has_phishing = self._detect_phishing_evidence(
            raw_url=raw_url,
            lexical_features=lexical_features,
            domain_report=domain_report,
            infra_report=infra_report,
        )
        has_malware = self._detect_malware_evidence(
            raw_url=raw_url,
            lexical_features=lexical_features,
            domain_report=domain_report,
            infra_report=infra_report,
        )

        verdict = self._determine_final_verdict(
            effective_score=final_risk_score,
            has_phishing=has_phishing,
            has_malware=has_malware,
        )

        # Classification and risk_level mapping (preserves gateway/threshold compatibility)
        if final_risk_score >= self.settings.risk_threshold_high:
            classification = "High Risk Scam"
            risk_level = "High"
        elif final_risk_score >= self.settings.risk_threshold_medium:
            classification = "Medium Risk"
            risk_level = "Medium"
        elif final_risk_score >= self.settings.risk_threshold_low:
            classification = "Suspicious"
            risk_level = "Suspicious"
        else:
            classification = "Low Risk"
            risk_level = "Low Risk"

        # Document high-risk verdict factor if >80% policy applied
        if final_risk_score > 80.0:
            contributing_factors.append(
                ContributingRiskFactor(
                    factor_id="high_risk_verdict_policy",
                    title=f"High-Risk Policy Verdict: {verdict}",
                    category="verdict_policy",
                    impact_score=round(max(0.0, final_risk_score - 80.0), 1),
                    evidence=(
                        f"Score ({final_risk_score:.1f}%) exceeds 80% boundary; "
                        f"assigned {verdict} based on specific threat indicators."
                    ),
                    confidence="high",
                    epistemic_type="heuristic",
                )
            )

        # Sort contributing factors by absolute impact magnitude
        contributing_factors.sort(key=lambda f: abs(f.impact_score), reverse=True)

        return ExplainableRiskAssessment(
            risk_score=final_risk_score,
            classification=classification,
            risk_level=risk_level,
            verdict=verdict,
            engine_version=self.settings.risk_engine_version,
            model_version=(ml_res.model_name if ml_res and ml_res.is_model_loaded else "none"),
            analysis_timestamp=timestamp_utc,
            active_weights={k: round(v, 4) for k, v in active_weights.items()},
            channel_scores={k: round(v, 1) for k, v in channel_scores.items()},
            contributing_factors=contributing_factors[:10],  # Return top 10 factors
            epistemic_breakdown=EpistemicEvidenceBreakdown(
                observed_facts=observed_facts,
                heuristic_indicators=heuristic_indicators,
                model_predictions=model_predictions,
            ),
            analysis_limitations=analysis_limitations,
        )

    # =========================================================================
    # Final Verdict & Indicator Classification Logic
    # =========================================================================

    def _determine_final_verdict(
        self,
        effective_score: float,
        has_phishing: bool,
        has_malware: bool,
    ) -> str:
        """Determine final operational verdict following research specifications:

        1. Score > 80%: Final verdict MUST be MALICIOUS, PHISHING, or SUSPICIOUS.
           Never SAFE.
           - PHISHING: If phishing indicators detected (fake login, verification, credential stealing).
           - MALICIOUS: If strong evidence indicates malware distribution or confirmed threat.
           - SUSPICIOUS: If score > 80% but insufficient evidence to distinguish.
        2. Score = 80%: Do not automatically classify as malicious. Apply standard classification.
        3. Score < 80%: Use classification logic to determine SAFE, SUSPICIOUS, PHISHING, or MALICIOUS.
        """
        # Rule 1: High-Risk Score > 80% (Never SAFE)
        if effective_score > 80.0:
            if has_malware and not has_phishing:
                return "MALICIOUS"
            elif has_phishing and not has_malware:
                return "PHISHING"
            elif has_malware and has_phishing:
                # If explicit malware dropper or verified threat feed, prioritize MALICIOUS
                return "MALICIOUS"
            else:
                return "SUSPICIOUS"

        # Rule 2: Exactly 80% (Standard rules, not automatically malicious)
        elif effective_score == 80.0:
            if has_malware:
                return "MALICIOUS"
            elif has_phishing:
                return "PHISHING"
            else:
                return "SUSPICIOUS"

        # Rule 3: Score < 80%
        else:
            if has_malware and effective_score >= 25.0:
                return "MALICIOUS"
            elif has_phishing and effective_score >= 25.0:
                return "PHISHING"
            elif effective_score >= self.settings.risk_threshold_low:  # >= 25.0
                return "SUSPICIOUS"
            else:
                return "SAFE"

    def _detect_phishing_evidence(
        self,
        raw_url: str,
        lexical_features: UrlLexicalFeatures,
        domain_report: DomainIntelligenceReport,
        infra_report: ThreatInfrastructureReport,
    ) -> bool:
        """Identify specific phishing indicators:
        - Sensitive login pages, fake account verification links, or credential-stealing patterns.
        - Homoglyph or punycode brand imitation.
        - Userinfo '@' delimiter spoofing.
        - Newly registered domain (NRD) with credential/brand paths.
        - Threat feed tagging phishing or credential harvesting.
        """
        # 1. Specific login, account verification, and credential-stealing keywords
        phish_keywords = {
            "login", "signin", "verify", "verification", "account",
            "credential", "password", "auth", "authorize", "banking",
            "bank", "confirm", "confirmation", "billing", "wallet",
            "paypal", "appleid", "microsoft", "chase", "wellsfargo"
        }
        found_kw = set(k.lower() for k in (lexical_features.suspicious_keywords_found or []))
        if found_kw.intersection(phish_keywords):
            return True

        # 2. Path patterns matching login, verify, auth, security
        path_lower = (lexical_features.path or "").lower()
        phish_path_patterns = (
            "/login", "/signin", "/auth", "/verify", "/verification",
            "/account", "/secure", "/banking", "/password", "/credential",
            "/update-account", "/billing", "/confirm", "/session", "/checkpoint"
        )
        if any(p in path_lower for p in phish_path_patterns):
            return True

        # 3. Targeted brand spoofing via homoglyphs or Punycode
        if lexical_features.has_homoglyphs or lexical_features.is_punycode:
            return True

        # 4. Userinfo '@' delimiter spoofing
        if lexical_features.has_at_symbol:
            return True

        # 5. Newly registered domain (NRD) combined with suspicious TLD or shortener
        if domain_report.registration.is_nrd and (
            lexical_features.is_suspicious_tld or infra_report.redirect_chain.is_shortened
        ):
            return True

        # 6. Reputation feed threat type
        rep = domain_report.reputation
        if rep.is_known_threat and rep.threat_type in (
            "phishing", "credential_harvesting", "social_engineering", "scam"
        ):
            return True

        return False

    def _detect_malware_evidence(
        self,
        raw_url: str,
        lexical_features: UrlLexicalFeatures,
        domain_report: DomainIntelligenceReport,
        infra_report: ThreatInfrastructureReport,
    ) -> bool:
        """Identify strong evidence indicating malware distribution or confirmed malicious threats:
        - Executable or malware dropper file extensions/paths in URL (.exe, .bin, .sh, .scr, .bat, .apk, .msi, .dll, /bin.sh, /i).
        - Threat intelligence feeds tagging malware, C2, botnet, trojan, dropper.
        - Prohibited SSRF probe blocked during redirect resolution.
        - Procedurally generated DGA domain algorithm (C2 rendezvous).
        - Private IP address resolution leak or fast-flux botnet network.
        """
        # 1. Executable and dropper script file patterns in path
        path_lower = (lexical_features.path or "").lower()
        malware_extensions = (
            ".exe", ".bin", ".sh", ".scr", ".bat", ".apk", ".msi", ".dll",
            ".vbs", ".ps1", ".elf", ".jar", ".iso", ".cmd",
            "/bin.sh", "/i", "/hiddenbin", "/mozi"
        )
        if any(path_lower.endswith(ext) or f"{ext}?" in path_lower or f"{ext}/" in path_lower for ext in malware_extensions):
            return True

        # 2. Known threat feed hits with malware/C2 tags
        rep = domain_report.reputation
        if rep.is_known_threat and (
            rep.threat_type in ("malware", "malware_dropper", "c2", "botnet", "trojan", "ransomware", "payload_delivery", "exploit")
            or not rep.threat_type
        ):
            return True

        # 3. Prohibited SSRF probe blocked during redirect resolution
        if infra_report.redirect_chain.ssrf_blocked:
            return True

        # 4. Procedural DGA domain generation (Command & Control)
        if infra_report.dga.is_dga_suspected and infra_report.dga.dga_score >= 0.60:
            return True

        # 5. Fast-flux DNS botnet infrastructure or Private IP resolution
        if domain_report.dns.is_fast_flux or domain_report.dns.is_private_ip_resolved:
            return True

        return False

    # =========================================================================
    # Individual Channel Evaluators
    # =========================================================================

    def _evaluate_lexical_structural(
        self, features: UrlLexicalFeatures
    ) -> Tuple[float, List[ContributingRiskFactor]]:
        """Evaluate static URL lexical and structural anomalies.

        Avoids linear explosion of keyword penalties via logarithmic dampening.
        """
        factors: List[ContributingRiskFactor] = []
        raw_score = 0.0

        # Subdomain depth anomaly (>= 3 subdomains)
        if features.num_subdomains >= 3:
            pts = min(20.0, float(features.num_subdomains * 5.0))
            raw_score += pts
            factors.append(
                ContributingRiskFactor(
                    factor_id="excessive_subdomains",
                    title="Excessive Subdomain Depth",
                    category="lexical_structural",
                    impact_score=pts,
                    evidence=f"Observed {features.num_subdomains} subdomain levels ('{features.subdomain}').",
                    confidence="high",
                    epistemic_type="heuristic",
                )
            )

        # Suspicious TLD penalty
        if features.is_suspicious_tld:
            pts = 25.0
            raw_score += pts
            factors.append(
                ContributingRiskFactor(
                    factor_id="high_risk_tld",
                    title="High-Risk Top-Level Domain",
                    category="lexical_structural",
                    impact_score=pts,
                    evidence=f"Target uses high-risk TLD '.{features.tld}', frequently leveraged in low-cost scam campaigns.",
                    confidence="high",
                    epistemic_type="heuristic",
                )
            )

        # Logarithmic saturation for keywords: prevents 5 keywords from blowing score to 100
        if features.suspicious_keyword_count > 0:
            # Saturation formula: 10 * ln(1 + count) / ln(2), capped at 30.0
            log_pts = min(30.0, round(10.0 * math.log2(1.0 + features.suspicious_keyword_count), 1))
            raw_score += log_pts
            matched = ", ".join(features.suspicious_keywords_found[:4])
            factors.append(
                ContributingRiskFactor(
                    factor_id="security_keywords_present",
                    title="Security & Credential Keywords in URL",
                    category="lexical_structural",
                    impact_score=log_pts,
                    evidence=f"Detected {features.suspicious_keyword_count} sensitive keyword(s): [{matched}].",
                    confidence="medium",
                    epistemic_type="heuristic",
                )
            )

        # Excessive URL length (> 120 chars)
        if features.url_length > 120:
            pts = min(15.0, (features.url_length - 120) * 0.1)
            raw_score += pts
            factors.append(
                ContributingRiskFactor(
                    factor_id="abnormal_url_length",
                    title="Abnormally Long URL",
                    category="lexical_structural",
                    impact_score=round(pts, 1),
                    evidence=f"Total URL length is {features.url_length} characters.",
                    confidence="medium",
                    epistemic_type="fact",
                )
            )

        # High digit ratio in URL or hostname
        if features.digit_ratio > 0.25:
            pts = 15.0
            raw_score += pts
            factors.append(
                ContributingRiskFactor(
                    factor_id="high_numeric_density",
                    title="High Numeric Character Density",
                    category="lexical_structural",
                    impact_score=pts,
                    evidence=f"Digits account for {features.digit_ratio * 100:.1f}% of total URL length.",
                    confidence="medium",
                    epistemic_type="heuristic",
                )
            )

        sub_score = min(max(raw_score, 0.0), 100.0)
        return sub_score, factors

    def _evaluate_entropy_obfuscation(
        self, features: UrlLexicalFeatures, dga: DgaAnalysisFeatures
    ) -> Tuple[float, List[ContributingRiskFactor]]:
        """Evaluate obfuscation techniques and Shannon entropy.

        Dampens entropy contribution if DGA analyzer already covers hostname randomness.
        """
        factors: List[ContributingRiskFactor] = []
        raw_score = 0.0

        # Percent-encoding obfuscation
        if features.is_double_encoded:
            pts = 35.0
            raw_score += pts
            factors.append(
                ContributingRiskFactor(
                    factor_id="double_percent_encoding",
                    title="Double Percent-Encoding Detected",
                    category="entropy_obfuscation",
                    impact_score=pts,
                    evidence="Double URL encoding (%25XX) used, typical of WAF/filter bypass evasion.",
                    confidence="high",
                    epistemic_type="heuristic",
                )
            )
        elif features.is_encoded and features.encoded_char_count >= 3:
            pts = min(20.0, float(features.encoded_char_count * 3.0))
            raw_score += pts
            factors.append(
                ContributingRiskFactor(
                    factor_id="percent_encoding_obfuscation",
                    title="Significant Percent-Encoding in URL",
                    category="entropy_obfuscation",
                    impact_score=round(pts, 1),
                    evidence=f"Detected {features.encoded_char_count} percent-encoded hex sequences.",
                    confidence="medium",
                    epistemic_type="heuristic",
                )
            )

        # Delimiter anomalies (@ in authority or misleading delimiters)
        if features.has_at_symbol:
            pts = 35.0
            raw_score += pts
            factors.append(
                ContributingRiskFactor(
                    factor_id="authority_at_symbol",
                    title="Misleading Authority Delimiter (@)",
                    category="entropy_obfuscation",
                    impact_score=pts,
                    evidence="Authority contains '@' symbol, which disguises actual destination hostname.",
                    confidence="high",
                    epistemic_type="heuristic",
                )
            )

        if features.has_misleading_delimiter:
            pts = 20.0
            raw_score += pts
            factors.append(
                ContributingRiskFactor(
                    factor_id="misleading_delimiters",
                    title="Deceptive Host Delimiters",
                    category="entropy_obfuscation",
                    impact_score=pts,
                    evidence="Detected misleading path/query delimiters embedded within domain host string.",
                    confidence="medium",
                    epistemic_type="heuristic",
                )
            )

        # Raw IP address as host (hex, octal, or dotted quad)
        if features.is_ip_address:
            pts = 40.0
            raw_score += pts
            factors.append(
                ContributingRiskFactor(
                    factor_id="direct_ip_destination",
                    title="Direct IP Address Host",
                    category="entropy_obfuscation",
                    impact_score=pts,
                    evidence=f"Target host is an explicit IP address ({features.hostname}, format: {features.ip_type}).",
                    confidence="high",
                    epistemic_type="fact",
                )
            )

        # Shannon Entropy on Path:
        # If DGA classifier already flagged high domain entropy, damp path entropy to avoid double-counting
        if features.path_entropy > 4.2 and features.path_length > 15:
            damping = 0.5 if dga.is_dga_suspected else 1.0
            pts = round(20.0 * damping, 1)
            raw_score += pts
            factors.append(
                ContributingRiskFactor(
                    factor_id="elevated_path_entropy",
                    title="Elevated Path Shannon Entropy",
                    category="entropy_obfuscation",
                    impact_score=pts,
                    evidence=f"Path Shannon entropy is {features.path_entropy:.2f} (expected normal < 4.0).",
                    confidence="medium",
                    epistemic_type="heuristic",
                )
            )

        sub_score = min(max(raw_score, 0.0), 100.0)
        return sub_score, factors

    def _evaluate_homoglyph_lookalike(
        self, features: UrlLexicalFeatures
    ) -> Tuple[float, List[ContributingRiskFactor]]:
        """Evaluate internationalized domain names (IDN), Punycode, and homoglyph spoofing.

        Avoids double-counting Punycode prefix if homoglyphs are already flagged.
        """
        factors: List[ContributingRiskFactor] = []
        raw_score = 0.0

        if features.has_homoglyphs:
            # Primary homoglyph confusable violation
            pts = 60.0
            raw_score += pts
            detail = "; ".join(features.homoglyph_details[:2]) if features.homoglyph_details else "Mixed-script confusable characters."
            factors.append(
                ContributingRiskFactor(
                    factor_id="homoglyph_confusable_domain",
                    title="Homoglyph Confusable Brand Spoofing",
                    category="homoglyph_lookalike",
                    impact_score=pts,
                    evidence=f"Mixed-script or lookalike characters detected: {detail}",
                    confidence="high",
                    epistemic_type="heuristic",
                )
            )
            # Collinearity note: Do NOT add additional penalty for is_punycode when has_homoglyphs is True
        elif features.is_punycode or features.is_idn:
            # Benign or unconfirmed Punycode domain
            pts = 20.0
            raw_score += pts
            factors.append(
                ContributingRiskFactor(
                    factor_id="punycode_encoded_domain",
                    title="Punycode / IDN Encoded Domain",
                    category="homoglyph_lookalike",
                    impact_score=pts,
                    evidence=f"Domain uses Internationalized Domain Name encoding ('{features.hostname}').",
                    confidence="medium",
                    epistemic_type="fact",
                )
            )

        sub_score = min(max(raw_score, 0.0), 100.0)
        return sub_score, factors

    def _evaluate_domain_registration(
        self, features: UrlLexicalFeatures, reg: DomainRegistrationFeatures
    ) -> Tuple[float, List[ContributingRiskFactor], bool, Optional[str]]:
        """Evaluate registration age, registrar metadata, and expiration.

        Gracefully deactivates channel when registration is unavailable or host is direct IP.
        """
        factors: List[ContributingRiskFactor] = []
        limitation: Optional[str] = None

        if features.is_ip_address:
            limitation = "Target is a direct IP address; domain registration and WHOIS channels were not applicable."
            return 0.0, factors, False, limitation

        if not reg.is_data_available:
            limitation = "WHOIS/RDAP registration lookup was unavailable or rate-limited; registration channel omitted and weights renormalized."
            return 0.0, factors, False, limitation

        raw_score = 0.0

        # Newly Registered Domain (<= 30 days)
        if reg.is_nrd and reg.age_days is not None:
            pts = 65.0
            raw_score += pts
            factors.append(
                ContributingRiskFactor(
                    factor_id="newly_registered_domain",
                    title="Newly Registered Domain (NRD)",
                    category="domain_registration",
                    impact_score=pts,
                    evidence=f"Domain is only {reg.age_days} day(s) old (Creation: {reg.creation_date or 'recent'}, threshold <= {self.settings.nrd_threshold_days}d).",
                    confidence="high",
                    epistemic_type="fact",
                )
            )
        elif reg.is_young_domain and reg.age_days is not None:
            pts = 30.0
            raw_score += pts
            factors.append(
                ContributingRiskFactor(
                    factor_id="young_domain",
                    title="Young Domain Registration",
                    category="domain_registration",
                    impact_score=pts,
                    evidence=f"Domain registered {reg.age_days} days ago (threshold <= {self.settings.nrd_warning_threshold_days}d).",
                    confidence="medium",
                    epistemic_type="fact",
                )
            )
        elif reg.age_days is not None:
            # Mitigating credit for long-established domains
            if reg.age_days >= 730:  # > 2 years
                mitigation = -30.0
                raw_score += mitigation
                factors.append(
                    ContributingRiskFactor(
                        factor_id="established_domain_age",
                        title="Established Domain History (Mitigating)",
                        category="domain_registration",
                        impact_score=mitigation,
                        evidence=f"Domain has been registered for {reg.age_days} days (~{reg.age_days // 365} years) since {reg.creation_date or 'unknown'}.",
                        confidence="high",
                        epistemic_type="fact",
                    )
                )
            elif reg.age_days >= 365:  # > 1 year
                mitigation = -15.0
                raw_score += mitigation
                factors.append(
                    ContributingRiskFactor(
                        factor_id="moderate_domain_age",
                        title="Moderate Domain Age (Mitigating)",
                        category="domain_registration",
                        impact_score=mitigation,
                        evidence=f"Domain has been continuously registered for {reg.age_days} days.",
                        confidence="medium",
                        epistemic_type="fact",
                    )
                )

        # DNSSEC signing mitigating credit
        if reg.dnssec_enabled:
            mitigation = -10.0
            raw_score += mitigation
            factors.append(
                ContributingRiskFactor(
                    factor_id="dnssec_signed",
                    title="Cryptographically Signed DNSSEC (Mitigating)",
                    category="domain_registration",
                    impact_score=mitigation,
                    evidence="Domain publishes cryptographically validated DNSSEC trust chain.",
                    confidence="high",
                    epistemic_type="fact",
                )
            )

        sub_score = min(max(raw_score, 0.0), 100.0)
        return sub_score, factors, True, None

    def _evaluate_dns_reputation(
        self,
        features: UrlLexicalFeatures,
        dns: DnsIntelligenceFeatures,
        rep: DomainReputationFeatures,
    ) -> Tuple[float, List[ContributingRiskFactor], bool, Optional[str]]:
        """Evaluate DNS resolution anomalies and threat feed reputation."""
        factors: List[ContributingRiskFactor] = []
        limitation: Optional[str] = None

        if not dns.dns_resolved and not rep.threat_feed_checked:
            limitation = "DNS resolution returned no records and threat feeds were offline; DNS/reputation channel omitted and weights renormalized."
            return 0.0, factors, False, limitation

        raw_score = 0.0

        # Fast-flux DNS behavior
        if dns.is_fast_flux:
            pts = 60.0
            raw_score += pts
            factors.append(
                ContributingRiskFactor(
                    factor_id="fast_flux_dns",
                    title="Fast-Flux DNS Infrastructure",
                    category="dns_reputation",
                    impact_score=pts,
                    evidence=f"High IP turnover ({dns.ip_count} IPs) observed with short TTL ({dns.min_ttl}s).",
                    confidence="high",
                    epistemic_type="heuristic",
                )
            )

        # Resolves to private / loopback IP
        if dns.is_private_ip_resolved:
            pts = 50.0
            raw_score += pts
            factors.append(
                ContributingRiskFactor(
                    factor_id="private_ip_resolution",
                    title="Resolves to RFC-1918 Private IP Space",
                    category="dns_reputation",
                    impact_score=pts,
                    evidence=f"DNS query returned private or loopback IP addresses: {dns.a_records}.",
                    confidence="high",
                    epistemic_type="fact",
                )
            )

        # Hosted on known dynamic DNS provider
        if dns.is_dynamic_dns:
            pts = 35.0
            raw_score += pts
            factors.append(
                ContributingRiskFactor(
                    factor_id="dynamic_dns_host",
                    title="Hosted on Dynamic DNS Provider",
                    category="dns_reputation",
                    impact_score=pts,
                    evidence="Domain is hosted under a free Dynamic DNS domain commonly used for transient infrastructure.",
                    confidence="high",
                    epistemic_type="fact",
                )
            )

        # Threat intelligence match
        if rep.is_known_threat:
            pts = 85.0
            raw_score += pts
            factors.append(
                ContributingRiskFactor(
                    factor_id="threat_feed_positive",
                    title="Threat Intelligence Feed Match",
                    category="dns_reputation",
                    impact_score=pts,
                    evidence=f"Domain listed in {rep.reputation_source or 'threat feed'} as {rep.threat_type or 'malicious'} (confidence {rep.confidence_score * 100:.0f}%).",
                    confidence="high",
                    epistemic_type="fact",
                )
            )

        sub_score = min(max(raw_score, 0.0), 100.0)
        return sub_score, factors, True, None

    def _evaluate_dga(
        self, features: UrlLexicalFeatures, dga: DgaAnalysisFeatures
    ) -> Tuple[float, List[ContributingRiskFactor], bool, Optional[str]]:
        """Evaluate Domain Generation Algorithm (DGA) characteristics."""
        factors: List[ContributingRiskFactor] = []
        limitation: Optional[str] = None

        if features.is_ip_address:
            limitation = "Target host is a direct IP address; DGA domain label analysis was not applicable."
            return 0.0, factors, False, limitation

        # Scale dga_score (0.0 to 1.0) to 100
        raw_score = dga.dga_score * 100.0

        if dga.is_dga_suspected:
            factors.append(
                ContributingRiskFactor(
                    factor_id="dga_algorithmic_domain",
                    title="Algorithmic Domain Generation (DGA) Suspected",
                    category="dga",
                    impact_score=round(raw_score, 1),
                    evidence=f"Label '{dga.label}' exhibits abnormal statistical entropy ({dga.label_entropy:.2f}), "
                             f"consonant clustering ({dga.max_consecutive_consonants} consecutive), "
                             f"and bigram perplexity ({dga.bigram_perplexity:.1f}).",
                    confidence="high",
                    epistemic_type="prediction",
                )
            )
        elif raw_score > 30.0:
            factors.append(
                ContributingRiskFactor(
                    factor_id="dga_statistical_elevation",
                    title="Slightly Elevated DGA Randomness",
                    category="dga",
                    impact_score=round(raw_score, 1),
                    evidence=f"Label '{dga.label}' has DGA likelihood score of {dga.dga_score:.2f}.",
                    confidence="medium",
                    epistemic_type="prediction",
                )
            )

        sub_score = min(max(raw_score, 0.0), 100.0)
        return sub_score, factors, True, None

    def _evaluate_shortener_redirect(
        self, chain: RedirectChainFeatures
    ) -> Tuple[float, List[ContributingRiskFactor], bool]:
        """Evaluate URL shorteners and redirect chains."""
        factors: List[ContributingRiskFactor] = []
        raw_score = 0.0

        # Critical SSRF attempt
        if chain.ssrf_blocked:
            pts = 100.0
            raw_score = pts
            factors.append(
                ContributingRiskFactor(
                    factor_id="ssrf_redirect_blocked",
                    title="SSRF / Private IP Redirect Blocked",
                    category="shortener_redirect",
                    impact_score=pts,
                    evidence="Redirect chain attempted to resolve to protected private or cloud metadata IP address.",
                    confidence="high",
                    epistemic_type="fact",
                )
            )
            return 100.0, factors, True

        # Redirect loop
        if chain.has_redirect_loop:
            pts = 45.0
            raw_score += pts
            factors.append(
                ContributingRiskFactor(
                    factor_id="redirect_loop_detected",
                    title="Cyclic HTTP Redirect Loop",
                    category="shortener_redirect",
                    impact_score=pts,
                    evidence="Redirect chain contained circular loops indicative of traffic cloaking or redirection trap.",
                    confidence="high",
                    epistemic_type="fact",
                )
            )

        # Cross-domain destination switch
        if chain.destination_domain_changed:
            pts = 30.0
            raw_score += pts
            factors.append(
                ContributingRiskFactor(
                    factor_id="cross_domain_redirect",
                    title="Cross-Domain Redirect Boundary Crossing",
                    category="shortener_redirect",
                    impact_score=pts,
                    evidence=f"Redirect chain moved from origin to external destination domain ('{chain.final_url}').",
                    confidence="medium",
                    epistemic_type="fact",
                )
            )

        # Known shortener
        if chain.is_shortened:
            pts = 20.0
            raw_score += pts
            factors.append(
                ContributingRiskFactor(
                    factor_id="url_shortener_cloaking",
                    title="Known URL Shortener Service",
                    category="shortener_redirect",
                    impact_score=pts,
                    evidence=f"Target URL is obscured using shortener service '{chain.shortener_provider or 'generic shortener'}'.",
                    confidence="high",
                    epistemic_type="fact",
                )
            )

        sub_score = min(max(raw_score, 0.0), 100.0)
        return sub_score, factors, True

    def _evaluate_machine_learning(
        self, ml_res: Optional[MlPredictionResult]
    ) -> Tuple[float, List[ContributingRiskFactor], bool, Optional[str]]:
        """Evaluate supervised machine learning prediction.

        Explicitly distinguishes model probability P from overall risk score R.
        """
        factors: List[ContributingRiskFactor] = []

        if ml_res is None or not ml_res.is_model_loaded:
            limitation = "Supervised machine learning model is offline or unloaded; ML prediction channel omitted and weights renormalized."
            return 0.0, factors, False, limitation

        # Model probability P in [0.0, 1.0] mapped to 0.0 - 100.0
        ml_sub_score = ml_res.malicious_probability * 100.0

        if ml_res.predicted_label == "malicious":
            factors.append(
                ContributingRiskFactor(
                    factor_id="ml_classifier_malicious",
                    title=f"Machine Learning Classifier ({ml_res.model_name}) Malicious Prediction",
                    category="machine_learning",
                    impact_score=round(ml_sub_score, 1),
                    evidence=f"Supervised model predicted malicious classification with probability {ml_res.malicious_probability:.2f} "
                             f"(confidence {ml_res.confidence:.1f}%, threshold {ml_res.decision_threshold:.2f}).",
                    confidence="high" if ml_res.confidence >= 80.0 else "medium",
                    epistemic_type="prediction",
                )
            )
        elif ml_sub_score < 20.0:
            # Clean model prediction mitigating signal
            mitigation = -15.0
            factors.append(
                ContributingRiskFactor(
                    factor_id="ml_classifier_benign",
                    title=f"Machine Learning Classifier ({ml_res.model_name}) Benign Confidence",
                    category="machine_learning",
                    impact_score=mitigation,
                    evidence=f"Model classified URL as legitimate with low malicious probability ({ml_res.malicious_probability:.2f}).",
                    confidence="medium",
                    epistemic_type="prediction",
                )
            )

        sub_score = min(max(ml_sub_score, 0.0), 100.0)
        return sub_score, factors, True, None

    # =========================================================================
    # Weight Renormalization & Collinearity Dampening
    # =========================================================================

    def _calculate_renormalized_weights(
        self, channel_active: Dict[str, bool], ml_active: bool
    ) -> Dict[str, float]:
        """Dynamically renormalize weights over active channels.

        Applies collinearity dampening to lexical heuristic channel when the ML model
        is active, because the ML model already captures lexical and structural features.
        """
        nominal_weights: Dict[str, float] = {
            "lexical_structural": self.settings.weight_lexical_structural,
            "entropy_obfuscation": self.settings.weight_entropy_obfuscation,
            "homoglyph_lookalike": self.settings.weight_homoglyph_lookalike,
            "domain_registration": self.settings.weight_domain_registration,
            "dns_reputation": self.settings.weight_dns_reputation,
            "dga": self.settings.weight_dga,
            "shortener_redirect": self.settings.weight_shortener_redirect,
            "machine_learning": self.settings.weight_machine_learning,
        }

        # Collinearity Dampening: If ML model is active, scale lexical heuristic weight down
        # by 40% to prevent double-counting lexical signals already internalized by ML.
        if ml_active:
            nominal_weights["lexical_structural"] *= 0.6

        # Zero out inactive channels
        active_nominal: Dict[str, float] = {
            ch: (nominal_weights[ch] if channel_active.get(ch, False) else 0.0)
            for ch in nominal_weights
        }

        total_active_weight = sum(active_nominal.values())
        if total_active_weight <= 0.0:
            # Fallback uniform distribution over active channels
            active_count = sum(1 for ch in channel_active if channel_active[ch])
            if active_count == 0:
                return {ch: 0.0 for ch in nominal_weights}
            return {ch: (1.0 / active_count if channel_active.get(ch, False) else 0.0) for ch in nominal_weights}

        # Normalize so sum of active weights == 1.00
        return {ch: active_nominal[ch] / total_active_weight for ch in nominal_weights}

    # =========================================================================
    # Contextual Synergy Rules and Sanity Caps
    # =========================================================================

    def _apply_contextual_rules(
        self,
        composite_score: float,
        lexical_features: UrlLexicalFeatures,
        domain_report: DomainIntelligenceReport,
        infra_report: ThreatInfrastructureReport,
        ml_res: Optional[MlPredictionResult],
    ) -> Tuple[float, List[ContributingRiskFactor]]:
        """Apply high-confidence compound threat boosters and established-domain false positive caps."""
        contextual_factors: List[ContributingRiskFactor] = []
        score = composite_score

        # Rule 1: High-Confidence Compound Phishing Synergy:
        # Newly Registered Domain (<=30 days) + Security/Login Keywords
        reg = domain_report.registration
        if reg.is_nrd and lexical_features.has_suspicious_keyword:
            boost = 25.0 if lexical_features.suspicious_keyword_count >= 2 else 15.0
            evidence_details = ["freshly registered domain", "sensitive credential/login keywords"]

            # Additional high-risk compound multipliers
            if ml_res and ml_res.is_model_loaded and ml_res.malicious_probability >= 0.80:
                boost += 20.0
                evidence_details.append(f"high ML malicious probability ({ml_res.malicious_probability * 100:.0f}%)")
            if lexical_features.is_suspicious_tld:
                boost += 10.0
                evidence_details.append(f"high-risk TLD (.{lexical_features.tld})")

            score += boost
            contextual_factors.append(
                ContributingRiskFactor(
                    factor_id="compound_nrd_phishing_synergy",
                    title="Compound Threat Synergy: NRD + Security Keywords",
                    category="domain_registration",
                    impact_score=boost,
                    evidence=f"High-risk compound threat alignment detected across {', '.join(evidence_details)}.",
                    confidence="high",
                    epistemic_type="heuristic",
                )
            )

        # Rule 1b: High-Risk TLD + Security Keyword Cluster + ML Alignment (Active even when WHOIS is unavailable)
        elif lexical_features.suspicious_keyword_count >= 2 and lexical_features.is_suspicious_tld:
            tld_boost = 15.0 if lexical_features.suspicious_keyword_count == 2 else 25.0
            evidence_details = [
                f"high-risk TLD (.{lexical_features.tld})",
                f"{lexical_features.suspicious_keyword_count} sensitive credential keywords",
            ]
            if ml_res and ml_res.is_model_loaded and ml_res.malicious_probability >= 0.80:
                tld_boost += 20.0
                evidence_details.append(f"high ML malicious probability ({ml_res.malicious_probability * 100:.0f}%)")

            score += tld_boost
            contextual_factors.append(
                ContributingRiskFactor(
                    factor_id="compound_tld_keyword_phishing_synergy",
                    title="Compound Synergy: High-Risk TLD + Sensitive Keywords",
                    category="lexical_structural",
                    impact_score=tld_boost,
                    evidence=f"Concentration of risk signals across {', '.join(evidence_details)}.",
                    confidence="high",
                    epistemic_type="heuristic",
                )
            )



        # Rule 2: Critical Threat Floors:
        # SSRF blocked or verified threat feed match enforces high risk floor
        if infra_report.redirect_chain.ssrf_blocked:
            score = max(score, 90.0)

        if domain_report.reputation.is_known_threat:
            score = max(score, 85.0)

        # Rule 3: False-Positive Resistance for Long-Established Domains:
        # If domain has been active for over 5 years (1825 days) and has no homoglyphs or threat matches,
        # its risk score is capped at 35.0 (Low/Suspicious) even if it contains auth keywords (e.g. accounts.google.com/signin).
        if (
            reg.age_days is not None
            and reg.age_days >= 1825
            and not lexical_features.has_homoglyphs
            and not domain_report.reputation.is_known_threat
            and not infra_report.redirect_chain.ssrf_blocked
        ):
            if score > 35.0:
                reduction = round(score - 35.0, 1)
                score = 35.0
                contextual_factors.append(
                    ContributingRiskFactor(
                        factor_id="established_domain_fp_guard",
                        title="Established Enterprise Domain Guardrail",
                        category="domain_registration",
                        impact_score=-reduction,
                        evidence=f"Domain has an unbroken registration history of {reg.age_days} days (>5 years); score capped to prevent false-positive credential flag.",
                        confidence="high",
                        epistemic_type="fact",
                    )
                )

        return score, contextual_factors

    # =========================================================================
    # Epistemic Evidence Collector
    # =========================================================================

    def _collect_epistemic_evidence(
        self,
        raw_url: str,
        lexical_features: UrlLexicalFeatures,
        domain_report: DomainIntelligenceReport,
        infra_report: ThreatInfrastructureReport,
        ml_res: Optional[MlPredictionResult],
        observed_facts: List[str],
        heuristic_indicators: List[str],
        model_predictions: List[str],
        limitations: List[str],
    ) -> None:
        """Categorize every piece of evidence into its exact epistemological tier."""
        # 1. Observed Facts
        observed_facts.append(f"Target URL scheme: '{lexical_features.scheme}', host: '{lexical_features.hostname}'.")
        if lexical_features.registered_domain:
            observed_facts.append(f"Registered apex domain: '{lexical_features.registered_domain}' (TLD: '.{lexical_features.tld}').")
        observed_facts.append(f"Total URL character length: {lexical_features.url_length}, hostname length: {lexical_features.hostname_length}.")

        reg = domain_report.registration
        if reg.is_data_available:
            age_str = f"{reg.age_days} days" if reg.age_days is not None else "unknown"
            observed_facts.append(f"Domain registration creation date: {reg.creation_date or 'N/A'}, calculated age: {age_str}.")
            if reg.registrar:
                observed_facts.append(f"Accredited registrar: '{reg.registrar}'.")
            if reg.dnssec_enabled:
                observed_facts.append("Registry confirms DNSSEC signatures are cryptographically published.")

        dns = domain_report.dns
        if dns.dns_resolved:
            observed_facts.append(f"DNS resolved {dns.ip_count} IPv4 address(es): {dns.a_records[:3]}.")
            if dns.mx_records:
                observed_facts.append(f"Configured MX record(s): {dns.mx_records[:2]}.")
            if dns.min_ttl is not None:
                observed_facts.append(f"Minimum resource record TTL: {dns.min_ttl} seconds.")

        chain = infra_report.redirect_chain
        if chain.is_redirected:
            observed_facts.append(f"HTTP redirect chain completed {chain.total_hops} hop(s), reaching final destination: '{chain.final_url}'.")
        elif chain.is_shortened:
            observed_facts.append(f"URL recognized as shortener link via service: '{chain.shortener_provider}'.")

        # 2. Heuristic Indicators
        if lexical_features.has_suspicious_keyword:
            heuristic_indicators.append(
                f"Rule-based detection matched {lexical_features.suspicious_keyword_count} sensitive keyword(s): {lexical_features.suspicious_keywords_found}."
            )
        if lexical_features.is_suspicious_tld:
            heuristic_indicators.append(f"Top-level domain '.{lexical_features.tld}' matched curated high-risk TLD list.")
        if lexical_features.num_subdomains >= 3:
            heuristic_indicators.append(f"Subdomain depth ({lexical_features.num_subdomains}) exceeds standard organizational threshold.")
        if lexical_features.has_homoglyphs:
            heuristic_indicators.append("Confusable script analysis detected lookalike characters mimicking target brand.")
        if lexical_features.is_double_encoded:
            heuristic_indicators.append("Double percent-encoding (%25) pattern detected.")
        if reg.is_nrd:
            heuristic_indicators.append(f"Domain classified as Newly Registered Domain (NRD) (age <= {self.settings.nrd_threshold_days} days).")
        if dns.is_fast_flux:
            heuristic_indicators.append("Fast-flux DNS heuristic triggered based on rapid IP turnover and ultra-short TTL.")
        if dns.is_dynamic_dns:
            heuristic_indicators.append("Domain host matches known dynamic DNS service provider pattern.")

        # 3. Model Predictions
        if infra_report.dga.is_dga_suspected or infra_report.dga.dga_score > 0.3:
            model_predictions.append(
                f"Statistical DGA analyzer assigned likelihood score of {infra_report.dga.dga_score:.2f} "
                f"to label '{infra_report.dga.label}' based on bigram perplexity and entropy."
            )
        else:
            model_predictions.append(
                f"Statistical DGA analyzer found low algorithmic likelihood ({infra_report.dga.dga_score:.2f}) for label '{infra_report.dga.label}'."
            )

        if ml_res and ml_res.is_model_loaded:
            model_predictions.append(
                f"Supervised ML classifier ({ml_res.model_name}) predicted class '{ml_res.predicted_label}' "
                f"with malicious probability {ml_res.malicious_probability:.2f} ({ml_res.confidence:.1f}% confidence)."
            )
        else:
            model_predictions.append("Supervised machine learning model was not active for this evaluation.")
