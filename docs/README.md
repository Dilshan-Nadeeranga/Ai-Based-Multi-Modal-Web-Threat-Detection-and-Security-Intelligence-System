# Project Documents — J26-SE-316

Shared project documentation for **ScamTrace: AI-Based Multi-Modal Web Threat
Detection and Security Intelligence System** (IT4010 Research Project, 2026 Jul,
SLIIT — Information Assurance & Security / Software Engineering).

## 📄 Documents

| Document | Description |
|---|---|
| [`TAF-J26-SE-316.pdf`](TAF-J26-SE-316.pdf) | Topic Assessment Form (v2.2) — research problem, existing work and gaps, proposed solution, objectives, novelty and member sub-objectives |

## 🔍 TAF Summary

**Research problem.** Sri Lanka faces rising phishing, fraudulent e-commerce,
investment/crypto scams, brand impersonation and other web threats (12,650+
CERT complaints in 2025; 8.6M+ web threats detected in 2024). Existing defenses
analyze URL, content, visual and code signals **independently**, missing
multi-modal scam campaigns.

**Proposed solution.** ScamTrace integrates four research components plus a
discovery layer (ThreatRadar) into one explainable threat-intelligence system:

| Component | Member | Focus |
|---|---|---|
| **C1 — Intelligent URL & Domain Analyzer** | W A D A K Appuhamy (IT23479746) | Lexical/structural URL analysis, DNS/RDAP intelligence, NRD & DGA detection, short-link and redirect-chain analysis |
| **C2 — Tri-Modal HTML, Content & Behavioral Intent Analyzer** | Dilshan N (IT23250574) | DOM structure, multilingual NLP (XLM-RoBERTa — English/Sinhala/Tamil), static JavaScript/dataflow intent analysis |
| **C3 — Social Media & Web Visual Threat Analyzer** | M.T.C. Peiris (IT23201200) | OCR, CLIP zero-shot brand detection, YOLO logo/UI detection, social-“bait” to web-“trap” cross-source consistency |
| **C4 — Code Quality & Vulnerability Auditor with LLM-Assisted Remediation** | M.S.N. Peiris (IT23201132) | AST/SAST repository auditing (Tree-sitter, Semgrep), context-grounded LLM remediation, HITL review, repository risk score |

**Key novelty.** Correlating multiple evidence sources (URL + content + visual +
social + code) in one lightweight architecture with explainable scores, instead
of blacklists or single-modality detection. C4 additionally contributes a hybrid
neuro-symbolic auditing framework where every LLM patch is context-grounded,
deterministically validated and human-approved — never applied autonomously.

**Alignment.** SDG 8 (economic growth), SDG 9 (resilient infrastructure),
SDG 16 (strong institutions); relevant to digital banking/FinTech, e-commerce,
telecom, SOCs/CERTs and DevSecOps.

## 🔗 Component Documentation

- C4 Code Quality & Vulnerability Auditor: [`services/c4-code-vulnerability-auditor/README.md`](../services/c4-code-vulnerability-auditor/README.md)
- C2 HTML/Content/Behavior Analyzer docs: `services/c2-html-content-behavior-analyzer/docs/`
- C3 Social Visual Analyzer docs: `services/c3-social-visual-analyzer/docs/`
