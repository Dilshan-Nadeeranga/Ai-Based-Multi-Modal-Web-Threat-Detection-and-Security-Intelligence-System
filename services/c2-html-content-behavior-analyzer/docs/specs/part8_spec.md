Read CLAUDE.md first. Parts 1–4 and 7 are done. Now implement Part 8 — Behavioral Intent Mapping (all 12 tasks), built ON TOP of Part 7's JsAnalysisResult (js_v1).
Work only inside services/c2-html-content-behavior-analyzer/. Use dataset v0.3 (5 classes) for the real-data run.

## Tasks
1 Define sensitive data sources · 2 Define dangerous/suspicious sinks · 3 Detect source-to-sink relationships
4 Detect credential-value access · 5 Detect external data transmission · 6 Detect credential exfiltration pattern
7 Detect forced redirect pattern · 8 Detect clipboard manipulation pattern · 9 Detect suspicious download pattern
10 Detect obfuscated execution pattern · 11 Generate behavioral intent vector · 12 Produce behavioral-analysis JSON

## Core principles (module docstrings)
- Part 7 says WHAT APIs are used; Part 8 says WHAT THE CODE IS TRYING TO DO by linking them: SOURCE (sensitive data) → FLOW → SINK (where it goes). A single API is never a pattern on its own (fetch alone is normal).
- Static only: never execute JS, no network. Reuse Part 7's tree-sitter ASTs (re-parse via Part 7's parser — don't write a second parser) and its detections; don't duplicate detectors.
- Lightweight, explainable, intra-script taint analysis — NOT a full JS interpreter. Be honest in docstrings about what it can't see (dynamic property names, cross-script globals beyond simple cases, external script content, runtime-built strings).
- Each finding must carry an EVIDENCE CHAIN a human can follow (source line → assignments → sink line), because Part 9 turns these into explanations (proposal TE4).
- Same path for dataset samples and the Part 9 API: map_behavior(parsed_page, js_result).

## 1. Sources & sinks (tasks 1–2) — configs/sources_sinks.yaml (exists — extend it)
SOURCES (each: id, description, sensitivity high/medium/low, matcher):
- credential_input: .value / FormData / serialize of inputs whose selector, id, name, type or the DOM element (look it up in ParsedPage forms/inputs by id/name) is password / email / username / OTP / PIN / card / CVV / NIC — reuse Part 3's field-detection regexes from configs (don't duplicate the lists)
- form_data_generic: FormData(form), new URLSearchParams(new FormData(...)), $(form).serialize()
- cookie_read, storage_read (local/session), clipboard_read
- keystrokes: event.key / keyCode / which inside keydown/keypress/keyup/input listeners
- page_url / location (low), document.referrer (low), navigator fingerprint props (low)
SINKS:
- network_external: fetch / XHR.open+send / sendBeacon / WebSocket / EventSource / image beacon / $.ajax|post|get — with url_is_external (vs page base_url) or unknown
- network_internal (same registrable domain) — lower risk
- form_action_external: form.action = external URL, then submit / requestSubmit
- redirect_external, redirect_internal, window.open
- clipboard_write, code_execution (eval/Function/string timers), html_injection (innerHTML/document.write), download (a.download, Blob/createObjectURL)
Known services (Telegram bot API api.telegram.org, Discord webhooks, Formspree/getform/submit-form, EmailJS, Google Apps Script script.google.com/macros, ngrok, webhook.site, pipedream …) in config as "exfil_endpoints" → raise severity when they are the sink.

## 2. Data flow (task 3) — behavior/dataflow.py
Intra-script, flow-insensitive-but-ordered taint propagation over the AST:
- variable declarations/assignments (let/const/var/=, destructuring basics), object literal properties ({u: user, p: pass}), JSON.stringify, string concatenation and template literals, array push/join, URLSearchParams/FormData append, encodeURIComponent/btoa wrappers (taint passes through, mark "encoded"), simple function parameters within the same script (call f(pwd) → param inside f), arrow functions/callbacks (.then, addEventListener handlers)
- event-handler code from Part 7 sources (onsubmit/onclick) analyzed with access to the same page's inline-script globals (simple global-name lookup, documented limitation)
- Output: flows[] = {source_id, sink_id, path: [{line, column, code ≤120 chars, step: source|assign|concat|call|encode|sink}], script_index, confidence (high = direct/short path, medium = through function/object, low = fallback/regex-only script), encoded (bool), sink_url_domain, sink_is_external, sink_is_known_exfil_endpoint}
- Hard caps (config): max path length, max taint vars per script, time budget per script → mark truncated, never hang.

## 3. Patterns (tasks 4–10) — behavior/patterns.py, rules in configs/behavior_patterns.yaml
Each pattern: id, name, description (plain English for explanations), severity (critical/high/medium/low), required evidence, and a message template. Detect:
- credential_access (task 4): credential_input source read in page-own code (low on its own — many login pages validate fields)
- external_data_transmission (task 5): any tainted flow to network_external (medium); untainted external requests are only counted, not flagged
- credential_exfiltration (task 6): credential_input/form_data/keystrokes → network_external or form_action_external (critical); add +known exfil endpoint, +encoded, +happens in submit handler with preventDefault() (classic phishing: stop the real submit, send creds elsewhere)
- keylogging (part of 6): keystroke source → any network sink (critical) / → storage (medium)
- forced_redirect (task 7): redirect_external without user interaction (top-level code, load/DOMContentLoaded, setTimeout) or immediately after credential capture (high); also meta refresh to external (from ParsedPage), history manipulation + redirect, and redirect gated on simple checks (e.g. navigator.webdriver, userAgent, referrer — "cloaking", medium)
- clipboard_manipulation (task 8): clipboard_write with a literal that looks like a crypto address (BTC/ETH/TRX/SOL regexes in config) or PowerShell/cmd command ("ClickFix"/paste-and-run lures: powershell, mshta, curl|bash, iex) (critical); copy/paste listener that rewrites clipboardData (high); clipboard_read → network (high)
- suspicious_download (task 9): programmatic download (a.download/click, Blob+createObjectURL, msSaveBlob, location to a file URL) of risky extensions (.exe .msi .apk .scr .js .vbs .hta .bat .ps1 .zip .iso .dmg — list in config), auto-triggered (no user click) → high; decoded/base64 Blob content → +1 level
- obfuscated_execution (task 10): decode (atob/unescape/fromCharCode/escape-heavy literal) flowing into code_execution or html_injection (high); packer signatures / high-entropy + eval from Part 7 obfuscation stats (medium); minified-only never counts
- anti_analysis (extra, low/medium): contextmenu/F12/devtools blocking, debugger loops, disabling selection
Each finding: {pattern_id, severity, confidence, message (filled template), evidence: [flows/detections refs with line + code], script_index}.
Library code (Part 7 in_library) is ignored for patterns.

## 4. Intent vector + JSON (tasks 11–12)
- configs/behavior_features.yaml (feature_set_version beh_v1, same style as dom_features.yaml): per pattern {present, count, max_severity_score}, plus: tainted_flow_count, external_tainted_flow_count, credential_flow_to_external, flow_to_known_exfil_endpoint, encoded_flow_count, max_flow_confidence, auto_redirect_external, clipboard_crypto_address, clickfix_command, risky_auto_download, decode_to_exec, anti_analysis_count, behavior_risk_score (0–100, simple documented weighted sum of severities, capped — descriptive, not the final verdict).
- BehaviorResult (pydantic, schemas/behavior.py — replace the stub signatures): meta, sources_found, sinks_found, flows, findings (sorted by severity), intent_vector (ordered), behavior_risk_score, top_findings (≤5 human-readable lines for Part 9), errors.
- data/processed/behavior/<version>/<sample_id>.json and behavior_features.csv (sample_id, label, language, cluster_id + features)
- reports/behavior/<version>_summary.{json,md}: per label % pages with each pattern and severity; flows per label; top 10 critical findings with sample_ids (for me to inspect); FP check — list every BENIGN page with a critical/high finding (I'll review these: they are either real problems in my rules or label errors); timing.

## 5. Behavior-only baseline (for my ablation study)
Reuse Part 4's training/evaluation code (don't copy it): train LogReg/RF/XGBoost on js_features (Part 7) + behavior_features (Part 8) only, same shared split (data/splits/<version>), same CV/test protocol, same report format → reports/behavior_baseline/<version>/results.md and models/behavior_baseline/<version>/. CLI: `scripts/map_behavior.py train-baseline --version v0.3`. Print a comparison table: DOM-only (Part 4, same version) vs Behavior-only.

## 6. CLI — scripts/map_behavior.py
`run --version v0.3 [--force] [--workers 4]` (runs Part 7 for missing samples) · `one --sample-id <id>` / `one --file page.html [--url]` (findings with evidence chains, readable) · `describe [--markdown]` · `train-baseline --version v0.3`.

## 7. Inspector + API
- Rename the JS tab to "JS Analysis & Behavior (Part 7–8)" or add a "Behavior (Part 8)" tab: behavior_risk_score gauge; findings cards (severity colour, message); for each finding an evidence chain shown as numbered steps (line + code in monospace via textContent) — this is the key demo view; flows table; intent vector table. textContent only (XSS rule).
- Sidebar filter "has critical behavior finding".
- Dev endpoint GET /api/v1/dev/samples/{id}/behavior; public POST /api/v1/behavior {html, url}. Swagger examples.

## 8. Tests (tests/test_behavior.py + fixtures/behavior/)
One fixture per pattern, positive AND a benign look-alike negative:
- exfil: password value → var → JSON.stringify → fetch external (critical); same but to same-domain endpoint (not critical); validation-only login page that reads .value but never sends it (only credential_access, low)
- submit handler with preventDefault + XHR to api.telegram.org (critical + known endpoint)
- keylogger: keydown event.key appended to array → image beacon external
- forced redirect: top-level location.replace to external; redirect inside click handler (not forced); meta refresh external
- clipboard: writeText with a BTC address (critical); ClickFix powershell string (critical); normal "copy coupon code" button (not critical)
- download: auto a.download of .exe via Blob(atob(...)) (high+); user-click download of .pdf (not flagged)
- obfuscation: eval(atob("...")) (high); minified library only (nothing)
- function-parameter and callback (.then) propagation; template literal; encodeURIComponent wrapper keeps taint
- caps: huge script / long taint chain → truncated flag, no hang
- existing fixture js_exfiltration.html → credential_exfiltration critical with an evidence chain from the password read line to the fetch line
- vector length/order = behavior_features.yaml; CSV columns; API == CLI; library code ignored

## Constraints
- Simple, commented, "why this exists" docstrings (viva): source/sink idea, why flows not single APIs, taint propagation rules and limits, severity scheme.
- Run full test suite + ruff + black.
- Run `map_behavior.py run --version v0.3` and `train-baseline --version v0.3`; show: per-label pattern table, number of benign pages with critical/high findings (and their ids), `one --sample-id c2_phishing_000081` output, and the DOM-only vs Behavior-only comparison table.
- Update CLAUDE.md Progress (Part 8 done) and README ("Behavioral intent mapping").
- Do not commit; I will commit myself.