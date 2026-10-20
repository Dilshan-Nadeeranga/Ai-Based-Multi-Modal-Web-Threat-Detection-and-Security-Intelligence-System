# ScamTrace — AI-Based Multi-Modal Web Threat Detection and Security Intelligence System

**SLIIT IT4010 Research Project (2026 Jul) · Project ID: J26-SE-316 · Information Assurance & Security (SE)**

ScamTrace is an integrated research platform that detects and explains web threats —
phishing, fraudulent e-commerce, investment scams, brand impersonation and insecure
code — by **correlating multiple evidence sources** (URL/domain, webpage content,
behavioral intent, social-media visuals and repository code) instead of relying on
blacklists or single-modality detection.

## 👥 Team & Components

| Component | Member | Description | Port |
|---|---|---|---|
| **C1 — Intelligent URL & Domain Analyzer** | W A D A K Appuhamy (IT23479746) | Lexical/structural URL features, DNS/RDAP/WHOIS intelligence, newly-registered-domain and DGA detection, short-link resolution, redirect-chain analysis, ML risk scoring | `8001` |
| **C2 — Tri-Modal HTML, Content & Behavioral Intent Analyzer** | Dilshan N (IT23250574) | DOM structure analysis, multilingual NLP (XLM-RoBERTa — English/Sinhala/Tamil), static JavaScript/dataflow intent detection, tri-modal fusion | `8002` |
| **C3 — Social Media & Web Visual Threat Analyzer** | M.T.C. Peiris (IT23201200) | OCR, CLIP zero-shot brand detection, YOLO logo/UI detection, visual similarity, social-"bait" → web-"trap" cross-source consistency scoring | `8003` |
| **C4 — Code Quality & Vulnerability Auditor** | M.S.N. Peiris (IT23201132) | AST/SAST repository auditing (Tree-sitter + Semgrep), context-grounded LLM-assisted remediation, HITL analyst review, preliminary repository risk score | `8000` |

**Shared services**

| Service | Description | Port |
|---|---|---|
| API Gateway (`backend/api-gateway`) | Express gateway: auth, routing, rate limiting | `5000` |
| Dashboard (`frontend/scamtrace-dashboard`) | React + Vite web dashboard for all components | `5173` |
| ThreatRadar (`ingestion/threat-radar`) | Discovery of suspicious social posts, URLs and domains | — |

## 🏗️ Architecture

```
            Social posts · URLs · Domains · User submissions · GitHub repos
                                     │
                              ThreatRadar (discovery)
                                     │
        ┌──────────────┬─────────────┼──────────────┬───────────────┐
        ▼              ▼             ▼              ▼               │
   C1 URL/Domain   C2 HTML/Content  C3 Social/Visual          C4 Repository
   Analyzer        & Behavior       Threat Analyzer           Auditor + LLM
   (pre-execution  (static tri-     (brand impersonation,     remediation
   screening)      modal analysis)  bait→trap correlation)    (HITL reviewed)
        │              │             │                            │
        └──────────────┴──────┬──────┘                            │
                              ▼                                   ▼
                   Evidence fusion & explainable          Repository security
                   web-threat assessment                  report + risk score
                              │                                   │
                              └──────────► API Gateway ◄──────────┘
                                               │
                                     React Dashboard (ScamTrace)
```

## 🚀 Getting Started

### Prerequisites

- Python 3.11+, Node.js 18+, PostgreSQL, Git

### Run the services

```powershell
# API Gateway (port 5000)
cd backend/api-gateway
npm install
npm run dev

# Frontend dashboard (port 5173)
cd frontend/scamtrace-dashboard
npm install
npm run dev

# C1 — URL & Domain Analyzer (port 8001)
cd services/c1-url-domain-analyzer
python -m venv .venv && .venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload --port 8001

# C2 — HTML/Content/Behavior Analyzer (port 8002)
cd services/c2-html-content-behavior-analyzer
python -m venv .venv && .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scripts/run_api.py

# C3 — Social Visual Analyzer (port 8003)
cd services/c3-social-visual-analyzer
python -m venv .venv && .venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8003

# C4 — Code Vulnerability Auditor (port 8000)
cd services/c4-code-vulnerability-auditor
python -m venv .venv && .venv\Scripts\Activate.ps1
pip install -r requirements.txt
.venv\Scripts\python -m uvicorn main:app --port 8000
```

Each service has its own `.env.example` — copy to `.env` and configure before starting.

## 📁 Repository Structure

```
J26-SE-316/
├── backend/api-gateway/            # Express gateway (auth, routing)      :5000
├── frontend/scamtrace-dashboard/   # React + Vite dashboard              :5173
├── services/
│   ├── c1-url-domain-analyzer/     # C1 — FastAPI                        :8001
│   ├── c2-html-content-behavior-analyzer/  # C2 — FastAPI                :8002
│   ├── c3-social-visual-analyzer/  # C3 — FastAPI                        :8003
│   └── c4-code-vulnerability-auditor/      # C4 — FastAPI                :8000
├── ingestion/threat-radar/         # ThreatRadar discovery layer
├── research/                       # Cross-component research notes
└── docs/                           # Project documents (TAF, etc.)
```

## 🧰 Technology Stack

- **Backends:** Python FastAPI (C1–C4), Node.js Express (gateway)
- **Frontend:** React, Vite, Tailwind CSS
- **ML / NLP / Vision:** scikit-learn, XGBoost/LightGBM, XLM-RoBERTa, CLIP, YOLO, OCR
- **Code analysis:** Tree-sitter, Semgrep, custom web-security rules, LLM-assisted remediation
- **Storage:** PostgreSQL (per component), threat-intelligence feeds

## 📚 Documentation

- Project documents (Topic Assessment Form): [`docs/`](docs/README.md)
- C2 docs: `services/c2-html-content-behavior-analyzer/docs/`
- C3 docs: `services/c3-social-visual-analyzer/docs/`
- C4 README + research: [`services/c4-code-vulnerability-auditor/`](services/c4-code-vulnerability-auditor/README.md)
- Cross-component research notes: `research/`

## ⚖️ Responsible Research

Malicious samples are analyzed statically or in isolated environments; no live
phishing infrastructure is attacked. Repository auditing never executes target
code, and LLM-suggested patches are applied only after human (analyst) approval.
Data handling follows Sri Lanka's Personal Data Protection Act No. 9 of 2022 and
Computer Crime Act No. 24 of 2007.
