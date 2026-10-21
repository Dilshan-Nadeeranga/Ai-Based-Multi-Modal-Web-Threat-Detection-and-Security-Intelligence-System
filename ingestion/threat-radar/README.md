# ThreatRadar

Domain-list downloads from [domains-monitor.com](https://domains-monitor.com/api/), plus Telegram / Reddit watch tooling.  
**Next.js** frontend (port 3000) + **Express** backend (port 4000).

## Prerequisites

- Node.js 20+
- Copy env files before the first run (see [Configuration](#configuration))

## Local development

Use **two terminals** — start the backend first, then the frontend.

### 1. Backend (port 4000)

```powershell
cd "ingestion\threat-radar\backend"
copy .env.example .env
# Edit .env — at least set DOMAINS_MONITOR_TOKEN if you use domain downloads

npm install
npm run dev
```

- `npm run dev` — auto-reload (`node --watch server.js`)
- `npm start` — production-style (`node server.js`)

Health / API base: [http://localhost:4000](http://localhost:4000)  
API routes are under `/api/...`.

### 2. Frontend (port 3000)

```powershell
cd "ingestion\threat-radar\frontend"
# Create .env.local (or .env) if missing:
#   BACKEND_URL=http://localhost:4000

npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

The Next.js app proxies `/api/*` to `BACKEND_URL` (see `frontend/next.config.ts`).  
If you change `BACKEND_URL`, restart `npm run dev`.

### Quick checklist

| Piece | Directory | Command | URL |
|---|---|---|---|
| Backend | `ingestion\threat-radar\backend` | `npm run dev` | http://localhost:4000 |
| Frontend | `ingestion\threat-radar\frontend` | `npm run dev` | http://localhost:3000 |

## Configuration

### Backend — `backend/.env`

Copy from `backend/.env.example`. Minimum for domain downloads:

```env
DOMAINS_MONITOR_TOKEN=your_token_here
PORT=4000
DOWNLOAD_CRON=15 14 * * *    # 7:45 PM Sri Lanka (14:15 UTC)
AUTO_DOWNLOAD=true
DAILY_ZONE=dailyupdate
DAILY_FORMAT=text
```

Optional scrapers (Telegram / Reddit), database, and Backblaze settings are documented in `.env.example`.  
Keep `SCRAPER_ENABLED=false` locally unless you intentionally run scrapers (`SCRAPER_ALLOW_LOCAL=true`).

### Frontend — `frontend/.env.local` (or `frontend/.env`)

```env
BACKEND_URL=http://localhost:4000
```

`BACKEND_URL` is **server-only** (used by Next.js rewrites). It is not exposed to the browser.

## Deploy frontend to Netlify

### 1. Deploy backend first

Deploy the `backend/` folder to a service that keeps Node.js running (e.g. [Render](https://render.com), [Railway](https://railway.app), [Fly.io](https://fly.io)).

Set the environment variables from `backend/.env.example` in that service's dashboard.  
Note the public URL, e.g. `https://threatradar.onrender.com`.

### 2. Deploy frontend to Netlify

1. Push this repo to GitHub.
2. Log in to [Netlify](https://app.netlify.com) → **Add new site → Import from Git**.
3. Select your GitHub repo.
4. Netlify auto-detects the settings from `netlify.toml` — no changes needed.
5. Go to **Site configuration → Environment variables → Add variable**:
   - Key: `BACKEND_URL`
   - Value: `https://threatradar.onrender.com`
6. Click **Deploy site**.

The frontend proxies all `/api/*` requests through Netlify to your backend — the backend URL never appears in the browser.

## CLI download (manual)

```powershell
cd "ingestion\threat-radar\backend"
node scripts/download.js dailyupdate text --dated
```

Saves a dated file like `dailyupdate_2026-06-16.txt` to `backend/data/downloads/`.

## Run ThreatRadar (quick)

Backend (port 4000) — terminal 1:

```powershell
cd "ingestion\threat-radar\backend"
npm run dev
```

Frontend (port 3000) — terminal 2:

```powershell
cd "ingestion\threat-radar\frontend"
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). Backend API: [http://localhost:4000](http://localhost:4000).
