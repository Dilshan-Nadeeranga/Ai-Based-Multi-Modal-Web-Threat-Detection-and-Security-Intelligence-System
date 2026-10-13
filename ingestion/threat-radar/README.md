# ThreatRadar

Download domain lists from [domains-monitor.com](https://domains-monitor.com/api/) — Next.js frontend + Express backend.

## Local development

```powershell
# Install all dependencies
npm run install:all

# Start backend (port 4000)
cd backend
node server.js      # or: npm run dev

# Start frontend (port 3000)
cd frontend
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

## Configuration

### Backend — `backend/.env`
```env
DOMAINS_MONITOR_TOKEN=your_token_here
PORT=4000
DOWNLOAD_CRON=15 14 * * *    # 7:45 PM Sri Lanka (14:15 UTC)
AUTO_DOWNLOAD=true
DAILY_ZONE=dailyupdate
DAILY_FORMAT=text
```

### Frontend — `frontend/.env.local`
```env
BACKEND_URL=http://localhost:4000
```

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
cd backend
node scripts/download.js dailyupdate text --dated
```

Saves a dated file like `dailyupdate_2026-06-16.txt` to `backend/data/downloads/`.
