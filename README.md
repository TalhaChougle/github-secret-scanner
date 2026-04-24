# 🔍 GitHub Secret History Scanner

A full-stack security tool that scans GitHub repository commit history for leaked API keys, passwords, tokens, and credentials — built with **FastAPI** + **vanilla JS**.

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green?style=flat-square&logo=fastapi)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

## ✨ Features

- **Real-time streaming** — results appear as commits are scanned via Server-Sent Events
- **24 detection patterns** — AWS keys, GitHub tokens, Stripe keys, DB passwords, JWT secrets, private keys, and more
- **Full git history scan** — traverses all commits, not just the latest
- **Paste mode** — scan any text directly without a GitHub connection
- **Severity triage** — Critical / High / Medium / Low with remediation guidance
- **Export** — download findings as JSON for reporting
- **Private repo support** — provide a GitHub PAT for private repos and higher API rate limits

## 🚀 Quick Start (Local)

### 1. Clone and set up the backend

```bash
git clone https://github.com/YOUR_USERNAME/github-secret-scanner
cd github-secret-scanner/backend

python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

uvicorn main:app --reload --port 8000
```

The API is now running at `http://localhost:8000`

API docs (Swagger UI): `http://localhost:8000/docs`

### 2. Open the frontend

Open `frontend/index.html` in your browser — or serve it:

```bash
# Python simple server from the project root
python -m http.server 3000 --directory frontend
```

Then visit `http://localhost:3000`

> The frontend auto-detects localhost and points to `http://localhost:8000` for the API.

---

## 📁 Project Structure

```
github-secret-scanner/
├── backend/
│   ├── main.py          # FastAPI app, API routes, SSE streaming
│   ├── scanner.py       # GitHub API client, commit traversal logic
│   ├── patterns.py      # 24 secret detection regex patterns
│   └── requirements.txt
├── frontend/
│   └── index.html       # Single-page app (no build step needed)
├── Dockerfile           # Docker deployment
├── render.yaml          # Render.com deployment config
├── vercel.json          # Vercel deployment config (frontend)
└── README.md
```

---

## 🌐 Deployment

### Frontend → Vercel (free)

```bash
npm i -g vercel
vercel --prod
```

### Backend → Render (free tier)

1. Push to GitHub
2. Go to [render.com](https://render.com) → New Web Service
3. Connect your repo, set root directory to `backend/`
4. Build command: `pip install -r requirements.txt`
5. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
6. After deploying, copy your Render URL into `frontend/index.html`:
   ```js
   const API_BASE = 'https://your-app.onrender.com';
   ```

### Docker (self-hosted)

```bash
docker build -t secret-scanner .
docker run -p 8000:8000 secret-scanner
```

---

## 📡 API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check |
| `/api/scan?repo=owner/repo` | GET | Stream scan results (SSE) |
| `/api/scan/text` | POST | Scan pasted text content |
| `/api/patterns` | GET | List all detection patterns |
| `/api/stats` | GET | Scanner statistics |
| `/docs` | GET | Interactive Swagger UI |

### Scan parameters

| Param | Type | Default | Description |
|---|---|---|---|
| `repo` | string | required | `owner/repo` or full GitHub URL |
| `token` | string | optional | GitHub PAT (increases rate limit from 60 to 5000 req/hr) |
| `max_commits` | int | 50 | How many commits to scan (max 200) |
| `deep` | bool | true | Scan all history vs. recent commits only |

---

## 🔐 Detection Patterns

| Pattern | Severity | Category |
|---|---|---|
| AWS Access Key ID | CRITICAL | Cloud |
| GitHub Personal Access Token | CRITICAL | VCS |
| Stripe Secret Key | CRITICAL | Payment |
| Firebase Service Account | CRITICAL | Cloud |
| RSA/EC Private Key | CRITICAL | Crypto |
| Google API Key | HIGH | Cloud |
| Slack API Token | HIGH | Comms |
| Database Connection String | HIGH | Database |
| JWT Hardcoded Secret | HIGH | Crypto |
| NPM Auth Token | HIGH | Registry |
| Discord Bot Token | HIGH | Comms |
| Slack Webhook URL | MEDIUM | Comms |
| Generic Secret/Password | MEDIUM | Generic |
| Stripe Publishable Key | LOW | Payment |
| ... and more | | |

---

## ⚠️ Ethical Use

This tool is for:
- Auditing **your own** repositories
- Authorized security assessments
- Educational purposes

Always obtain proper authorization before scanning repositories you don't own. Secrets found in public repos should be reported to the repository owner.

---

## 🛠 Tech Stack

- **Backend**: Python 3.11, FastAPI, httpx (async HTTP), Server-Sent Events
- **Frontend**: Vanilla JS, no framework, no build step
- **Deployment**: Vercel (frontend) + Render/Railway (backend)

## 📄 License

MIT — see [LICENSE](LICENSE)
