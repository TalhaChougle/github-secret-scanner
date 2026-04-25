# 🔍 GitHub Secret History Scanner

> A full-stack security tool that scans GitHub repository commit history for leaked API keys, passwords, tokens, and credentials — in real time.

![Python](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## 🎯 What is this?

When developers accidentally commit secrets (API keys, passwords, tokens) to GitHub — even if they delete them in the next commit — those secrets **live forever in git history**. Anyone can scroll back through old commits and find them.

This tool automates that process for security auditing. It:

- Connects to the **real GitHub API**
- Walks through every commit in a repo's history
- Scans file contents using **24 regex detection patterns**
- Streams findings **live** as they are discovered
- Shows the exact file, line number, code context, and remediation steps

This is how tools like **TruffleHog** and **GitLeaks** work — and how attackers scan public repos for exposed credentials.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔴 Real-time streaming | Results appear live via Server-Sent Events as commits are scanned |
| 🔎 24 detection patterns | AWS, GitHub, Stripe, Google, Discord, JWT, DB passwords, private keys & more |
| 📜 Full history scan | Traverses all commits, not just the latest — secrets deleted years ago are still found |
| 📋 Paste mode | Scan any text, config file, or code snippet directly — no GitHub needed |
| 🎯 Severity triage | Critical / High / Medium / Low with exact line numbers and code context |
| 🔧 Remediation guidance | Every finding includes specific steps to fix the exposure |
| 📤 JSON export | Download findings as a report for documentation or incident response |
| 🔑 Private repo support | Add a GitHub PAT to scan private repos and get 5000 req/hr vs 60 |
| ⚡ Auto token loading | Store token in `.env` — never paste it manually again |

---

## 🖥 Demo

> Scanned `TalhaChougle/neural-trace` and found a real Google API key committed in the initial commit inside a `.env` file.

```
HIGH  |  Google API Key
      |  .env : line 1
      |  VITE_GOOGLE_API_KEY=AIzaSyC1CJ9tL22d...
      |  Commit: 19d0f1d | Author: amrshaikh | 2025-12-18
      |  Remediation: Revoke at console.cloud.google.com/apis/credentials
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Git

### 1 — Clone the repo

```bash
git clone https://github.com/TalhaChougle/github-secret-scanner.git
cd github-secret-scanner
```

### 2 — One click start (Windows)

```
Double-click start.bat
```

Your browser opens automatically at `http://localhost:3000`. Done.

### 3 — Manual start (Mac/Linux or if start.bat doesn't work)

**Terminal 1 — Backend:**
```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

**Terminal 2 — Frontend:**
```bash
cd frontend
python -m http.server 3000
```

Visit `http://localhost:3000`

### 4 — Add your GitHub token (removes rate limit)

Create `backend/.env`:
```
GITHUB_TOKEN=ghp_your_token_here
```

Get a free token at [github.com/settings/tokens](https://github.com/settings/tokens) — only needs `public_repo` scope.

This gives you **5,000 requests/hour** instead of 60 — enough to scan any repo.

---

## 📁 Project Structure

```
github-secret-scanner/
├── backend/
│   ├── main.py          # FastAPI app — API routes, SSE streaming, .env loading
│   ├── scanner.py       # GitHub API client — commit traversal, file fetching
│   ├── patterns.py      # 24 secret detection regex patterns with metadata
│   └── requirements.txt
├── frontend/
│   └── index.html       # Full SPA — no framework, no build step needed
├── start.bat            # One-click Windows launcher
├── start.sh             # One-click Mac/Linux launcher
├── Dockerfile           # Docker deployment
├── render.yaml          # Render.com backend deployment config
├── vercel.json          # Vercel frontend deployment config
└── README.md
```

---

## 🔐 Detection Patterns

| Pattern | Severity | Example Match |
|---|---|---|
| AWS Access Key ID | 🔴 CRITICAL | `AKIA` + 16 chars |
| GitHub Personal Access Token | 🔴 CRITICAL | `ghp_` + 36 chars |
| Stripe Secret Key | 🔴 CRITICAL | `sk_live_` + 24 chars |
| Firebase Service Account | 🔴 CRITICAL | `"type": "service_account"` |
| RSA / EC Private Key | 🔴 CRITICAL | `-----BEGIN RSA PRIVATE KEY-----` |
| Google API Key | 🟠 HIGH | `AIza` + 35 chars |
| Slack API Token | 🟠 HIGH | `xox[baprs]-` |
| Database Connection String | 🟠 HIGH | `postgres://user:pass@host` |
| JWT Hardcoded Secret | 🟠 HIGH | `jwt_secret = "..."` |
| Discord Bot Token | 🟠 HIGH | Discord token format |
| NPM Auth Token | 🟠 HIGH | `_authToken=` |
| SendGrid API Key | 🟠 HIGH | `SG.` + 65 chars |
| Slack Webhook URL | 🟡 MEDIUM | `hooks.slack.com/services/...` |
| Generic Secret / Password | 🟡 MEDIUM | `password = "..."` |
| Stripe Publishable Key | 🟢 LOW | `pk_live_` |
| + 9 more | | |

---

## 📡 API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check + token status |
| `/api/scan` | GET | Stream scan via SSE |
| `/api/scan/text` | POST | Scan pasted text |
| `/api/patterns` | GET | All 24 detection patterns |
| `/api/stats` | GET | Scanner statistics |
| `/docs` | GET | Interactive Swagger UI |

### Query parameters for `/api/scan`

| Param | Type | Default | Description |
|---|---|---|---|
| `repo` | string | required | `owner/repo` or full GitHub URL |
| `token` | string | optional | GitHub PAT — overrides `.env` token |
| `max_commits` | int | 50 | Commits to scan (max 500) |
| `deep` | bool | true | Full history vs recent only |

---

## 🌐 Deployment

### Backend → Render (free)

1. Go to [render.com](https://render.com) → New Web Service
2. Connect this repo
3. Root directory: `backend`
4. Build: `pip install -r requirements.txt`
5. Start: `uvicorn main:app --host 0.0.0.0 --port $PORT`
6. Add env var: `GITHUB_TOKEN` = your token

### Frontend → Netlify (free)

1. Go to [netlify.com](https://netlify.com)
2. Drag and drop the `frontend/` folder
3. Update `DEPLOYED_API` in `frontend/index.html` with your Render URL

### Docker

```bash
docker build -t secret-scanner .
docker run -p 8000:8000 -e GITHUB_TOKEN=ghp_xxx secret-scanner
```

---

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, FastAPI, httpx (async) |
| Streaming | Server-Sent Events (SSE) |
| Frontend | Vanilla JS, no framework, no build step |
| Detection | Regex pattern matching (24 patterns) |
| GitHub data | GitHub REST API v3 |
| Deployment | Render (backend) + Netlify (frontend) |

---

## ⚠️ Ethical Use

This tool is intended for:
- Auditing **your own** repositories
- Authorized penetration testing engagements
- Security awareness and education

Always get proper authorization before scanning repositories you do not own. If you find exposed secrets in someone else's public repo, report them responsibly to the owner.

---

## 📄 License

MIT — free to use, modify, and distribute.

---

<p align="center">Built as part of a cybersecurity portfolio · <a href="https://github.com/TalhaChougle">@TalhaChougle</a></p>