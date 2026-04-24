"""
GitHub repository scanner — fetches commits and file content via GitHub API
and runs secret detection patterns against them.
"""

import asyncio
import httpx
import base64
import re
from typing import AsyncGenerator
from patterns import scan_content, SEVERITY_ORDER

GITHUB_API = "https://api.github.com"

# File extensions worth scanning
SCANNABLE_EXTENSIONS = {
    ".env", ".env.local", ".env.development", ".env.production", ".env.bak",
    ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".py", ".rb", ".php", ".java", ".go", ".rs", ".cs", ".cpp", ".c",
    ".sh", ".bash", ".zsh", ".fish", ".ps1",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".config",
    ".xml", ".properties", ".gradle",
    ".tf", ".tfvars",
    ".dockerfile", ".dockercompose",
    ".gitconfig", ".npmrc", ".pypirc",
    ".pem", ".key", ".cert", ".crt",
    "makefile", "dockerfile",
}

# Always skip these
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".woff", ".woff2", ".ttf",
    ".mp4", ".mp3", ".avi", ".mov", ".lock",
    ".min.js", ".min.css", ".map",
}

# Skip these directories
SKIP_DIRS = {
    "node_modules", ".git", "vendor", "dist", "build", "__pycache__",
    ".next", ".nuxt", "coverage", ".pytest_cache", "venv", ".venv",
}


def parse_repo(repo_input: str) -> tuple[str, str] | None:
    """Parse owner/repo from various input formats."""
    repo_input = repo_input.strip()

    # Full URL
    match = re.match(r'https?://github\.com/([^/]+)/([^/\s?#]+)', repo_input)
    if match:
        return match.group(1), match.group(2).rstrip(".git")

    # owner/repo format
    match = re.match(r'^([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+)$', repo_input)
    if match:
        return match.group(1), match.group(2)

    return None


def make_headers(token: str | None = None) -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "github-secret-scanner/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def get_repo_info(client: httpx.AsyncClient, owner: str, repo: str, token: str | None) -> dict:
    resp = await client.get(f"{GITHUB_API}/repos/{owner}/{repo}", headers=make_headers(token))
    resp.raise_for_status()
    return resp.json()


async def get_commits(client: httpx.AsyncClient, owner: str, repo: str, token: str | None, max_commits: int = 100) -> list[dict]:
    """Fetch recent commits from the default branch."""
    commits = []
    page = 1
    per_page = min(max_commits, 100)

    while len(commits) < max_commits:
        resp = await client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/commits",
            headers=make_headers(token),
            params={"per_page": per_page, "page": page},
            timeout=30,
        )
        if resp.status_code == 409:  # empty repo
            break
        resp.raise_for_status()
        batch = resp.json()
        if not batch:
            break
        commits.extend(batch)
        if len(batch) < per_page:
            break
        page += 1

    return commits[:max_commits]


async def get_tree(client: httpx.AsyncClient, owner: str, repo: str, sha: str, token: str | None) -> list[dict]:
    """Get full file tree for a commit."""
    resp = await client.get(
        f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{sha}",
        headers=make_headers(token),
        params={"recursive": "1"},
        timeout=30,
    )
    if resp.status_code in (404, 409):
        return []
    resp.raise_for_status()
    data = resp.json()
    return data.get("tree", [])


async def get_file_content(client: httpx.AsyncClient, owner: str, repo: str, path: str, ref: str, token: str | None) -> str | None:
    """Fetch and decode a file's content at a specific commit."""
    try:
        resp = await client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}",
            headers=make_headers(token),
            params={"ref": ref},
            timeout=20,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if data.get("encoding") == "base64" and data.get("content"):
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


def should_scan_file(path: str) -> bool:
    """Decide if a file path is worth scanning."""
    lower = path.lower()

    # Skip blacklisted dirs
    for skip in SKIP_DIRS:
        if f"/{skip}/" in f"/{lower}/" :
            return False

    # Skip blacklisted extensions
    for ext in SKIP_EXTENSIONS:
        if lower.endswith(ext):
            return False

    # High-value filenames (no extension check needed)
    high_value = [".env", ".envrc", "secrets", "credentials", "config", "settings",
                  ".npmrc", ".pypirc", ".gitconfig", "id_rsa", "id_ed25519"]
    basename = lower.split("/")[-1]
    for hv in high_value:
        if hv in basename:
            return True

    # Check extension
    for ext in SCANNABLE_EXTENSIONS:
        if lower.endswith(ext):
            return True

    # Scan files with no extension if they're small config-like names
    if "." not in basename:
        return basename in {"makefile", "dockerfile", "procfile", "gemfile", "rakefile"}

    return False


async def scan_repository(
    owner: str,
    repo: str,
    token: str | None,
    max_commits: int = 50,
    scan_all_history: bool = True,
) -> AsyncGenerator[dict, None]:
    """
    Main scanner coroutine. Yields progress events and findings as dicts.
    Event types: 'progress', 'finding', 'done', 'error'
    """
    async with httpx.AsyncClient(timeout=30) as client:
        # --- Repo info ---
        try:
            repo_info = await get_repo_info(client, owner, repo, token)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                yield {"type": "error", "message": f"Repository {owner}/{repo} not found or is private. Provide a GitHub token for private repos."}
            elif e.response.status_code == 403:
                yield {"type": "error", "message": "Rate limited by GitHub API. Provide a GitHub token for higher limits (5000 req/hr vs 60 req/hr)."}
            else:
                yield {"type": "error", "message": f"GitHub API error: {e.response.status_code}"}
            return

        yield {
            "type": "progress",
            "message": f"Found repo: {repo_info['full_name']} ({repo_info.get('stargazers_count',0):,} ★)",
            "percent": 5,
        }

        # --- Commits ---
        yield {"type": "progress", "message": "Fetching commit history...", "percent": 10}

        try:
            commits = await get_commits(client, owner, repo, token, max_commits=max_commits)
        except Exception as e:
            yield {"type": "error", "message": f"Failed to fetch commits: {str(e)}"}
            return

        total_commits = len(commits)
        yield {
            "type": "progress",
            "message": f"Found {total_commits} commits to scan",
            "percent": 15,
        }

        if total_commits == 0:
            yield {"type": "done", "total_commits": 0, "files_scanned": 0, "findings_count": 0}
            return

        # Decide which commits to scan
        if scan_all_history:
            commits_to_scan = commits
        else:
            commits_to_scan = commits[:10]  # latest 10 only

        all_findings = []
        seen_matches = set()  # deduplicate identical secrets
        files_scanned = 0

        # --- Scan each commit ---
        for i, commit in enumerate(commits_to_scan):
            sha = commit["sha"]
            short_sha = sha[:7]
            author = commit["commit"]["author"]["name"]
            date = commit["commit"]["author"]["date"][:10]
            message = commit["commit"]["message"].splitlines()[0][:60]

            percent = 15 + int((i / len(commits_to_scan)) * 75)
            yield {
                "type": "progress",
                "message": f"[{i+1}/{len(commits_to_scan)}] {short_sha} — {message[:40]}",
                "percent": percent,
            }

            # Get the file tree at this commit
            try:
                tree = await get_tree(client, owner, repo, sha, token)
            except Exception:
                continue

            # Filter to scannable files
            scannable = [f for f in tree if f.get("type") == "blob" and should_scan_file(f.get("path", ""))]

            # Limit files per commit to avoid API hammering
            # For older commits, only scan high-value files
            if i > 5:
                high_value_paths = [".env", "config", "secret", "credential", "key", "token", "password"]
                scannable = [f for f in scannable if any(hv in f["path"].lower() for hv in high_value_paths)]

            # Cap at 20 files per commit
            scannable = scannable[:20]

            for file_item in scannable:
                path = file_item["path"]
                content = await get_file_content(client, owner, repo, path, sha, token)
                if not content:
                    continue

                files_scanned += 1
                findings = scan_content(content, path)

                for finding in findings:
                    # Deduplicate: same secret in same file across commits
                    dedup_key = (finding["pattern_id"], finding["filename"], finding["match"])
                    if dedup_key in seen_matches:
                        continue
                    seen_matches.add(dedup_key)

                    finding_with_meta = {
                        **finding,
                        "commit": short_sha,
                        "commit_full": sha,
                        "author": author,
                        "date": date,
                        "commit_message": message,
                        "repo": f"{owner}/{repo}",
                    }
                    all_findings.append(finding_with_meta)

                    yield {
                        "type": "finding",
                        "finding": finding_with_meta,
                    }

            # Small delay to be respectful of rate limits
            await asyncio.sleep(0.1)

        # Sort findings by severity
        all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

        yield {
            "type": "done",
            "total_commits": total_commits,
            "commits_scanned": len(commits_to_scan),
            "files_scanned": files_scanned,
            "findings_count": len(all_findings),
        }
