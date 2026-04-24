"""
Secret detection patterns for the GitHub Secret History Scanner.
Each pattern includes a name, severity, regex, and remediation guidance.
"""

import re

PATTERNS = [
    {
        "id": "aws_access_key",
        "name": "AWS Access Key ID",
        "severity": "CRITICAL",
        "regex": re.compile(r'AKIA[0-9A-Z]{16}'),
        "category": "Cloud Credentials",
        "remediation": "Immediately revoke this key in AWS IAM console. Check CloudTrail for unauthorized usage. Rotate all associated secrets.",
    },
    {
        "id": "aws_secret_key",
        "name": "AWS Secret Access Key",
        "severity": "CRITICAL",
        "regex": re.compile(r'(?i)aws.{0,20}secret.{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]'),
        "category": "Cloud Credentials",
        "remediation": "Revoke the AWS key pair immediately. Audit CloudTrail logs for unauthorized API calls.",
    },
    {
        "id": "github_pat",
        "name": "GitHub Personal Access Token",
        "severity": "CRITICAL",
        "regex": re.compile(r'ghp_[a-zA-Z0-9]{36}'),
        "category": "VCS Tokens",
        "remediation": "Revoke at github.com/settings/tokens. This may expose private repositories and org data.",
    },
    {
        "id": "github_oauth",
        "name": "GitHub OAuth Token",
        "severity": "CRITICAL",
        "regex": re.compile(r'gho_[a-zA-Z0-9]{36}'),
        "category": "VCS Tokens",
        "remediation": "Revoke the OAuth token immediately. Audit connected applications.",
    },
    {
        "id": "github_app_token",
        "name": "GitHub App Token",
        "severity": "HIGH",
        "regex": re.compile(r'(ghu|ghs)_[a-zA-Z0-9]{36}'),
        "category": "VCS Tokens",
        "remediation": "Revoke the GitHub App installation token. Regenerate app credentials.",
    },
    {
        "id": "stripe_secret",
        "name": "Stripe Secret Key",
        "severity": "CRITICAL",
        "regex": re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
        "category": "Payment Credentials",
        "remediation": "Roll key at dashboard.stripe.com/apikeys. Check for unauthorized charges immediately.",
    },
    {
        "id": "stripe_restricted",
        "name": "Stripe Restricted Key",
        "severity": "HIGH",
        "regex": re.compile(r'rk_live_[0-9a-zA-Z]{24,}'),
        "category": "Payment Credentials",
        "remediation": "Revoke and regenerate the restricted key in the Stripe dashboard.",
    },
    {
        "id": "stripe_publishable",
        "name": "Stripe Publishable Key",
        "severity": "LOW",
        "regex": re.compile(r'pk_live_[0-9a-zA-Z]{24,}'),
        "category": "Payment Credentials",
        "remediation": "Publishable keys are less sensitive but should be rotated if leaked alongside secret keys.",
    },
    {
        "id": "google_api_key",
        "name": "Google API Key",
        "severity": "HIGH",
        "regex": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        "category": "Cloud Credentials",
        "remediation": "Revoke at console.cloud.google.com/apis/credentials. Restrict key usage by API and referrer.",
    },
    {
        "id": "google_oauth",
        "name": "Google OAuth Client Secret",
        "severity": "HIGH",
        "regex": re.compile(r'(?i)google.{0,20}[\'"][0-9a-zA-Z\-_]{24}[\'"]'),
        "category": "Cloud Credentials",
        "remediation": "Rotate the OAuth client secret in Google Cloud Console.",
    },
    {
        "id": "slack_token",
        "name": "Slack API Token",
        "severity": "HIGH",
        "regex": re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'),
        "category": "Communication",
        "remediation": "Revoke token at api.slack.com/apps. Audit what the token had access to.",
    },
    {
        "id": "slack_webhook",
        "name": "Slack Webhook URL",
        "severity": "MEDIUM",
        "regex": re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24,}'),
        "category": "Communication",
        "remediation": "Revoke webhook in Slack API settings. Anyone with this URL can post to your channel.",
    },
    {
        "id": "discord_token",
        "name": "Discord Bot Token",
        "severity": "HIGH",
        "regex": re.compile(r'[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}'),
        "category": "Communication",
        "remediation": "Regenerate token in Discord Developer Portal. Audit bot permissions and recent actions.",
    },
    {
        "id": "discord_webhook",
        "name": "Discord Webhook URL",
        "severity": "MEDIUM",
        "regex": re.compile(r'https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[a-zA-Z0-9_-]{68}'),
        "category": "Communication",
        "remediation": "Delete the webhook in Discord server settings and create a new one.",
    },
    {
        "id": "jwt_secret",
        "name": "Hardcoded JWT Secret",
        "severity": "HIGH",
        "regex": re.compile(r'(?i)(jwt.?secret|jwt.?key|token.?secret)\s*[=:]\s*[\'"][^\'"]{8,}[\'"]'),
        "category": "Cryptographic",
        "remediation": "Rotate the JWT secret. All existing tokens signed with this secret must be invalidated.",
    },
    {
        "id": "private_key",
        "name": "RSA/EC Private Key",
        "severity": "CRITICAL",
        "regex": re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        "category": "Cryptographic",
        "remediation": "Immediately revoke and reissue all certificates signed with this key. Rotate any associated services.",
    },
    {
        "id": "db_password",
        "name": "Database Password",
        "severity": "HIGH",
        "regex": re.compile(r'(?i)(db_pass|database_password|postgres_password|mysql_password|mongo_password)\s*[=:]\s*[\'"]?[^\s\'"]{6,}[\'"]?'),
        "category": "Database",
        "remediation": "Change the database password immediately. Audit DB access logs for unauthorized connections.",
    },
    {
        "id": "db_connection_string",
        "name": "Database Connection String",
        "severity": "HIGH",
        "regex": re.compile(r'(postgres|mysql|mongodb|redis|mssql)://[^:\s]+:[^@\s]+@[^\s]+'),
        "category": "Database",
        "remediation": "Rotate database credentials. Update connection strings in your secrets manager.",
    },
    {
        "id": "sendgrid_key",
        "name": "SendGrid API Key",
        "severity": "HIGH",
        "regex": re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'),
        "category": "Email Services",
        "remediation": "Revoke key at app.sendgrid.com/settings/api_keys. Check for spam/phishing sent via your account.",
    },
    {
        "id": "twilio_key",
        "name": "Twilio API Key",
        "severity": "HIGH",
        "regex": re.compile(r'SK[a-f0-9]{32}'),
        "category": "Communication",
        "remediation": "Revoke the API key in the Twilio console. Check for unauthorized SMS/calls.",
    },
    {
        "id": "npm_token",
        "name": "NPM Auth Token",
        "severity": "HIGH",
        "regex": re.compile(r'//registry\.npmjs\.org/:_authToken=[a-zA-Z0-9_-]{36,}'),
        "category": "Package Registry",
        "remediation": "Revoke token at npmjs.com/settings/tokens. Check for unauthorized package publishes.",
    },
    {
        "id": "firebase_key",
        "name": "Firebase/GCP Service Account",
        "severity": "CRITICAL",
        "regex": re.compile(r'"type":\s*"service_account"'),
        "category": "Cloud Credentials",
        "remediation": "Delete the service account key in Firebase/GCP console. Audit what data was accessible.",
    },
    {
        "id": "generic_secret",
        "name": "Generic Secret / Password",
        "severity": "MEDIUM",
        "regex": re.compile(r'(?i)(secret|password|passwd|api_key|apikey|auth_token)\s*[=:]\s*[\'"][^\'"]{8,}[\'"]'),
        "category": "Generic",
        "remediation": "Evaluate and rotate this credential. Store secrets in environment variables or a secrets manager.",
    },
    {
        "id": "generic_token",
        "name": "Generic Bearer Token",
        "severity": "MEDIUM",
        "regex": re.compile(r'(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}'),
        "category": "Generic",
        "remediation": "Rotate the token and ensure it is never committed to source control.",
    },
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def scan_content(content: str, filename: str = "") -> list:
    """Scan a string of content for secrets. Returns list of findings."""
    findings = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
        # Skip obvious false positives
        if any(skip in line.lower() for skip in [
            "example", "placeholder", "your_", "<your", "xxx", "changeme",
            "todo", "fixme", "test_key", "sample", "replace_with"
        ]):
            continue

        for pattern in PATTERNS:
            match = pattern["regex"].search(line)
            if match:
                # Build context window (3 lines around the finding)
                start = max(0, line_num - 2)
                end = min(len(lines), line_num + 1)
                context_lines = lines[start:end]

                findings.append({
                    "pattern_id": pattern["id"],
                    "type": pattern["name"],
                    "severity": pattern["severity"],
                    "category": pattern["category"],
                    "remediation": pattern["remediation"],
                    "line_number": line_num,
                    "line_content": line.strip()[:200],  # truncate long lines
                    "match": match.group(0)[:60] + ("..." if len(match.group(0)) > 60 else ""),
                    "context": context_lines,
                    "filename": filename,
                })
                break  # one finding per line per scan pass

    return findings
