# scanner.py - Full security scanner with severity scoring
import requests
import ssl
import socket
import json
import urllib.parse
from datetime import datetime, timezone

SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}

SECURITY_HEADERS = [
    {"name": "Content-Security-Policy",        "severity": "high",     "fix": "Add a Content-Security-Policy header to prevent XSS attacks. Start with: Content-Security-Policy: default-src 'self'"},
    {"name": "Strict-Transport-Security",       "severity": "high",     "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"},
    {"name": "X-Frame-Options",                 "severity": "medium",   "fix": "Add: X-Frame-Options: DENY to prevent clickjacking attacks"},
    {"name": "X-Content-Type-Options",          "severity": "medium",   "fix": "Add: X-Content-Type-Options: nosniff"},
    {"name": "Referrer-Policy",                 "severity": "low",      "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin"},
    {"name": "Permissions-Policy",              "severity": "low",      "fix": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"},
    {"name": "Cross-Origin-Opener-Policy",      "severity": "low",      "fix": "Add: Cross-Origin-Opener-Policy: same-origin"},
    {"name": "Cross-Origin-Resource-Policy",    "severity": "low",      "fix": "Add: Cross-Origin-Resource-Policy: same-origin"},
]

EXPOSED_PATHS = [
    "/.env", "/.git/HEAD", "/config.php", "/wp-config.php",
    "/.htaccess", "/server-status", "/phpinfo.php", "/.DS_Store",
]

INFO_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

def _issue(title, detail, severity, fix, category):
    return {
        "title": title,
        "detail": detail,
        "severity": severity,
        "fix": fix,
        "category": category,
    }

def _check_tls(hostname):
    issues = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()

                # TLS version check
                if tls_version in ("TLSv1", "TLSv1.1"):
                    issues.append(_issue(
                        f"Outdated TLS version ({tls_version})",
                        f"Server negotiated {tls_version} which is deprecated and insecure.",
                        "critical",
                        "Upgrade to TLS 1.2 minimum, preferably TLS 1.3.",
                        "tls"
                    ))

                # Certificate expiry
                expire_str = cert.get("notAfter", "")
                if expire_str:
                    expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (expire_dt - datetime.now(timezone.utc)).days
                    if days_left < 0:
                        issues.append(_issue(
                            "SSL certificate has expired",
                            f"Certificate expired {abs(days_left)} days ago.",
                            "critical",
                            "Renew your SSL certificate immediately.",
                            "tls"
                        ))
                    elif days_left < 30:
                        issues.append(_issue(
                            f"SSL certificate expires soon ({days_left} days)",
                            f"Certificate expires on {expire_str}.",
                            "high",
                            f"Renew your SSL certificate. Only {days_left} days remaining.",
                            "tls"
                        ))

    except ssl.SSLCertVerificationError as e:
        issues.append(_issue(
            "SSL certificate verification failed",
            str(e),
            "critical",
            "Install a valid SSL certificate from a trusted Certificate Authority.",
            "tls"
        ))
    except ssl.SSLError as e:
        issues.append(_issue(
            "SSL handshake error",
            str(e),
            "high",
            "Check your SSL/TLS configuration.",
            "tls"
        ))
    except Exception:
        pass
    return issues

def _check_redirects(url):
    issues = []
    try:
        session = requests.Session()
        resp = session.get(url, allow_redirects=False, timeout=8)
        chain = [url]
        max_hops = 10
        hops = 0
        while resp.is_redirect and hops < max_hops:
            location = resp.headers.get("Location", "")
            if not location:
                break
            # Resolve relative redirects
            location = urllib.parse.urljoin(chain[-1], location)
            chain.append(location)
            # Detect HTTPS → HTTP downgrade
            if chain[-2].startswith("https://") and location.startswith("http://"):
                issues.append(_issue(
                    "HTTPS to HTTP downgrade in redirect chain",
                    f"Redirect from {chain[-2]} goes to {location} (HTTP).",
                    "critical",
                    "Ensure all redirects stay on HTTPS.",
                    "redirects"
                ))
            resp = session.get(location, allow_redirects=False, timeout=8)
            hops += 1

        if hops >= max_hops:
            issues.append(_issue(
                "Redirect loop detected",
                f"More than {max_hops} redirects — possible loop.",
                "medium",
                "Fix your redirect configuration to avoid loops.",
                "redirects"
            ))
    except Exception:
        pass
    return issues

def _check_headers(headers):
    issues = []
    for hdr in SECURITY_HEADERS:
        if hdr["name"] not in headers:
            issues.append(_issue(
                f"Missing header: {hdr['name']}",
                f"The {hdr['name']} header was not found in the server response.",
                hdr["severity"],
                hdr["fix"],
                "headers"
            ))
    return issues

def _check_info_disclosure(headers):
    issues = []
    for hdr in INFO_HEADERS:
        if hdr in headers:
            val = headers[hdr]
            issues.append(_issue(
                f"Server information disclosed: {hdr}",
                f"Header '{hdr}' reveals: {val}",
                "low",
                f"Remove or obscure the {hdr} response header to avoid revealing stack details.",
                "disclosure"
            ))
    return issues

def _check_cookies(headers):
    issues = []
    raw = headers.get("Set-Cookie", "")
    if not raw:
        return issues
    cookies = raw if isinstance(raw, list) else [raw]
    for cookie in cookies:
        name = cookie.split("=")[0].strip()
        lower = cookie.lower()
        if "secure" not in lower:
            issues.append(_issue(
                f"Cookie missing Secure flag: {name}",
                f"Cookie '{name}' can be sent over unencrypted HTTP connections.",
                "medium",
                f"Add the Secure flag to the '{name}' cookie: Set-Cookie: {name}=...; Secure",
                "cookies"
            ))
        if "httponly" not in lower:
            issues.append(_issue(
                f"Cookie missing HttpOnly flag: {name}",
                f"Cookie '{name}' is accessible to JavaScript — vulnerable to XSS theft.",
                "medium",
                f"Add the HttpOnly flag to the '{name}' cookie.",
                "cookies"
            ))
        if "samesite" not in lower:
            issues.append(_issue(
                f"Cookie missing SameSite attribute: {name}",
                f"Cookie '{name}' has no SameSite attribute — may be vulnerable to CSRF.",
                "low",
                f"Add SameSite=Strict or SameSite=Lax to the '{name}' cookie.",
                "cookies"
            ))
    return issues

def _check_exposed_paths(base_url):
    issues = []
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    for path in EXPOSED_PATHS:
        try:
            r = requests.get(origin + path, timeout=5, allow_redirects=False)
            if r.status_code == 200:
                issues.append(_issue(
                    f"Sensitive file exposed: {path}",
                    f"{origin + path} returned HTTP 200.",
                    "critical",
                    f"Restrict access to {path} immediately via your server config or firewall.",
                    "disclosure"
                ))
        except Exception:
            pass
    return issues

def _compute_score(issues):
    if not issues:
        return 100
    total_deductions = sum(SEVERITY_WEIGHTS.get(i["severity"], 0) for i in issues)
    score = max(0, 100 - total_deductions)
    return score

def scan_url(url):
    issues = []

    # Normalise URL
    if not url.startswith("http"):
        url = "https://" + url

    # HTTPS check
    if url.startswith("http://"):
        issues.append(_issue(
            "Site not using HTTPS",
            "All traffic is unencrypted and can be intercepted.",
            "critical",
            "Obtain an SSL certificate and redirect all HTTP traffic to HTTPS.",
            "tls"
        ))

    # TLS / cert checks (HTTPS only)
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname
    if url.startswith("https://") and hostname:
        issues += _check_tls(hostname)

    # Redirect chain
    issues += _check_redirects(url)

    # Fetch main page
    status_code = None
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "WebScanner/1.0 Security Audit"})
        status_code = resp.status_code
        headers = resp.headers

        issues += _check_headers(headers)
        issues += _check_info_disclosure(headers)
        issues += _check_cookies(headers)

    except requests.exceptions.SSLError as e:
        issues.append(_issue("SSL connection error", str(e), "critical", "Fix your SSL certificate configuration.", "tls"))
    except requests.exceptions.ConnectionError:
        return {"url": url, "error": "Could not connect to host.", "issues": [], "score": 0, "status_code": None}
    except requests.exceptions.Timeout:
        return {"url": url, "error": "Request timed out.", "issues": [], "score": 0, "status_code": None}
    except Exception as e:
        return {"url": url, "error": str(e), "issues": [], "score": 0, "status_code": None}

    # Exposed sensitive paths
    issues += _check_exposed_paths(url)

    score = _compute_score(issues)

    # Deduplicate by title
    seen = set()
    unique_issues = []
    for i in issues:
        if i["title"] not in seen:
            seen.add(i["title"])
            unique_issues.append(i)

    return {
        "url": url,
        "status_code": status_code,
        "score": score,
        "issues": unique_issues,
    }
