# backend/ai_analyzer.py
import json

def generate_brief_output(vulns, headers_suggestions):
    if vulns:
        vuln_count = len(vulns)
        return (
            f"{vuln_count} potential issue(s) detected. "
            "Review vulnerabilities and apply recommended mitigations."
        )
    elif headers_suggestions:
        return (
            "No major vulnerabilities found, but important security headers "
            "are missing. Adding them will strengthen security."
        )
    else:
        return "Website looks safe based on the heuristic scan."

def rule_based_analysis(url, scan_data):
    """
    Simple heuristic 'AI-like' analysis without external API.
    Uses links, params, forms, cookies, headers to guess risks.
    """

    params = scan_data.get("params", []) or []
    forms = scan_data.get("forms", []) or []
    headers = scan_data.get("headers", {}) or {}
    cookies = scan_data.get("cookies", {}) or {}

    vulnerabilities = []
    security_headers_suggestions = []

    xss_param_keywords = {"q", "query", "search", "msg", "message", "comment"}
    has_xss_like_param = any(
        p.lower() in xss_param_keywords for p in params
    )

    if has_xss_like_param:
        vulnerabilities.append({
            "type": "Reflected XSS (Heuristic)",
            "evidence": (
                "Found parameters commonly used for user-controlled input: "
                + ", ".join(params)
            ),
            "example_payloads": [
                "\"><script>alert(1)</script>",
                "\"><img src=x onerror=alert(1)>"
            ],
            "validation_approach": (
                "Inject harmless test payloads into these parameters and check "
                "if they are reflected unsanitized in the response."
            ),
            "mitigations": (
                "Apply output encoding, sanitize inputs, enforce CSP, and use secure templates."
            )
        })

    sqli_param_keywords = {"id", "user", "uid", "item", "product", "pid"}
    has_sqli_like_param = any(
        p.lower() in sqli_param_keywords for p in params
    )

    if has_sqli_like_param:
        vulnerabilities.append({
            "type": "SQL Injection (Heuristic)",
            "evidence": (
                "Found database-like parameters: "
                + ", ".join(sorted(set(params)))
            ),
            "example_payloads": [
                "' OR '1'='1",
                "1 OR 1=1"
            ],
            "validation_approach": (
                "Use harmless SQL probe payloads in a development environment "
                "to detect unexpected DB errors or responses."
            ),
            "mitigations": (
                "Use prepared statements and avoid string concatenation in SQL."
            )
        })

    has_post_forms = any(f.get("method", "").upper() == "POST" for f in forms)

    has_csrf_token = any(
        any("csrf" in (inp.get("name", "").lower()) or "token" in (inp.get("name", "").lower())
            for inp in f.get("inputs", []))
        for f in forms
    )

    if has_post_forms and not has_csrf_token:
        vulnerabilities.append({
            "type": "CSRF (Heuristic)",
            "evidence": (
                "Detected POST forms without anti-CSRF token fields."
            ),
            "example_payloads": [
                "Auto-submitting hidden form exploiting missing CSRF protection."
            ],
            "validation_approach": (
                "Attempt cross-site POST from another origin during an active session."
            ),
            "mitigations": (
                "Implement CSRF tokens, SameSite cookies, and validate Origin/Referer headers."
            )
        })

    set_cookie_header = headers.get("Set-Cookie", "")

    if cookies:
        if "httponly" not in set_cookie_header.lower():
            vulnerabilities.append({
                "type": "Insecure Cookie (Missing HttpOnly)",
                "evidence": "Session cookies are not marked HttpOnly.",
                "example_payloads": [],
                "validation_approach": "Check if cookies are readable via document.cookie.",
                "mitigations": "Add HttpOnly flag to session cookies."
            })

        if "secure" not in set_cookie_header.lower():
            vulnerabilities.append({
                "type": "Insecure Cookie (Missing Secure)",
                "evidence": "Session cookies are not marked Secure.",
                "example_payloads": [],
                "validation_approach": "Check cookies over HTTP vs HTTPS.",
                "mitigations": "Add Secure flag to session cookies."
            })

    if "Content-Security-Policy" not in headers:
        security_headers_suggestions.append("Content-Security-Policy header is missing.")

    if "X-Frame-Options" not in headers:
        security_headers_suggestions.append("X-Frame-Options header is missing.")

    if "X-Content-Type-Options" not in headers:
        security_headers_suggestions.append("X-Content-Type-Options: nosniff recommended.")

    if "Referrer-Policy" not in headers:
        security_headers_suggestions.append("Referrer-Policy header is missing.")

    if url.lower().startswith("https") and "Strict-Transport-Security" not in headers:
        security_headers_suggestions.append("HSTS header (Strict-Transport-Security) missing.")

    summary = "Heuristic analysis completed. "
    summary += f"Found {len(vulnerabilities)} possible issue(s). "
    summary += f"Suggested {len(security_headers_suggestions)} security header improvement(s)."

    return {
    "summary": summary,
    "brief": generate_brief_output(vulnerabilities, security_headers_suggestions),
    "vulnerabilities": vulnerabilities,
    "security_headers_suggestions": security_headers_suggestions
}



def analyze_with_ai(url, scan_data):
    """Wrapper for the Flask route."""
    return rule_based_analysis(url, scan_data)
