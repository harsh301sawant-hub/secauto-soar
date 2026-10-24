import re
import time
from datetime import datetime

# In-memory tracking of rapid attempts (IP -> list of timestamps)
login_attempt_history = {}
BRUTE_FORCE_THRESHOLD = 4  # 4 failed attempts within 30 seconds
WINDOW_SECONDS = 30

# SQL Injection signature patterns
SQLI_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"(union\s+select)",
    r"(or\s+1\s*=\s*1)",
    r"(drop\s+table)",
    r"(exec(\s|\+)+(s|x)p\w+)"
]

# Suspicious / Homoglyph / Phishing indicators
PHISHING_KEYWORDS = [
    "verify-account", "paypal-update", "secure-bank-login", "billing-resolve", 
    "support-apple-id", "account-alert", "wallet-connect"
]

def analyze_login_attempt(ip: str, username: str, success: bool):
    """
    Detects Brute-Force / Credential Stuffing attacks in real-time.
    """
    if success:
        return None
    
    current_time = time.time()
    if ip not in login_attempt_history:
        login_attempt_history[ip] = []
    
    # Prune timestamps older than window
    login_attempt_history[ip] = [t for t in login_attempt_history[ip] if current_time - t <= WINDOW_SECONDS]
    login_attempt_history[ip].append(current_time)
    
    attempts = len(login_attempt_history[ip])
    
    if attempts >= BRUTE_FORCE_THRESHOLD:
        return {
            "attack_type": "Brute-Force & Credential Stuffing",
            "severity": "CRITICAL",
            "source_ip": ip,
            "target_user": username,
            "details": f"Detected {attempts} failed login attempts within {WINDOW_SECONDS} seconds against account '{username}'. Exceeded threshold ({BRUTE_FORCE_THRESHOLD}).",
            "auto_playbook": "Playbook_BruteForce_Mitigate"
        }
    return None

def analyze_web_payload(ip: str, path: str, payload: str):
    """
    Detects Web Attacks (SQL Injection, Command Injection).
    """
    combined = f"{path} {payload}".lower()
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return {
                "attack_type": "SQL Injection (SQLi) Attempt",
                "severity": "HIGH",
                "source_ip": ip,
                "target_user": "Web Endpoint",
                "details": f"Malicious SQL syntax pattern '{pattern}' detected in HTTP payload: {payload[:80]}",
                "auto_playbook": "Playbook_WAF_Block"
            }
    return None

def analyze_url_or_domain(url: str):
    """
    Analyzes URLs for phishing signatures, deceptive subdomains, and keywords.
    """
    url_lower = url.lower()
    risk_score = 0
    reasons = []

    # 1. Check deceptive keywords
    for kw in PHISHING_KEYWORDS:
        if kw in url_lower:
            risk_score += 40
            reasons.append(f"Suspicious credential-harvesting keyword: '{kw}'")

    # 2. Check for suspicious TLDs often abused
    suspicious_tlds = [".cc", ".tk", ".top", ".xyz", ".club", ".buzz", ".work"]
    if any(url_lower.endswith(tld) or (tld + "/") in url_lower for tld in suspicious_tlds):
        risk_score += 25
        reasons.append("High-risk / free TLD frequently associated with phishing")

    # 3. Check for multiple subdomains (e.g. secure.login.paypal.verify-site.com)
    if url_lower.count(".") > 3:
        risk_score += 20
        reasons.append("Deceptive deep subdomain hierarchy")

    # 4. Check for IP address in URL instead of hostname
    if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url_lower):
        risk_score += 35
        reasons.append("Direct IP address used instead of valid registered domain")

    risk_score = min(risk_score, 100)
    verdict = "MALICIOUS" if risk_score >= 60 else "SUSPICIOUS" if risk_score >= 30 else "SAFE"
    
    return {
        "url": url,
        "risk_score": risk_score,
        "verdict": verdict,
        "reasons": reasons if reasons else ["No immediate threat indicators found."]
    }
