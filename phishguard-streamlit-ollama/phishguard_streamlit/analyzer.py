import re, socket, ssl, ipaddress
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup

TIMEOUT = 7
USER_AGENT = "PhishGuardAI/1.0 defensive-security-scanner"

SUSPICIOUS_WORDS = [
    "verify", "verification", "login", "signin", "sign-in", "password", "otp", "pin",
    "urgent", "suspended", "unlock", "confirm", "security alert", "wallet", "invoice",
    "refund", "gift card", "crypto", "bank", "payment", "limited time"
]
BRANDS = ["google", "microsoft", "apple", "amazon", "paypal", "netflix", "instagram", "facebook", "bank"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rebrand.ly", "shorturl.at"}


def safe_public_url(raw):
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.I): raw = "https://" + raw
    p = urlparse(raw)
    if not p.hostname: raise ValueError("Invalid URL: hostname is missing.")
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(p.hostname))
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValueError("For safety, private/local network targets are blocked.")
    except socket.gaierror:
        pass
    return raw, p


def domain_parts(host):
    h = (host or "").lower().strip(".")
    return h, h.split(".")[-2:] if "." in h else [h]


def homograph_or_lookalike(host):
    h = host.lower()
    if "xn--" in h: return True, "Punycode / IDN hostname detected."
    if re.search(r"[а-яА-ЯёЁıłøα-ωΑ-Ω]", h): return True, "Non-Latin characters in hostname may indicate a lookalike domain."
    compact = re.sub(r"[^a-z0-9]", "", h)
    for brand in BRANDS:
        if brand in compact and not h.endswith("." + brand + ".com") and h not in {brand + ".com"}:
            if any(ch.isdigit() for ch in compact): return True, f"Possible lookalike use of brand name '{brand}'."
    return False, ""


def analyze_url(raw):
    url, p = safe_public_url(raw)
    evidence, positives = [], []
    score = 5.0
    details = {"submitted_url": url, "hostname": p.hostname, "https": p.scheme.lower() == "https"}

    host = p.hostname.lower()
    hparts = domain_parts(host)
    if p.scheme.lower() != "https":
        score += 18; evidence.append("❌ URL uses HTTP instead of HTTPS.")
    else: positives.append("✅ URL uses HTTPS.")
    if len(url) > 120:
        score += 7; evidence.append("⚠️ URL is unusually long.")
    if len(re.findall(r"[@%]", url)) >= 3:
        score += 8; evidence.append("⚠️ URL contains several encoded/suspicious characters.")
    if host.count("-") >= 3:
        score += 7; evidence.append("⚠️ Hostname contains many hyphens.")
    if len(hparts[0]) > 30:
        score += 6; evidence.append("⚠️ Very long subdomain/host label detected.")
    if host in SHORTENERS:
        score += 12; evidence.append("⚠️ URL shortener hides the final destination.")
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host):
        score += 30; evidence.append("❌ URL uses a raw IP address instead of a domain name.")

    look, reason = homograph_or_lookalike(host)
    if look:
        score += 32; evidence.append("❌ " + reason)

    try:
        socket.gethostbyname(host)
        positives.append("✅ DNS hostname resolves successfully.")
    except Exception:
        score += 12; evidence.append("⚠️ DNS hostname could not be resolved.")

    if p.scheme.lower() == "https":
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            if cert: positives.append("✅ TLS certificate was successfully validated.")
        except Exception as e:
            score += 15; evidence.append("⚠️ HTTPS certificate/connection validation failed.")
            details["tls_error"] = str(e)[:180]

    try:
        r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT}, allow_redirects=True, stream=True)
        final_url = r.url
        details["status_code"] = r.status_code
        details["final_url"] = final_url
        details["redirect_count"] = len(r.history)
        if len(r.history) >= 3:
            score += 10; evidence.append(f"⚠️ Multiple redirects detected ({len(r.history)} hops).")
        if urlparse(final_url).hostname and urlparse(final_url).hostname.lower() != host:
            score += 12; evidence.append("⚠️ Final destination uses a different hostname.")
        if r.status_code >= 400:
            score += 5; evidence.append(f"⚠️ Destination returned HTTP {r.status_code}.")
        content_type = r.headers.get("content-type", "")
        body = r.text[:800000] if "text" in content_type or "html" in content_type else ""
        soup = BeautifulSoup(body, "html.parser") if body else None
        title = soup.title.get_text(" ", strip=True) if soup and soup.title else ""
        forms = soup.find_all("form") if soup else []
        password_inputs = soup.select('input[type="password"]') if soup else []
        text = soup.get_text(" ", strip=True).lower() if soup else body.lower()
        details.update({"title": title, "forms": len(forms), "password_fields": len(password_inputs)})
        if password_inputs:
            score += 12; evidence.append("⚠️ Page contains a password/credential input form.")
        sensitive = sum(text.count(w) for w in ["otp", "pin", "credit card", "cvv", "password", "bank account"])
        if sensitive >= 2:
            score += 14; evidence.append("⚠️ Page text contains multiple sensitive-data request terms.")
        script_text = " ".join(s.get_text(" ", strip=True) for s in soup.find_all("script")) if soup else ""
        if re.search(r"eval\s*\(|atob\s*\(|fromCharCode|document\.write", script_text, re.I):
            score += 10; evidence.append("⚠️ Potentially obfuscated JavaScript patterns detected.")
        if title: positives.append(f"ℹ️ Page title: {title[:120]}")
        r.close()
    except requests.RequestException as e:
        score += 8; evidence.append("⚠️ The page could not be fetched for content analysis.")
        details["fetch_error"] = str(e)[:180]

    score = max(0, min(99.9, score))
    if score >= 75: level, classification, confidence = "Critical", "PHISHING", "High"
    elif score >= 50: level, classification, confidence = "High", "PHISHING", "High"
    elif score >= 25: level, classification, confidence = "Moderate", "SUSPICIOUS", "Medium"
    else: level, classification, confidence = "Low", "SAFE", "Medium"
    if not evidence: evidence = ["✅ No major phishing indicators were detected by the local heuristic checks."]
    recommendation = {
        "SAFE": "No major phishing indicators were detected. Still verify the domain before entering sensitive information.",
        "SUSPICIOUS": "Proceed with caution. Verify the domain independently and avoid entering passwords, OTPs or financial information.",
        "PHISHING": "Do not enter passwords, OTPs, card details or other sensitive information. Close the page and verify the organization through an official channel."
    }[classification]
    return {"target": url, "classification": classification, "risk_score": score, "risk_level": level, "confidence": confidence,
            "evidence": evidence + positives, "recommendation": recommendation, "details": details}


def analyze_text(text, kind):
    low = text.lower()
    evidence = []
    score = 5.0
    urls = re.findall(r"https?://[^\s<>\"']+", text, re.I)
    urgency = sum(low.count(x) for x in ["urgent", "immediately", "within 24 hours", "act now", "suspended", "final warning"])
    credential = sum(low.count(x) for x in ["password", "otp", "pin", "cvv", "card number", "verify your account"])
    money = sum(low.count(x) for x in ["refund", "payment", "invoice", "gift card", "crypto", "wire transfer"])
    if urgency: score += min(20, urgency * 5); evidence.append("⚠️ Urgency/coercion language detected.")
    if credential: score += min(28, credential * 7); evidence.append("❌ Credential or sensitive-information request detected.")
    if money: score += min(15, money * 5); evidence.append("⚠️ Financial/payment language detected.")
    if urls: score += min(25, len(urls) * 8); evidence.append(f"⚠️ {len(urls)} hyperlink(s) found; verify each destination independently.")
    suspicious_domains = []
    for u in urls[:8]:
        try:
            h = urlparse(u).hostname or ""
            if h in SHORTENERS or "xn--" in h or re.search(r"\d", h): suspicious_domains.append(h)
        except Exception: pass
    if suspicious_domains:
        score += 12; evidence.append("❌ Link(s) include shortener, punycode or digit-heavy hostname patterns.")
    score = min(99.9, score)
    if score >= 75: level, classification, confidence = "Critical", "PHISHING", "High"
    elif score >= 50: level, classification, confidence = "High", "PHISHING", "High"
    elif score >= 25: level, classification, confidence = "Moderate", "SUSPICIOUS", "Medium"
    else: level, classification, confidence = "Low", "SAFE", "Medium"
    if not evidence: evidence = ["✅ No major social-engineering indicators were detected."]
    recommendation = "Do not click links or provide sensitive information until the sender and destination are independently verified." if classification != "SAFE" else "The message appears low-risk based on local checks, but remain cautious with unexpected links."
    return {"target": f"{kind} text", "classification": classification, "risk_score": score, "risk_level": level, "confidence": confidence,
            "evidence": evidence, "recommendation": recommendation,
            "details": {"type": kind, "links_found": urls, "urgency_hits": urgency, "credential_hits": credential, "financial_hits": money}}


def ollama_explain(result, model, base_url):
    prompt = f"""You are a cybersecurity assistant. Explain this phishing-screening result clearly for a student. Do not claim certainty. Mention the strongest evidence, what it means, and 3 safe next steps. Keep it under 180 words.\n\nResult JSON:\n{result}"""
    try:
        r = requests.post(base_url.rstrip("/") + "/api/generate", json={"model": model, "prompt": prompt, "stream": False, "options": {"temperature": 0.2}}, timeout=45)
        r.raise_for_status()
        return r.json().get("response", "Ollama returned no explanation.")
    except Exception as e:
        return f"Ollama is unavailable. The rule-based result above is still valid as a local screening result. ({e})"
