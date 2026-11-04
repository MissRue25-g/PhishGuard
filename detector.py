
import re
from urllib.parse import urlparse
import ipaddress


def analyze_url(url):
    """
    Analyse a URL for common phishing indicators.
    """

    if not isinstance(url, str) or not url.strip():
        return {
            "error": "Please enter a valid URL."
        }

    url = url.strip()

    # Add a scheme if the user leaves it out
    if "://" not in url:
        url = "http://" + url

    try:
        parsed_url = urlparse(url)
        domain = parsed_url.hostname

        if parsed_url.scheme not in ("http", "https") or not domain:
            raise ValueError

        # Check whether the domain is a valid IP address
        is_ip = False
        try:
            ipaddress.ip_address(domain)
            is_ip = True
        except ValueError:
            pass

    except ValueError:
        return {"error": "Invalid URL. Please enter a valid website address."}

    risk_score = 0
    findings = []

    # 1. Check HTTPS
    if parsed_url.scheme != "https":
        risk_score += 20
        findings.append("Website does not use HTTPS.")

    # 2. Check suspicious keywords
    suspicious_words = [
        "login", "verify", "account", "update",
        "secure", "banking", "password", "confirm"
    ]

    found_words = [
        word for word in suspicious_words
        if word in url.lower()
    ]

    if found_words:
        risk_score += 20
        findings.append(
            "Suspicious keywords found: " + ", ".join(found_words)
        )

    # 3. Check IP address usage
    if is_ip:
        risk_score += 30
        findings.append("Website uses an IP address instead of a domain name.")

    # 4. Check URL length
    if len(url) > 75:
        risk_score += 15
        findings.append("Unusually long URL detected.")

    # 5. Check for '@' symbol
    if "@" in parsed_url.netloc:
        risk_score += 25
        findings.append("URL contains an @ symbol in its network location.")

    # 6. Check for excessive subdomains
    if not is_ip:
        domain_parts = domain.split(".")
        if len(domain_parts) > 3:
            risk_score += 15
            findings.append("Unusually many subdomain components detected.")

    # Limit score to 100
    risk_score = min(risk_score, 100)

    # Determine risk level
    if risk_score >= 50:
        risk_level = "High"
    elif risk_score >= 20:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    if not findings:
        findings.append("No suspicious indicators detected by basic checks.")

    return {
        "url": url,
        "domain": domain,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "findings": findings
    }
