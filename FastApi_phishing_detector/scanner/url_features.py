import re
import ssl
import socket
import fnmatch
import requests
from urllib.parse import urlparse
from datetime import datetime, timezone
import tldextract
import dns.resolver
import whois
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Reference lists

keywords = [
    "login", "log-in", "signin", "sign-in", "verify", "update", "secure",
    "verification", "portal", "authenticate", "checkpoint", "access",
    "account", "accounts", "bank", "confirm", "continue", "password",
    "auth", "credential", "identity", "urgent", "action-required", "alert",
    "suspend", "locked", "expired", "expiration", "disabled", "attention",
    "important", "warning", "click", "recover", "reactivate", "unlock",
    "invoice", "document", "doc", "file", "sharepoint", "onedrive",
    "docusign", "efax", "vmail", "voicemail", "scanned", "payment",
    "billing", "salary", "bonus", "cdn", "api", "static", "support",
    "service-desk", "helpdesk", "cloud", "server", "secure-login", "vault",
    "sync", "patch",
]

extentions = [
    ".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".paper", ".app",
]

queries = [
    "id=", "uid=", "sid=", "dest=", "destination", "redirect=", "url=",
    "next=", "u=", "rlkey=", "auth=", "session=", "token=", "enail=",
    "user=", "brand=", "service=", "cmd=", "action=", "m=", "mid=",
    "tenant=", "domain=", "apiv=", "data=", "msg=", "payload=", "hash=",
    "error=", "err_code=", "security", "urgent", "importance=high",
    "priority=1", "attempt=", "clickid=", "gclid=", "utm_source=",
    "utm_medium=", "bot_check=", "?", "&", "aff=", "affiliate=",
    "campaign=", "cid=", "step=", "key=",
]

free_domains = [
    "docs.google.com", "sites.google.com", "dropbox.com", "firebaseapp.com",
    "framer.app", "webcindario.com", "campaign-archive.com",
    "new.express.adobe.com", "jotform.com", "hsforms.com",
    "forms.office.com", "ipfs.io", "ipfs.best-practice.se",
    "adobe.com/webpage",
]

url_shorteners = [
    "bit.ly", "t.co", "tinyurl.com", "qrco.de", "q-r.to", "l.ead.me",
    "did.li", "linkin.bio",
]

trusted_big_cas = [
    "digicert", "globalsign", "sectigo", "godaddy", "let's encrypt", "amazon",
    "geotrust", "thawte", "verisign", "comodo", "google trust services",
    "cloudflare", "microsoft", "network solutions", "entrust", "trustwave",
    "dotster",
]


# ---------------------------------------------------------------------------
# Helpers

def get_soup(url):
    """Fetch page and return BeautifulSoup object and raw HTML."""
    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
            ),
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }
        response = requests.get(url, headers=headers, timeout=10)
        return BeautifulSoup(response.text, "html.parser"), response.text
    except Exception:
        return None, None


def get_certificate(hostname, port=443):
    """Connect to server and retrieve SSL certificate."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert()
    except Exception:
        return None


def _parse_cert_date(date_value):
    """Parse certificate date from various formats into a datetime object.

    getpeercert() may return dates as:
      - A tuple like (2024, 1, 15, 0, 0, 0)
      - A dict like {'year': 2024, 'month': 1, 'day': 15, ...}
      - A string like 'Jan 15 00:00:00 2024 GMT'
    """
    if date_value is None:
        return None
    try:
        if isinstance(date_value, tuple) and len(date_value) >= 6:
            return datetime(
                date_value[0], date_value[1], date_value[2],
                date_value[3], date_value[4], date_value[5],
                tzinfo=timezone.utc
            )
        if isinstance(date_value, dict):
            return datetime(
                date_value["year"], date_value["month"],
                date_value.get("day", 1),
                date_value.get("hour", 0), date_value.get("minute", 0),
                date_value.get("second", 0),
                tzinfo=timezone.utc
            )
        if isinstance(date_value, str):
            for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%d %H:%M:%S"):
                try:
                    return datetime.strptime(date_value, fmt).replace(
                        tzinfo=timezone.utc
                    )
                except ValueError:
                    continue
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# 1. has_ip

def has_ip(url):
    """Check if the hostname is an IP address. Returns (bool, detail)."""
    try:
        host = urlparse(url).hostname or ""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        if re.search(ip_pattern, host):
            return True, f"Hostname is an IP address: {host}"
        return False, f"Hostname is a domain name: {host}"
    except Exception:
        return False, "Unable to parse URL for IP check"


# ---------------------------------------------------------------------------
# 2. has_at_sign

def has_at_sign(url):
    """Check for @ in URL. Returns (bool, detail)."""
    if "@" in url:
        return True, "URL contains '@' character"
    return False, "No '@' character found"


# ---------------------------------------------------------------------------
# 3. url_length

def url_length(url):
    """Check if URL length > 54. Returns (bool, detail)."""
    length = len(url)
    if length > 54:
        return True, f"URL length {length} exceeds threshold of 54"
    return False, f"URL length {length} is within threshold"


# ---------------------------------------------------------------------------
# 4. dash_in_domain

def dash_in_domain(url):
    """Check for dash in hostname. Returns (bool, detail)."""
    try:
        host = urlparse(url).hostname or ""
        if "-" in host:
            return True, f"Dash found in domain: {host}"
        return False, f"No dash in domain: {host}"
    except Exception:
        return False, "Unable to parse URL"


# ---------------------------------------------------------------------------
# 5. sub_multisub_domain


def sub_multi_sub_domain(url):
    """Check for sub/multi-subdomain.

    Original logic: strip 'www.', count dots in domain after removing ccTLD.
    dots == 1 → Legitimate, dots != 1 → Suspicious.
    Returns (bool, detail).
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        # Remove www. prefix (matching original code)
        if domain.startswith("www."):
            domain = domain[4:]
        parts = domain.split(".")
        # Remove ccTLD (2-letter country code suffix)
        if len(parts[-1]) == 2:
            parts = parts[:-1]
        domain = ".".join(parts)
        dots = domain.count(".")

        if dots == 1:
            return False, f"Single domain level: {domain}"
        else:
            return True, (
                f"Multiple domain levels ({dots} dots): {domain}"
            )
    except Exception:
        return False, "Unable to extract domain structure"


# ---------------------------------------------------------------------------
# 6. http_https

def http_https(url):
    """Check if URL uses HTTP (not HTTPS). True = suspicious. Returns (bool, detail)."""
    if "https" in url:
        return False, "URL uses HTTPS"
    else:
        return True, "URL does NOT use HTTPS (HTTP only)"


# ---------------------------------------------------------------------------
# 7. https_certificate

def https_certificate(url):
    """Evaluate HTTPS and certificate properties.

    Returns dict with boolean flags matching original training code:
      HTTP_HTTPS: True if NOT https (suspicious)
      No_Cert: True if cert cannot be retrieved (suspicious)
      Issuer_Name: True if issuer has NO organizationName (suspicious)
      Subject_Name: True if subject has NO commonName (suspicious)
      Self_Signed: True if issuer org name == subject common name (suspicious)
      Cert_Age_Days: True if cert age < 7 days (suspicious)
      Cert_Validity_Days: True if cert validity < 14 days (suspicious)
      Trusted_Cert: True if issuer is NOT a well-known CA (suspicious)
    Plus detail strings for reporting.
    """
    # Default flags matching original code
    flags = {
        "HTTP_HTTPS": False,
        "No_Cert": False,
        "Issuer_Name": False,
        "Subject_Name": False,
        "Self_Signed": False,
        "Cert_Age_Days": False,
        "Cert_Validity_Days": False,
        "Trusted_Cert": False,
        # Detail strings (not used by ML)
        "cert_detail": "",
        "issuer_detail": "",
        "subject_detail": "",
        "cert_age_detail": "",
        "cert_validity_detail": "",
        "trusted_ca_detail": "",
    }

    parsed = urlparse(url)

    # HTTP_HTTPS: True if not https (suspicious)
    if parsed.scheme == "https":
        flags["HTTP_HTTPS"] = False
        flags["cert_detail"] = f"HTTPS detected for {parsed.hostname}"
    else:
        flags["HTTP_HTTPS"] = True
        flags["cert_detail"] = "URL does not use HTTPS"

    hostname = parsed.hostname
    cert = get_certificate(hostname)

    # No_Cert: True if cert cannot be retrieved (matching original default = False, then set True if None)
    flags["No_Cert"] = False
    if cert is None:
        flags["No_Cert"] = True
        flags["cert_detail"] += " - Could not retrieve SSL certificate"
        return flags

    flags["No_Cert"] = False
    flags["cert_detail"] = f"Certificate retrieved for {hostname}"

    # Extract issuer and subject info (matching original code logic)
    try:
        issuer = dict(x[0] for x in cert.get("issuer", []))
        issuer_name = issuer.get("organizationName", "").lower()
    except Exception:
        issuer_name = ""

    try:
        subject = dict(x[0] for x in cert.get("subject", []))
        subject_name = subject.get("commonName", "").lower()
    except Exception:
        subject_name = ""

    flags["issuer_detail"] = f"Issuer: {issuer_name if issuer_name else '(none)'}"
    flags["subject_detail"] = f"Subject: {subject_name if subject_name else '(none)'}"

    # Issuer_Name: True if NO issuer name (suspicious) - matching original
    if issuer_name:
        flags["Issuer_Name"] = False
    else:
        flags["Issuer_Name"] = True

    # Subject_Name: True if NO subject name (suspicious) - matching original
    if subject_name:
        flags["Subject_Name"] = False
    else:
        flags["Subject_Name"] = True

    # Self_Signed: True if issuer org name == subject common name - matching original
    self_signed = issuer_name == subject_name
    flags["Self_Signed"] = self_signed
    if self_signed:
        flags["cert_detail"] += " (Self-signed certificate)"

    # Cert age: True if age < 7 days (suspicious) - matching original threshold
    not_before = _parse_cert_date(cert.get("notBefore"))
    if not_before:
        now = datetime.now(timezone.utc)
        cert_age_days = (now - not_before).days
        if cert_age_days < 7:
            flags["Cert_Age_Days"] = True
            flags["cert_age_detail"] = (
                f"Certificate is only {cert_age_days} days old (threshold: 7)"
            )
        else:
            flags["Cert_Age_Days"] = False
            flags["cert_age_detail"] = f"Certificate age: {cert_age_days} days"
    else:
        flags["Cert_Age_Days"] = False
        flags["cert_age_detail"] = "Could not parse certificate start date"

    # Cert validity: True if validity < 14 days (suspicious) - matching original threshold
    not_after = _parse_cert_date(cert.get("notAfter"))
    if not_after and not_before:
        cert_validity_days = (not_after - not_before).days
        if cert_validity_days < 14:
            flags["Cert_Validity_Days"] = True
            flags["cert_validity_detail"] = (
                f"Certificate validity only {cert_validity_days} days (threshold: 14)"
            )
        else:
            flags["Cert_Validity_Days"] = False
            flags["cert_validity_detail"] = (
                f"Certificate validity: {cert_validity_days} days"
            )
    else:
        flags["Cert_Validity_Days"] = False
        flags["cert_validity_detail"] = "Could not parse certificate dates"

    # Trusted_Cert: True if NOT from a well-known CA (suspicious) - matching original
    if not any(ca in issuer_name.lower() for ca in trusted_big_cas):
        flags["Trusted_Cert"] = True
        flags["trusted_ca_detail"] = (
            f"Issuer '{issuer_name}' is NOT a recognized trusted CA"
        )
    else:
        flags["Trusted_Cert"] = False
        flags["trusted_ca_detail"] = (
            f"Issuer '{issuer_name}' is a recognized trusted CA"
        )

    return flags


# ---------------------------------------------------------------------------
# 8. iframe_redirection (matches original logic)

def is_cross_domain(page_url, iframe_src):
    """Check if iframe points to a different domain."""
    if not iframe_src or iframe_src.startswith("#"):
        return False
    page_domain = urlparse(page_url).netloc
    iframe_domain = urlparse(iframe_src).netloc
    return iframe_domain and iframe_domain != page_domain


def legit_iframes(src):
    """Check if iframe source is from a known legitimate service."""
    legit_cross_domains = [
        "googletagmanager.com", "google.com/recaptcha", "youtube.com",
        "youtu.be", "vimeo.com", "stripe.com", "paypal.com",
        "facebook.com", "twitter.com", "linkedin.com",
    ]
    for domain in legit_cross_domains:
        if domain in src:
            return True
    return False


def iframe_redirection(url):
    """Analyze iframes for phishing indicators.

    Returns dict with boolean flags matching original training code,
    plus detail strings for reporting.
    """
    result = {
        "No_Soup": False,
        "Invisible_Iframe": False,
        "Cross_Domain_Iframe": False,
        "Nested_Iframes": False,
        "No_Visible_Purpose": False,
        "Overlay_Behavior": False,
        # Details
        "iframe_count": 0,
        "invisible_detail": "",
        "cross_domain_detail": "",
    }

    soup, html = get_soup(url)
    if soup is None:
        result["No_Soup"] = True
        result["invisible_detail"] = "Could not fetch page content"
        result["cross_domain_detail"] = "Could not fetch page content"
        return result

    result["No_Soup"] = False
    iframes = soup.find_all("iframe")
    inputs = soup.find_all("input")
    result["iframe_count"] = len(iframes)

    invisible_count = 0
    cross_domain_count = 0

    for iframe in iframes:
        src = iframe.get("src", "")
        width = iframe.get("width", "")
        height = iframe.get("height", "")
        style = iframe.get("style", "").lower()

        if legit_iframes(src):
            continue

        # Invisible iframe check (matching original patterns)
        invisible_patterns = ["display:none", "visibility:hidden", "opacity:0"]
        if (
            width == "0" or height == "0" or
            any(p in style for p in invisible_patterns)
        ):
            invisible_count += 1

        # Cross-domain iframe
        if is_cross_domain(url, src):
            cross_domain_count += 1

        # Nested iframes
        if iframe.find("iframe"):
            result["Nested_Iframes"] = True

        # No visible purpose
        if not iframe.text.strip() and not src:
            result["No_Visible_Purpose"] = True

        # Overlay behavior (matching original heuristic)
        if "position:absolute" in style or "position:fixed" in style:
            for inp in inputs:
                if inp.get("type", "") in ["text", "password", "email"]:
                    result["Overlay_Behavior"] = True
                    break

    result["Invisible_Iframe"] = invisible_count > 0
    result["Cross_Domain_Iframe"] = cross_domain_count > 0

    result["invisible_detail"] = (
        f"Found {invisible_count} invisible iframe(s) out of {len(iframes)} total"
    )
    result["cross_domain_detail"] = (
        f"Found {cross_domain_count} cross-domain iframe(s) out of {len(iframes)} total"
    )

    return result


# ---------------------------------------------------------------------------
# 9. dns_records

def resolve_A_cname(domain):
    """Resolve A records, following CNAME chains."""
    resolved_ips = []
    visited = set()
    resolver = dns.resolver.Resolver()

    current = domain
    while current not in visited:
        visited.add(current)
        try:
            answer = resolver.resolve(current, "A")
            for rdata in answer:
                resolved_ips.append(rdata.address)
            return resolved_ips
        except dns.resolver.NoAnswer:
            try:
                cname_answer = resolver.resolve(current, "CNAME")
                current = str(cname_answer[0].target).rstrip(".")
            except dns.resolver.NoAnswer:
                break
        except (dns.resolver.NXDOMAIN, Exception):
            break

    return resolved_ips


def parent_domain(url):
    """Extract the registered domain."""
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}"


def dns_records(url):
    """Check DNS records and domain age.

    Returns dict with boolean flags matching original training code:
      A_Record: True if NO A record (suspicious)
      AAAA_Record: True if NO AAAA record (suspicious)
      MX_Record: True if NO MX record (suspicious)
      NS_Record: True if NO NS record (suspicious)
      Age_Days: True if domain age <= 7 days (suspicious)
    Plus detail strings.
    """
    result = {
        "A_Record": False,
        "AAAA_Record": False,
        "MX_Record": False,
        "NS_Record": False,
        "Age_Days": False,
        # Details
        "resolved_ips_detail": "",
        "mx_records_detail": "",
        "ns_records_detail": "",
        "domain_age_detail": "",
    }

    try:
        domain = parent_domain(url)
    except Exception:
        result["resolved_ips_detail"] = "Could not extract domain"
        return result

    # A Record: True = suspicious (NO record found)
    ips = resolve_A_cname(domain)
    if ips:
        result["A_Record"] = False  # has A record = legit
        result["resolved_ips_detail"] = f"A records: {', '.join(ips)}"
    else:
        result["A_Record"] = True  # no A record = suspicious
        result["resolved_ips_detail"] = "No A record found"

    # AAAA Record
    result["AAAA_Record"] = True  # default suspicious
    try:
        aaaa_records = dns.resolver.resolve(domain, "AAAA")
        aaaa_list = [ip.to_text() for ip in aaaa_records]
        result["AAAA_Record"] = False
        result["resolved_ips_detail"] += f" | AAAA: {', '.join(aaaa_list)}"
    except dns.resolver.NoAnswer:
        pass
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        try:
            aaaa_records = dns.resolver.resolve("www." + domain, "AAAA")
            result["AAAA_Record"] = False
        except Exception:
            pass
    except Exception:
        pass

    # MX Record
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        mx_list = [str(mx.exchange.to_text()) for mx in mx_records]
        result["MX_Record"] = False  # has MX = legit
        result["mx_records_detail"] = f"MX records: {', '.join(mx_list)}"
    except Exception:
        result["MX_Record"] = True  # no MX = suspicious
        result["mx_records_detail"] = "No MX record found"

    # NS Record
    try:
        ns_records = dns.resolver.resolve(domain, "NS")
        ns_list = [str(ns.to_text()) for ns in ns_records]
        result["NS_Record"] = False  # has NS = legit
        result["ns_records_detail"] = f"NS records: {', '.join(ns_list)}"
    except Exception:
        result["NS_Record"] = True  # no NS = suspicious
        result["ns_records_detail"] = "No NS record found"

    # Domain age from WHOIS
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            if isinstance(creation_date, str):
                creation_date = datetime.fromisoformat(
                    creation_date.replace("Z", "+00:00")
                )
            now = datetime.now(timezone.utc)
            age_days = (now - creation_date).days
            # Age_Days: True if age <= 7 (suspicious) - matching original
            if age_days > 7:
                result["Age_Days"] = False
            else:
                result["Age_Days"] = True
            result["domain_age_detail"] = f"Domain age: {age_days} days"
        else:
            result["Age_Days"] = True  # no date = suspicious
            result["domain_age_detail"] = "No creation date found in WHOIS"
    except Exception:
        result["Age_Days"] = True  # WHOIS failed = suspicious
        result["domain_age_detail"] = "WHOIS lookup failed"

    return result


# ---------------------------------------------------------------------------
# 10. url_path

def url_path(url):
    """Analyze URL path and query string.

    Returns dict with boolean flags matching original training code,
    plus lists of matched items for detailed reporting.
    """
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    result = {
        "URL_Short": False,
        "Free_Domain": False,
        "Phish_Keyword": False,
        "File_Extension": False,
        "Segment": False,
        "Digits": False,
        "Query": False,
        "Depth_Segments": False,
        # Matched items for reporting
        "matched_shortener": "",
        "matched_free_domain": "",
        "matched_keywords": [],
        "matched_extensions": [],
        "matched_queries": [],
        "matched_segments": [],
        "depth_detail": "",
    }

    # URL shortener
    for us in url_shorteners:
        if us in domain:
            result["URL_Short"] = True
            result["matched_shortener"] = us
            break

    # Free domain
    for fd in free_domains:
        if fd in domain:
            result["Free_Domain"] = True
            result["matched_free_domain"] = fd
            break

    # Phishing keywords in path
    for pk in keywords:
        if pk in path:
            result["Phish_Keyword"] = True
            result["matched_keywords"].append(pk)

    # Suspicious file extensions
    for ext in extentions:
        if ext in path or ext in domain:
            result["File_Extension"] = True
            result["matched_extensions"].append(ext)
            break

    # Long random path segments (>18 chars with digits)
    for seg in path.split("/"):
        if len(seg) > 18 and re.search(r"\d", seg):
            result["Segment"] = True
            result["matched_segments"].append(seg)
            break

    # Excessive digits in path
    digits = sum(c.isdigit() for c in path)
    if digits > 5:
        result["Digits"] = True

    # Query parameters
    for q in queries:
        if q in query:
            result["Query"] = True
            result["matched_queries"].append(q)

    # Path depth: True if > 3 segments
    depth = 0
    for s in path.split("/"):
        depth += 1
    if depth > 3:
        result["Depth_Segments"] = True
    result["depth_detail"] = f"Path has {depth} segment(s)"

    return result


# ---------------------------------------------------------------------------
# 11. domain_age

def domain_age(url):
    """Check domain registration age.

    Returns (True, detail) if domain is < 7 days old (suspicious).
    Returns (False, detail) if domain is >= 7 days old (legitimate).
    Returns (True, detail) on error (treating as suspicious - matching original).
    """
    try:
        domain = whois.whois(tldextract.extract(url).registered_domain)
        creation_date = domain.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            if isinstance(creation_date, str):
                creation_date = datetime.fromisoformat(
                    creation_date.replace("Z", "+00:00")
                )
            today = datetime.now()
            age_days = (today - creation_date).days
            if age_days > 7:
                return False, f"Domain age: {age_days} days (legitimate)"
            else:
                return True, f"Domain is only {age_days} days old (suspicious)"
        else:
            return True, "No creation date found (treating as suspicious)"
    except Exception:
        return True, "WHOIS lookup failed (treating as suspicious)"


# ---------------------------------------------------------------------------
# 12. right_click

def right_click(url):
    """Check if right-click is disabled in page.

    Returns (True, detail) if disabled (suspicious).
    Returns (False, detail) if not disabled or page unreachable.
    """
    _, html_content = get_soup(url)
    if not html_content:
        return False, "Could not fetch page content"

    if "event.button==2" in html_content or "contextmenu" in html_content.lower():
        return True, "Right-click is disabled in page code"
    else:
        return False, "Right-click is NOT disabled"


# ---------------------------------------------------------------------------
# 13. custom_status_bar

def custom_status_bar(url):
    """Check for onmouseover / window.status manipulation.

    Returns (True, detail) if manipulation detected (suspicious).
    Returns (False, detail) if not detected or page unreachable.
    """
    _, html_content = get_soup(url)
    if not html_content:
        return False, "Could not fetch page content"

    if "onmouseover" in html_content.lower() and "window.status" in html_content.lower():
        return True, "Status bar manipulation detected (onmouseover + window.status)"
    else:
        return False, "No status bar manipulation detected"


# ---------------------------------------------------------------------------
# main function extract_all_url_features

def extract_all_url_features(url):
    """Extract all URL-based features for phishing detection.

    Returns a dict with two sections:
      - "features": {name: bool/int} matching EXACTLY the ML model columns
      - "details":  {name: str/list} human-readable information for reports

    Feature names and boolean logic match the original training code exactly.
    """
    features = {}
    details = {}

    # --- Simple boolean features ---
    ip_flag, ip_detail = has_ip(url)
    features["Has_Ip"] = ip_flag
    details["Has_Ip"] = ip_detail

    at_flag, at_detail = has_at_sign(url)
    features["At_Sign"] = at_flag
    details["At_Sign"] = at_detail

    len_flag, len_detail = url_length(url)
    features["Url_Length"] = len_flag
    details["Url_Length"] = len_detail

    dash_flag, dash_detail = dash_in_domain(url)
    features["Dash_In_Domain"] = dash_flag
    details["Dash_In_Domain"] = dash_detail

    sub_flag, sub_detail = sub_multi_sub_domain(url)
    features["Sub_Multisub"] = sub_flag
    details["Sub_Multisub"] = sub_detail

    http_flag, http_detail = http_https(url)
    features["HTTP_HTTPS"] = http_flag
    details["HTTP_HTTPS"] = http_detail

    # --- Certificate features ---
    cert = https_certificate(url)
    for key in ["No_Cert", "Issuer_Name", "Subject_Name", "Self_Signed",
                "Cert_Age_Days", "Cert_Validity_Days", "Trusted_Cert"]:
        features[key] = cert[key]

    details["No_Cert"] = cert["cert_detail"]
    details["Issuer_Name"] = cert["issuer_detail"]
    details["Subject_Name"] = cert["subject_detail"]
    details["Self_Signed"] = (
        "Self-signed certificate" if cert["Self_Signed"]
        else "Certificate issued by external CA"
    )
    details["Cert_Age_Days"] = cert["cert_age_detail"]
    details["Cert_Validity_Days"] = cert["cert_validity_detail"]
    details["Trusted_Cert"] = cert["trusted_ca_detail"]

    # --- Iframe features ---
    iframe = iframe_redirection(url)
    for key in ["No_Soup", "Invisible_Iframe", "Cross_Domain_Iframe",
                "Nested_Iframes", "No_Visible_Purpose", "Overlay_Behavior"]:
        features[key] = iframe[key]

    details["No_Soup"] = (
        "Page content could NOT be fetched" if iframe["No_Soup"]
        else "Page content fetched successfully"
    )
    details["Invisible_Iframe"] = iframe["invisible_detail"]
    details["Cross_Domain_Iframe"] = iframe["cross_domain_detail"]
    details["Nested_Iframes"] = (
        "Nested iframes detected" if iframe["Nested_Iframes"]
        else "No nested iframes"
    )
    details["No_Visible_Purpose"] = (
        "All iframes have no visible purpose" if iframe["No_Visible_Purpose"]
        else "Iframes have visible purpose"
    )
    details["Overlay_Behavior"] = (
        "Overlay behavior detected" if iframe["Overlay_Behavior"]
        else "No overlay behavior"
    )

    # --- DNS features ---
    dns = dns_records(url)
    for key in ["A_Record", "AAAA_Record", "MX_Record", "NS_Record"]:
        features[key] = dns[key]
    features["DNS_Age_Days"] = dns["Age_Days"]

    details["A_Record"] = dns["resolved_ips_detail"]
    details["AAAA_Record"] = dns["resolved_ips_detail"]
    details["MX_Record"] = dns["mx_records_detail"]
    details["NS_Record"] = dns["ns_records_detail"]
    details["DNS_Age_Days"] = dns["domain_age_detail"]

    # --- URL path features ---
    path_info = url_path(url)
    for key in ["URL_Short", "Free_Domain", "Phish_Keyword", "File_Extension",
                "Segment", "Digits", "Query", "Depth_Segments"]:
        features[key] = path_info[key]

    details["URL_Short"] = (
        f"URL shortener detected: {path_info['matched_shortener']}"
        if path_info["URL_Short"] else "Not a URL shortener"
    )
    details["Free_Domain"] = (
        f"Free hosting domain: {path_info['matched_free_domain']}"
        if path_info["Free_Domain"] else "Not a free hosting domain"
    )
    details["Phish_Keyword"] = (
        path_info["matched_keywords"] if path_info["matched_keywords"]
        else "No phishing keywords found in path"
    )
    details["File_Extension"] = (
        path_info["matched_extensions"] if path_info["matched_extensions"]
        else "No suspicious file extensions"
    )
    details["Segment"] = (
        path_info["matched_segments"] if path_info["matched_segments"]
        else "No suspicious path segments"
    )
    details["Digits"] = (
        "Excessive digits found in path" if path_info["Digits"]
        else "No excessive digits"
    )
    details["Query"] = (
        path_info["matched_queries"] if path_info["matched_queries"]
        else "No suspicious query parameters"
    )
    details["Depth_Segments"] = path_info["depth_detail"]

    # --- Domain age ---
    age_flag, age_detail = domain_age(url)
    features["Domain_Age"] = age_flag
    details["Domain_Age"] = age_detail

    # --- Right-click ---
    rc_flag, rc_detail = right_click(url)
    features["Right_Click"] = rc_flag
    details["Right_Click"] = rc_detail

    # --- Custom status bar ---
    sb_flag, sb_detail = custom_status_bar(url)
    features["Custom_status_bar"] = sb_flag
    details["Custom_status_bar"] = sb_detail

    return {"features": features, "details": details}
