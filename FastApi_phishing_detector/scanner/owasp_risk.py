"""
OWASP-conformant Risk Assessment module for phishing detection.

Converts ML confidence scores and detected feature indicators into
an industry-standard risk rating (Critical / High / Medium / Low / Informational)
using a Likelihood × Impact methodology aligned with OWASP Risk Rating.
"""

# ---------------------------------------------------------------------------
# Feature-to-severity mapping with descriptions

CRITICAL_INDICATORS = {
    "Invisible_Iframe": "Hidden iframe detected — commonly used for credential theft",
    "Overlay_Behavior": "Overlay attack detected — malicious input capture mechanism",
    "Custom_status_bar": "Status bar manipulation — URL obfuscation technique",
    "Right_Click": "Right-click disabled — prevents user page inspection",
    "Self_Signed": "Self-signed certificate — no third-party CA validation",
}

HIGH_INDICATORS = {
    "Has_Ip": "IP address used as hostname — no domain registration",
    "At_Sign": "URL contains '@' character — credential/URL obfuscation",
    "Free_Domain": "Hosted on free platform — common phishing infrastructure",
    "URL_Short": "URL shortener detected — real destination is obscured",
    "Cross_Domain_Iframe": "Cross-domain iframe — potential content injection",
    "No_Cert": "No SSL certificate present — unencrypted connection",
    "Trusted_Cert": "Certificate issued by untrusted certificate authority",
    "No_Visible_Purpose": "Iframes present with no visible legitimate purpose",
    "Nested_Iframes": "Nested iframe structure — complex attack vector",
}

MEDIUM_INDICATORS = {
    "Dash_In_Domain": "Dash character in domain name — phishing domain pattern",
    "Sub_Multisub": "Multiple subdomain levels — possible domain impersonation",
    "Phish_Keyword": "Phishing-related keywords detected in URL path",
    "File_Extension": "Suspicious file extension present in URL",
    "Segment": "Random-looking path segments detected in URL",
    "Digits": "Excessive digits found in URL path",
    "No_Soup": "Page content could not be fetched — possible access blocking",
    "Issuer_Name": "Certificate missing issuer organization name",
    "Subject_Name": "Certificate missing subject common name",
}

LOW_INDICATORS = {
    "Url_Length": "URL length exceeds typical threshold (54 characters)",
    "HTTP_HTTPS": "Using HTTP instead of HTTPS",
    "Query": "Suspicious query parameters detected in URL",
    "Depth_Segments": "Deep URL path structure detected",
    "Cert_Age_Days": "Certificate is recently issued (less than 7 days)",
    "Cert_Validity_Days": "Short certificate validity period (less than 14 days)",
    "Domain_Age": "Domain is recently registered (less than 7 days)",
    "DNS_Age_Days": "DNS records recently created",
}

# ---------------------------------------------------------------------------
# OWASP Top 10 (2021) category mapping

OWASP_CATEGORIES = {
    "A02:2021": {
        "name": "Cryptographic Failures",
        "description": "Failures related to cryptography which often lead to sensitive data exposure.",
        "keywords": ["certificate", "ssl", "issuer", "subject", "trusted", "self-signed", "https"],
    },
    "A01:2021": {
        "name": "Broken Access Control",
        "description": "Allows users to act outside their intended permissions, including impersonation.",
        "keywords": ["ip address", "@", "obfuscation", "free platform", "shortener"],
    },
    "A07:2021": {
        "name": "Identification & Authentication Failures",
        "description": "Confirmation of user identity, authentication, and session management failures.",
        "keywords": ["phishing keyword", "credential", "harvesting", "nltk", "keyword"],
    },
    "A08:2021": {
        "name": "Software & Data Integrity Failures",
        "description": "Code and infrastructure that does not protect against integrity violations.",
        "keywords": ["iframe", "overlay", "right-click", "status bar", "nested", "cross-domain"],
    },
    "A05:2021": {
        "name": "Security Misconfiguration",
        "description": "Improperly configured security settings, missing patches, or default accounts.",
        "keywords": ["domain age", "dns age", "certificate age", "certificate validity", "newly"],
    },
}

# ---------------------------------------------------------------------------
# Compliance framework mapping

COMPLIANCE_CONTROLS = {
    "NIST SP 800-53": {
        "all": "SI-4 (System Monitoring), AU-6 (Audit Review, Analysis, Reporting)",
        "high": "SI-3 (Malicious Code Protection), SC-7 (Boundary Protection), IR-4 (Incident Handling), IA-5 (Authenticator Management)",
        "ssl": "SC-8 (Transmission Confidentiality & Integrity), SC-13 (Cryptographic Protection)",
    },
    "PCI DSS v4.0": {
        "all": "Req 6.5 (Common Coding Vulnerabilities), Req 10 (Logging & Monitoring)",
        "high": "Req 1.3 (Restrict Connections), Req 12.10 (Incident Response), Req 6.3.1 (Remove Unnecessary Features)",
        "ssl": "Req 4.1 (Strong Cryptography), Req 4.2 (Transmission Encryption)",
    },
    "ISO 27001:2022": {
        "all": "A.12.4 (Logging and Monitoring), A.16.1 (Incident Management Planning)",
        "high": "A.13.1 (Network Controls), A.8.2 (Information Classification), A.5.21 (Information Security in Project Lifecycle)",
        "ssl": "A.8.24 (Use of Cryptography)",
    },
    "CIS Controls v8": {
        "all": "Control 7 (Email & Web Browser Protections), Control 13 (Network Monitoring & Defense)",
        "high": "Control 3 (Data Protection), Control 17 (Incident Response Management), Control 6 (Access Control)",
        "ssl": "Control 3.6 (Data at Rest), Control 3.7 (Data in Transit)",
    },
}


# ---------------------------------------------------------------------------
# Helper: classify findings

def _classify_findings(url_features, nltk_details):
    """Classify detected features into severity categories.

    Returns dict with keys: critical, high, medium, low — each a list of
    {feature, description} dicts for indicators that are True.
    """
    findings = {"critical": [], "high": [], "medium": [], "low": []}

    for feature, desc in CRITICAL_INDICATORS.items():
        if url_features.get(feature):
            findings["critical"].append({"feature": feature, "description": desc})

    for feature, desc in HIGH_INDICATORS.items():
        if url_features.get(feature):
            findings["high"].append({"feature": feature, "description": desc})

    for feature, desc in MEDIUM_INDICATORS.items():
        if url_features.get(feature):
            findings["medium"].append({"feature": feature, "description": desc})

    for feature, desc in LOW_INDICATORS.items():
        if url_features.get(feature):
            findings["low"].append({"feature": feature, "description": desc})

    # NLTK text analysis findings
    total_weight = nltk_details.get("total_weight", 0)
    found_keywords = nltk_details.get("found_keywords", [])

    if total_weight > 100 or len(found_keywords) >= 5:
        findings["critical"].append({
            "feature": "NLTK_High_Weight_Keywords",
            "description": (
                f"Page content contains high-weight phishing keywords "
                f"(weight score: {total_weight}, {len(found_keywords)} keywords) "
                f"— indicates active credential harvesting"
            ),
        })
    elif total_weight > 50 or len(found_keywords) >= 3:
        findings["high"].append({
            "feature": "NLTK_Moderate_Weight_Keywords",
            "description": (
                f"Page content contains moderate-weight phishing keywords "
                f"(weight score: {total_weight}, {len(found_keywords)} keywords) "
                f"— suggests social engineering attempt"
            ),
        })
    elif total_weight > 20:
        findings["medium"].append({
            "feature": "NLTK_Low_Weight_Keywords",
            "description": (
                f"Page content contains some phishing-related keywords "
                f"(weight score: {total_weight}, {len(found_keywords)} keywords)"
            ),
        })
    elif total_weight > 0:
        findings["low"].append({
            "feature": "NLTK_Minimal_Keywords",
            "description": (
                f"Minor phishing keyword presence detected "
                f"(weight score: {total_weight}, {len(found_keywords)} keyword(s))"
            ),
        })

    return findings


# ---------------------------------------------------------------------------
# calculate the likelihood score

def _calculate_likelihood(verdict, confidence):
    """Convert ML verdict and confidence into OWASP likelihood score (1-10).

    For phishing verdicts, confidence directly drives likelihood.
    For legitimate verdicts, likelihood is capped low.
    """
    if verdict == "Phishing":
        score = round(confidence * 10)
        score = max(1, min(10, score))
    else:
        # Even for legitimate, if low confidence there's slight uncertainty
        score = max(1, round((1 - confidence) * 3))

    if score >= 9:
        level = "Almost Certain"
    elif score >= 7:
        level = "Likely"
    elif score >= 5:
        level = "Possible"
    elif score >= 3:
        level = "Unlikely"
    else:
        level = "Rare"

    return score, level


# ---------------------------------------------------------------------------
# calculate the impact score


def _calculate_impact(findings):
    """Calculate OWASP impact score (1-10) from classified findings.

    Uses weighted scoring: Critical=1.5, High=1.0, Medium=0.5, Low=0.25.
    """
    impact = 1.0  # base impact
    impact += len(findings["critical"]) * 1.5
    impact += len(findings["high"]) * 1.0
    impact += len(findings["medium"]) * 0.5
    impact += len(findings["low"]) * 0.25

    impact = min(10, max(1, round(impact)))

    if impact >= 9:
        level = "Severe"
    elif impact >= 7:
        level = "Significant"
    elif impact >= 5:
        level = "Moderate"
    elif impact >= 3:
        level = "Minor"
    else:
        level = "Minimal"

    return impact, level


# ---------------------------------------------------------------------------
# determining the risk rating

def _determine_risk_rating(risk_score):
    """Map risk score to OWASP risk rating."""
    if risk_score >= 75:
        return "Critical"
    elif risk_score >= 50:
        return "High"
    elif risk_score >= 25:
        return "Medium"
    elif risk_score >= 10:
        return "Low"
    else:
        return "Informational"


# ---------------------------------------------------------------------------
# map findings to OWASP categories

def _map_to_owasp_categories(findings):
    """Map detected findings to relevant OWASP Top 10 (2021) categories."""
    # Collect all finding descriptions as lowercase text
    all_descriptions = []
    for severity in findings.values():
        for f in severity:
            all_descriptions.append(f["description"].lower())

    all_text = " ".join(all_descriptions)

    relevant_categories = []
    for cat_id, cat_info in OWASP_CATEGORIES.items():
        matched_keywords = []
        for kw in cat_info["keywords"]:
            if kw.lower() in all_text:
                matched_keywords.append(kw)

        if matched_keywords:
            # Determine relevance level based on which severity the matches came from
            max_severity = "low"
            for severity in ["critical", "high", "medium", "low"]:
                for f in findings[severity]:
                    for kw in matched_keywords:
                        if kw.lower() in f["description"].lower():
                            max_severity = severity
                            break
                    if max_severity != "low":
                        break
                if max_severity != "low":
                    break

            relevance_map = {
                "critical": "Critical",
                "high": "High",
                "medium": "Medium",
                "low": "Low",
            }

            relevant_categories.append({
                "id": cat_id,
                "name": cat_info["name"],
                "description": cat_info["description"],
                "relevance": relevance_map[max_severity],
                "matched_indicators": matched_keywords,
            })

    # Sort by relevance (Critical first)
    relevance_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    relevant_categories.sort(key=lambda x: relevance_order.get(x["relevance"], 4))

    return relevant_categories


# ---------------------------------------------------------------------------
# getting the recommended actions

def _get_recommended_actions(risk_rating, findings, verdict):
    """Generate prioritized recommended actions based on risk rating."""
    actions = []

    if risk_rating == "Critical":
        actions.append({
            "priority": "IMMEDIATE",
            "action": "Block access to this URL across all network endpoints",
            "detail": "High-confidence phishing with active malicious indicators detected",
        })
        actions.append({
            "priority": "IMMEDIATE",
            "action": "Initiate security incident investigation",
            "detail": "Collect evidence and assess scope of potential credential compromise",
        })
        actions.append({
            "priority": "SHORT",
            "action": "Add URL and associated domains to threat intelligence blocklist",
            "detail": "Prevent future access attempts and share with threat intel platforms",
        })
        if any("credential" in f["description"].lower() or "harvesting" in f["description"].lower()
               for f in findings["critical"] + findings["high"]):
            actions.append({
                "priority": "SHORT",
                "action": "Notify potentially affected users and initiate credential reset",
                "detail": "Active credential harvesting indicators suggest user credentials may be at risk",
            })
        actions.append({
            "priority": "MEDIUM",
            "action": "Report to relevant CERT and security organizations",
            "detail": "Share indicators of compromise for community defense",
        })
    elif risk_rating == "High":
        actions.append({
            "priority": "IMMEDIATE",
            "action": "Display prominent security warning to users attempting access",
            "detail": "Warn users before allowing continued access to this URL",
        })
        actions.append({
            "priority": "SHORT",
            "action": "Add URL to monitoring watchlist for continuous analysis",
            "detail": "Track for infrastructure changes or related domain registrations",
        })
        actions.append({
            "priority": "SHORT",
            "action": "Submit indicators to threat intelligence platform",
            "detail": "Enrich with external data sources for broader context",
        })
        actions.append({
            "priority": "MEDIUM",
            "action": "Review access logs for any prior access to this URL",
            "detail": "Determine if any users have already been exposed",
        })
    elif risk_rating == "Medium":
        actions.append({
            "priority": "SHORT",
            "action": "Flag URL for manual security team review",
            "detail": "Automated analysis suggests potential risk — human validation recommended",
        })
        actions.append({
            "priority": "MEDIUM",
            "action": "Add to periodic re-evaluation monitoring queue",
            "detail": "Schedule follow-up scan to detect any changes in risk profile",
        })
        actions.append({
            "priority": "MEDIUM",
            "action": "Document finding in security assessment log",
            "detail": "Maintain audit trail for compliance and trend analysis",
        })
    elif risk_rating == "Low":
        actions.append({
            "priority": "MEDIUM",
            "action": "Log finding for ongoing trend analysis",
            "detail": "Minor indicators detected — monitor for pattern escalation",
        })
        actions.append({
            "priority": "LOW",
            "action": "No immediate protective action required",
            "detail": "URL presents minimal risk based on current analysis",
        })
    else:
        actions.append({
            "priority": "INFO",
            "action": "No security concerns identified",
            "detail": "URL analysis found no significant phishing or malicious indicators",
        })

    return actions


# ---------------------------------------------------------------------------
# get compliance mapping

def _get_compliance_mapping(risk_rating, findings):
    """Map risk findings to relevant compliance framework controls."""
    compliance = []

    has_ssl_findings = any(
        any(kw in f["description"].lower()
            for kw in ["certificate", "ssl", "issuer", "subject", "trusted", "self-signed"])
        for f in findings["critical"] + findings["high"]
    )

    if risk_rating in ["Critical", "High"]:
        for framework, controls in COMPLIANCE_CONTROLS.items():
            if "high" in controls:
                compliance.append({
                    "framework": framework,
                    "controls": controls["high"],
                })

    if has_ssl_findings:
        for framework, controls in COMPLIANCE_CONTROLS.items():
            if "ssl" in controls:
                # Avoid duplicate framework entries
                existing = [c["framework"] for c in compliance]
                if framework not in existing:
                    compliance.append({
                        "framework": framework,
                        "controls": controls["ssl"],
                    })
                else:
                    for c in compliance:
                        if c["framework"] == framework:
                            c["controls"] += ", " + controls["ssl"]

    if risk_rating == "Medium":
        for framework, controls in COMPLIANCE_CONTROLS.items():
            if "all" in controls:
                compliance.append({
                    "framework": framework,
                    "controls": controls["all"],
                })

    return compliance


# ---------------------------------------------------------------------------
# MAIN FUNCTION: generate_owasp_report

def generate_owasp_report(url_features, nltk_details, verdict, confidence):
    """Generate a complete OWASP-conformant risk assessment report.

    Converts ML detection results into an industry-standard risk rating
    using Likelihood × Impact methodology.

    Args:
        url_features: dict of boolean/int feature flags from extract_all_url_features()
        nltk_details: dict with NLTK analysis details from extract_nltk_features()
        verdict: "Phishing" or "Legitimate"
        confidence: float 0-1, confidence of the predicted class

    Returns:
        dict with complete OWASP risk report including:
          - risk_rating, risk_score
          - likelihood (score, level, basis)
          - impact (score, level, findings by severity)
          - owasp_categories (mapped OWASP Top 10 categories)
          - recommended_actions (prioritized list)
          - compliance_mapping (relevant framework controls)
    """
    # Classify all findings by severity
    findings = _classify_findings(url_features, nltk_details)
    total_indicators = (
        len(findings["critical"]) + len(findings["high"]) +
        len(findings["medium"]) + len(findings["low"])
    )

    # Calculate likelihood
    likelihood_score, likelihood_level = _calculate_likelihood(verdict, confidence)

    if verdict == "Phishing":
        likelihood_basis = (
            f"ML models classified URL as phishing with {confidence:.1%} confidence "
            f"({likelihood_score}/10 likelihood)"
        )
    else:
        likelihood_basis = (
            f"ML models classified URL as legitimate with {confidence:.1%} confidence "
            f"({likelihood_score}/10 residual uncertainty)"
        )

    # Calculate impact
    impact_score, impact_level = _calculate_impact(findings)

    # Compute risk score and rating
    risk_score = likelihood_score * impact_score  # 1-100
    risk_rating = _determine_risk_rating(risk_score)

    # Map to OWASP categories
    owasp_categories = _map_to_owasp_categories(findings)

    # Generate recommended actions
    recommended_actions = _get_recommended_actions(risk_rating, findings, verdict)

    # Map to compliance frameworks
    compliance_mapping = _get_compliance_mapping(risk_rating, findings)

    return {
        "risk_rating": risk_rating,
        "risk_score": risk_score,
        "likelihood": {
            "score": likelihood_score,
            "level": likelihood_level,
            "basis": likelihood_basis,
        },
        "impact": {
            "score": impact_score,
            "level": impact_level,
            "findings": findings,
            "total_indicators": total_indicators,
        },
        "owasp_categories": owasp_categories,
        "recommended_actions": recommended_actions,
        "compliance_mapping": compliance_mapping,
    }
