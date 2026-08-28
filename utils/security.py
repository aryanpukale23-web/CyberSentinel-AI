# CyberSentinel AI
# Intelligent Cyber Incident Risk Engine

import re


# Incident Type Scores

INCIDENT_TYPE_SCORES = {
    "phishing": 25,
    "account compromise": 30,
    "malware": 30,
    "ransomware": 30,
    "data breach": 30,
    "identity theft": 25,
    "financial fraud": 25,
    "password attack": 20,
    "social engineering": 20,
    "suspicious activity": 10,
    "other": 10
}


# Impact Scores

IMPACT_SCORES = {
    "critical": 25,
    "high": 20,
    "medium": 12,
    "low": 5
}


# Data Exposure Scores

DATA_SCORES = {
    "yes": 20,
    "no": 0
}


# Frequency Scores

FREQUENCY_SCORES = {
    "multiple": 15,
    "repeated": 15,
    "once": 5
}


# Evidence Scores

EVIDENCE_SCORES = {
    "yes": 10,
    "no": 0
}


# Normalize Text

def normalize_text(value):

    if value is None:
        return ""

    return str(value).strip().lower()


# Get Risk Level

def get_risk_level(score):

    if score >= 70:
        return "High"

    elif score >= 40:
        return "Medium"

    return "Low"


# Generate Reason

def generate_reason(
    incident_type,
    impact,
    sensitive_data,
    frequency,
    evidence
):

    reasons = []

    if incident_type:
        reasons.append(
            f"The incident type '{incident_type}' "
            "has a significant cybersecurity risk."
        )

    if impact in ["critical", "high"]:
        reasons.append(
            "The reported impact level is high."
        )

    if sensitive_data == "yes":
        reasons.append(
            "Sensitive or confidential information may be involved."
        )

    if frequency in ["multiple", "repeated"]:
        reasons.append(
            "The incident has occurred repeatedly."
        )

    if evidence == "yes":
        reasons.append(
            "Supporting evidence has been provided."
        )

    if not reasons:
        reasons.append(
            "The incident currently shows limited risk indicators."
        )

    return " ".join(reasons)


# Generate Impact

def generate_impact(
    incident_type,
    impact,
    sensitive_data
):

    if impact == "critical":

        return (
            "The incident may cause serious financial, "
            "operational, privacy, or security damage."
        )

    if sensitive_data == "yes":

        return (
            "Sensitive information may be exposed, "
            "leading to privacy or security consequences."
        )

    if incident_type in [
        "ransomware",
        "malware",
        "data breach",
        "account compromise"
    ]:

        return (
            "The incident may affect system security, "
            "user accounts, or organizational operations."
        )

    return (
        "The incident may cause limited security or "
        "operational impact if not addressed."
    )


# Response Recommendations

def generate_response_recommendation(
    incident_type,
    risk_level
):

    if incident_type == "phishing":

        return (
            "Do not click suspicious links or open attachments. "
            "Change affected account passwords, enable MFA, "
            "and report the suspicious message."
        )

    if incident_type == "account compromise":

        return (
            "Immediately change the affected password, "
            "enable multi-factor authentication, "
            "terminate unknown sessions, and review account activity."
        )

    if incident_type == "malware":

        return (
            "Disconnect the affected device from the network, "
            "run a trusted security scan, remove malicious software, "
            "and investigate the source of infection."
        )

    if incident_type == "ransomware":

        return (
            "Isolate affected systems immediately, "
            "do not interact with suspicious files, "
            "preserve evidence, and contact the security team."
        )

    if incident_type == "data breach":

        return (
            "Identify the exposed information, secure affected accounts, "
            "preserve evidence, investigate the breach source, "
            "and follow the organization's incident response procedure."
        )

    if incident_type == "financial fraud":

        return (
            "Contact the relevant financial service provider, "
            "secure affected accounts, preserve transaction evidence, "
            "and report the fraudulent activity."
        )

    if risk_level == "High":

        return (
            "Immediately isolate the affected account or system, "
            "preserve evidence, and escalate the incident "
            "for further security investigation."
        )

    if risk_level == "Medium":

        return (
            "Review the affected account or system, "
            "change relevant credentials, monitor activity, "
            "and investigate the incident further."
        )

    return (
        "Monitor the affected account or system, "
        "apply recommended security practices, "
        "and continue monitoring for suspicious activity."
    )


# Prevention Tips

def generate_prevention_tips(incident_type):

    if incident_type == "phishing":

        return (
            "Verify email senders and website URLs before interacting. "
            "Avoid unknown attachments and links. "
            "Use MFA and keep security software updated."
        )

    if incident_type == "account compromise":

        return (
            "Use strong unique passwords, enable MFA, "
            "avoid password reuse, and regularly review "
            "account login activity."
        )

    if incident_type in ["malware", "ransomware"]:

        return (
            "Keep operating systems and applications updated, "
            "use trusted security software, avoid suspicious downloads, "
            "and maintain regular backups."
        )

    if incident_type == "data breach":

        return (
            "Minimize access to sensitive data, use encryption, "
            "apply strong authentication, and regularly review "
            "security controls."
        )

    return (
        "Use strong passwords, enable MFA, keep software updated, "
        "avoid suspicious links and files, and follow "
        "cybersecurity best practices."
    )


# Main Risk Analysis Function

def analyze_incident(
    incident_type,
    impact="medium",
    sensitive_data="no",
    frequency="once",
    evidence="no"
):

    incident_type = normalize_text(incident_type)
    impact = normalize_text(impact)
    sensitive_data = normalize_text(sensitive_data)
    frequency = normalize_text(frequency)
    evidence = normalize_text(evidence)

    # Get Individual Scores

    incident_score = INCIDENT_TYPE_SCORES.get(
        incident_type,
        INCIDENT_TYPE_SCORES["other"]
    )

    impact_score = IMPACT_SCORES.get(
        impact,
        IMPACT_SCORES["medium"]
    )

    data_score = DATA_SCORES.get(
        sensitive_data,
        0
    )

    frequency_score = FREQUENCY_SCORES.get(
        frequency,
        FREQUENCY_SCORES["once"]
    )

    evidence_score = EVIDENCE_SCORES.get(
        evidence,
        0
    )

    # Calculate Total Score

    risk_score = (
        incident_score
        + impact_score
        + data_score
        + frequency_score
        + evidence_score
    )

    # Maximum 100

    risk_score = min(
        100,
        max(0, risk_score)
    )

    # Risk Level

    risk_level = get_risk_level(
        risk_score
    )

    # Reason

    reason = generate_reason(
        incident_type,
        impact,
        sensitive_data,
        frequency,
        evidence
    )

    # Impact

    impact_description = generate_impact(
        incident_type,
        impact,
        sensitive_data
    )

    # Response

    response_recommendation = generate_response_recommendation(
        incident_type,
        risk_level
    )

    # Prevention

    prevention_tips = generate_prevention_tips(
        incident_type
    )

    # Return Complete Analysis

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reason": reason,
        "impact": impact_description,
        "response_recommendation": response_recommendation,
        "prevention_tips": prevention_tips
    }
