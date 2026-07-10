from flask import Flask, render_template, request, send_file
import whois
import requests
import base64
import datetime
import re
import validators
import math
from urllib.parse import urlparse
from collections import Counter
import io

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

app = Flask(__name__)

# 🔑 PASTE YOUR VIRUSTOTAL API KEY HERPASTE_YOUR_API_KEY_HEREE
VIRUSTOTAL_API_KEY = "18159d3402795521e047ab32c82730588f59e92e7bef7f7d160e88808bb4613d"


# -----------------------------
# Entropy Calculation
# -----------------------------
def calculate_entropy(string):
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy


# -----------------------------
# VirusTotal Check
# -----------------------------
def check_virustotal(url):
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        # Submit URL
        requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        response = requests.get(vt_url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return malicious, suspicious
        else:
            return None, None

    except:
        return None, None


# -----------------------------
# Main Risk Analysis
# -----------------------------
def calculate_risk(url):
    score = 0
    reasons = []

    if not validators.url(url):
        return {
            "score": 100,
            "reasons": ["Invalid URL format"],
            "entropy": 0,
            "tld": "N/A",
            "subdomains": 0
        }

    parsed = urlparse(url)
    domain = parsed.netloc
    tld = domain.split('.')[-1].lower()
    subdomains = domain.count('.') - 1

    # HTTPS
    if parsed.scheme != "https":
        score += 20
        reasons.append("Not using HTTPS")

    # IP Address
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        score += 25
        reasons.append("Using IP address instead of domain")

    # Long URL
    if len(url) > 75:
        score += 10
        reasons.append("URL unusually long")

    # Suspicious Keywords
    suspicious_keywords = ["login", "verify", "update", "bank", "secure", "account"]
    for word in suspicious_keywords:
        if word in url.lower():
            score += 15
            reasons.append(f"Suspicious keyword detected: {word}")
            break

    # Suspicious TLDs
    suspicious_tlds = ["xyz", "top", "click", "gq", "tk"]
    if tld in suspicious_tlds:
        score += 20
        reasons.append(f"Suspicious TLD detected: .{tld}")

    # Entropy
    entropy = calculate_entropy(domain)
    if entropy > 4:
        score += 15
        reasons.append("High domain randomness (entropy anomaly)")

    # WHOIS Domain Age
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.datetime.now() - creation_date).days
            reasons.append(f"Domain age: {age_days} days")
            if age_days < 180:
                score += 25
                reasons.append("Domain less than 6 months old")
    except:
        score += 10
        reasons.append("Unable to verify domain age")

    # Security Headers
    try:
        response = requests.get(url, timeout=3)
        headers = response.headers

        if "Strict-Transport-Security" not in headers:
            score += 5
            reasons.append("Missing HSTS header")

        if "Content-Security-Policy" not in headers:
            score += 5
            reasons.append("Missing Content-Security-Policy header")

        if "X-Frame-Options" not in headers:
            score += 5
            reasons.append("Missing X-Frame-Options header")

    except:
        reasons.append("Could not retrieve security headers")

    # VirusTotal
    malicious, suspicious = check_virustotal(url)

    if malicious is not None:
        if malicious > 0:
            score += 40
            reasons.append(f"VirusTotal: {malicious} engines flagged as malicious")
        elif suspicious > 0:
            score += 20
            reasons.append(f"VirusTotal: {suspicious} engines flagged as suspicious")
        else:
            reasons.append("VirusTotal: No engines flagged this URL")
    else:
        reasons.append("VirusTotal check unavailable")

    return {
        "score": min(score, 100),
        "reasons": reasons,
        "entropy": round(entropy, 2),
        "tld": tld,
        "subdomains": subdomains
    }


# -----------------------------
# PDF Generator
# -----------------------------
def generate_pdf_report(result):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer)
    elements = []

    styles = getSampleStyleSheet()

    elements.append(Paragraph("PhishGuard Security Assessment Report", styles["Heading1"]))
    elements.append(Spacer(1, 0.3 * inch))

    elements.append(Paragraph(f"<b>Analyzed URL:</b> {result['url']}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Risk Score:</b> {result['score']}%", styles["Normal"]))
    elements.append(Paragraph(f"<b>Risk Level:</b> {result['risk']}", styles["Normal"]))
    elements.append(Spacer(1, 0.3 * inch))

    elements.append(Paragraph("<b>Detected Indicators:</b>", styles["Heading2"]))
    elements.append(Spacer(1, 0.2 * inch))

    indicator_list = []
    for reason in result["reasons"]:
        indicator_list.append(ListItem(Paragraph(reason, styles["Normal"])))

    elements.append(ListFlowable(indicator_list, bulletType="bullet"))

    elements.append(Spacer(1, 0.5 * inch))
    elements.append(Paragraph("Generated by PhishGuard | Cybersecurity Prototype", styles["Normal"]))

    doc.build(elements)
    buffer.seek(0)
    return buffer


# -----------------------------
# Routes
# -----------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        url = request.form["url"]
        analysis = calculate_risk(url)

        score = analysis["score"]

        if score <= 25:
            risk_level = "Low Risk"
            color = "success"
        elif score <= 50:
            risk_level = "Medium Risk"
            color = "warning"
        else:
            risk_level = "High Risk"
            color = "danger"

        result = {
            "url": url,
            "score": score,
            "risk": risk_level,
            "color": color,
            "reasons": analysis["reasons"],
            "entropy": analysis["entropy"],
            "tld": analysis["tld"],
            "subdomains": analysis["subdomains"]
        }

    return render_template("index.html", result=result)


@app.route("/download", methods=["POST"])
def download():
    url = request.form["url"]
    analysis = calculate_risk(url)
    score = analysis["score"]

    if score <= 25:
        risk_level = "Low Risk"
    elif score <= 50:
        risk_level = "Medium Risk"
    else:
        risk_level = "High Risk"

    result = {
        "url": url,
        "score": score,
        "risk": risk_level,
        "reasons": analysis["reasons"]
    }

    pdf = generate_pdf_report(result)

    return send_file(
        pdf,
        as_attachment=True,
        download_name="PhishGuard_Report.pdf",
        mimetype="application/pdf"
    )


if __name__ == "__main__":
    app.run(debug=True)
