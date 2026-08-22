import socket
import requests
import dns.resolver
import whois
from ipwhois import IPWhois
import ssl
from flask import Flask, request, render_template_string, send_file
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER
from io import BytesIO
from html import escape

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>CyberIntel Scanner</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: #07111f;
    color: #e2e8f0;
    font-family: Arial, sans-serif;
}

.header {
    background: #0b1728;
    border-bottom: 1px solid #1e3a52;
    padding: 22px;
    text-align: center;
}

.logo {
    font-size: 30px;
    font-weight: bold;
    color: #38bdf8;
}

.header p {
    margin: 7px 0 0;
    color: #94a3b8;
}

.container {
    max-width: 1100px;
    margin: auto;
    padding: 35px 20px;
}

.search-box {
    background: #0d1b2d;
    border: 1px solid #1e3a52;
    border-radius: 14px;
    padding: 25px;
    text-align: center;
}

.search-box h2 {
    margin-top: 0;
}

.search-box p {
    color: #94a3b8;
}

input {
    width: 70%;
    padding: 15px;
    background: #07111f;
    color: white;
    border: 1px solid #334155;
    border-radius: 8px;
    font-size: 16px;
}

button {
    padding: 15px 25px;
    margin-left: 8px;
    border: none;
    border-radius: 8px;
    background: #38bdf8;
    color: #07111f;
    font-weight: bold;
    cursor: pointer;
}

button:hover {
    background: #7dd3fc;
}

.report-button {
    display: block;
    margin: 25px auto 0;
    background: #22c55e;
}

.grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 18px;
    margin-top: 25px;
}

.card {
    background: #0d1b2d;
    border: 1px solid #1e3a52;
    border-radius: 12px;
    padding: 20px;
}

.card.full {
    grid-column: 1 / -1;
}

.card h2 {
    margin-top: 0;
    color: #38bdf8;
    font-size: 19px;
}

.item {
    padding: 10px 0;
    border-bottom: 1px solid #1e293b;
    word-break: break-word;
}

.item:last-child {
    border-bottom: none;
}

.label {
    color: #94a3b8;
}

.value {
    color: #f8fafc;
}

.status {
    display: inline-block;
    padding: 6px 10px;
    border-radius: 20px;
    background: #064e3b;
    color: #6ee7b7;
    font-size: 13px;
    font-weight: bold;
}

.error {
    margin-top: 20px;
    padding: 15px;
    background: #3f1720;
    border: 1px solid #7f1d1d;
    color: #fda4af;
    border-radius: 10px;
    text-align: center;
}

.notice {
    margin-top: 25px;
    padding: 14px;
    background: #0b1728;
    border-left: 4px solid #38bdf8;
    color: #94a3b8;
    font-size: 13px;
}

footer {
    text-align: center;
    color: #64748b;
    margin-top: 35px;
    padding-bottom: 20px;
}

@media (max-width: 700px) {

    .grid {
        grid-template-columns: 1fr;
    }

    .card.full {
        grid-column: auto;
    }

    input {
        width: 100%;
        margin-bottom: 10px;
    }

    button {
        width: 100%;
        margin-left: 0;
    }

}

</style>

</head>

<body>

<div class="header">

    <div class="logo">
        🛡️ CyberIntel Scanner
    </div>

    <p>
        Domain & IP Intelligence System
    </p>

</div>


<div class="container">

<div class="search-box">

    <h2>🔎 Scan a Domain or IP Address</h2>

    <p>
        Enter a domain or IP to view publicly available information.
    </p>

    <form method="POST">

        <input
            type="text"
            name="target"
            placeholder="example.com or 8.8.8.8"
            required
        >

        <button type="submit">
            SCAN TARGET
        </button>

    </form>

</div>


{% if result %}

{% if result.error %}

<div class="error">
    ⚠️ {{ result.error }}
</div>

{% else %}

<div class="grid">

<div class="card">

<h2>🌐 Basic Information</h2>

<div class="item">
<span class="label">Target:</span><br>
<span class="value">{{ result.target }}</span>
</div>

<div class="item">
<span class="label">IP Address:</span><br>
<span class="value">{{ result.ip }}</span>
</div>

<div class="item">
<span class="label">Hostname:</span><br>
<span class="value">{{ result.hostname }}</span>
</div>

<div class="item">
<span class="label">Organization / ISP:</span><br>
<span class="value">{{ result.org }}</span>
</div>

<div class="item">
<span class="label">Country:</span><br>
<span class="value">{{ result.country }}</span>
</div>

<div class="item">
<span class="label">City:</span><br>
<span class="value">{{ result.city }}</span>
</div>

</div>


<div class="card">

<h2>🛰️ ASN / Network</h2>

<div class="item">
<span class="label">ASN:</span><br>
<span class="value">{{ result.asn }}</span>
</div>

<div class="item">
<span class="label">ASN Description:</span><br>
<span class="value">{{ result.asn_description }}</span>
</div>

<div class="item">
<span class="label">Network:</span><br>
<span class="value">{{ result.network }}</span>
</div>

<div class="item">
<span class="label">Network Name:</span><br>
<span class="value">{{ result.network_name }}</span>
</div>

</div>


<div class="card">

<h2>🔄 Reverse DNS</h2>

<div class="item">

<span class="label">
Reverse Hostname:
</span>

<br>

<span class="value">
{{ result.reverse_dns }}
</span>

</div>

</div>


<div class="card">

<h2>🔐 SSL Certificate</h2>

<div class="item">

<span class="label">Status:</span><br>

<span class="status">
{{ result.ssl.status }}
</span>

</div>

<div class="item">
<span class="label">Subject:</span><br>
{{ result.ssl.subject }}
</div>

<div class="item">
<span class="label">Issuer:</span><br>
{{ result.ssl.issuer }}
</div>

<div class="item">
<span class="label">Valid Until:</span><br>
{{ result.ssl.valid_until }}
</div>

</div>


<div class="card full">

<h2>📡 DNS Records</h2>

<div class="item">
<span class="label">A:</span>
{{ result.dns.A }}
</div>

<div class="item">
<span class="label">AAAA:</span>
{{ result.dns.AAAA }}
</div>

<div class="item">
<span class="label">MX:</span>
{{ result.dns.MX }}
</div>

<div class="item">
<span class="label">NS:</span>
{{ result.dns.NS }}
</div>

<div class="item">
<span class="label">CNAME:</span>
{{ result.dns.CNAME }}
</div>

</div>


<div class="card full">

<h2>📋 WHOIS Information</h2>

<div class="item">
<span class="label">Registrar:</span><br>
{{ result.whois.registrar }}
</div>

<div class="item">
<span class="label">Creation Date:</span><br>
{{ result.whois.creation_date }}
</div>

<div class="item">
<span class="label">Expiration Date:</span><br>
{{ result.whois.expiration_date }}
</div>

<div class="item">
<span class="label">Name Servers:</span><br>
{{ result.whois.name_servers }}
</div>

</div>

</div>


<form method="POST" action="/report">

<input
    type="hidden"
    name="target"
    value="{{ result.target }}"
>

<button class="report-button" type="submit">
📄 Generate PDF Report
</button>

</form>


<div class="notice">

🛡️ <b>Ethical Use:</b>
This tool is designed for educational,
defensive, and authorized cybersecurity
information gathering. It displays
publicly available information only.

</div>

{% endif %}

{% endif %}

<footer>
CyberIntel Scanner • Educational Cybersecurity Project
</footer>

</div>

</body>
</html>
"""


def get_dns_records(domain):

    records = {}

    for record_type in ["A", "AAAA", "MX", "NS", "CNAME"]:

        try:

            answers = dns.resolver.resolve(
                domain,
                record_type
            )

            records[record_type] = [
                str(answer) for answer in answers
            ]

        except Exception:

            records[record_type] = ["Not available"]

    return records


def get_whois_info(domain):

    try:

        data = whois.whois(domain)

        return {
            "registrar": data.get("registrar") or "Not available",
            "creation_date": data.get("creation_date") or "Not available",
            "expiration_date": data.get("expiration_date") or "Not available",
            "name_servers": data.get("name_servers") or "Not available"
        }

    except Exception:

        return {
            "registrar": "Not available",
            "creation_date": "Not available",
            "expiration_date": "Not available",
            "name_servers": "Not available"
        }


def get_reverse_dns(ip):

    try:

        return socket.gethostbyaddr(ip)[0]

    except Exception:

        return "Not available"


def get_asn_info(ip):

    try:

        obj = IPWhois(ip)

        result = obj.lookup_rdap(depth=1)

        network = result.get("network") or {}

        return {
            "asn": result.get("asn") or "Not available",
            "asn_description":
                result.get("asn_description")
                or "Not available",
            "network":
                network.get("cidr")
                or "Not available",
            "network_name":
                network.get("name")
                or "Not available"
        }

    except Exception:

        return {
            "asn": "Not available",
            "asn_description": "Not available",
            "network": "Not available",
            "network_name": "Not available"
        }


def get_ssl_info(domain):

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (domain, 443),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as secure_socket:

                certificate = secure_socket.getpeercert()

        # ``getpeercert()`` may return ``None`` and its subject/issuer
        # entries are nested sequences rather than key/value pairs.
        subject = {}
        for item in (certificate or {}).get("subject", ()):
            if isinstance(item, (list, tuple)) and len(item) > 0:
                attribute = item[0]
                if isinstance(attribute, (list, tuple)) and len(attribute) > 1:
                    subject[attribute[0]] = attribute[1]

        issuer = {}
        for item in (certificate or {}).get("issuer", ()):
            if isinstance(item, (list, tuple)) and len(item) > 0:
                attribute = item[0]
                if isinstance(attribute, (list, tuple)) and len(attribute) > 1:
                    issuer[attribute[0]] = attribute[1]

        return {

            "status":
                "Valid HTTPS certificate",

            "subject":
                subject.get(
                    "commonName",
                    "Not available"
                ),

            "issuer":
                issuer.get(
                    "organizationName",
                    "Not available"
                ),

            "valid_until":
                (certificate or {}).get(
                    "notAfter",
                    "Not available"
                )
        }

    except Exception:

        return {

            "status":
                "SSL information unavailable",

            "subject":
                "Not available",

            "issuer":
                "Not available",

            "valid_until":
                "Not available"
        }


def collect_data(target):

    if not target or len(target) > 253:
        raise ValueError("Invalid target")

    ip = socket.gethostbyname(target)

    response = requests.get(
        f"https://ipinfo.io/{ip}/json",
        timeout=5
    )

    data = response.json()

    asn_info = get_asn_info(ip)

    return {

        "target": target,

        "ip": ip,

        "hostname":
            socket.getfqdn(ip),

        "org":
            data.get(
                "org",
                "Not available"
            ),

        "country":
            data.get(
                "country",
                "Not available"
            ),

        "city":
            data.get(
                "city",
                "Not available"
            ),

        "reverse_dns":
            get_reverse_dns(ip),

        "dns":
            get_dns_records(target),

        "whois":
            get_whois_info(target),

        "asn":
            asn_info["asn"],

        "asn_description":
            asn_info["asn_description"],

        "network":
            asn_info["network"],

        "network_name":
            asn_info["network_name"],

        "ssl":
            get_ssl_info(target)
    }


@app.route("/", methods=["GET", "POST"])
def home():

    result = None

    if request.method == "POST":

        target = request.form["target"].strip()

        try:

            result = collect_data(target)

        except Exception:

            result = {
                "error":
                "Could not find information. Check the domain/IP."
            }

    return render_template_string(
        HTML,
        result=result
    )


@app.route("/report", methods=["POST"])
def report():

    target = request.form["target"].strip()

    try:

        result = collect_data(target)

    except Exception:

        return "Unable to generate report for this target.", 400

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        title="CyberIntel Scan Report"
    )

    styles = getSampleStyleSheet()

    title_style = styles["Title"]
    title_style.alignment = TA_CENTER

    story = []

    story.append(
        Paragraph(
            "CyberIntel Scanner Report",
            title_style
        )
    )

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            f"<b>Target:</b> {escape(str(result['target']))}",
            styles["Normal"]
        )
    )

    story.append(Spacer(1, 8))

    sections = [

        (
            "Basic Information",
            [
                f"IP Address: {escape(str(result['ip']))}",
                f"Hostname: {escape(str(result['hostname']))}",
                f"Organization / ISP: {escape(str(result['org']))}",
                f"Country: {escape(str(result['country']))}",
                f"City: {escape(str(result['city']))}"
            ]
        ),

        (
            "ASN / Network",
            [
                f"ASN: {escape(str(result['asn']))}",
                f"ASN Description: {escape(str(result['asn_description']))}",
                f"Network: {escape(str(result['network']))}",
                f"Network Name: {escape(str(result['network_name']))}"
            ]
        ),

        (
            "Reverse DNS",
            [
                f"Reverse Hostname: {escape(str(result['reverse_dns']))}"
            ]
        ),

        (
            "SSL Certificate",
            [
                f"Status: {escape(str(result['ssl']['status']))}",
                f"Subject: {escape(str(result['ssl']['subject']))}",
                f"Issuer: {escape(str(result['ssl']['issuer']))}",
                f"Valid Until: {escape(str(result['ssl']['valid_until']))}"
            ]
        ),

        (
            "WHOIS",
            [
                f"Registrar: {escape(str(result['whois']['registrar']))}",
                f"Creation Date: {escape(str(result['whois']['creation_date']))}",
                f"Expiration Date: {escape(str(result['whois']['expiration_date']))}",
                f"Name Servers: {escape(str(result['whois']['name_servers']))}"
            ]
        )

    ]

    for section_name, items in sections:

        story.append(
            Spacer(1, 12)
        )

        story.append(
            Paragraph(
                f"<b>{section_name}</b>",
                styles["Heading2"]
            )
        )

        for item in items:

            story.append(
                Paragraph(
                    item,
                    styles["Normal"]
                )
            )

            story.append(
                Spacer(1, 5)
            )


    story.append(
        Spacer(1, 15)
    )

    story.append(
        Paragraph(
            "DNS Records",
            styles["Heading2"]
        )
    )

    for record_type, values in result["dns"].items():

        story.append(
            Paragraph(
                f"<b>{escape(str(record_type))}:</b> "
                f"{escape(', '.join(map(str, values)))}",
                styles["Normal"]
            )
        )

        story.append(
            Spacer(1, 5)
        )


    story.append(
        Spacer(1, 20)
    )

    story.append(
        Paragraph(
            "Generated for educational and authorized cybersecurity use.",
            styles["Normal"]
        )
    )

    document.build(story)

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="cyberintel_report.pdf",
        mimetype="application/pdf"
    )


if __name__ == "__main__":
    app.run(debug=False)
