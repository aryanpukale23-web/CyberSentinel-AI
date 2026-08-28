import re
import os
import uuid

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_file
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename

from utils.database import (
    get_db_connection,
    init_db
)

from utils.security import analyze_incident


# FLASK APPLICATION

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "dev-secret-key"
)

init_db()
# EVIDENCE UPLOAD CONFIGURATION

UPLOAD_FOLDER = os.path.join(
    app.root_path,
    "static",
    "uploads"
)

ALLOWED_EXTENSIONS = {
    "jpg",
    "jpeg",
    "png",
    "pdf",
    "txt",
    "log",
    "eml"
}

MAX_FILE_SIZE = 10 * 1024 * 1024

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE


# FILE VALIDATION

def allowed_file(filename):

    if not filename:
        return False

    if "." not in filename:
        return False

    extension = filename.rsplit(
        ".",
        1
    )[1].lower()

    return extension in ALLOWED_EXTENSIONS


# PASSWORD VALIDATION

def validate_password(password):

    errors = []

    if len(password) < 6:
        errors.append(
            "Password must be at least 6 characters long."
        )

    if not re.search(r"[A-Z]", password):
        errors.append(
            "Capital letter is missing."
        )

    if not re.search(r"[a-z]", password):
        errors.append(
            "Small letter is missing."
        )

    if not re.search(r"[0-9]", password):
        errors.append(
            "Number is missing."
        )

    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append(
            "Special symbol is missing."
        )

    return errors

# CYBER INCIDENT VALIDATION
# Selected incident type must match the details

def validate_cyber_incident(incident_type, title, description):

    incident_type = (incident_type or "").strip().lower()
    title = (title or "").strip().lower()
    description = (description or "").strip().lower()

    text = f"{title} {description}"

    # Keywords for each incident type
    incident_keywords = {

"phishing": [
    "phishing",
    "phishing email",
    "phishing link",
    "phishing website",
    "spear phishing",
    "whaling",
    "smishing",
    "vishing",
    "fake email",
    "fake login",
    "fake website",
    "malicious link",
    "suspicious link",
    "credential phishing"
],

"hacking": [
    "hack",
    "hacked",
    "hacking",
    "hacker",
    "hacking attempt",
    "hacking attack",
    "unauthorized access",
    "unauthorised access",
    "unauthorized login",
    "unauthorised login",
    "account hacked",
    "account compromised",
    "account takeover",
    "system hacked",
    "server hacked",
    "computer hacked",
    "device hacked",
    "website hacked"
],

"malware": [
    "malware",
    "malware attack",
    "malware infection",
    "malicious software",
    "virus",
    "computer virus",
    "trojan",
    "trojan horse",
    "worm",
    "spyware",
    "adware",
    "rootkit",
    "keylogger",
    "backdoor",
    "botnet",
    "infected computer",
    "infected device",
    "malicious program",
    "malicious application"
],

"ransomware": [
    "ransomware",
    "ransomware attack",
    "ransomware infection",
    "encrypted files",
    "files encrypted",
    "ransom demand",
    "ransom payment",
    "ransomware threat"
],

"data_breach": [
    "data breach",
    "data leak",
    "data leakage",
    "data theft",
    "data stolen",
    "database breach",
    "database hacked",
    "information stolen",
    "personal data stolen",
    "sensitive data stolen",
    "confidential data stolen",
    "credential leak",
    "data exposure",
    "information leak",
    "database leak"
],

"credential_attack": [
    "password stolen",
    "password compromised",
    "password leaked",
    "credential theft",
    "stolen credentials",
    "compromised credentials",
    "credential attack",
    "brute force",
    "brute force attack",
    "credential stuffing",
    "password spraying",
    "password attack",
    "login attack",
    "account takeover"
],

"web_attack": [
    "sql injection",
    "sqli",
    "cross site scripting",
    "cross-site scripting",
    "xss",
    "csrf",
    "command injection",
    "code injection",
    "path traversal",
    "directory traversal",
    "remote code execution",
    "rce",
    "ssrf",
    "web attack",
    "web vulnerability",
    "website vulnerability",
    "website compromise",
    "website compromised",
    "web application attack"
],

"network_attack": [
    "network attack",
    "network intrusion",
    "network breach",
    "network compromise",
    "port scanning",
    "port scan",
    "network scanning",
    "dns spoofing",
    "arp spoofing",
    "ip spoofing",
    "man in the middle",
    "man-in-the-middle",
    "mitm attack",
    "network sniffing",
    "packet sniffing",
    "packet interception"
],

"ddos": [
    "dos attack",
    "denial of service",
    "ddos",
    "ddos attack",
    "distributed denial of service",
    "server flooding",
    "traffic flooding",
    "service disruption",
    "network flooding"
],

"spoofing": [
    "spoofing",
    "email spoofing",
    "website spoofing",
    "identity spoofing",
    "ip spoofing",
    "dns spoofing",
    "arp spoofing",
    "caller id spoofing"
],

"cyber_fraud": [
    "cyber fraud",
    "cybercrime",
    "cyber crime",
    "online fraud",
    "online scam",
    "cyber scam",
    "internet scam",
    "financial fraud",
    "payment fraud",
    "banking fraud",
    "credit card fraud",
    "online theft",
    "digital fraud",
    "internet fraud"
],

"cloud_attack": [
    "cloud attack",
    "cloud security",
    "cloud breach",
    "cloud data breach",
    "cloud account compromised",
    "cloud account hacked",
    "cloud vulnerability",
    "cloud security vulnerability",
    "cloud misconfiguration",
    "cloud data exposure",
    "cloud data leak",
    "cloud storage exposure",
    "storage bucket exposure",
    "cloud intrusion",
    "cloud compromise",
    "cloud security incident",
    "cloud threat"
],

"mobile_attack": [
    "mobile malware",
    "mobile attack",
    "mobile phishing",
    "android malware",
    "android attack",
    "android security",
    "malicious app",
    "fake app",
    "mobile security",
    "mobile vulnerability",
    "sim swapping",
    "sim swap",
    "mobile data theft"
],

"vulnerability": [
    "vulnerability",
    "security vulnerability",
    "critical vulnerability",
    "software vulnerability",
    "system vulnerability",
    "network vulnerability",
    "web vulnerability",
    "zero day",
    "zero-day",
    "security exploit",
    "exploit",
    "exploited vulnerability",
    "unpatched vulnerability",
    "missing security patch",
    "security flaw",
    "software flaw",
    "system flaw"
],

"insider_threat": [
    "insider threat",
    "insider attack",
    "insider access",
    "malicious insider",
    "employee security breach",
    "employee data theft",
    "internal threat",
    "internal attack"
],

"digital_forensics": [
    "digital evidence",
    "forensic evidence",
    "digital forensic",
    "forensic investigation",
    "security investigation",
    "malicious file",
    "suspicious file",
    "malware sample",
    "security log",
    "incident log",
    "attack log"
],

"email_attack": [
    "email attack",
    "malicious email",
    "email compromise",
    "email account hacked",
    "email account compromised",
    "business email compromise",
    "email scam",
    "email spoofing",
    "suspicious email",
    "phishing email",
    "malicious attachment",
    "suspicious attachment"
],

"other": [
    "other",
    "social engineering",
    "social engineering attack",
    "social engineering attempt",
    "suspicious activity",
    "unusual activity",
    "security incident",
    "cybersecurity activity",
    "cyber security activity",
    "cyber incident",
    "cyber threat",
    "security threat",
    "suspicious behavior",
    "suspicious behaviour",
    "potential security threat",
    "malicious activity",
    "security concern",
    "security issue",
    "security problem",
    "unknown activity",
    "unusual behavior",
    "unusual behaviour"
]

    }

    # 
    # FIND MATCHING INCIDENT TYPE
    # 

    selected_keywords = None

    for incident_name, keywords in incident_keywords.items():

        if incident_name in incident_type:

            selected_keywords = keywords
            break

    # 
    # IF INCIDENT TYPE IS NOT FOUND
    # 

    if selected_keywords is None:

        return False

    # 
    # CHECK TITLE + DESCRIPTION
    # 

    for keyword in selected_keywords:

        if keyword in text:
            return True

    # 
    # WRONG DETAILS FOR SELECTED TYPE
    # 

    return False

# HOME

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# LOGIN

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        conn = get_db_connection()

        user = conn.execute(
            """
            SELECT
                id,
                full_name,
                email,
                password
            FROM users
            WHERE email = %s
            """,
            (email,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(
            user["password"],
            password
        ):

            session["user_id"] = user["id"]
            session["user_name"] = user["full_name"]
            session["user_email"] = user["email"]

            return redirect(
                url_for("dashboard")
            )

        return render_template(
            "login.html",
            error="Invalid email or password.",
            email=email
        )

    return render_template(
        "login.html"
    )


# REGISTER

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        full_name = request.form.get(
            "full_name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        ).strip()

        # REQUIRED FIELD VALIDATION

        if not full_name:

            return render_template(
                "register.html",
                error="Please enter your full name."
            )

        if not email:

            return render_template(
                "register.html",
                error="Please enter your email address."
            )

        if not password:

            return render_template(
                "register.html",
                error="Please enter your password."
            )

        # PASSWORD VALIDATION

        password_errors = validate_password(
            password
        )

        if password_errors:

            return render_template(
                "register.html",
                error=password_errors[0],
                full_name=full_name,
                email=email
            )

        full_name = full_name.title()

        # DATABASE

        conn = get_db_connection()

        existing_user = conn.execute(
            """
            SELECT id
            FROM users
            WHERE email = %s
            """,
            (email,)
        ).fetchone()

        if existing_user:

            conn.close()

            return render_template(
                "register.html",
                error="An account with this email already exists.",
                full_name=full_name,
                email=email
            )

        # HASH PASSWORD

        password_hash = generate_password_hash(
            password
        )

        # INSERT USER

        conn.execute(
            """
            INSERT INTO users
            (
                full_name,
                email,
                password
            )
            VALUES (%s, %s, %s)
            """,
            (
                full_name,
                email,
                password_hash
            )
        )

        conn.commit()
        conn.close()

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# DASHBOARD

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]

    conn = get_db_connection()

    # TOTAL INCIDENTS

    total_incidents = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM incidents
        WHERE user_id = %s
        """,
        (user_id,)
    ).fetchone()["count"]

    # HIGH RISK

    high_risk = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM incidents
        WHERE user_id = %s
        AND risk_level = 'High'
        """,
        (user_id,)
    ).fetchone()["count"]

    # MEDIUM RISK

    medium_risk = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM incidents
        WHERE user_id = %s
        AND risk_level = 'Medium'
        """,
        (user_id,)
    ).fetchone()["count"]

    # LOW RISK

    low_risk = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM incidents
        WHERE user_id = %s
        AND risk_level = 'Low'
        """,
        (user_id,)
    ).fetchone()["count"]

    # AVERAGE RISK SCORE

    average_result = conn.execute(
        """
        SELECT AVG(risk_score) AS average_score
        FROM incidents
        WHERE user_id = %s
        """,
        (user_id,)
    ).fetchone()

    if average_result["average_score"] is not None:
        average_risk_score = round(
            average_result["average_score"]
        )
    else:
        average_risk_score = 0

    # EVIDENCE COUNT

    evidence_result = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM incidents
        WHERE user_id = %s
        AND evidence_path IS NOT NULL
        AND evidence_path != ''
        """,
        (user_id,)
    ).fetchone()

    evidence_count = evidence_result["count"]

    # HIGHEST RISK INCIDENT

    highest_risk_incident = conn.execute(
        """
        SELECT
            id,
            title,
            risk_score,
            risk_level
        FROM incidents
        WHERE user_id = %s
        ORDER BY risk_score DESC
        LIMIT 1
        """,
        (user_id,)
    ).fetchone()

    # RECENT INCIDENT HISTORY

    recent_incidents = conn.execute(
        """
        SELECT
            id,
            incident_type,
            title,
            risk_score,
            risk_level,
            status,
            created_at
        FROM incidents
        WHERE user_id = %s
        ORDER BY created_at DESC
        """,
        (user_id,)
    ).fetchall()

    # INCIDENT TYPE DATA

    incident_type_data = conn.execute(
        """
        SELECT
            incident_type,
            COUNT(*) AS count
        FROM incidents
        WHERE user_id = %s
        GROUP BY incident_type
        ORDER BY COUNT(*) DESC
        """,
        (user_id,)
    ).fetchall()

    conn.close()

    # SEND DATA TO DASHBOARD

    return render_template(
        "dashboard.html",

        username=session["user_name"],

        total_incidents=total_incidents,

        high_risk=high_risk,

        medium_risk=medium_risk,

        low_risk=low_risk,

        average_risk_score=average_risk_score,

        evidence_count=evidence_count,

        highest_risk_incident=highest_risk_incident,

        recent_incidents=recent_incidents,

        incident_type_data=incident_type_data
    )


# REPORT INCIDENT

@app.route(
    "/incident/report",
    methods=["GET", "POST"]
)
def report_incident():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    # GET REQUEST

    if request.method == "GET":

        return render_template(
            "report.html"
        )

    # FORM DATA

    incident_type = request.form.get(
        "incident_type",
        ""
    ).strip()

    title = request.form.get(
        "title",
        ""
    ).strip()

    description = request.form.get(
        "description",
        ""
    ).strip()

    # REQUIRED VALIDATION

    if (
        not incident_type
        or not title
        or not description
    ):

        return render_template(
            "report.html",

            error="Please fill all required fields.",

            incident_type=incident_type,

            title=title,

            description=description
        )

    # CYBER INCIDENT VALIDATION

    if not validate_cyber_incident(
        incident_type,
        title,
        description
    ):

        return render_template(
            "report.html",

            error=(
                "Please enter a valid cyber security incident. "
                "For example: phishing, hacking, malware, "
                "ransomware, data breach, unauthorized access, "
                "or another genuine security incident."
            ),

            incident_type=incident_type,

            title=title,

            description=description
        )

    # EVIDENCE

    evidence_path = None

    evidence_file = request.files.get(
        "evidence"
    )

    if evidence_file:

        original_filename = (
            evidence_file.filename or ""
        ).strip()

        if original_filename:

            # EXTENSION CHECK

            if not allowed_file(
                original_filename
            ):

                return render_template(
                    "report.html",

                    error=(
                        "Invalid evidence file type. "
                        "Allowed formats: JPG, JPEG, PNG, "
                        "PDF, TXT, LOG and EML."
                    ),

                    incident_type=incident_type,

                    title=title,

                    description=description
                )

            # FILE SIZE CHECK

            evidence_file.seek(
                0,
                os.SEEK_END
            )

            file_size = evidence_file.tell()

            evidence_file.seek(0)

            if file_size > MAX_FILE_SIZE:

                return render_template(
                    "report.html",

                    error=(
                        "Evidence file is too large. "
                        "Maximum allowed size is 10 MB."
                    ),

                    incident_type=incident_type,

                    title=title,

                    description=description
                )

            # SECURE FILE NAME

            safe_filename = secure_filename(
                original_filename
            )

            # EXTENSION

            extension = ""

            if "." in safe_filename:

                extension = (
                    safe_filename
                    .rsplit(".", 1)[1]
                    .lower()
                )

            # UNIQUE FILE NAME

            unique_filename = (
                f"{uuid.uuid4().hex}.{extension}"
            )

            # COMPLETE PATH

            file_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                unique_filename
            )

            # SAVE

            evidence_file.save(
                file_path
            )

            # DATABASE PATH

            evidence_path = (
                f"uploads/{unique_filename}"
            )

    # INCIDENT ANALYSIS

    analysis = analyze_incident(
    incident_type=incident_type,
    impact=request.form.get("impact", "medium"),
    sensitive_data=request.form.get("sensitive_data", "no"),
    frequency=request.form.get("frequency", "once"),
    evidence="yes" if evidence_path else "no"
)
    

    risk_score = analysis[
        "risk_score"
    ]

    risk_level = analysis[
        "risk_level"
    ]

    impact = analysis[
        "impact"
    ]

    reason = analysis[
        "reason"
    ]

    response_recommendation = analysis[
        "response_recommendation"
    ]

    prevention_tips = analysis[
        "prevention_tips"
    ]

    status = "Open"


    # SAVE INCIDENT

    conn = get_db_connection()

    try:
        cursor = conn.execute(
    """
    INSERT INTO incidents
    (
        user_id,
        incident_type,
        title,
        description,
        risk_score,
        risk_level,
        impact,
        reason,
        response_recommendation,
        prevention_tips,
        status,
        evidence_path
    )
    VALUES (
        %s, %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s, %s
    )
    RETURNING id
    """,
            (
                session["user_id"],
                incident_type,
                title,
                description,
                risk_score,
                risk_level,
                impact,
                reason,
                response_recommendation,
                prevention_tips,
                status,
                evidence_path
            )
        )

        incident_id = cursor.fetchone()["id"]
        conn.commit()

    except Exception as e:

        print("INCIDENT SAVE ERROR:", e)

        conn.rollback()

        if evidence_path:

            uploaded_file_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                os.path.basename(evidence_path)
            )

            if os.path.exists(uploaded_file_path):
                os.remove(uploaded_file_path)

        return render_template(
            "report.html",
            error=f"Database Error: {e}",
            incident_type=incident_type,
            title=title,
            description=description
        )

    finally:
        conn.close()

    # INCIDENT DETAILS

    return redirect(
        url_for(
            "incident_details",
            incident_id=incident_id
        )
    )
# INCIDENT DETAILS

@app.route(
    "/incident/<int:incident_id>"
)
def incident_details(incident_id):

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    incident = conn.execute(
        """
        SELECT
            id,
            user_id,
            incident_type,
            title,
            description,
            risk_score,
            risk_level,
            impact,
            reason,
            response_recommendation,
            prevention_tips,
            status,
            evidence_path,
            created_at
        FROM incidents
        WHERE id = %s
        AND user_id = %s
        """,
        (
            incident_id,
            session["user_id"]
        )
    ).fetchone()

    conn.close()

    if not incident:

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "incident_details.html",
        incident=incident
    )


# DOWNLOAD INCIDENT PDF

@app.route("/incident/<int:incident_id>/download")
def download_incident_pdf(incident_id):

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    incident = conn.execute(
        """
        SELECT
            id,
            user_id,
            incident_type,
            title,
            description,
            risk_score,
            risk_level,
            impact,
            reason,
            response_recommendation,
            prevention_tips,
            status,
            evidence_path,
            created_at
        FROM incidents
        WHERE id = %s
        AND user_id = %s
        """,
        (
            incident_id,
            session["user_id"]
        )
    ).fetchone()

    conn.close()

    if not incident:

        return redirect(
            url_for("dashboard")
        )

    # REPORTLAB

    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle
    )
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.enums import TA_CENTER
    from io import BytesIO

    # PDF BUFFER

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = styles["Title"]

    title_style.alignment = TA_CENTER

    heading_style = styles["Heading2"]

    normal_style = styles["BodyText"]

    normal_style.leading = 16

    story = []

    # TITLE

    story.append(
        Paragraph(
            "CyberSentinel AI",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Cybersecurity Incident Report",
            styles["Heading2"]
        )
    )

    story.append(
        Spacer(1, 20)
    )

    # INCIDENT INFORMATION

    incident_data = [

        [
            "Incident ID",
            str(incident["id"])
        ],

        [
            "Incident Type",
            str(incident["incident_type"] or "N/A")
        ],

        [
            "Title",
            str(incident["title"] or "N/A")
        ],

        [
            "Risk Score",
            f"{incident['risk_score'] or 0}/100"
        ],

        [
            "Risk Level",
            str(incident["risk_level"] or "N/A")
        ],

        [
            "Status",
            str(incident["status"] or "N/A")
        ],

        [
            "Created At",
            str(incident["created_at"] or "N/A")
        ]

    ]

    table = Table(
        incident_data,
        colWidths=[130, 360]
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#E8F5F0")
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, -1),
                    colors.black
                ),

                (
                    "FONTNAME",
                    (0, 0),
                    (0, -1),
                    "Helvetica-Bold"
                ),

                (
                    "FONTNAME",
                    (1, 0),
                    (1, -1),
                    "Helvetica"
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),

                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    8
                )
            ]
        )
    )

    story.append(table)

    story.append(
        Spacer(1, 20)
    )

    # HELPER FUNCTION

    def add_section(title, content):

        story.append(
            Paragraph(
                title,
                heading_style
            )
        )

        story.append(
            Spacer(1, 6)
        )

        safe_content = (
            str(content)
            if content
            else "Not available."
        )

        safe_content = safe_content.replace(
            "\n",
            "<br/>"
        )

        story.append(
            Paragraph(
                safe_content,
                normal_style
            )
        )

        story.append(
            Spacer(1, 15)
        )

    # SECTIONS

    add_section(
        "Incident Description",
        incident["description"]
    )

    add_section(
        "Impact",
        incident["impact"]
    )

    add_section(
        "Analysis Reason",
        incident["reason"]
    )

    add_section(
        "Response Recommendation",
        incident["response_recommendation"]
    )

    add_section(
        "Prevention Tips",
        incident["prevention_tips"]
    )

    add_section(
        "Evidence",
        incident["evidence_path"]
        if incident["evidence_path"]
        else "No evidence attached."
    )


    # OFFICIAL CYBER CRIME INFORMATION

    story.append(
        Spacer(1, 15)
    )

    story.append(
        Paragraph(
            "Official Cyber Crime Assistance",
            heading_style
        )
    )

    story.append(
        Spacer(1, 6)
    )

    official_text = """
    Cyber Crime Helpline: 1930<br/>
    Official Cyber Crime Reporting Portal: cybercrime.gov.in<br/><br/>

    If this incident involves cyber fraud, online scam, phishing,
    account compromise, financial fraud, data theft or any other
    cybercrime, report it to the official cybercrime authorities.<br/><br/>

    Important: CyberSentinel AI provides cybersecurity analysis
    and guidance. It does not replace official law-enforcement
    or cybercrime reporting services.
    """

    story.append(
        Paragraph(
            official_text,
            normal_style
        )
    )

    story.append(
        Spacer(1, 15)
    )




    # FOOTER TEXT

    story.append(
        Spacer(1, 15)
    )

    story.append(
        Paragraph(
            "Generated by CyberSentinel AI",
            styles["Italic"]
        )
    )

    # BUILD PDF

    document.build(story)

    buffer.seek(0)

    # DOWNLOAD

    from flask import send_file

    return send_file(
        buffer,
        as_attachment=True,
        download_name=(
            f"CyberSentinel_Incident_{incident_id}.pdf"
        ),
        mimetype="application/pdf"
    )


# LOGOUT

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# APPLICATION ERROR HANDLER

@app.errorhandler(413)
def file_too_large(error):

    return render_template(
        "report.html",
        error=(
            "Evidence file is too large. "
            "Maximum allowed size is 10 MB."
        )
    ), 413


# RUN APPLICATION

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )
