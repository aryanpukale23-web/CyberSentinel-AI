# 🛡️ CyberSentinel AI

## Intelligent Cyber Incident Response System

CyberSentinel AI is a web-based cybersecurity incident management and response system developed using Python and Flask.

The system allows users to report cybersecurity incidents, analyze their risk level, and receive intelligent response and prevention recommendations.

---

## 🚀 Features

- 👤 User Registration and Login
- 📝 Cybersecurity Incident Reporting
- 🔍 Incident Classification
- 📊 Intelligent Risk Score (0–100)
- 🔴 High, 🟠 Medium and 🟢 Low Risk Levels
- 💡 Impact and Analysis Reason
- 🛡️ Response Recommendations
- 🔐 Prevention Tips
- 📎 Evidence / Screenshot Upload
- 📈 Security Dashboard
- 📜 Incident History
- 🔎 Search and Risk Filtering
- 📄 Incident PDF Report Generation
- 👤 User Profile

---

## 🛠️ Technologies Used

### Frontend
- HTML5
- CSS3
- Bootstrap 5
- JavaScript
- Chart.js

### Backend
- Python
- Flask

### Database
- SQLite

### PDF Generation
- ReportLab

---

## 📁 Project Structure

```text
CyberSentinel-AI/
│
├── database/
│   ├── database.db
│   ├── database_backup.db
│   ├── init_db.py
│   └── schema.sql
│
├── static/
│   ├── css/
│   ├── images/
│   ├── js/
│   └── uploads/
│
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── history.html
│   ├── incident_details.html
│   ├── index.html
│   ├── login.html
│   ├── profile.html
│   ├── register.html
│   ├── report.html
│   └── scan.html
│
├── utils/
│
├── app.py
├── config.py
├── requirements.txt
├── setup_db.py
└── README.md