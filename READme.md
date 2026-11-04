# 🛡️ PhishGuard – Phishing URL Detection System

## About the Project
PhishGuard is a beginner-friendly cybersecurity web application built using Python and Flask. It analyses website URLs for suspicious characteristics that may indicate phishing attempts.

The application uses rule-based heuristic analysis to calculate a risk score and classify URLs as Low, Medium, or High Risk.

## Features
- URL analysis
- HTTPS security check
- Suspicious keyword detection
- IP address detection
- URL length analysis
- Suspicious `@` symbol detection
- Subdomain analysis
- Risk score and risk-level classification

## Technologies Used
- Python
- Flask
- HTML
- CSS

## Risk Classification
| Score | Risk Level |
|---|---|
| 0–19 | Low |
| 20–49 | Medium |
| 50–100 | High |

## How to Run

1. Clone or download this repository.
2. Open the project folder in VS Code.
3. Create and activate a virtual environment.
4. Install dependencies:

```bash
pip install -r requirements.txt
```

5. Start the application:

```bash
python app.py
```

6. Open `http://127.0.0.1:5000` in your browser.

## Project Structure

```text
PhishGuard/
├── app.py
├── detector.py
├── requirements.txt
├── templates/
│   └── index.html
├── static/
│   └── style.css
└── README.md
```

## Disclaimer
PhishGuard is an educational project. Its heuristic checks provide risk indicators, not definitive proof that a website is safe or malicious.

## Future Improvements
- Improved phishing detection rules
- Domain reputation checking
- Machine learning-based detection
- More detailed security reports

---
**Project:** PhishGuard  
**Category:** Cybersecurity  
**Year:** 2026