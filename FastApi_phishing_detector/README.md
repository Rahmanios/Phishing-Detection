# Project Title: A Machine Learning-Based Phishing Detection System Using Random Forest with OWASP-Compliant Web Application
## Author: Osama Rahmani 
## Student ID: 13286530
## Email: rahmanio@coventry.ac.uk

# FastApi Phishing Detector

A FastAPI-based phishing detection web app that analyzes submitted URLs with three machine learning models, generates an OWASP-style risk assessment, and stores scan history in SQLite.

## What It Does

- Scans a URL through:
  - a Random Forest model trained
  - an XGBoost model trained
  - an NLTK-based Random Forest model trained on page-text phishing signals
- Combines model outputs with majority voting to produce a final verdict
- Generates an OWASP-inspired risk report with:
  - risk rating
  - likelihood and impact scoring
  - mapped OWASP Top 10 categories
  - recommended actions
  - compliance framework references
- Stores previous scans in `scan_history.db`
- Provides a browser UI for scanning and viewing history

## Tech Stack

- `FastAPI`
- `Uvicorn`
- `Jinja2`
- `SQLAlchemy`
- `SQLite`
- `scikit-learn`
- `xgboost`
- `nltk`
- `requests`
- `beautifulsoup4`
- `dnspython`
- `python-whois`

## Project Structure

```text
.
├── main.py
├── database.py
├── requirements.txt
├── templates/
│   └── index.html
├── scanner/
│   ├── predictor.py
│   ├── url_features.py
│   ├── nltk_features.py
│   └── owasp_risk.py
├── models/
│   ├── phishing_random_forest_model.pkl
│   ├── phishing_xgboost_model.pkl
│   └── NLTK_random_forest_model.pkl
└── scan_history.db
```

## How It Works

1. A user submits a URL from the web form.
2. The app normalizes the URL by adding `http://` if no scheme is present.
3. URL-based features are extracted 
4. Text-based features are extracted from fetched page content using NLTK keyword weighting.
5. Three models score the URL.
6. A final verdict is chosen by majority vote.
7. An OWASP-style report is generated and the result is saved to SQLite.

## Requirements

- Python 3.10+ recommended
- Internet access at runtime for scanning
- Ability to make outbound:
  - HTTP/HTTPS requests
  - DNS lookups
  - WHOIS lookups
  - TLS certificate checks

## Installation

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python -m fastapi dev main.py
```

Then open:

```text
http://127.0.0.1:8000
```

## Available Routes

- `GET /`  
  Displays the scan form.

- `POST /scan`  
  Runs the phishing scan and renders the result page.

- `GET /history`  
  Shows saved scan history with pagination and search.

- `GET /history/{scan_id}`  
  Displays a single stored scan result.

- `GET /history/{scan_id}/delete`  
  Deletes a stored scan and redirects back to history.

## Notes And Caveats

- The trained model files are already included under `models/`.
- `scan_history.db` is created and migrated automatically on startup.
- The NLTK feature module attempts to download required corpora on first run if they are missing.
- URL scans depend on live network calls, so failures in DNS, WHOIS, page fetches, or certificate retrieval can affect feature extraction.
- Some phishing checks intentionally favor caution. In uncertain or tied cases, the final voting logic can default to `Phishing`.



