# Project Title: A Machine Learning-Based Phishing Detection System Using Random Forest with OWASP-Compliant Web Application
## Author: Osama Rahmani 
## Student ID: 13286530
## Email: rahmanio@coventry.ac.uk


# Phishing Detection

Python-based phishing detection project that combines:

- URL and domain feature extraction
- Webpage text and language-based NLP features
- Machine learning models (Random Forest, XGBoost) for phishing and legitimate classification

The repository includes feature extraction scripts, processed CSV datasets, and trained model artifacts for Random Forest and XGBoost classifiers.

## Project Structure

- `URL_Feature_Extraction.py` extracts URL-, domain-, certificate-, DNS-, and page-behavior-based features.
- `NLTK_Features.py` extracts text features from webpage content using NLTK and fastText language detection.
- `Extract_Combine_CSVs.py` combines generated CSV files into training-ready datasets.
- `URL_Features_ML_RF.py` trains and evaluates a Random Forest model on URL-based features.
- `URL_Features_ML_XGBoost.py` trains and evaluates an XGBoost model on URL-based features.
- `NLTK_Features_ML.py` trains and evaluates a model using NLP-derived features.
- `certificate.py`, `dns_records.py`, `redirection.py`, and `url_path.py` contain supporting feature logic.

## Data And Models

Datasets are stored under `Content/CSVs/` and include:

- phishing and legitimate URL sources
- processed feature datasets
- combined training datasets
- test CSV files

Pretrained model files included in the repo:

- `phishing_random_forest_model.pkl`
- `phishing_xgboost_model.pkl`
- `NLTK_random_forest_model.pkl`

Language detection uses the bundled fastText model:

- `lid.176.bin`

## Requirements

This project uses Python and common data science / scraping libraries, including:

- `pandas`
- `numpy`
- `scikit-learn`
- `matplotlib`
- `xgboost`
- `nltk`
- `fasttext`
- `requests`
- `beautifulsoup4`
- `tldextract`
- `dnspython`
- `python-whois`
- `tqdm`

Install dependencies with your preferred environment manager, for example:

```bash
pip install pandas numpy scikit-learn matplotlib xgboost nltk fasttext requests beautifulsoup4 tldextract dnspython python-whois tqdm
```

Depending on your environment, `fasttext` may require system build tools.

## Running The Project

### 1. Extract datasets

```bash
python Extract_Combine_CSVs.py
```

### 2. Extract features

Run the feature extraction scripts to generate or refresh processed data:

```bash
python URL_Feature_Extraction.py
python NLTK_Features.py
```

### 3. Train models

Train the URL-based models:

```bash
python URL_Features_ML_RF.py
python URL_Features_ML_XGBoost.py
```

Train the NLP-based model:

```bash
python NLTK_Features_ML.py
```
