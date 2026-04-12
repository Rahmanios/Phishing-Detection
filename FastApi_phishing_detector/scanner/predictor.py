import joblib
import numpy as np
import pandas as pd
import os

# ---------------------------------------------------------------------------
# Model directory and file paths

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models")

_rf_path = os.path.join(MODEL_DIR, "phishing_random_forest_model.pkl")
_xgb_path = os.path.join(MODEL_DIR, "phishing_xgboost_model.pkl")
_nltk_path = os.path.join(MODEL_DIR, "NLTK_random_forest_model.pkl")

# ---------------------------------------------------------------------------
# Load models at module level

try:
    rf_model = joblib.load(_rf_path)
except Exception as e:
    rf_model = None

try:
    xgb_model = joblib.load(_xgb_path)
except Exception as e:
    xgb_model = None

try:
    nltk_model = joblib.load(_nltk_path)
except Exception as e:
    nltk_model = None

# ---------------------------------------------------------------------------
# Feature column definitions (exact names from training data)

URL_FEATURE_COLUMNS = [
    "Has_Ip", "At_Sign", "Url_Length", "Dash_In_Domain", "Sub_Multisub",
    "HTTP_HTTPS",
    "No_Cert", "Issuer_Name", "Subject_Name", "Self_Signed",
    "Cert_Age_Days", "Cert_Validity_Days", "Trusted_Cert",
    "No_Soup", "Invisible_Iframe", "Cross_Domain_Iframe",
    "Nested_Iframes", "No_Visible_Purpose", "Overlay_Behavior",
    "A_Record", "AAAA_Record", "MX_Record", "NS_Record", "DNS_Age_Days",
    "URL_Short", "Free_Domain", "Phish_Keyword", "File_Extension",
    "Segment", "Digits", "Query", "Depth_Segments",
    "Domain_Age", "Right_Click", "Custom_status_bar",
]

NLTK_FEATURE_COLUMNS = [
    "url_len", "total_weight", "total_weight_log", "total_weight_norm",
]

# Label mapping: model class index → human-readable label
# Standard convention: class 0 = Legitimate, class 1 = Phishing
_LABEL_MAP = {0: "Legitimate", 1: "Phishing"}


# ---------------------------------------------------------------------------
# Helper: predict with probability

def _predict_with_proba(model, feature_df):
    """Run prediction and return (label, probability_of_phishing).

    Tries predict_proba first; falls back to predict if unavailable.
    Returns ("Error", 0.0) if model is None.
    Accepts a pandas DataFrame with feature names to avoid sklearn warnings.
    """
    if model is None:
        return "Error", 0.0

    try:
        proba = model.predict_proba(feature_df)
        # Probability of class 1 (Phishing)
        phishing_prob = float(proba[0][1]) if proba.shape[1] > 1 else float(proba[0][0])
        prediction = int(model.predict(feature_df)[0])
        label = _LABEL_MAP.get(prediction, "Unknown")
        return label, phishing_prob
    except (AttributeError, IndexError):
        try:
            prediction = int(model.predict(feature_df)[0])
            label = _LABEL_MAP.get(prediction, "Unknown")
            return label, 1.0 if label == "Phishing" else 0.0
        except Exception:
            return "Error", 0.0


# ---------------------------------------------------------------------------
# predict_url
def predict_url(features_dict):
    """Run URL-based phishing prediction using RF and XGBoost models.

    Args:
        features_dict: The "features" dict from extract_all_url_features().

    Returns:
        dict with rf_prediction, rf_probability, xgb_prediction, xgb_probability.
    """
    # Build feature array in the exact column order
    values = []
    for col in URL_FEATURE_COLUMNS:
        val = features_dict.get(col, 0)
        if isinstance(val, bool):
            val = int(val)
        elif isinstance(val, (int, float)):
            val = int(val) if isinstance(val, bool) else val
        values.append(val)

    feature_df = pd.DataFrame([values], columns=URL_FEATURE_COLUMNS)

    rf_label, rf_prob = _predict_with_proba(rf_model, feature_df)
    xgb_label, xgb_prob = _predict_with_proba(xgb_model, feature_df)

    return {
        "rf_prediction": rf_label,
        "rf_probability": rf_prob,
        "xgb_prediction": xgb_label,
        "xgb_probability": xgb_prob,
    }


# ---------------------------------------------------------------------------
# predict_nltk

def predict_nltk(features_dict):
    """Run NLTK-based phishing prediction using the NLTK RF model.

    Args:
        features_dict: The "features" dict from extract_nltk_features().

    Returns:
        dict with nltk_prediction, nltk_probability.
    """
    values = []
    for col in NLTK_FEATURE_COLUMNS:
        val = features_dict.get(col, 0)
        if isinstance(val, bool):
            val = int(val)
        values.append(val)

    feature_df = pd.DataFrame([values], columns=NLTK_FEATURE_COLUMNS)

    nltk_label, nltk_prob = _predict_with_proba(nltk_model, feature_df)

    return {
        "nltk_prediction": nltk_label,
        "nltk_probability": nltk_prob,
    }


# ---------------------------------------------------------------------------
# get_final_verdict

def get_final_verdict(url_result, nltk_result):
    """Combine URL and NLTK results using majority voting (best 2 of 3).

    Args:
        url_result: dict from predict_url()
        nltk_result: dict from predict_nltk()

    Returns:
        dict with verdict, confidence, votes, summary.
    """
    votes = {
        "rf": url_result.get("rf_prediction", "Error"),
        "xgb": url_result.get("xgb_prediction", "Error"),
        "nltk": nltk_result.get("nltk_prediction", "Error"),
    }

    phishing_count = sum(1 for v in votes.values() if v == "Phishing")
    legitimate_count = sum(1 for v in votes.values() if v == "Legitimate")
    error_count = sum(1 for v in votes.values() if v == "Error")

    # Determine verdict by majority vote
    if phishing_count >= 2:
        verdict = "Phishing"
    elif legitimate_count >= 2:
        verdict = "Legitimate"
    elif phishing_count > legitimate_count:
        verdict = "Phishing"
    elif legitimate_count > phishing_count:
        verdict = "Legitimate"
    else:
        # Tie or all errors – default to Phishing for safety
        verdict = "Phishing"

    # Confidence: average probability of the predicted class
    probs = []
    if votes["rf"] == verdict:
        if verdict == "Phishing":
            probs.append(url_result.get("rf_probability", 0.0))
        else:
            probs.append(1.0 - url_result.get("rf_probability", 1.0))
    if votes["xgb"] == verdict:
        if verdict == "Phishing":
            probs.append(url_result.get("xgb_probability", 0.0))
        else:
            probs.append(1.0 - url_result.get("xgb_probability", 1.0))
    if votes["nltk"] == verdict:
        if verdict == "Phishing":
            probs.append(nltk_result.get("nltk_probability", 0.0))
        else:
            probs.append(1.0 - nltk_result.get("nltk_probability", 1.0))

    confidence = round(sum(probs) / len(probs), 4) if probs else 0.0

    # Build summary
    agreeing = [k.upper() for k, v in votes.items() if v == verdict]
    disagreeing = [k.upper() for k, v in votes.items() if v != verdict and v != "Error"]
    summary = (
        f"Verdict: {verdict} ({confidence:.1%} confidence). "
        f"Agreeing models: {', '.join(agreeing)}."
    )
    if disagreeing:
        summary += f" Disagreeing: {', '.join(disagreeing)}."

    return {
        "verdict": verdict,
        "confidence": confidence,
        "votes": votes,
        "summary": summary,
    }
