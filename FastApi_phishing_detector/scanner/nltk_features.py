import re
import urllib3
import numpy as np
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
import nltk
from bs4 import BeautifulSoup
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Ensure required NLTK data is available
for resource in ("stopwords", "punkt", "punkt_tab", "wordnet", "omw-1.4"):
    try:
        nltk.data.find(f"tokenizers/{resource}") if resource.startswith("punkt") else None
        nltk.data.find(f"corpora/{resource}") if resource in ("stopwords", "wordnet", "omw-1.4") else None
    except LookupError:
        if resource.startswith("punkt"):
            nltk.download(resource, quiet=True)
        elif resource in ("stopwords", "wordnet", "omw-1.4"):
            nltk.download(resource, quiet=True)


# ---------------------------------------------------------------------------
# Keyword dictionary with weights

phish_keywords = {
    "ssn": 5, "otp": 5, "2fa": 5, "passcode": 5, "unauthorized": 5,
    "compromised": 5, "breach": 5, "suspended": 5, "termination": 5,
    "reactivate": 5, "verify": 5, "verification": 5, "confirmidentity": 5,
    "securitycheck": 5, "accountupdate": 5,
    "urgent": 4, "immediately": 4, "asap": 4, "deadline": 4,
    "expires": 4, "expired": 4, "suspend": 4, "restricted": 4,
    "blocked": 4, "disabled": 4, "reset": 4, "recover": 4,
    "password": 4, "credentials": 4, "refund": 4, "claim": 4,
    "prize": 4, "lottery": 4, "click": 4, "download": 4,
    "install": 4, "paypal": 4, "irs": 4,
    "login": 3, "signin": 3, "validate": 3, "secure": 3,
    "security": 3, "bank": 3, "payment": 3, "invoice": 3,
    "delivery": 3, "parcel": 3, "tracking": 3, "winner": 3,
    "gift": 3, "bonus": 3, "attachment": 3, "attached": 3,
    "alert": 3, "notification": 3, "incident": 3,
    "account": 2, "access": 2, "update": 2, "confirm": 2,
    "review": 2, "check": 2, "order": 2, "purchase": 2,
    "subscription": 2, "customer": 2, "support": 2, "service": 2,
    "website": 2, "portal": 2, "link": 2, "limited": 2,
    "temporary": 2, "pending": 2,
    "information": 1, "details": 1, "email": 1, "message": 1,
    "notice": 1, "department": 1, "manager": 1,
}


# ---------------------------------------------------------------------------

def getting_text(url):
    """Fetch the page and extract text content.

    Returns (clean_text, raw_text) on success, (-1, None) on failure.
    SSL verification is disabled.
    """
    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
            ),
        }
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        raw_html = response.text

        soup = BeautifulSoup(raw_html, "html.parser")

        # Remove script and style elements
        for tag in soup(["script", "style", "noscript", "meta", "link"]):
            tag.decompose()

        # Extract visible text
        text = soup.get_text(separator=" ", strip=True)

        # Clean up whitespace
        clean_text = re.sub(r"\s+", " ", text).strip()

        if not clean_text:
            return -1, None

        return clean_text, raw_html
    except Exception:
        return -1, None


# ---------------------------------------------------------------------------

def process_text(text, lang_code="english"):
    """Tokenize text, remove stopwords, and lemmatize.

    Returns a list of processed (lowercased, lemmatized) words.
    """
    try:
        stop_words = set(stopwords.words(lang_code))
        lemmatizer = WordNetLemmatizer()

        tokens = word_tokenize(text.lower())
        processed = [
            lemmatizer.lemmatize(token)
            for token in tokens
            if token.isalpha() and token not in stop_words and len(token) > 1
        ]
        return processed
    except Exception:
        return []


# ---------------------------------------------------------------------------

def NLTK_feature(url):
    """Analyze page text for phishing keywords with weighted scoring.
    Returns a dict with url, url_len, total_weight, found_keywords, error.
    """
    result = {
        "url": url,
        "url_len": len(url),
        "total_weight": 0,
        "found_keywords": [],
        "error": None,
    }

    clean_text, raw_html = getting_text(url)
    if clean_text == -1 or clean_text is None:
        result["error"] = "Could not fetch or extract text from URL"
        return result

    words = process_text(clean_text)
    if not words:
        result["error"] = "No processable text found on page"
        return result

    # Build word frequency map
    word_freq = {}
    for word in words:
        word_freq[word] = word_freq.get(word, 0) + 1

    # Keyword matching with weight scoring
    total_weight = 0
    word_freQ = 0  # Running accumulator – NOT reset between keywords
    found_keywords = []

    for keyword, weight in phish_keywords.items():
        keyword_lower = keyword.lower()

        # Check if the keyword appears in our processed words
        if keyword_lower in word_freq:
            freq = word_freq[keyword_lower]
            word_freQ += freq  # Accumulate (intentional bug from original code)
            weight_score = word_freQ * weight
            total_weight += weight_score

            found_keywords.append({
                "word": keyword,
                "frequency": freq,
                "weight": weight,
                "weight_score": weight_score,
            })

    result["total_weight"] = total_weight
    result["found_keywords"] = found_keywords
    return result


# ---------------------------------------------------------------------------
# MAIN FUNCTION extract_nltk_features

def extract_nltk_features(url):
    """Extract NLTK-based text features for phishing detection.

    Returns a dict with two sections:
      - "features": {url_len, total_weight, total_weight_log, total_weight_norm}
      - "details":  {url_len, total_weight, total_weight_log, total_weight_norm,
                     found_keywords, text_preview, word_count}
    """
    nltk_result = NLTK_feature(url)

    total_weight = nltk_result["total_weight"]
    total_weight_log = int(np.log1p(total_weight))
    # Normalize: 1 if total_weight > 0, else 0
    total_weight_norm = 1 if total_weight > 0 else 0

    # Get text preview for details
    clean_text, _ = getting_text(url)
    text_preview = ""
    word_count = 0
    if clean_text and clean_text != -1:
        text_preview = clean_text[:200]
        words = process_text(clean_text)
        word_count = len(words)

    features = {
        "url_len": nltk_result["url_len"],
        "total_weight": total_weight,
        "total_weight_log": total_weight_log,
        "total_weight_norm": total_weight_norm,
    }

    details = {
        "url_len": nltk_result["url_len"],
        "total_weight": total_weight,
        "total_weight_log": total_weight_log,
        "total_weight_norm": total_weight_norm,
        "found_keywords": nltk_result["found_keywords"],
        "text_preview": text_preview,
        "word_count": word_count,
    }

    if nltk_result["error"]:
        details["error"] = nltk_result["error"]

    return {"features": features, "details": details}
