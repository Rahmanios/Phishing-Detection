import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from bs4 import BeautifulSoup
import requests
import re
from nltk.stem import WordNetLemmatizer
import pandas as pd
from tqdm import tqdm

import numpy as np
from sklearn.preprocessing import MinMaxScaler
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) #reducing ssl errors #(1)
# Save the original array function
_old_array = np.array

# Create a wrapper that ignores the 'copy' argument if it causes trouble
def _patched_array(*args, **kwargs):
    if 'copy' in kwargs:
        kwargs.pop('copy')
    return _old_array(*args, **kwargs)

# Replace the original with our patch
np.array = _patched_array

import fasttext #sudo apt-get install python3-fasttext
#fasttext.load_model('/lid.176.bin')
#necessary NLTK datasets
#nltk.download("punkt") #trained model for tokenizing text
#nltk.download("stopwords") # common words
#nltk.download("punkt_tab") #specific tokenizer data required for newer NLTK versions
#nltk.download('wordnet')


url_phish1 = "http://receptive-purpose-551959.framer.app/"
url_phish2 = "https://juegnjkwn.firebaseapp.com/"
url_phish3 = "https://www.dropbox.com/scl/fi/xs5b6d59p6mzlxtyf6qeh/CLICK-TO-CONTINUE-SIGN-IN.paper?dl=0&rlkey=u42md1bnw846o3enf479kqcne"
url_phish4 = "https://us20.campaign-archive.com/?u=285c8bc038ed2212d4b526c88&id=7e54fd6db8"
url_phish5 = "https://sites.google.com/view/oiuiruieor98490krejjkljklejkef/home"
url_phish6 = "https://us4.campaign-archive.com/?u=ceaa7afce9a47d3287576542f&id=d598bafb0f"
url_phish7 = "https://webbcpbob.webcindario.com/"
url_phish8 = "https://new.express.adobe.com/webpage/S6HFqlMxGdnb4"
url_phish9 = "https://bravera-q1.firebaseapp.com/"
url_phish10 = "https://docs.google.com/presentation/d/e/2PACX-1vTZxtPjCpcovLY-qQXUKXoVPlrOLY8qM7NBw88itlKlpFhjVsmcKANIqU9kIK9Mcv-M4xcaD76D0IUZ/pub?start=false&amp;loop=false&amp;delayms=3000"
url_phish11 = "https://cisse-ec919.firebaseapp.com/"

url_legit1 = "https://www.thoughtfullearning.com"
url_legit2 = "https://www.lastbryggan.se"
url_legit3 = "https://www.oncoguia.org.br"
url_legit4 = "https://www.amazon.co.uk"
url_legit5 = "https://www.tkani-textiliya.ru"
url_legit6 = "https://www.hepsiburadaefaturam.com"
url_legit7 = "https://www.firstrunfeatures.com"
url_legit8 = "https://www.holzmann-maschinen.at"
url_legit9 = "https://www.skinsmonkey.com"
url_legit10 = "https://www.redlineinventory.com"



def getting_text(url):
    try:
        #headers = {"User-Agent": "Mozilla/5.0"}
        #headers = {
                #"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                #"(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
        #}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        # #(1) Error Fetching URL:HTTPSConnectionPool(host='login.5n6tk57.cn', port=443): Max retries exceeded with url: /6yMK23 (Caused by SSLError(SSLError(1, '[SSL] unknown error (_ssl.c:1033)')))
        response = requests.get(url, headers=headers, timeout=10, verify = False)
        #session = requests.Session()
        #response = session.get(url, headers=headers, timeout=10)

        html_content = response.text
        soup = BeautifulSoup(html_content, "html.parser")
        text = soup.getText()
        #print("---------------------------","\n")
        #print(text)
        #print("---------------------------","\n")
        clean_text = re.sub(r"\s+"," ",text).strip()
        return clean_text #, url_len #url
    #except:
        #return -1
    except Exception as e:
        print(f"Error Fetching URL:{e}")
        return -1
#print(getting_text(url_legit1))

def process_text(text, lang_code='english'):
    """Updated to use the detected language for stopwords."""
    tokens = word_tokenize(text.lower())
    #words = [word for word in tokens if word.isalpha()]
    words = []
    for word in tokens:
        if word.isalpha():
            words.append(word)
    #print("WORDS------>>>",words)

    # Map fastText codes to NLTK stopword names (Basic mapping)
    lang_mapping = {
        'en': 'english', 'fr': 'french', 'es': 'spanish', 
        'de': 'german', 'it': 'italian', 'pt': 'portuguese'
    }
    nltk_lang = lang_mapping.get(lang_code, 'english')
    
    try:
        stop_words = set(stopwords.words(nltk_lang))
    except:
        stop_words = set(stopwords.words('english')) # Fallback
        
    #filtered_words = [word for word in words if word not in stop_words]
    filtered_words = []
    for word in words:
        if word not in stop_words:
            filtered_words.append(word)

    
    lemmatizer = WordNetLemmatizer()
    #lemmatized_words = [lemmatizer.lemmatize(word) for word in filtered_words]
    lemmatized_words = []
    for word in filtered_words:
        root = lemmatizer.lemmatize(word)
        lemmatized_words.append(root)
    
    return lemmatized_words

lang_model = fasttext.load_model('lid.176.bin')

def detect_language(text):
    """Identifies the language and returns the ISO code and confidence score."""
    if not text.strip():
        return "unknown", 0.0
    
    #print(text)
    #print("1111111111111111111111111111111111111111111111111111111111111")
    # fastText expects a single line of text
    single_line_text = text.replace('\n', ' ')
    #print(single_line_text)
    # Predict returns: (('__label__en',), array([0.98]))
    predictions = lang_model.predict(single_line_text, k=1)
    
    lang_code = predictions[0][0].replace('__label__', '')
    confidence = predictions[1][0]
    
    print(f"DETECTED LANGUAGE: {lang_code} (Confidence: {confidence:.2f})")
    return lang_code, confidence

def NLTK_feature(url, Label):#Words
    url_len = len(url)
    clean_text = getting_text(url)
    if clean_text == -1:
        return {
            "url": url,
            "url_len": len(url),
            "Detected_lan": "unknown",
            "total_weight": 0,
            "Label": Label
        }


    # detect Language
    language, confidence = detect_language(clean_text)

    processed_text = process_text(clean_text, lang_code=language)

    #feature extraction
    #NLTK_extraction, weight = NLTK_feature(processed_text)


    phish_keywords = {
    #-------- very strong signal (5)
    "ssn":5,"otp":5,"2fa":5,"passcode":5,
    "unauthorized":5,"compromised":5,"breach":5,
    "suspended":5,"termination":5,"reactivate":5,
    "verify":5,"verification":5,"confirmidentity":5,
    "securitycheck":5,"accountupdate":5,

    #-------- strong signal (4)
    "urgent":4,"immediately":4,"asap":4,"deadline":4,
    "expires":4,"expired":4,"suspend":4,"restricted":4,
    "blocked":4,"disabled":4,"reset":4,"recover":4,
    "password":4,"credentials":4,
    "refund":4,"claim":4,"prize":4,"lottery":4,
    "click":4,"download":4,"install":4,
    "paypal":4,"irs":4,

    #-------- medium signal (3)
    "login":3,"signin":3,"validate":3,
    "secure":3,"security":3,
    "bank":3,"payment":3,"invoice":3,
    "delivery":3,"parcel":3,"tracking":3,
    "winner":3,"gift":3,"bonus":3,
    "attachment":3,"attached":3,
    "alert":3,"notification":3,"incident":3,

    #-------- weak signal (2)
    "account":2,"access":2,"update":2,
    "confirm":2,"review":2,"check":2,
    "order":2,"purchase":2,"subscription":2,
    "customer":2,"support":2,"service":2,
    "website":2,"portal":2,"link":2,
    "limited":2,"temporary":2,"pending":2,

    #------- very weak signal (1)
    "information":1,"details":1,
    "email":1,"message":1,"notice":1,
    "department":1,"manager":1
    }
    freqquency = nltk.FreqDist(processed_text) #Words
    print("frequency----->>>>", freqquency)
    word_freQ = 0
    found_keywords = []
    keywords_weight = []
    total_weight = 0
    for word, weight in phish_keywords.items():
        if word in freqquency:
            
            word_frequency = freqquency[word]
            #print("word_frequency---->>",word_frequency)
            word_freQ += word_frequency
            
            weight_score = word_freQ * weight 
            total_weight = total_weight + weight_score
            #weight_score = word_frequency * weight
            #total_weight += weight_score
            
            print("____",word,"____", "WORD FREQUENCY:", word_freQ, " WEIGHT:", weight)
            found_keywords.append(f"{word}({word_freQ})")
            keywords_weight.append(f"{word}({weight_score})")
            #weight_score = word_freQ * weight 
            #total_weight += weight_score
    
    print("\ntotal weight--------->>>", total_weight)
    print("word_freQ--------->>>", word_freQ)
    #print("found_keywords--------->>>", found_keywords)
    print("keywords_weight--------->>>", keywords_weight)

    #return keywords_weight, total_weight
    
    return {
        "url": url,
        "url_len" : url_len,
        "Detected_lan": language,
        #"keywords_weight": keywords_weight,
        "total_weight": total_weight,
        "Label": Label
    }
    

#text = getting_text(url_legit4)
#processed_text = process_text(text)
#language, lang_conf = detect_language(text)
#NLTK_extraction = NLTK_feature(processed_text)
#print(NLTK_extraction)

#Ouput for ML
# URL, Detected Language, Keyword Score.
# https://bit.ly/3Vol9pv,UK, 5


'''
clean_text = getting_text(url_legit5)

# detect Language First
language, lang_conf = detect_language(clean_text)

# pass the detected language into your processing function
processed_text = process_text(clean_text, lang_code=language)

# run feature extraction
NLTK_extraction, weight = NLTK_feature(processed_text, label = 1)
print("---------------------\n")
#print(url," | ",url_len," | ", language," | ", lang_conf," | ", weight)
'''


Phish_url_10000 = "Content/CSVs/phish_urls_extracted_10000.csv"
Legit_url_10000 = "Content/CSVs/Legit_urls_extracted_10000.csv"

phish_urls_for_test = "Content/CSVs/Test_CSVs/phish_urls_FOR_TEST.csv"
Legit_urls_for_test = "Content/CSVs/Test_CSVs/LEGIT_urls__FOR_TEST.csv"
def process_urls_NLTK(csv_path, label, url_column_name="url"):
    df = pd.read_csv(csv_path)

    if url_column_name not in df.columns:
        df.columns = ["url"]

    urls = df["url"].dropna().tolist()

    dataset = []

    for url in tqdm(urls):
        try:
            features = NLTK_feature(url, label)

            # skip if language not english
            if features["Detected_lan"] != "en":
                print(f"Skipping non-English URL: {url}")
                continue
            #features["url"] = url
            dataset.append(features)
        except Exception as e:
            print(f"Error processing {url}: {e}")

    return pd.DataFrame(dataset)
'''
#PHISH
NLTK_features = process_urls_NLTK(Phish_url_10000, label = 1)
NLTK_features["total_weight_log"] = np.log1p(NLTK_features["total_weight"])

scaler = MinMaxScaler()
NLTK_features["total_weight_norm"] = scaler.fit_transform(
    NLTK_features[["total_weight_log"]]
)
NLTK_features.to_csv("Content/CSVs/NLTK_Phish__PROCESSED.csv", index = False)
'''



#LEGITIMATE
NLTK_features = process_urls_NLTK(Legit_url_10000, label = 0)
NLTK_features["total_weight_log"] = np.log1p(NLTK_features["total_weight"])

scaler = MinMaxScaler()
NLTK_features["total_weight_norm"] = scaler.fit_transform(
    NLTK_features[["total_weight_log"]]
)
NLTK_features.to_csv("Content/CSVs/NLTK_Legit__PROCESSED.csv", index = False)

