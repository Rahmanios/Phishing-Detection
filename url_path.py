from urllib.parse import urlparse
import re

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

#----------------------------------------
keywords = [
    "login", "log-in", "signin", "sign-in", "verify", "update", "secure", "verification", "portal", "authenticate", "checkpoint", "access",
    "account", "accounts", "bank", "confirm", "continue", "password", "auth", "credential", "identity", "urgent", "identity", "receive",
    "action-required", "alert", "suspend", "locked", "expired", "expiration", "disabled", "attention", "important", "warning", "click"
    "recover", "reactivate", "unlock", "invoice", "document", "doc", "file", "sharepoint", "onedrive", "docusign", "efax", "vmail", 
    "voicemail", "scanned", "payment", "billing", "salary", "bonus", "cdn", "api", "static", "support", "service-desk", "helpdesk", 
    "cloud", "server", "secure-login", "vault", "sync", "patch"
]

extentions = [
    ".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".paper", ".app"
]

queries = [
    "id=", "uid=", "sid=", "dest=", "destination", "redirect=", "url=", "next=", "u=", "rlkey=", "auth=", "session=", "token=",
    "enail=", "user=", "brand=", "service=", "cmd=", "action=", "m=", "mid=", "tenant=", "domain=", "apiv=", "data=", "msg=",
    "payload=", "hash=", "error=", "err_code=", "security", "urgent", "importance=high", "priority=1", "attempt=", "clickid=",
    "gclid=", "utm_source=", "utm_medium=", "bot_check=", "?", "&", "aff=", "affiliate=", "campaign=", "cid=", "step=", "key="
]

free_domains = [
    "docs.google.com",
    "sites.google.com",
    "dropbox.com",
    "firebaseapp.com",
    "framer.app",
    "webcindario.com",
    "campaign-archive.com",
    "new.express.adobe.com",
    "jotform.com",
    "hsforms.com",
    "forms.office.com",
    "ipfs.io",
    "ipfs.best-practice.se"
    "adobe.com/webpage"
]

url_shorteners = [
    "bit.ly","t.co","tinyurl.com","qrco.de","q-r.to",
    "l.ead.me","did.li","linkin.bio"
]

def url_path(url):
    print(url, "\n")
    parsed = urlparse(url)
    print("Parsed: \n", parsed, "\n")
    domain = parsed.netloc.lower()
    print("Domain: ", domain)
    path = parsed.path.lower()
    print("path: ", path)
    query = parsed.query.lower()
    print("Query: ", query, "\n\n")

    path_result = {}
    
    #short url
    for us in url_shorteners:
        if us in domain:
            print("url shortener used: ", us)
            path_result["URL_short"] = True
        else:
            path_result["URL_short"] = False
    print("path_result[URL_short]:", path_result["URL_short"], "\n")

    #using free domains as a legit base
    for fd in free_domains:
        if fd in domain:
            print("free domain used: ", fd)
            path_result["Free_domains"] = True
            break
        else:
            path_result["Free_domains"] = False
    print("path_result[Free_domains]:", path_result["Free_domains"], "\n")

    #using phishing keyword
    path_result["Phish_keyword"] = False
    for pk in keywords:
        if pk in path:
            print("Phish keyword used: ", pk)
            path_result["Phish_keyword"] = True
        
    print("path_result[Phish_keyword]:", path_result["Phish_keyword"], "\n")

    #suspecious file extensions in path
    for ext in extentions:
        if ext in path or ext in domain:
            print("-----------------extension used in path:", ext)
            path_result["file_extension"] = True
            break
        else:
            path_result["file_extension"] = False
    print("path_result[file_extension]: ", path_result["file_extension"], "\n")

    #long random path segments
    path_result["segment"] = False
    for seg in path.split("/"):
        if len(seg) > 18 and re.search(r"\d", seg):
            print("Segment: ", seg)
            path_result["segment"] = True
            break
        print("path_result[segment]: ", path_result["segment"], "\n")

    #excessive digits in path
    digits = sum(c.isdigit() for c in path)
    if digits > 5:
        print("digits: ", digits)
        path_result["digits"] = True
        print("path_result[digits]: ", path_result["digits"], "\n")

    #query parameters
    path_result["query"] = False
    for q in queries:
        if q in query:
            print("query used: ", q)
            path_result["query"] = True
    print("path_result[query]", path_result["query"], "\n")

    #path depth by each segments seprated by /
    depth = 0
    for s in path.split("/"):
        depth += 1
    if depth > 3:
        print("url depth", depth)
        path_result["depth segments"] = True
        print("path_result[depth segments]", path_result["depth segments"], "\n")

    return path_result




result = url_path(url_phish3)
for key, value in result.items():
    print(f"{key}: {value}")