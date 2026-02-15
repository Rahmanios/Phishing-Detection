import ipaddress
import re
from urllib.parse import urlparse
import tldextract
import ssl
import socket
import dns.resolver
from datetime import datetime, timezone
import whois
import fnmatch
import requests
from bs4 import BeautifulSoup
from datetime import datetime


url_random = "http://www.192.168.199.122.co.uk//@aaaaa/sfds56565-6mndasAKB1/sfsdsf-fsdfsfs/32.php"

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


flags = {
    "has_ip" : False,
    "has_at_sign" : False,
    "redirection" : False,
    "url_length" : False,
    "dash_in_domain" : False,
    "sub_multisub" : False,
    "http_https" : False,
    "domain_expiry" : False,
    "domain_age" : False,
    "right_click" : False,
    "custom_status_bar" : False

}

"""
def get_soup(url):
    #try:
    #print("Attempting to get ", url)
    response = requests.get(url, timeout = 10)
    print(BeautifulSoup(response.text, "html.parser"))
    return BeautifulSoup(response.text, "html.parser"), response.text
    #except:
    #    return None, None
"""
def get_soup(url):
    try:
        response = requests.get(url, timeout=10)
        return BeautifulSoup(response.text, "html.parser"), response.text
    except:
        return None, None
    
print("|||||||||||||||||||||||||||||||||||||||")
def get_certificate(hostname, port=443): #document 1.1.8
    """
    Connecting to the server and retrieving the certificate.
    Returns the certificate dictionary or None if connection fails.
    """
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception:
        return None
    
def get_domain(url): #document 1.3.5
    try:
        return urlparse(url).netloc
    except:
        return ""
print("|||||||||||||||||||||||||||||||||||||||")




def has_ip(url): #document 1.1.1
    '''
    If there is IP instead of domain name, its likely someone is trying to steal personal information
    '''
    host = urlparse(url).hostname
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b' # raw string 
    if re.search(ip_pattern,host):
        ip = 1
        print("has ip: ", ip)
        flags["has_ip"] = True
        return flags["has_ip"]
    else:
        ip = 0
        print("No ip: ", ip)
        flags["has_ip"] = False
        return flags["has_ip"]
#has_ip(url_random)

print("|||||||||||||||||||||||||||||||||||||||")
def has_at_sign(url): #document 1.1.4
    '''
    if @ presence in URL then browser ignores everything and process the @
    '''
    if "@" in url:
        at = 1
        flags["has_at_sign"] = True
        return flags["has_at_sign"]
    else:
        at = 0
        flags["has_at_sign"] = False

    print("@ in url: ", at)
    return flags["has_at_sign"]
    
print("|||||||||||||||||||||||||||||||||||||||") # to be deleted later
'''
def redirection(url): #document 1.1.5
    pos = url.rfind("//") # rfind finds the last occurance
    redirect = 0
    if pos > 6:
        redirect=1
        flags["redirection"] = True
    else:
        redirect=0
        
        flags["redirection"] = False

    print("redirection: ", redirect)
    return flags["redirection"]
'''
print("|||||||||||||||||||||||||||||||||||||||") 
def url_length(url): # #document 1.1.2
    url_len = len(url)
    length = 0
    if(url_len > 54):
        length = 1
        flags["url_length"] = True
    else:
        length = 0
        flags["url_length"] = False
    
    print("url_length:", url_len , "|  length: ", length)
    return flags["url_length"]

print("|||||||||||||||||||||||||||||||||||||||")
def dash_in_domain(url): # document 1.1.6
    host = urlparse(url).hostname
    dash_count = 0
    if "-" in host:
        dash = 1
        flags["dash_in_domain"] = True
    else:
        dash = 0
        flags["dash_in_domain"] = False
    
    print("dash_in_domain: ", dash)
    return flags["dash_in_domain"]

print("|||||||||||||||||||||||||||||||||||||||")
def sub_multisub_domain(url): #document 1.1.7
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    print("domain: ", domain)
    if domain.startswith("www."):
        domain = domain[4:] #removing the www. part
    #print("domain without www.===>>", domain)
    parts = domain.split(".")   #spliting each part of the domain 
    #print("parts: ", parts)
    #print(len(parts [-1]))
    if len(parts[-1]) == 2: #is the last part a 2letter country code?  country-code top-level domains (ccTLD) length ==2
        parts = parts[:-1]  #take the last cc
        #print("if parts:", parts)
    #print("PARTS::::",parts)
    domain = ".".join(parts) #converting back to string
    #print("NEW DOMAIN::",domain)
    dots = domain.count(".")
    print("dots: ", dots)
    if dots == 1:
        dots_count = 0
        flags["sub_multisub"] = False  #legit
    #elif dots == 2:
        #dots_count = 2 #lets consider 2 as suspicious until further decision
    else:
        dots_count = 1
        flags["sub_multisub"] = True  #phish

    print("sub_multisub: ", dots_count)
    return flags["sub_multisub"]

print("|||||||||||||||||||||||||||||||||||||||")
def http_https(url): #document 1.1.12
    if "https" in url:
        https = 0
        flags["http_https"] = False
    else:
        https = 1
        flags["http_https"] = True

    print("http_https: ", https)
    return flags["http_https"]

print("|||||||||||||||||||||||||||||||||||||||")
def https_certificate(url): #document 1.1.8
    """
    Evaluating the HTTPS and certificate properties to classify the URL
    """
    print(url)
    parsed = urlparse(url)
    flags = {}

    # If not HTTPS → phishing
    print("parsed.sceme = ",parsed.scheme)
    #if parsed.scheme != "https":
        #return 2  # Phishing
    if parsed.scheme == "https":
        flags["http / https"] = False
    else:
        flags["http / https"] = True
        


    hostname = parsed.hostname
    cert = get_certificate(hostname)
    print("cert::::: ", cert)
    # If certificate cannot be retrieved → phishing
    flags["No Cert"] = False
    if cert is None:
        flags["No Cert"] = True
    else:

    # Extract certificate validity dates
        not_before = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
        not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        now = datetime.now(timezone.utc)
        cert_age_days = (datetime.utcnow() - not_before).days
        cert_validity_days = (not_after - not_before).days

        issuer = dict(x[0] for x in cert['issuer'])
        issuer_name = issuer.get('organizationName', '').lower()
        if issuer_name:
            print("issuer name:",issuer_name)
            flags["issuer name"] = False
        else:
            flags["issuer name"] = True #no issuer name Phish


        subject = dict(x[0] for x in cert['subject'])
        subject_name = subject.get('commonName', '').lower()
        if subject_name:
            print("subject name:",subject_name)
            flags["subject name"] = False
        else:
            flags["subject name"] = True  #no subject name Phish
  

        self_signed = issuer_name == subject_name
        #print("self_signed--------->",self_signed)
        flags["self signed"] = self_signed

        print("cert age days: ", cert_age_days)
        if cert_age_days < 7: #30
            flags["Cert age days"] = True #very new - Phish
        #elif cert_age_days < 365:
            # Suspicious
        else:
            flags["Cert age days"] = False

        print("cert_validity_days: ",cert_validity_days)
        if cert_validity_days < 14: ####90
            flags["cert validity days"] = True    # Short-lived cert
        else:
            flags["cert validity days"] = False

        print("self signed: ", self_signed)
        if self_signed:
            flags["self signed: "] = True  #Phish
        else:
            flags["self signed: "] = False

        trusted_big_cas = [
            "digicert", "globalsign", "sectigo", "godaddy", "let's encrypt", "amazon",
            "geotrust", "thawte", "verisign", "comodo", "google trust services","cloudflare",
            "microsoft", "network solutions", "entrust", "trustwave", "dotster", 
        ]
        if not any(ca in issuer_name.lower() for ca in trusted_big_cas):
            flags["trusted cert"] = True
        else:
            flags["trusted cert"] = False

        print("issuer name: ", issuer_name)

        print("host name: ", hostname)
        print("subject name: ", subject_name)  
        #if subject_name not in hostname:
        if fnmatch.fnmatch(subject_name, hostname):
            flags["Host_subject_names: "] = True   #Phish
    return flags

print("|||||||||||||||||||||||||||||||||||||||")
def is_cross_domain(page_url, iframe_src): #document 1.3.5
    if not iframe_src or iframe_src.startswith("#"):
        return False
    page_domain = get_domain(page_url)
    print("---page_domain---", page_domain)
    iframe_domain = get_domain(iframe_src)
    print("---iframe_domain---", iframe_domain)
    return iframe_domain and iframe_domain != page_domain

def legit_iframes(src): # for lowering the false positives # document 1.3.5
    legit_cross_domains = [
        "googletagmanager.com",
        "google.com/recaptcha",
        "youtube.com",
        "youtu.be",
        "vimeo.com",
        "stripe.com",
        "paypal.com",
        "facebook.com",
        "twitter.com",
        "linkedin.com"
    ]

    for domain in legit_cross_domains:
        if domain in src:
            return True
    return False

def iframe_redirection(url): # document 1.3.5
    print("url: ", url)
    print("----------------------")
    soup, html = get_soup(url)
    
    flags = {
        "No Soup" : False,
        "invisible_iframe": False,
        "cross_domain_iframe": False,
        "nested_iframes": False,
        "no_visible_purpose": False,
        "overlay_behavior": False
    }

    if soup is None:
        flags["No Soup"] = True
        print("No Soup!!!")
        return flags

    iframes = soup.find_all("iframe")
    inputs = soup.find_all("input")
    print("Soup is returned")


    page_domain = get_domain(url)

    for iframe in iframes:
        src = iframe.get("src", "")
        print("src:", src)
        width = iframe.get("width", "")
        print("width:", width)
        height = iframe.get("height", "")
        print("height:", height)
        style = iframe.get("style", "").lower()

        if legit_iframes(src):
            continue

        # invisible iframe
        invisible_patterns = [
            "display:none", "visibility:hidden", "opacity:0"
        ]

        if (
            width == "0" or height == "0" or
            any(p in style for p in invisible_patterns)
        ):
            flags["invisible_iframe"] = True

        # cross-domain iframe
        if is_cross_domain(url, src):
            flags["cross_domain_iframe"] = True
            print("url ", url)
            print("src ", src)

        # nested iframes
        if iframe.find("iframe"):
            flags["nested_iframes"] = True
            print("iframe ", iframe)

        # no visible purpose / the iframe shows no content to user
        if not iframe.text.strip() and not src:
            flags["no_visible_purpose"] = True

        # overlay behavior (heuristic)
        if "position:absolute" in style or "position:fixed" in style:
            for inp in inputs:
                if inp.get("type", "") in ["text", "password", "email"]:
                    flags["overlay_behavior"] = True
                    break


    return flags
    #{
    #    "flags": flags,
    #    "iframe_count": len(iframes)
    #}
print("|||||||||||||||||||||||||||||||||||||||")
"""
def domain_expiry(url): #document 1.1.9
    #if domain expires in <= 1 year is Phish
    #expire_date = 0
    try:
        domain = whois.whois(tldextract.extract(url).registered_domain)
        print("domain: ", domain)
        expiry_date = domain.expiration_date
        print("TRY: expiry_date: ", expiry_date)
        if isinstance(expiry_date, list): # if the expiry_date exist as list pick the first item
            expiry_date = expiry_date[0]
        today = datetime.now()
        print("today : ",today)
        days_left = (expiry_date - today).days
        print("days left: ", days_left)
        if days_left >= 365:
            expiry_date = 0 #legit
        else:
            expiry_date = 1 #phish
    except:
        expiry_date = 2 # needs to be reviewed and discussed
    
    print("expiry date: ", expiry_date)
    return expiry_date

#domain_expiry(url_legit4)
"""
print("|||||||||||||||||||||||||||||||||||||||")
def resolve_A_cname(url): #document 1.4.2
    resolved_ips = []
    visited = set()
    resolver = dns.resolver.Resolver()
    print(resolver)
    while url not in visited:
        visited.add(url)
        print(f"Resolving: {url}")
        
        try:
            # 1. Trying to get A records
            print("---1---")
            answer = resolver.resolve(url, "A")
            for rdata in answer:
                resolved_ips.append(rdata.address)
                print("resolved_ips: ",resolved_ips)
            return resolved_ips

        except dns.resolver.NoAnswer:
            # 2. checking the CNAME if there is no A record
            try:
                print("---2---")
                cname_answer = resolver.resolve(url, "CNAME")
                # Update domain to the new target and loop again
                url = str(cname_answer[0].target).rstrip(".")
                print("CNAME: ",cname_answer)
            except dns.resolver.NoAnswer:
                print("No A or CNAME record found.")
                break
        except dns.resolver.NXDOMAIN:
            print(f"Domain {url} does not exist.")
            break
        except Exception as e:
            print(f"Unexpected error: {e}")
            break
            
    return resolved_ips

#-------------------
def parent_domain(url): #document 1.4.2
    """
    Extracting the registered domain 
    """
    ext = tldextract.extract(url)
    print("DOMAIN: ",f"{ext.domain}.{ext.suffix}")
    return f"{ext.domain}.{ext.suffix}"


def dns_records(url): #document 1.4.2
    #print("domain: ",domain)
    results = {}
    flags = {}

    domain = parent_domain(url)
    results["domain"] = domain
    print("parent domain: ",results["domain"])

# 1. Resolving A records with CNAME 
    ips = resolve_A_cname(domain)
    results["resolved_ips"] = ips

    if ips:
        flags["A"] = False
    else:
        flags["A"] = True


# 2. Check AAAA record (IPv6 address)
    results["AAAA_record"] = None
    flags["AAAA"] = True
    try:
        aaaa_records = dns.resolver.resolve(domain, "AAAA")
        results["AAAA_record"] = [ip.to_text() for ip in aaaa_records]
        flags["AAAA"] = False
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        try:
            aaaa_records = dns.resolver.resolve("www." + domain, "AAAA")
            results["AAAA_record"] = [ip.to_text() for ip in aaaa_records]
            flags["AAAA"] = False
        except Exception:
            # If both fail, we just leave records["AAAA"] as False
            pass 
    except Exception as e:
        print(f"Unexpected DNS error: {e}")

    print("AAAA_record:", results["AAAA_record"])


# 3. Checking MX on parent domain
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        results["MX_record"] = [mx.exchange.to_text() for mx in mx_records]
        print("MX_Records", results["MX_record"])
        flags["MX"] = False
    except:
        results["MX_record"] = None
        flags["MX"] = True

# 4. Checking NS on parent domain
    try:
        ns_records = dns.resolver.resolve(domain, "NS")
        results["NS_record"] = [ns.to_text() for ns in ns_records]
        print("NS_record: ", results["NS_record"])
        flags["NS"] = False
    except:
        results["NS_record"] = None
        flags["NS"] = True

# 5. Domain age from WHOIS
    try:
        domain_info = whois.whois(domain)
        #print("################")
        #print(domain_info)
        #print("################")
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age_days = (datetime.now() - creation_date).days
        results["domain_age_days"] = age_days
        print("Domain age days: ", age_days)
        if age_days > 7:
            flags["Age days"] = False
    except:
        results["domain_age_days"] = None
        flags["Age days"] = True
    # output

    print("-------------------------------|")
    return flags
print("|||||||||||||||||||||||||||||||||||||||")

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

print("|||||||||||||||||||||||||||||||||||||||")
def domain_age(url):    # document 1.4.1
    try:
        domain = whois.whois(tldextract.extract(url).registered_domain)
        print("domain: ", domain)
        creation_date = domain.creation_date
        print("creation_date: ", creation_date)
        if isinstance(creation_date, list): # if the expiry_date exist as list pick the first item
            creation_date = creation_date[0]
        today = datetime.now()
        print("today : ",today)
        age_days = (today - creation_date).days
        print("Month left: ", age_days)
        if age_days > 7:
            domain_age = 0 #legit
            print("Legit")
            flags["domain_age"] = False
            return flags["domain_age"]
        else:
            domain_age = 1 #phish
            print("Phish")
            flags["domain_age"] = True
            return flags["domain_age"]
    except:
        domain_age = 2 # needs to be reviewed and discussed
        print("Suspecious")
        flags["domain_age"] = True #more likely there is no record or timeout
        return flags["domain_age"]

#domain_age(url_phish3)

    
print("|||||||||||||||||||||||||||||||||||||||")
def right_click(url): #document 1.3.3
    _, html_content = get_soup(url)
    if not html_content: 
        print("no HTML content")
        right_click = 1
        flags["Right_click"] = True
        return right_click
    if "event.button==2" in html_content or "contextmenu" in html_content.lower():
        print("Right click disabled")
        right_click = 1
        flags["Right_click"] = True
        return right_click
    else:
        print("Right click is NOT disabled")
        right_click = 0
        print("right_click: ", right_click)
        flags["Right_click"] = False
        return flags["Right_click"]

#right_click(url_phish3)


print("|||||||||||||||||||||||||||||||||||||||")
def custom_status_bar(url):    #Document 1.3.2
    _,html_content = get_soup(url)
    #print(get_soup(url))
    if not html_content:
        status_bar = 1
        print("No html content, Phish",status_bar)
        flags["Status_bar"] = True
        return flags["Status_bar"]
    if "onmouseover" in html_content.lower() and "window.status" in html_content.lower():
        status_bar = 1
        print("Mouseover or Window status, Phish",status_bar)
        flags["Status_bar"] = True
        return flags["Status_bar"]
    else:
        status_bar = 0
        print("No status bar customized, Legit",status_bar)
        flags["Status_bar"] = False
        return flags["Status_bar"]

#custom_status_bar(url_legit5)


print("|||||||||||||||||||||||||||||||||||||||")
# the main extraction function 
def feature_extraction(url):
    features={}
    
    features["has_IP"] = has_ip(url)
    features["at sign"] = has_at_sign(url)
    #features["Redirection"] = redirection(url)
    features["URL Length"] = url_length(url)
    features["dash - in domain"] = dash_in_domain(url)
    features["Sub domain"] = sub_multisub_domain(url)
    features["HTTP / HTTPS"] = http_https(url)

    features["HTTPS cert's"] = https_certificate(url)
    features["Redirection"] = iframe_redirection(url)
    features["DNS records"] = dns_records(url)
    features["Path_result"] = url_path(url)

    #features["has DNS"] = has_dns(url)
    #features["Domain Expiry"] = domain_expiry(url) #
    features["Domain Age"] = domain_age(url) #
    features["Right_Click"] = right_click(url) #
    features["Custom status bar"] = custom_status_bar(url) #
    features["Label"] = False   #Legit


    print("------------------------------------------------------")
    print(url)
    #print("features: ",features)

    print("------------------------------------------------------")
    #total = sum(features.values())
    #print("Total feature value: ", total)
    return features

features = feature_extraction(url_phish4)
all_flags = {}


#print(features)

for key, value in features.items():
    if isinstance(value, dict):
        for sub_key, sub_value in value.items():
            all_flags[f"{sub_key}"] = sub_value
    else:
        all_flags[key] = value

for key, value in all_flags.items():
    print(f"{key.title()}: {value}")
