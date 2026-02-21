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

import pandas as pd
from tqdm import tqdm


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
    "Has_Ip" : False,
    "At_Sign" : False,
    "Url_Length" : False,
    "Dash_In_Domain" : False,
    "sub_multisub" : False,
    "HTTP_HTTPS" : False,
    "domain_expiry" : False,
    "domain_age" : False,
    "right_click" : False,
    "custom_status_bar" : False

}



def get_soup(url):
    try:
        response = requests.get(url, timeout=10)
        return BeautifulSoup(response.text, "html.parser"), response.text
    except:
        return None, None
    
##---===>print("|||||||||||||||||||||||||||||||||||||||")
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
##---===>print("|||||||||||||||||||||||||||||||||||||||")




def has_ip(url): #document 1.1.1
    '''
    If there is IP instead of domain name, its likely someone is trying to steal personal information
    '''
    host = urlparse(url).hostname
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b' # raw string 
    if re.search(ip_pattern,host):
        ip = 1
        print("Has_Ip: ", ip)
        flags["Has_Ip"] = True
        return flags["Has_Ip"]
    else:
        ip = 0
        print("No IP: ", ip)
        flags["Has_Ip"] = False
        return flags["Has_Ip"]
#has_ip(url_random)

##---===>print("|||||||||||||||||||||||||||||||||||||||")
def has_at_sign(url): #document 1.1.4
    '''
    if @ presence in URL then browser ignores everything and process the @
    '''
    if "@" in url:
        at = 1
        flags["At_Sign"] = True
        return flags["At_Sign"]
    else:
        at = 0
        flags["At_Sign"] = False

    print("@ in url: ", at)
    return flags["At_Sign"]
    
##---===>print("|||||||||||||||||||||||||||||||||||||||") # to be deleted later
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
##---===>print("|||||||||||||||||||||||||||||||||||||||") 
def url_length(url): # #document 1.1.2
    url_len = len(url)
    length = 0
    if(url_len > 54):
        length = 1
        flags["Url_Length"] = True
    else:
        length = 0
        flags["Url_Length"] = False
    
    print("Url_Length:", url_len , "|  length: ", length)
    return flags["Url_Length"]

##---===>print("|||||||||||||||||||||||||||||||||||||||")
def dash_in_domain(url): # document 1.1.6
    host = urlparse(url).hostname
    dash_count = 0
    if "-" in host:
        dash = 1
        flags["Dash_In_Domain"] = True
    else:
        dash = 0
        flags["Dash_In_Domain"] = False
    
    print("Dash_In_Domain: ", dash)
    return flags["Dash_In_Domain"]

##---===>print("|||||||||||||||||||||||||||||||||||||||")
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
        flags["Sub_Multisub"] = False  #legit
    #elif dots == 2:
        #dots_count = 2 #lets consider 2 as suspicious until further decision
    else:
        dots_count = 1
        flags["Sub_Multisub"] = True  #phish

    ##---===>print("Sub_Multisub: ", dots_count)
    return flags["Sub_Multisub"]

##---===>print("|||||||||||||||||||||||||||||||||||||||")
def http_https(url): #document 1.1.12
    if "https" in url:
        https = 0
        flags["HTTP_HTTPS"] = False
    else:
        https = 1
        flags["HTTP_HTTPS"] = True

    ##---===>print("HTTP_HTTPS: ", https)
    return flags["HTTP_HTTPS"]

##---===>print("|||||||||||||||||||||||||||||||||||||||")
def https_certificate(url): #document 1.1.8
    """
    Evaluating the HTTPS and certificate properties to classify the URL
    """
    ##---===>print(url)
    parsed = urlparse(url)
    flags = {
        "HTTP_HTTPS" : False,
        "No_Cert" : False,
        "Issuer_Name" : False,
        "Subject_Name" : False,
        "Self_Signed" : False,
        "Cert_Age_Days" : False,
        "Cert_Validity_Days" : False,
        "Trusted_Cert" : False,
        "Host_subject_names" : True 
    }

    # If not HTTPS → phishing
    ##---===>print("parsed.scheme = ",parsed.scheme)

    if parsed.scheme == "https":
        flags["HTTP_HTTPS"] = False
    else:
        flags["HTTP_HTTPS"] = True
        
    hostname = parsed.hostname
    cert = get_certificate(hostname)
    ##---===>print("cert::::: ", cert)
    # If certificate cannot be retrieved → phishing
    flags["No_Cert"] = False
    if cert is None:
        flags["No_Cert"] = True
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
            ##---===>print("issuer name:",issuer_name)
            flags["Issuer_Name"] = False
        else:
            flags["Issuer_Name"] = True #no issuer name Phish


        subject = dict(x[0] for x in cert['subject'])
        subject_name = subject.get('commonName', '').lower()
        if subject_name:
            ##---===>print("subject name:",subject_name)
            flags["Subject_Name"] = False
        else:
            flags["Subject_Name"] = True  #no subject name Phish
  

        self_signed = issuer_name == subject_name
        #print("self_signed--------->",self_signed)
        flags["Self_Signed"] = self_signed

        ##---===>print("cert age days: ", cert_age_days)
        if cert_age_days < 7: #30
            flags["Cert_Age_Days"] = True #very new - Phish
        #elif cert_age_days < 365:
            # Suspicious
        else:
            flags["Cert_Age_Days"] = False

        ##---===>print("cert_validity_days: ",cert_validity_days)
        if cert_validity_days < 14: ####90
            flags["Cert_Validity_Days"] = True    # Short-lived cert
        else:
            flags["Cert_Validity_Days"] = False

        ##---===>print("self signed: ", self_signed)
        if self_signed:
            flags["Self_Signed"] = True  #Phish
        else:
            flags["Self_Signed"] = False

        trusted_big_cas = [
            "digicert", "globalsign", "sectigo", "godaddy", "let's encrypt", "amazon",
            "geotrust", "thawte", "verisign", "comodo", "google trust services","cloudflare",
            "microsoft", "network solutions", "entrust", "trustwave", "dotster", 
        ]
        if not any(ca in issuer_name.lower() for ca in trusted_big_cas):
            flags["Trusted_Cert"] = True
        else:
            flags["Trusted_Cert"] = False

        ##---===>print("issuer name: ", issuer_name)

        ##---===>print("host name: ", hostname)
        ##---===>print("subject name: ", subject_name)  
        #if subject_name not in hostname:
        if fnmatch.fnmatch(subject_name, hostname):
            flags["Host_subject_names"] = True   #Phish
    return flags

##---===>print("|||||||||||||||||||||||||||||||||||||||")
def is_cross_domain(page_url, iframe_src): #document 1.3.5
    if not iframe_src or iframe_src.startswith("#"):
        return False
    page_domain = get_domain(page_url)
    ##---===>print("---page_domain---", page_domain)
    iframe_domain = get_domain(iframe_src)
    ##---===>print("---iframe_domain---", iframe_domain)
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
    ##---===>print("url: ", url)
    ##---===>print("----------------------")
    soup, html = get_soup(url)
    
    flags = {
        "No_Soup" : False,
        "Invisible_Iframe": False,
        "Cross_Domain_Iframe": False,
        "Nested_Iframes": False,
        "No_Visible_Purpose": False,
        "Overlay_Behavior": False
    }

    if soup is None:
        flags["No_Soup"] = True
        ##---===>print("No Soup!!!")
        return flags

    iframes = soup.find_all("iframe")
    inputs = soup.find_all("input")
    ##---===>print("Soup is returned")


    page_domain = get_domain(url)

    for iframe in iframes:
        src = iframe.get("src", "")
        ##---===>print("src:", src)
        width = iframe.get("width", "")
        ##---===>print("width:", width)
        height = iframe.get("height", "")
        ##---===>print("height:", height)
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
            flags["Invisible_Iframe"] = True

        # cross-domain iframe
        if is_cross_domain(url, src):
            flags["Cross_Domain_Iframe"] = True
            ##---===>print("url ", url)
            ##---===>print("src ", src)

        # nested iframes
        if iframe.find("iframe"):
            flags["Nested_Iframes"] = True
            ##---===>print("iframe ", iframe)

        # no visible purpose / the iframe shows no content to user
        if not iframe.text.strip() and not src:
            flags["No_Visible_Purpose"] = True

        # overlay behavior (heuristic)
        if "position:absolute" in style or "position:fixed" in style:
            for inp in inputs:
                if inp.get("type", "") in ["text", "password", "email"]:
                    flags["Overlay_Behavior"] = True
                    break


    return flags

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
##---===>print("|||||||||||||||||||||||||||||||||||||||")
def resolve_A_cname(url): #document 1.4.2
    resolved_ips = []
    visited = set()
    resolver = dns.resolver.Resolver()
    ##---===>print(resolver)
    while url not in visited:
        visited.add(url)
        ##---===>print(f"Resolving: {url}")
        
        try:
            # 1. Trying to get A records
            ##---===>print("---1---")
            answer = resolver.resolve(url, "A")
            for rdata in answer:
                resolved_ips.append(rdata.address)
                ##---===>print("resolved_ips: ",resolved_ips)
            return resolved_ips

        except dns.resolver.NoAnswer:
            # 2. checking the CNAME if there is no A record
            try:
                ##---===>print("---2---")
                cname_answer = resolver.resolve(url, "CNAME")
                # Update domain to the new target and loop again
                url = str(cname_answer[0].target).rstrip(".")
                ##---===>print("CNAME: ",cname_answer)
            except dns.resolver.NoAnswer:
                ##---===>print("No A or CNAME record found.")
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
    flags = {
        "A_Record" : False,
        "AAAA_Record" : False,
        "MX_Record" : False,
        "NS_Record" : False,
        "Age_Days" : False
    }

    domain = parent_domain(url)
    results["domain"] = domain
    ##---===>print("parent domain: ",results["domain"])

# 1. Resolving A records with CNAME 
    ips = resolve_A_cname(domain)
    results["resolved_ips"] = ips

    if ips:
        flags["A_Record"] = False
    else:
        flags["A_Record"] = True


# 2. Check AAAA record (IPv6 address)
    results["AAAA_record"] = None
    flags["AAAA_Record"] = True
    try:
        aaaa_records = dns.resolver.resolve(domain, "AAAA")
        results["AAAA_record"] = [ip.to_text() for ip in aaaa_records]
        flags["AAAA_Record"] = False
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        try:
            aaaa_records = dns.resolver.resolve("www." + domain, "AAAA")
            results["AAAA_record"] = [ip.to_text() for ip in aaaa_records]
            flags["AAAA_Record"] = False
        except Exception:
            # If both fail, we just leave records["AAAA"] as False
            pass 
    except Exception as e:
        print(f"Unexpected DNS error: {e}")

    ##---===>print("AAAA_record:", results["AAAA_record"])


# 3. Checking MX on parent domain
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        results["MX_record"] = [mx.exchange.to_text() for mx in mx_records]
        ##---===>print("MX_Records", results["MX_record"])
        flags["MX_Record"] = False
    except:
        results["MX_record"] = None
        flags["MX_Record"] = True

# 4. Checking NS on parent domain
    try:
        ns_records = dns.resolver.resolve(domain, "NS")
        results["NS_record"] = [ns.to_text() for ns in ns_records]
        ##---===>print("NS_record: ", results["NS_record"])
        flags["NS_Record"] = False
    except:
        results["NS_record"] = None
        flags["NS_Record"] = True

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
        ##---===>print("Domain age days: ", age_days)
        if age_days > 7:
            flags["Age_Days"] = False
    except:
        results["domain_age_days"] = None
        flags["Age_Days"] = True
    # output

    ##---===>print("-------------------------------|")
    return flags
##---===>print("|||||||||||||||||||||||||||||||||||||||")

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
    ##---===>print(url, "\n")
    parsed = urlparse(url)
    ##---===>print("Parsed: \n", parsed, "\n")
    domain = parsed.netloc.lower()
    ##---===>print("Domain: ", domain)
    path = parsed.path.lower()
    ##---===>print("path: ", path)
    query = parsed.query.lower()
    ##---===>print("Query: ", query, "\n\n")

    path_result = {}
    
    #short url
    path_result["URL_Short"] = False
    for us in url_shorteners:
        if us in domain:
            ##---===>print("url shortener used: ", us)
            path_result["URL_Short"] = True
    ##---===>print("path_result[URL_Short]:", path_result["URL_Short"], "\n")

    #using free domains as a legit base
    path_result["Free_Domain"] = False
    for fd in free_domains:
        if fd in domain:
            ##---===>print("free domain used: ", fd)
            path_result["Free_Domain"] = True
            break
    ##---===>print("path_result[Free_Domain]:", path_result["Free_Domain"], "\n")

    #using phishing keyword
    path_result["Phish_Keyword"] = False
    for pk in keywords:
        if pk in path:
            ##---===>print("Phish keyword used: ", pk)
            path_result["Phish_Keyword"] = True
        
    ##---===>print("path_result[Phish_Keyword]:", path_result["Phish_Keyword"], "\n")

    #suspecious file extensions in path
    path_result["File_Extension"] = False
    for ext in extentions:
        if ext in path or ext in domain:
            ##---===>print("-----------------extension used in path:", ext)
            path_result["File_Extension"] = True
            break
    ##---===>print("path_result[File_Extension]: ", path_result["File_Extension"], "\n")

    #long random path segments
    path_result["Segment"] = False
    for seg in path.split("/"):
        if len(seg) > 18 and re.search(r"\d", seg):
            ##---===>print("Segment: ", seg)
            path_result["Segment"] = True
            break
    ##---===>print("path_result[Segment]: ", path_result["Segment"], "\n")

    #excessive digits in path
    path_result["Digits"] = False
    digits = sum(c.isdigit() for c in path)
    if digits > 5:
        ##---===>print("Digits: ", digits)
        path_result["Digits"] = True
        ##---===>print("path_result[Digits]: ", path_result["Digits"], "\n")

    #query parameters
    path_result["Query"] = False
    for q in queries:
        if q in query:
            ##---===>print("Query used: ", q)
            path_result["Query"] = True
    ##---===>print("path_result[Query]", path_result["Query"], "\n")

    #path depth by each segments seprated by /
    depth = 0
    path_result["Depth_Segments"] = False
    for s in path.split("/"):
        depth += 1
    if depth > 3:
        ##---===>print("Depth_Segments", depth)
        path_result["Depth_Segments"] = True
        ##---===>print("path_result[Depth_Segments]", path_result["Depth_Segments"], "\n")

    return path_result

##---===>print("|||||||||||||||||||||||||||||||||||||||")
def domain_age(url):    # document 1.4.1
    try:
        domain = whois.whois(tldextract.extract(url).registered_domain)
        ##---===>print("domain: ", domain)
        creation_date = domain.creation_date
        ##---===>print("creation_date: ", creation_date)
        if isinstance(creation_date, list): # if the expiry_date exist as list pick the first item
            creation_date = creation_date[0]
        today = datetime.now()
        ##---===>print("today : ",today)
        age_days = (today - creation_date).days
        ##---===>print("days left: ", age_days)
        if age_days > 7:
            domain_age = 0 #legit
            ##---===>print("Legit")
            flags["Domain_Age"] = False
            return flags["Domain_Age"]
        else:
            domain_age = 1 #phish
            ##---===>print("Phish")
            flags["Domain_Age"] = True
            return flags["Domain_Age"]
    except:
        domain_age = 2 # needs to be reviewed and discussed
        ##---===>print("Suspecious")
        flags["Domain_Age"] = True #more likely there is no record or timeout
        return flags["Domain_Age"]

#domain_age(url_phish3)

    
##---===>print("|||||||||||||||||||||||||||||||||||||||")
def right_click(url): #document 1.3.3
    _, html_content = get_soup(url)
    if not html_content: 
        ##---===>print("no HTML content")
        right_click = 1
        flags["Right_Click"] = True
        return flags["Right_Click"]
    if "event.button==2" in html_content or "contextmenu" in html_content.lower():
        ##---===>print("Right click disabled")
        right_click = 1
        flags["Right_Click"] = True
        return flags["Right_Click"]
    else:
        ##---===>print("Right click is NOT disabled")
        right_click = 0
        ##---===>print("right_click: ", right_click)
        flags["Right_Click"] = False
        return flags["Right_Click"]

#right_click(url_phish3)


print("|||||||||||||||||||||||||||||||||||||||")
def custom_status_bar(url):    #Document 1.3.2
    _,html_content = get_soup(url)
    #print(get_soup(url))
    if not html_content:
        status_bar = 1
        ##---===>print("No html content, Phish",status_bar)
        flags["Custom_Status_Bar"] = True
        return flags["Custom_Status_Bar"]
    if "onmouseover" in html_content.lower() and "window.status" in html_content.lower():
        status_bar = 1
        ##---===>print("Mouseover or Window status, Phish",status_bar)
        flags["Custom_Status_Bar"] = True
        return flags["Custom_Status_Bar"]
    else:
        status_bar = 0
        ##---===>print("No status bar customized, Legit",status_bar)
        flags["Custom_Status_Bar"] = False
        return flags["Custom_Status_Bar"]

#custom_status_bar(url_legit5)


##---===>print("|||||||||||||||||||||||||||||||||||||||")
# the main extraction function 
def feature_extraction(url, label):
    print("--------------")
    print(url)
    features={}
    
    features["Has_Ip"] = has_ip(url)
    features["At_Sign"] = has_at_sign(url)
    features["Url_Length"] = url_length(url)
    features["Dash_In_Domain"] = dash_in_domain(url)
    features["Sub_Multisub"] = sub_multisub_domain(url)
    features["HTTP_HTTPS"] = http_https(url)

    #features["HTTPS cert's"] = https_certificate(url)
    cert = https_certificate(url)
    features["No_Cert"] = cert["No_Cert"]
    features["Issuer_Name"] = cert["Issuer_Name"]
    features["Subject_Name"] = cert["Subject_Name"]
    features["Self_Signed"] = cert["Self_Signed"]
    features["Cert_Age_Days"] = cert["Cert_Age_Days"]
    features["Cert_Validity_Days"] = cert["Cert_Validity_Days"]
    features["Trusted_Cert"] = cert["Trusted_Cert"]
    
    #features["Redirection"] = iframe_redirection(url)
    iframe = iframe_redirection(url)
    features["No_Soup"] = iframe["No_Soup"]
    features["Invisible_Iframe"] = iframe["Invisible_Iframe"]
    features["Cross_Domain_Iframe"] = iframe["Cross_Domain_Iframe"]
    features["Nested_Iframes"] = iframe["Nested_Iframes"]
    features["No_Visible_Purpose"] = iframe["No_Visible_Purpose"]
    features["Overlay_Behavior"] = iframe["Overlay_Behavior"]

    #features["DNS records"] = dns_records(url)
    dns = dns_records(url)
    features["A_Record"] = dns["A_Record"]
    features["AAAA_Record"] = dns["AAAA_Record"]
    features["MX_Record"] = dns["MX_Record"]
    features["NS_Record"] = dns["NS_Record"]
    features["DNS_Age_Days"] = dns["Age_Days"]

    #features["Path_result"] = url_path(url)
    path = url_path(url)
    features["URL_Short"] = path["URL_Short"]
    features["Free_Domain"] = path["Free_Domain"]
    features["Phish_Keyword"] = path["Phish_Keyword"]
    features["File_Extension"] = path["File_Extension"]
    features["Segment"] = path["Segment"]
    features["Digits"] = path["Digits"]
    features["Query"] = path["Query"]
    features["Depth_Segments"] = path["Depth_Segments"]

    features["Domain_Age"] = domain_age(url) #
    features["Right_Click"] = right_click(url) #
    features["Custom_status_bar"] = custom_status_bar(url) #

    features["Label"] = label   #Phish / Legit


    ##---===>
    ##---===>print("features: ",features)

    #total = sum(features.values())
    #print("Total feature value: ", total)
    return features

''' #printing a test url
result = feature_extraction(url_phish10, 1)

for key, value in result.items():
    print(f"{key.title()}: {value}")
'''

### importing the csv's and trying the feature extraction
#Phish_csv = pd.read_csv("Content/CSVs/phish_urls_extracted_10000.csv")
#Legit_csv = pd.read_csv("Content/CSVs/Legit_urls_extracted_10000.csv", header=None)

Phish_csv_path = "Content/CSVs/phish_urls_extracted_10000.csv"
Legit_csv_path = "Content/CSVs/Legit_urls_extracted_10000.csv"
Phish_TEST_path = "Content/CSVs/phish_urls_FOR_TEST.csv"

def process_urls_csv(csv_path, label, url_column_name="url"):
    df = pd.read_csv(csv_path)

    if url_column_name not in df.columns:
        df.columns = ["url"]

    urls = df["url"].dropna().tolist()

    dataset = []

    for url in tqdm(urls):
        try:
            features = feature_extraction(url, label)
            dataset.append(features)
        except Exception as e:
            print(f"Error processing {url}: {e}")
    
    return pd.DataFrame(dataset)


phish_features = process_urls_csv(Phish_TEST_path, label = 1)

phish_features.to_csv("Content/CSVs/Phish_features_processed.csv", index = False)