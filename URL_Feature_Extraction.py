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
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        response = requests.get(url,headers=headers, timeout=10)
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

def has_ip(url): #document 1.1.1 address bar feature
    '''
    If there is IP instead of domain name, its likely someone is trying to steal personal information
    '''
    host = urlparse(url).hostname
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b' # raw string 
    if re.search(ip_pattern,host):
        ip = 1
        #print("Has_Ip: ", ip)
        flags["Has_Ip"] = True
        return flags["Has_Ip"]
    else:
        ip = 0
        #print("No IP: ", ip)
        flags["Has_Ip"] = False
        return flags["Has_Ip"]
#has_ip(url_random)

##---===>print("|||||||||||||||||||||||||||||||||||||||")
def has_at_sign(url): #document 1.1.4 address bar feature
    '''
    checks if @ presence in URL then browser ignores everything and process the @
    '''
    if "@" in url:
        at = 1
        flags["At_Sign"] = True
        return flags["At_Sign"]
    else:
        at = 0
        flags["At_Sign"] = False

    #print("@ in url: ", at)
    return flags["At_Sign"]
    
##---===>print("|||||||||||||||||||||||||||||||||||||||") 
def url_length(url): # #document 1.1.2 address bar feature
    """
    Gets the length of URL and sets the flags["Url_Length"] to boolean value of True or False
    if the length is more or less than 54
    """
    url_len = len(url)
    length = 0
    if(url_len > 54):
        length = 1
        flags["Url_Length"] = True
    else:
        length = 0
        flags["Url_Length"] = False
    
    #print("Url_Length:", url_len , "|  length: ", length)
    return flags["Url_Length"]

##---===>print("|||||||||||||||||||||||||||||||||||||||")
def dash_in_domain(url): # document 1.1.6 address bar feature
    host = urlparse(url).hostname
    dash_count = 0
    if "-" in host:
        dash = 1
        flags["Dash_In_Domain"] = True
    else:
        dash = 0
        flags["Dash_In_Domain"] = False
    
    #print("Dash_In_Domain: ", dash)
    return flags["Dash_In_Domain"]

##---===>print("|||||||||||||||||||||||||||||||||||||||")
def sub_multisub_domain(url): #document 1.1.7 address bar feature
    """
    Analyzes the URL's domain structure to detect suspicious subdomains.

    This feature carries out phishing detection logic ( Address bar feature 1.1.7 ). 
    by counting the dots in the domain with the prefix of the www. removed and 
    country code top-level domain (ccTLD such as .uk, .jp). 

    The reasoning is along the following lines:
    - 0 to 1 dots (post processing): Legitimate (returns False)
    - 2 or above dots: Potential Phishing/Multi-subdomain (True)

    Args:
        url (str): The complete URL that is to be analyzed.

    Returns:
        bool: 
            - False (0): Normative (Normal domain/subdomain count).
            - True (1): Phishing (Too many subdomains).

    Side Effects:
        Adds a key to a global dictionary, using the key Sub_Multisub.

    Note:
        The function explicitly deals with ccTLDs, and removes the final portion. 
        of the domain should it have a set of two characters only (e.g., '.co.uk' 
        is worked to as '.co' in the count).
    """
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    #print("domain: ", domain)
    if domain.startswith("www."):
        domain = domain[4:] #removing the www. part
    parts = domain.split(".")   #spliting each part of the domain 
    
    #print(len(parts [-1]))
    if len(parts[-1]) == 2: #is the last part a 2letter country code?  country-code top-level domains (ccTLD) length ==2
        parts = parts[:-1]  #take the last cc
        
    domain = ".".join(parts) #converting back to string
    dots = domain.count(".")
    #print("dots: ", dots)
    if dots == 1:
        dots_count = 0
        flags["Sub_Multisub"] = False  #legit
    else:
        dots_count = 1
        flags["Sub_Multisub"] = True  #phish

    ##---===>print("Sub_Multisub: ", dots_count)
    return flags["Sub_Multisub"]

##---===>print("|||||||||||||||||||||||||||||||||||||||")
def http_https(url): #document 1.1.12
    """
    Checks if the URL has HTTPS  
    """
    if "https" in url:
        https = 0
        flags["HTTP_HTTPS"] = False
    else:
        https = 1
        flags["HTTP_HTTPS"] = True

    return flags["HTTP_HTTPS"]

##---===>print("|||||||||||||||||||||||||||||||||||||||")
def https_certificate(url): #document 1.1.8 address bar feature
    """
    Analyzes the HTTPS and SSL/TLS certificate properties to identify phishing indicators.

    This function implements phishing detection logic (Address Bar Feature 1.1.8). 
    It fetches the SSL certificate for the given URL and evaluates it against several 
    risk factors including certificate age, trusted Certificate Authorities (CAs), 
    and self-signing.

    Args:
        url (str): The full URL string of the site to evaluate.

    Returns:
        dict: A dictionary of boolean flags where 'True' typically indicates a 
              suspicious/phishing attribute:
            - HTTP_HTTPS (bool): True if the scheme is not HTTPS.
            - No_Cert (bool): True if the SSL certificate could not be retrieved.
            - Issuer_Name (bool): True if the issuer organization name is missing.
            - Subject_Name (bool): True if the common name is missing.
            - Self_Signed (bool): True if the issuer and subject are the same.
            - Cert_Age_Days (bool): True if the certificate is very new (< 7 days).
            - Cert_Validity_Days (bool): True if the total lifespan is short (< 14 days).
            - Trusted_Cert (bool): True if the issuer is not in the 'trusted_big_cas' list.
            - Host_subject_names (bool): True if the subject name matches the hostname.

    Note:
        The function relies on a helper `get_certificate(hostname)` and expects 
        standard library imports like `datetime`, `fnmatch`, and `urlparse`.
    """
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

    if parsed.scheme == "https":
        flags["HTTP_HTTPS"] = False
    else:
        flags["HTTP_HTTPS"] = True
        
    hostname = parsed.hostname
    cert = get_certificate(hostname)
    ##---===>print("cert::::: ", cert)
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

        if fnmatch.fnmatch(subject_name, hostname):
            flags["Host_subject_names"] = True   #Phish
    return flags

##---===>print("|||||||||||||||||||||||||||||||||||||||")
def is_cross_domain(page_url, iframe_src): #document 1.3.5
    """
    Checks if an iframe source URL belongs to a different domain than the parent page.

    Args:
        page_url (str): The URL of the main parent webpage.
        iframe_src (str): The 'src' attribute value of the iframe.

    Returns:
        bool: True if the iframe points to a different domain (excluding anchors), 
              False if domains match or the source is invalid/local.
    """
    if not iframe_src or iframe_src.startswith("#"):
        return False
    page_domain = get_domain(page_url)
    ##---===>print("---page_domain---", page_domain)
    iframe_domain = get_domain(iframe_src)
    ##---===>print("---iframe_domain---", iframe_domain)
    return iframe_domain and iframe_domain != page_domain

def legit_iframes(src): # for lowering the false positives # document 1.3.5
    """
    Determines if an iframe source belongs to a known legitimate third-party service.

    This helps filter out common cross-domain iframes used for reCAPTCHA, 
    social media embeds, payment gateways, and video hosting.

    Args:
        src (str): The 'src' attribute of the iframe to check.

    Returns:
        bool: True if the source matches a known legitimate domain, False otherwise.
    """
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
    """
    Analyzes webpage iframes for phishing and clickjacking indicators.

    This function scans all <iframe> tags in the HTML to detect suspicious 
    behavior, such as hidden iframes, cross-domain sources (excluding a 
    whitelist), and potential UI overlays designed to steal credentials.

    Args:
        url (str): The URL of the webpage to analyze.

    Returns:
        dict: A dictionary of boolean flags where 'True' indicates a risk factor:
            - No_Soup (bool): True if the HTML content could not be parsed.
            - Invisible_Iframe (bool): True if hidden via CSS or 0-size dimensions.
            - Cross_Domain_Iframe (bool): True if content is pulled from an 
              external untrusted domain.
            - Nested_Iframes (bool): True if an iframe contains another iframe.
            - No_Visible_Purpose (bool): True if the iframe lacks both text and a source.
            - Overlay_Behavior (bool): True if an absolute/fixed iframe exists 
              on a page with sensitive input fields (potential Clickjacking).

    Note:
        Relies on 'get_soup(url)' for HTML parsing and 'get_domain(url)' 
        for domain extraction.
    """
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
        width = iframe.get("width", "")
        height = iframe.get("height", "")
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


        # nested iframes
        if iframe.find("iframe"):
            flags["Nested_Iframes"] = True

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

def resolve_A_cname(url): #document 1.4.2
    """
    Recursively resolves a domain to its IPv4 (A) addresses, following CNAME chains.

    This function attempts to find the final IP address of a host. If an 'A' record 
    is not immediately found, it looks for a 'CNAME' (alias), updates the target, 
    and repeats the process until an IP is resolved or the chain ends.

    Args:
        url (str): The domain name or URL to resolve.

    Returns:
        list[str]: A list of resolved IPv4 addresses. Returns an empty list if 
                   no records are found or the domain does not exist.
    """
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
    #print("DOMAIN: ",f"{ext.domain}.{ext.suffix}")
    return f"{ext.domain}.{ext.suffix}"


def dns_records(url): #document 1.4.2
    """
    Assesses DNS health, and age of registration of a domain to detect phishing.

    Phishing domains might have no valid mail records (MX), and have temporary names. 
    servers, or were very recently registered. This function checks for the 
    presence of A, AAA, MX and NS records and queries WHOIS with. 
    domain age.

    Args:
        url (str): The URL to analyse.

    Returns:
        dict: Dictionary of indicative flags where True means a risk factor:
            - ARecord (bool): True when there are no IPv4 addresses.
            - AAAA_Record (bool): True when there are no IPv6 addresses.
            - MX_Record (bool): True when there are no records of Mail Exchange (uncharacteristic of legitimate sites).
            - NS_Record (bool): True when no records in Name Server.
            - Age_Days (bool): True if the domain is < 7 days old or age is unavailable.

    Note:
        Needs libraries such as dnspython, tldextract and python-whois. 
        Absence of DNS records is a good sign of malicious or ephemeral domain.
    """
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
    "docs.google.com", "sites.google.com", "dropbox.com", "firebaseapp.com", "framer.app", "webcindario.com", "campaign-archive.com",
    "new.express.adobe.com", "jotform.com", "hsforms.com", "forms.office.com", "ipfs.io", "ipfs.best-practice.se", "adobe.com/webpage"
]

url_shorteners = [
    "bit.ly","t.co","tinyurl.com","qrco.de","q-r.to",
    "l.ead.me","did.li","linkin.bio"
]

def url_path(url):
    """
    Examines the lexical composition of a URL to find patterns that could be related to phishing.

    This role breaks down the URL into its parts and verifies the existence of. 
    standard obfuscation methods, such as using URL shorteners, 
    free hosting domains, questionable keywords in the path, and high. 
    lexical complexity (unnecessary digits or complexity).

    Args:
        url (str): the complete URL that should be analyzed.

    Returns:
        dict: dictionary of Boolean flags, with True meaning a risk factor:
            - URL_Short (bool): True when an established URL shortener (e.g. bit.ly) was used.
            - Free_Domain (bool): True when the site is on a free domain host.
            - Phish_Keyword (bool): True when there are typical phishing words (e.g., 'login', 'verify'). 
              appear in the path.
            - File_Extension (bool): True when it contains suspicious file extensions (e.g.,.exe, .zip). 
              are located in the realm or direction.
            - Segment (bool): The path segment is long (more than 18 chars) and has numbers.
            - Digits (bool): True when the path has over 5 numeric digits.
            - Query (bool): True when there are suspicious parameters in the query string.
            - Depth_Segments (bool): True when the URL path has more than 3 levels.

        The operation depends on a number of external lists to make a comparison: `url shorteners. 
        free_domains, keywords, extentions and queries.
    """
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
    """
    Validates the age of the domain with WHOIS registration information.

    This operation identifies the registered domain and makes queries of WHOIS records. 
    find the days since it was created. Most phishing campaigns 
    use domains that have been registered in the recent days in order to be ahead of blacklists.

    Args:
        url (str): The entire URL being tested.

    Returns:
        bool: 
            - False (0): Legitimate (Domain age is > 7 days).
            - True (1): Phishing (Domain age is <= 7 days, or no record is found).

    Side Effects:
        Updates the global `flags` dictionary with the "Domain_Age" key.
    """
    try:
        domain = whois.whois(tldextract.extract(url).registered_domain)
        creation_date = domain.creation_date
        if isinstance(creation_date, list): # if the expiry_date exist as list pick the first item
            creation_date = creation_date[0]
        today = datetime.now()
        ##---===>print("today : ",today)
        age_days = (today - creation_date).days
        if age_days > 7:
            domain_age = 0 #legit
            flags["Domain_Age"] = False
            return flags["Domain_Age"]
        else:
            domain_age = 1 #phish
            flags["Domain_Age"] = True
            return flags["Domain_Age"]
    except:
        domain_age = 2 # needs to be reviewed and discussed
        flags["Domain_Age"] = True #more likely there is no record or timeout
        return flags["Domain_Age"]

    
##---===>print("|||||||||||||||||||||||||||||||||||||||")
def right_click(url): #document 1.3.3
    """
    Checks whether the right-click context menu has been disabled (JavaScript).

    This function searches the HTML source for 'contextmenu' event listeners 
    or particular 'event.button' checks to block the right-click menu.

    Args:
        url (str): The URL of the webpage to scrape and analyze.

    Returns:
        bool: 
            - True (1): Phishing (Right-click is disabled or HTML is unreachable).
            - False (0): Legitimate (No context menu manipulation detected).
    """
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
    """
    Identifies if JavaScript is used to hide or spoof the browser's status bar.

    This is a function that seeks the occurrence of both onmouseover events and. 
    'window.status' assignments. This trick is employed in order to deceive users. 
    so that they believe they are clicking on a valid link by displaying a. 
    spoofed URL in the browser status bar.

    Args:
        url (str): URL of the webpage to be analysed.

    Returns:
        bool: 
            - True (1): Phishing (Status bar manipulation detected or no HTML).
            - False (0): Legitimate (No status bar tampering detected).
    """
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
    """
    Plays the role of the central orchestrator to elicit all the multi-dimensional phishing features.

    This role is a compilation of five key types of analysis outputs:
    1. Address Bar: IP presence, at symbol, length of URL and subdomains.
    2. SSL/TLS Certificate Features: Trust, age, validity, and issuer details.
    3. HTML/JavaScript Features: Hidden iframes, clickjacking overlays, and disabled UI.
    4. Network/DNS Features: Record existence (A, AAAAA, MX, NS) and domain age.
    5. Lexical/Path Features: URL redirection, free hosting, and suspicious keywords.

    Args:
        url (str): The target URL which is going to be analyzed.
        label (int/str): The label of the classification (1 is Phish, 0 is Legit) 
            to be added to the feature set.

    Returns:
        dict: A dictionary that is a flattened version of all extracted dictionary entries, both boolean and numeric. 
              target label, among others. This dictionary is suitable 
              to convert into a pandas DataFrame to be processed by ML.
    """
    #print("--------------")
    print(url, "\n")
    features={}
    
    features["url"] = url
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


    return features

''' #printing a test url
result = feature_extraction(url_phish10, 1)

for key, value in result.items():
    print(f"{key.title()}: {value}")
'''


Phish_csv_path = "Content/CSVs/phish_urls_extracted_10000.csv"
Legit_csv_path = "Content/CSVs/Legit_urls_extracted_10000.csv"
Phish_TEST_path = "Content/CSVs/Test_CSVs/phish_urls_FOR_TEST.csv"
Legit_TEST_path = "Content/CSVs/Test_CSVs/LEGIT_urls__FOR_TEST.csv"

def process_urls_csv(csv_path, label, url_column_name="url"):
    """
    Extracts features in batches on the list of URLs sorted in a CSV file.

    This operation automates the extraction process of an entire end-to-end. 
    dataset. It reads the source file, removes entries that are missing, and runs the. 
    coordinated multi-dimensional feature_extraction pipeline per URL. The results 
    are combined into one pandas DataFrame, which is best suited to. 
    creating training or testing data.

    Args:
        csv_path (str): The local or remote file path to the CSV file.
        label (int/str): The label that will be given to each of the URLs in this. 
            batch (e.g., 0 as the case of Legitimate, 1 as the case of Phishing).
        url_column_name (str, optional): The name of the column that is holding the. 
            target URLs. In case the column is not found, it assumes the first. 
            column is the URL column. Defaults to "url".

    Returns:
        pd.DataFrame: A DataFrame in which the rows are processed URLs. 
            and its respective features (lexical, DNS, SSL and behavioral).

    Note:
        - The function uses `tqdm` to display a progress bar in the console.
        - URLs that do not process (e.g. because of network timeouts or 
          parsing errors) are reported and ignored.
        - Missing (NaN) values in the URL column are dropped before processing.
    """
    df = pd.read_csv(csv_path)

    if url_column_name not in df.columns:
        df.columns = ["url"]

    urls = df["url"].dropna().tolist()

    dataset = []

    for url in tqdm(urls):
        try:
            features = feature_extraction(url, label)
            features["url"] = url
            dataset.append(features)
        except Exception as e:
            print(f"Error processing {url}: {e}")
    
    return pd.DataFrame(dataset)


#phish_features = process_urls_csv(Phish_csv_path, label = 1)
#phish_features.to_csv("Content/CSVs/Phish_features_PROCESSED.csv", index = False)

legit_features = process_urls_csv(Legit_csv_path, label = 0)
legit_features.to_csv("Content/CSVs/Legit_features_PROCESSED.csv", index = False)