import ipaddress
import re
from urllib.parse import urlparse
import tldextract
import ssl 
import socket
#import datetime
from datetime import datetime, timezone
import whois
import dns.resolver
import requests
from bs4 import BeautifulSoup

'''
def have_ip(url): # If there is IP instead of domain name, its likely someone is trying to steal personal information
    host = urlparse(url).hostname
    #print(host)
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # raw string 
    #ipaddress.ip_address(host)
    if re.search(ip_pattern,host):
        ip = 1
    else:
        ip = 0

def have_at_sign(url): # if @ presence in URL then browser ignores everything and process the @
    at = 0
    if "@" in url:
        at = 1
    else:
        at = 0
    return at

def redirection(url):
    pos = url.rfind("//") # rfind finds the last occurance
    redirect = 0
    if pos > 6:
        redirect=1
    else:
        redirect=0
    return redirect

def url_len(url): # url length 
    url_len = len(url)
    len = 0
    if(len<54):
        len = 0
    else:
        len = 1
    return len

def dash_in_domain(url): # dash - in domain name part
    host = urlparse(url).hostname
    if "-" in host:
        dash = 1
    else:
        dash = 0
    return dash

def sub_multisub_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    #print("domain: ", domain)
    if domain.startswith("www."):
        domain = domain[4:] #removing the www. part
    #print("domain without www.===>>", domain)
    parts = domain.split(".")   #spliting each part of the domain 
    #print(parts)
    #print(len(parts [-1]))
    if len(parts[-1]) == 2: #is the last part a 2letter country code?  country-code top-level domains (ccTLD) length ==2
        parts = parts[:-1]  #take the last cc
        #print("if parts:", parts)
    #print("PARTS::::",parts)
    #print("DOMAIN::::",domain)
    domain = ".".join(parts) #converting back to string
    #print("NEW DOMAIN::",domain)
    dots = domain.count(".")
    print("dots: ", dots)
    if dots == 1:
        dots_count = 0
        #print("Legit")
    elif dots == 2:
        dots_count = 2 #lets consider 2 as suspicious until further decision
    else:
        dots_count = 1
        #print("Phish")
    return dots_count

def http_https(url):
    if "https" in url:
        https = 0
    else:
        https = 1
    return https



# the main extraction function 
def feature_extraction(url):
    features=[]
    features.append(have_ip(url))
    features.append(have_at_sign(url))



    return features
'''

'''''''TESTING'''''''

url_random = "http://www.192.168.199.122.co.uk//@aaaaa/192.168.133.199/sfds565656mndasAKB1/32.php"
url_phish1 = "https://qrco.de/bfHZzy"
url_phish2 = "https://juegnjkwn.firebaseapp.com/"
url_phish3 = "https://www.dropbox.com/scl/fi/xs5b6d59p6mzlxtyf6qeh/CLICK-TO-CONTINUE-SIGN-IN.paper?dl=0&rlkey=u42md1bnw846o3enf479kqcne"
url_legit1 = "https://www.thoughtfullearning.com"
url_legit2 = "https://www.lastbryggan.se"
url_legit3 = "https://www.oncoguia.org.br"
url_legit4 = "https://www.amazon.co.uk"

#domain = urlparse(url).path.count("/")
#print("domain / -> ", domain)

#ssl certificate 
# NEED REVIEW ******* 1-the expiry date issue base on the document    2-phishers buy old domain to trick the detections 3-what if there is no ssl certificate (url_Phish2) or connection problem maybe ??

def certificate_info(url):
    host = urlparse(url).hostname
    print("host:", host)
    print("---------------------------------------------------")

    try:
        # Resolve hostname to IP first (critical)
        ip = socket.gethostbyname(host)
        print("IP: ",ip)
        context = ssl.create_default_context()

        with socket.create_connection((ip, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        print("cert:", cert)
        print("---------------------------------------------------")
        return cert

    except Exception as e:
        print("Could not retrieve certificate:", e)
        return None


def certificate_extract_features(cert):
    issuer = dict(x[0] for x in cert["issuer"])["organizationName"] #dict of issuer
    print("Issuer: ", issuer)

    valid_from = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
    valid_from = valid_from.replace(tzinfo=timezone.utc)  
    print("valid_from: ", valid_from)

    valid_to = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    valid_to = valid_to.replace(tzinfo=timezone.utc)
    print("valid_to: ", valid_to)

    ###age_days = (datetime.utcnow() - valid_from).days
    now = datetime.now(timezone.utc)
    #print("now: ", now)
    age_days = (now - valid_from).days
    print("age_days: ",age_days)
    age_years = age_days / 365
    print("age_years: ", age_years)
    return issuer, age_years

def https_cert_url(url):
    trusted_issuers = [
    "DigiCert Inc",
    "Let's Encrypt",
    "GlobalSign",
    "Sectigo Limited",
    "GoDaddy.com, Inc.",
    "Google Trust Services"
    ]
    try:
        cert = certificate_info(url)
        issuer, age_years = certificate_extract_features(cert)
        uses_https = url.startswith("https")
        print("Uses HTTPS : ", uses_https)

        #if uses_https and issuer in trusted_issuers and age_years >= 1:
        if uses_https and age_years >= 1:
            cert_ok = 0
            return "Legit"
            print(cert_ok)
        #elif uses_https and issuer not in trusted_issuers:
        elif uses_https and age_years <= 1:
            cert_ok = 2 # considered as suspicious temp
            return "Suspicious"
            print(cert_ok)
        else:
            cert_ok = 1
            return "Phish"
            print(cert_ok)
    except:
        cert_ok = 1
        return "Phish"
        print(cert_ok)

print("-----------------")

print(https_cert_url(url_phish2))
print("-----------------")
print("-----------------")

def has_dns(url):       #document 1.4.2
    cert = certificate_info(url)
    host = urlparse(url).hostname

    dns_names = []

    if cert is None:
        print("No Certificate returned, Phish")
        return 1
    
    if "subjectAltName" in cert:
        for entry in cert["subjectAltName"]:
            if entry[0] == "DNS":
                dns_names.append(entry[1])
                print("DNS:", entry[1])

        # Check if host matches any DNS entry (including wildcards)
        for dns in dns_names:
            if dns == host:
                print("Legit - exact match")
                return 0

            if dns.startswith("*."):
                base = dns[2:]
                if host.endswith(base):
                    print("Legit - wildcard match")
                    return 0

        print("Host NOT covered by certificate DNS → PHISH")
        return 1

    else:
        print("No subjectAltName in cert → PHISH")
        return 1
    
has_dns(url_phish2)
#other 
'''
#ip=0
host = urlparse(url).hostname
print("host: ",host)
ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # raw string \es are chars not escape codes
#ipaddress.ip_address(host)
if re.search(ip_pattern,host):
    ip = 1
else:
    ip = 0

print("IP: ",ip)
#--------------------------
pos = url.rfind("//")
print(pos)
redirect = 0
if pos > 6:
    redirect=1
else:
    redirect=0
print("redirect value: ",redirect)
url_len = len(url)
print("Len: ", url_len)
if(url_len<54):
    len = 0
else:
    len = 1
print("len: ",len)

if "-" in host:
    dash = 1
else:
    dash = 0

print("dash: ", dash)

parsed_url = urlparse(url2) 
domain = parsed_url.netloc
#print("domain: ", domain)
if domain.startswith("www."):
    domain = domain[4:] #removing the www. part
#print("domain without www.===>>", domain)
parts = domain.split(".")   #spliting each part of the domain 
#print(parts)
#print(len(parts [-1]))
if len(parts[-1]) == 2: #is the last part a 2letter country code?  country-code top-level domains (ccTLD) length ==2
    parts = parts[:-1]  #take the last cc
    #print("if parts:", parts)
#print("PARTS::::",parts)
#print("DOMAIN::::",domain)
domain = ".".join(parts) #converting back to string
#print("NEW DOMAIN::",domain)
dots = domain.count(".")
print("dots: ", dots)
if dots == 1:
    dots_count = 0
    print("Legit")
elif dots == 2:
    dots_count = 2 #lets consider 2 as suspicious until further decision
else:
    dots_count = 1
    print("Phish")
'''

#------ domain-based ------#
##domain = whois.whois(tldextract.extract(url_phish3).registered_domain)
##print("domain details: ",domain)
#domain = tldextract.extract(url_phish1).registered_domain
#print("doooomain: ", domain)
#print("whoooois: ", whois.whois(domain))
#print("--------------------------------------")
'''
def domain_expiry(url):
    #if domain expires in <= 1 year is Phish    #document 1.1.9
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

domain_expiry(url_legit4)
'''
'''
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
        month_passed = (today - creation_date).days / 30
        print("Month left: ", month_passed)
        if month_passed >= 6:
            domain_age = 0 #legit
            print("Legit")
            return "Legit"
        else:
            domain_age = 1 #phish
            print("Phish")
            return "Phish"
    except:
        domain_age = 2 # needs to be reviewed and discussed
        print("Suspecious")
        return "Suspecious"
    
  
domain_age(url_phish3)
'''
    

def get_soup(url):
    try:
        response = requests.get(url, timeout = 5)
        print(BeautifulSoup(response.text, "html.parser"))
        return BeautifulSoup(response.text, "html.parser"), response.text
    except:
        return None, None

def feature_right_click(url):   #document 1.3.3
    _, html_content = get_soup(url)
    if not html_content: 
        print("no HTML content")
        right_click = 1
        return right_click
    if "event.button==2" in html_content or "contextmenu" in html_content.lower():
        print("Right click disabled")
        right_click = 1
        return right_click
    else:
        print("Right click is NOT disabled")
        right_click = 0
        print("right_click: ", right_click)
        return right_click

feature_right_click(url_phish3)