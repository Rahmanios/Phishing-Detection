import ipaddress
import re
from urllib.parse import urlparse
import tldextract
import ssl
import socket
import dns.resolver
from datetime import datetime, timezone
import whois

import requests
from bs4 import BeautifulSoup
#import Extract_Combine_CSVs


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


def http_https(url): #document 1.1.12
    if "https" in url:
        https = 0
        flags["http_https"] = False
    else:
        https = 1
        flags["http_https"] = True

    print("http_https: ", https)
    return flags["http_https"]


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

print("---------------------")

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

print("---------------------")

# the main extraction function 
def feature_extraction(url):
    features={}
    
    features["has_IP"] = has_ip(url)
    features["at sign"] = has_at_sign(url)
    features["Redirection"] = redirection(url)
    features["URL Length"] = url_length(url)
    features["dash - in domain"] = dash_in_domain(url)
    features["Sub domain"] = sub_multisub_domain(url)
    features["HTTP / HTTPS"] = http_https(url)
    #features["HTTPS cert"] = https_cert_url(url)
    #features["has DNS"] = has_dns(url)
    #features["Domain Expiry"] = domain_expiry(url) #
    features["Domain Age"] = domain_age(url) #
    features["Right_Click"] = right_click(url) #
    features["Custom status bar"] = custom_status_bar(url) #
    features["Label"] = False   #Legit


    print("------------------------------------------------------")
    print(url)
    print("features: ",features)

    print("------------------------------------------------------")
    total = sum(features.values())
    print("Total feature value: ", total)
    return features

feature_extraction(url_legit4)

