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
import ipaddress


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

    
def get_soup(url):
    try:
        response = requests.get(url, timeout=10)
        return BeautifulSoup(response.text, "html.parser"), response.text
    except:
        return None, None

def get_domain(url): #document 1.3.5
    try:
        return urlparse(url).netloc
    except:
        return ""

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

        #if legit_iframes(src):
            #continue

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


    return {
        "flags": flags,
        "iframe_count": len(iframes)
    }

result = iframe_redirection(url_legit1)
print("---------------------")

#print("result: ",result)

print("---------------------")
for flag, value in result["flags"].items():
    print(f"{flag.title()}: {value}")

#for flag, value in result.items():
    #print(f"{flag}: {value}")

