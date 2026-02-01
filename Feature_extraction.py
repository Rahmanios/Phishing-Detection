import ipaddress
import re
from urllib.parse import urlparse
import tldextract

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




# the main extraction function 
def feature_extraction(url):
    features=[]
    features.append(have_ip(url))
    features.append(have_at_sign(url))



    return features


url = "https://www.192.168.199.122.co.uk//@aaaaa/192.168.133.199/sfds565656mndasAKB1"
url2 = "https://www.thoughtfullearning.com"
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
'''
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
    print("Legit")
elif dots == 2:
    dots_count = 2 #lets consider 2 as suspicious until further decision
else:
    dots_count = 1
    print("Phish")

