import ipaddress
import re
from urllib.parse import urlparse
import tldextract

def have_ip(url): # If there is IP instead of domain name, its likely someone is trying to steal personal information
    host = urlparse(url).hostname
    #print(host)
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # raw string \es are chars not escape codes \d=0-9    {1,3}=quantifier, between 1 and 3 times
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



# the main extraction function 
def feature_extraction(url):
    features=[]
    features.append(have_ip(url))
    features.append(have_at_sign(url))



    return features
'''

url = "https://www.192.168.199.122.com//@aaaaa/192.168.133.199/sfds565656"
#ip=0
host = urlparse(url).hostname
print(host)
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
'''
