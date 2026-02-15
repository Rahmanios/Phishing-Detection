import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
import fnmatch


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


def get_certificate(hostname, port=443):
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

def https_certificate(url):
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
        flags["Has https"] = False
    else:
        flags["has https"] = True
        


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
    
cert = https_certificate(url_phish5)
print("--------------------")
for key, value in cert.items():
    print(f"{key.title()}: {value}")
