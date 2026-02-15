import dns.resolver
import whois
import tldextract
from datetime import datetime

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

#domain age days needs decision
def resolve_A_cname(url):
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
def parent_domain(url):
    """
    Extracting the registered domain 
    """
    ext = tldextract.extract(url)
    print("DOMAIN: ",f"{ext.domain}.{ext.suffix}")
    return f"{ext.domain}.{ext.suffix}"


def check_dns_records(url):
    #print("domain: ",domain)
    results = {}
    records = {}

    domain = parent_domain(url)
    results["domain"] = domain
    print("parent domain: ",results["domain"])

# 1. Resolving A records with CNAME 
    ips = resolve_A_cname(domain)
    results["resolved_ips"] = ips

    if ips:
        records["A"] = True
    else:
        records["A"] = False


# 2. Check AAAA record (IPv6 address)
    results["AAAA_record"] = None
    records["AAAA"] = False
    try:
        aaaa_records = dns.resolver.resolve(domain, "AAAA")
        results["AAAA_record"] = [ip.to_text() for ip in aaaa_records]
        records["AAAA"] = True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        try:
            aaaa_records = dns.resolver.resolve("www." + domain, "AAAA")
            results["AAAA_record"] = [ip.to_text() for ip in aaaa_records]
            records["AAAA"] = True
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
        records["MX"] = True
    except:
        results["MX_record"] = None
        records["MX"] = False

# 4. Checking NS on parent domain
    try:
        ns_records = dns.resolver.resolve(domain, "NS")
        results["NS_record"] = [ns.to_text() for ns in ns_records]
        print("NS_record: ", results["NS_record"])
        records["NS"] = True
    except:
        results["NS_record"] = None
        records["NS"] = False

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
            records["Age days"] = True
    except:
        results["domain_age_days"] = None
        records["Age days"] = False
    # output


    print("-------------------------------|")
    return {
        "results" : results,
        "records" : records
    }

print("|---------------results----------------|")
dns = (check_dns_records(url_legit4))


for item, value in dns["results"].items():
    print(f"{item.title()}: {value}")
print("-------------------------------|")
for item, value in dns["records"].items():
    print(f"{item.title()}: {value}")