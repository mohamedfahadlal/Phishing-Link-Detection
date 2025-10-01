import sys
import whois
import socket
import requests
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse

try:
    import tldextract
except Exception:
    sys.exit("Install tldextract: pip install tldextract")

# ----------------------------- Helpers -----------------------------
def normalize_domain(host_or_url):
    if host_or_url.startswith(("http://", "https://")):
        host_or_url = urlparse(host_or_url).netloc
    if "@" in host_or_url:
        host_or_url = host_or_url.split("@")[-1]
    if ":" in host_or_url:
        host_or_url = host_or_url.split(":")[0]
    ext = tldextract.extract(host_or_url)
    return ext.registered_domain.lower() if ext.registered_domain else host_or_url.lower().lstrip("www.")

# ----------------------------- Features -----------------------------
def check_domain_age(host):
    try:
        reg = normalize_domain(host)
        w = whois.whois(reg)
        creation_date = w.creation_date

        # Handle lists of dates
        if isinstance(creation_date, list):
            for d in creation_date:
                if isinstance(d, datetime):
                    creation_date = d
                    break
                elif isinstance(d, str):
                    try:
                        creation_date = datetime.strptime(d.split()[0], "%Y-%m-%d")
                        break
                    except:
                        continue
            else:
                return 0

        # Handle string dates
        if isinstance(creation_date, str):
            for fmt in ("%Y-%m-%d", "%d-%b-%Y", "%d.%m.%Y"):
                try:
                    creation_date = datetime.strptime(creation_date.split()[0], fmt)
                    break
                except:
                    continue
            else:
                return 0

        if not isinstance(creation_date, datetime):
            return 0

        age_months = (datetime.now() - creation_date).days // 30
        return 1 if age_months >= 6 else -1
    except:
        return 0

def check_dns_record(host):
    try:
        # Resolve the full host (including subdomain)
        socket.gethostbyname(host)
        return 1
    except:
        return -1

def check_traffic_rank(host, tranco_file="tranco.csv"):
    try:
        reg = normalize_domain(host)
        with open(tranco_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) < 2:
                    continue
                rank = int(parts[0])
                if normalize_domain(parts[1]) == reg:
                    return 1 if rank < 100000 else 0
        return 0  # Unknown domains now return 0 instead of -1
    except:
        return 0

def check_pagerank(value=None):
    return 0

def check_google_index(indexed=True):
    return 1 if indexed else -1

def check_external_links(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        resp = requests.get(url, timeout=7, headers={"User-Agent":"Mozilla/5.0"})
        src_reg = normalize_domain(urlparse(url).netloc)
        regs = set()
        for a in BeautifulSoup(resp.text, "html.parser").find_all('a', href=True):
            href = a['href'].strip()
            if href.startswith(("javascript:", "mailto:", "#")):
                continue
            parsed = urlparse(href)
            if not parsed.netloc:
                continue
            regs.add(normalize_domain(parsed.netloc))
        regs.discard(src_reg)
        n = len(regs)
        return -1 if n == 0 else (0 if n <= 2 else 1)
    except:
        return 0

def load_blacklist(blacklist_file="openphish.csv"):
    bl_set = set()
    try:
        with open(blacklist_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith(("http://","https://")):
                    line = urlparse(line).netloc
                bl_set.add(normalize_domain(line))
    except:
        pass
    return bl_set

def check_blacklists(host, bl_set=None):
    if bl_set is None:
        return 0
    return -1 if normalize_domain(host) in bl_set else 1

# ----------------------------- Single URL -----------------------------
def classify_url(url, tranco_file="tranco.csv", blacklist_file="openphish.csv"):
    bl_set = load_blacklist(blacklist_file)
    url_for_req = url if url.startswith(("http://","https://")) else "http://" + url
    host = urlparse(url_for_req).netloc
    features = {
        "domain_age": check_domain_age(host),
        "dns_record": check_dns_record(host),
        "traffic_rank": check_traffic_rank(host, tranco_file),
        "pagerank": check_pagerank(None),
        "google_index": check_google_index(True),
        "external_links": check_external_links(url_for_req),
        "blacklist": check_blacklists(host, bl_set)
    }
    return features

# ----------------------------- Script -----------------------------
if __name__ == "__main__":
    url = input("Enter a URL: ").strip()
    features = classify_url(url)
    print("\nFeatures Dictionary:")
    print(features)
