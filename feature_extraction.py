import re
from urllib.parse import urlparse, urljoin
import ipaddress
import ssl
import socket
import whois
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import sys




features = {}

shorteners = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", 
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rebrand.ly",
    "shorte.st", "trib.al", "t.ly", "soo.gd", "lnkd.in"
]

def having_ip_address(url):
    # Regex
    _IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    _DECIMAL_INTEGER_RE = re.compile(r"^\d+$")
    _HEX_RE = re.compile(r"^(0x[0-9a-fA-F]+)$")

    def host_from_url(url):
        parsed = urlparse(url)
        netloc = parsed.netloc
        if "@" in netloc:  # remove credentials
            netloc = netloc.split("@", 1)[1]
        return netloc

    def is_ipv4_dotted(host):
        if ":" in host and not host.startswith("["):
            host = host.split(":", 1)[0]
        if _IPV4_RE.match(host):
            parts = host.split(".")
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                return False
        return False

    def is_ipv6_literal(host):
        if host.startswith("["):
            if "]:" in host:
                host = host.split("]:", 1)[0] + "]"
            inside = host.strip("[]")
            try:
                ipaddress.IPv6Address(inside)
                return True
            except:
                return False
        try:
            ipaddress.IPv6Address(host)
            return True
        except:
            return False

    def is_ip_numeric_encoding(host):
        if ":" in host and not host.startswith("["):
            host = host.split(":", 1)[0]
        h = host.lower()
        if _DECIMAL_INTEGER_RE.match(h):
            try:
                val = int(h, 10)
                return 0 <= val <= 0xFFFFFFFF
            except:
                return False
        if _HEX_RE.match(h):
            try:
                val = int(h, 16)
                return 0 <= val <= 0xFFFFFFFF
            except:
                return False
        return False

    def is_ipv4_dotted_hex(host):
        if ":" in host and not host.startswith("["):
            host = host.split(":", 1)[0]
        parts = host.split(".")
        if all(p.lower().startswith("0x") for p in parts if p):
            try:
                nums = [int(p, 16) for p in parts]
                return all(0 <= n <= 255 for n in nums)
            except:
                return False
        return False

    def url_contains_ip(url):
        host = host_from_url(url)
        if not host:
            return (False, None)
        if is_ipv6_literal(host):
            return (True, 'ipv6')
        if is_ipv4_dotted(host):
            return (True, 'ipv4')
        if is_ipv4_dotted_hex(host):
            return (True, 'ipv4_hex')
        if is_ip_numeric_encoding(host):
            return (True, 'numeric')
        return (False, None)

    
    res = url_contains_ip(url)
    if res[0]:
        return 0
    else: 
        return 1

def url_length(url):
    length = len(url)
    if(length <54):
        return 1
    elif length>=54 and length<=75:
        return 0
    else:
        return -1

def is_shortened_url(url):
    # Extract domain name
    domain = urlparse(url).netloc.lower()
    
    # Remove "www." if present
    if domain.startswith("www."):
        domain = domain[4:]
    
    # Check if domain matches any known shortener
    if domain in shorteners:
        return -1
    else:
        return 1

def have_at_symbol(url):
    if "@" in url:
        return -1
    else:
        return 1

def double_slash(url):
    count_double_slashes = url.count("//")
    if count_double_slashes > 1:
        return -1
    elif count_double_slashes == 1:
        return 1
    else:
        return 0

def have_hyphen(url):
    if "-" in url:
        return -1
    else:
        return 1

def check_subdomains(url):
    domain = urlparse(url).netloc.lower()

    # Remove "www."
    if domain.startswith("www."):
        domain = domain[4:]
    
    # Split by dots
    parts = domain.split(".")
    
    # Remove TLD/ccTLD (.com, .org, .ac.uk etc.)
    if len(parts) > 2:
        parts = parts[:-2]   # remove last two (SLD + TLD)
    
    # Count remaining dots
    dots = len(".".join(parts).split(".")) - 1
    
    if dots == 0:
        return 1
    elif dots == 1:
        return 0
    else:
        return -1
    
def check_https_legitimacy(url) :
    """
    Checks a URL's legitimacy based on its HTTPS certificate properties.

    Args:
        url: The full URL to check (e.g., 'https://www.google.com').

    Returns:
        A string classification: 'Legitimate', 'Suspicious', or 'Phishing'.
    """
    # CORRECTED: Added "Google" to the list of trusted issuers.
    TRUSTED_ISSUERS = [
        "GeoTrust", "GoDaddy", "Network Solutions", "Thawte", 
        "Comodo", "Doster", "VeriSign", "DigiCert", "Let's Encrypt",
        "Google", "Amazon", "Sectigo"
    ]

    if not url.lower().startswith('https://'):
        return -1


    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return -1
             

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # CORRECTED: More robust check of the issuer's identity.
        issuer_details = dict(x[0] for x in cert['issuer'])
        issuer_org = issuer_details.get('organizationName', '')
        issuer_cn = issuer_details.get('commonName', '')
        
        # Check if any trusted name appears in the organization OR the common name.
        issuer_full_identity = (issuer_org + issuer_cn).lower()
        is_trusted = any(trusted.lower() in issuer_full_identity for trusted in TRUSTED_ISSUERS)

        issue_date_str = cert['notBefore']
        issue_date = datetime.strptime(issue_date_str, '%b %d %H:%M:%S %Y %Z')
        age_in_years = (datetime.now() - issue_date).days / 365.25

        if is_trusted and age_in_years >= 1:
            return 1
        elif is_trusted and age_in_years<1:
            return 0
        elif not is_trusted:
            return 0
        else:
            # This covers trusted issuers with certs < 1 year old
           return  -1

    except (socket.gaierror, socket.timeout, ssl.SSLCertVerificationError, ConnectionRefusedError, OSError):
        return -1

def check_domain_registration_length(url):
    """
    Checks a domain's registration length, classifying lookup failures
    as 'Suspicious'.
    """
    try:
        domain_name = urlparse(url).netloc
        if not domain_name:
            # An invalid URL format is a strong indicator of an issue.
            return 0

        domain_info = whois.whois(domain_name)
        exp_date = domain_info.expiration_date

        if exp_date is None:
            # CHANGED: Data found, but no expiration date is suspicious.
            return 0

        if isinstance(exp_date, list):
            expiration_date = max(exp_date)
        else:
            expiration_date = exp_date
        
        time_remaining = expiration_date - datetime.now()

        if time_remaining.days <= 365:
            return -1
        else:
            return 1

    except Exception as e:
        # CHANGED: If WHOIS data is not found, classify as suspicious.
        return 0


def check_favicon(url):
    """
    Checks if a webpage's favicon is loaded from an external domain.

    Args:
        url: The full URL of the webpage to check.
    
    Returns:
        A string classification: 'Phishing' or 'Legitimate'.
    """
    try:
        # Get the base domain of the webpage for comparison later
        page_domain = urlparse(url).netloc
        if not page_domain:
            return-1 # Invalid URL

        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, timeout=5, headers=headers)
        response.raise_for_status() # Raise an exception for bad status codes

        # Parse the HTML content
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find the link tag for the favicon. This can have various 'rel' values.
        # We search for any link tag where 'rel' contains 'icon'.
        favicon_link = soup.find('link', rel=lambda r: r and 'icon' in r.lower())

        # If no favicon link is specified in the HTML, the browser defaults to the
        # same domain (/favicon.ico), so it's legitimate according to the rule.
        if not favicon_link:
            return 1


        # Get the href attribute, which contains the favicon's URL
        favicon_href = favicon_link.get('href')
        if not favicon_href:
            return 1
            return None # Empty href is not external

        # The href can be a relative path, so we must join it with the base URL
        # to create a full, absolute URL.
        favicon_full_url = urljoin(url, favicon_href)

        # Get the domain of the favicon
        favicon_domain = urlparse(favicon_full_url).netloc
        
        # Rule: If favicon domain is different from page domain, it's phishing.
        # We use endswith to allow for subdomains (e.g., icons.google.com on google.com)
        if not favicon_domain.endswith(page_domain):
            return -1
        else:
            return 1

    except requests.exceptions.RequestException as e:
        # If the page can't be reached or has an error, it's a red flag.
        return -1
    except Exception as e:
        return 0


def check_non_standard_port(url):
    """
    Checks if a URL uses a non-standard port for web traffic.

    Args:
        url: The URL to check.
    
    Returns:
        A string classification: 'Phishing' or 'Legitimate'.
    """
    try:
        parsed_url = urlparse(url)
        port = parsed_url.port

        # If no port is specified, the browser uses the default (80 or 443),
        # which is legitimate.
        if port is None:
            return 1

        # Standard ports for web traffic are 80 (HTTP) and 443 (HTTPS).
        # If the URL explicitly uses one of these, it's also legitimate.
        if port == 80 or port == 443:
            return 1
        
        # If any other port is explicitly used, it's considered phishing.
        else:
            return -1
            
    except Exception as e:
        # If the URL is malformed or can't be parsed.
        # print(f"Could not parse URL {url}: {e}")
        return 0



def check_http_token_in_domain(url):
    """
    Checks for the presence of 'http' or 'https' in the domain name of a URL.

    Args:
        url: The URL to check.
    
    Returns:
        A string classification: 'Phishing' or 'Legitimate'.
    """
    try:
        # Extract the domain part (netloc) from the URL
        domain = urlparse(url).netloc
        if not domain:
            return 0 # Invalid or empty URL

        # Rule: Check if "http" or "https" is a substring in the domain name.
        # .lower() is used for a case-insensitive match.
        if "http" in domain.lower():
           return -1
        else:
            return 1

    except Exception as e:
        # If the URL is malformed and cannot be parsed.
        return 0

def check_abnormal_url(url):
    """
    Checks if the registrant's identity from WHOIS is reflected in the domain name.

    Args:
        url: The URL to check.

    Returns:
        "Legitimate", "Phishing", or "Error".
    """
    try:
        # 1. Extract the domain name from the URL
        domain = urlparse(url).netloc
        if not domain:
            return 0

        # 2. Perform a WHOIS lookup on the domain
        domain_info = whois.whois(domain)

        # 3. Check if WHOIS data exists. If not, it could be a newly registered domain.
        if not domain_info.org and not domain_info.name:
            # If there's no organization or registrant name, we can't verify identity.
            # This is suspicious for a major website.
            return 0

        # 4. Get the registrant's organization or name
        # Prioritize organization name, fall back to registrant name
        registrant_identity = domain_info.org if domain_info.org else domain_info.name
        
        # Ensure we are working with a string
        if isinstance(registrant_identity, list):
            registrant_identity = registrant_identity[0] # Take the first entry if it's a list
        
        if not isinstance(registrant_identity, str):
            return 0 # Could not determine a valid string identity

        # 5. Clean and compare the identity with the domain name
        # Convert to lowercase for case-insensitive comparison
        registrant_identity = registrant_identity.lower()
        domain = domain.lower()

        # Remove common corporate suffixes like 'llc', 'inc', 'ltd', etc.
        registrant_identity = re.split(r'[,.\s]', registrant_identity)[0]

        # The core logic: Check if the cleaned identity is part of the domain name
        if registrant_identity in domain:
            return 1
        else:
            return -1

    except whois.parser.PywhoisError:
        # This error often means the domain does not exist or has no WHOIS record
        return 0
    except Exception as e:
        return 0

# --- Example Usage ---
# legitimate_url = "https://www.google.com"
# suspicious_url = "http://www.secure-paypal-info.com" # A hypothetical phishing site
# nonexistent_url = "http://thissitedoesnotexist12345.com"

# print(f"Checking '{legitimate_url}': {check_abnormal_url(legitimate_url)}")
# print(f"Checking '{suspicious_url}': {check_abnormal_url(suspicious_url)}")
# print(f"Checking '{nonexistent_url}': {check_abnormal_url(nonexistent_url)}")



# # --- Example Usage ---

# # Legitimate: No "http" token in the domain.
# url_legit = "https://www.paypal.com/signin"

# # Phishing: The example from your image.
# url_phishing1 = "http://https-www-paypal-it-webapps-mpp-home.soft-hair.com/"

# # Phishing: Another common pattern.
# url_phishing2 = "https://login-microsoftonline.com-secure.net/common/oauth2/"

# print(f"'{url_legit}' is classified as: {check_http_token_in_domain(url_legit)}")
# print(f"'{url_phishing1}' is classified as: {check_http_token_in_domain(url_phishing1)}")
# print(f"'{url_phishing2}' is classified as: {check_http_token_in_domain(url_phishing2)}")






# --- Example Usage ---

# # Legitimate: No port specified (defaults to 443)
# url_legit1 = "https://www.google.com"

# # Legitimate: Standard HTTPS port explicitly mentioned
# url_legit2 = "https://www.google.com:443" 

# # Phishing: Using a non-standard port (e.g., a common proxy port)
# url_phishing1 = "http://phishing-site.com:8080"

# # Phishing: Using the port for Remote Desktop Protocol (RDP)
# url_phishing2 = "http://bad-actor-site.net:3389"

# print(f"'{url_legit1}' is classified as: {check_non_standard_port(url_legit1)}")
# print(f"'{url_legit2}' is classified as: {check_non_standard_port(url_legit2)}")
# print(f"'{url_phishing1}' is classified as: {check_non_standard_port(url_phishing1)}")
# print(f"'{url_phishing2}' is classified as: {check_non_standard_port(url_phishing2)}")












# We can see from merriam-webster's source, its favicon is on `https://merriam-webster.com/assets/mw/images/favicon/favicon-32x32.png`.
# The domain `merriam-webster.com` ends with `merriam-webster.com`, so it is correctly marked legitimate.

# Example tests
# print(check_subdomains("http://www.hud.ac.uk/students/"))   # Legitimate
# print(check_subdomains("http://mail.google.com"))           # Suspicious
# print(check_subdomains("http://login.secure.update.mail.google.com"))  # Phishing


# Test
# url = "http://login.secure.update.mail.google.com"
# having_ip_address(url)

# url_length(url)

# is_shortened_url(url)

# have_at_symbol(url)

# double_slash(url)

# have_hyphen(url)

# check_subdomains(url)

# check_https_legitimacy(url)

# check_domain_registration_length(url)

# check_favicon(url)

# check_non_standard_port(url)

# check_http_token_in_domain(url)

# check_abnormal_url(url)

# print(features)

# Examples


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


def check_website_forwarding(url):
    """
    Checks the number of redirects for a given URL to classify it.

    Args:
        url: The URL to check.

    Returns:
        "Legitimate", "Suspicious", "Phishing", or "Error".
    """
    try:
        # Use a HEAD request to be efficient (don't download the whole page)
        # allow_redirects=True is the default, but we're explicit here.
        # Set a timeout to prevent waiting indefinitely.
        response = requests.head(url, allow_redirects=True, timeout=10)

        # The number of redirects is the length of the 'history' list
        redirect_count = len(response.history)

        # print(f"URL '{url}' redirected {redirect_count} time(s).")

        # Apply the rule from the image
        if redirect_count <= 1:
            return 1
        elif 2 <= redirect_count < 4:
            return 0
        else: # redirect_count >= 4
            return -1

    except requests.exceptions.Timeout:
        return 0
    except requests.exceptions.RequestException as e:
        return 0

def check_for_status_bar_spoofing(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all elements with an 'onmouseover' attribute
        elements_with_mouseover = soup.find_all(onmouseover=True)

        for element in elements_with_mouseover:
            mouseover_script = element['onmouseover']
            # Use regex to check for 'window.status' or 'status='
            if re.search(r'window\.status|status\s*=', mouseover_script):
                return -1
        
        return 1
        
    except requests.RequestException as e:
        return 0

def check_for_disabled_right_click(url):
    """
    Checks if a webpage's source code attempts to disable the right-click context menu.

    Args:
        url: The URL of the webpage to check.

    Returns:
        "Phishing" if detection patterns are found, otherwise "Legitimate".
    """
    try:
        response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        
        # Check 1: Search the raw HTML for oncontextmenu="return false"
        if re.search(r'oncontextmenu\s*=\s*["\']return false["\']', response.text, re.IGNORECASE):
            return -1
            
        soup = BeautifulSoup(response.text, 'html.parser')

        # Check 2: Find any tag with an 'oncontextmenu' attribute
        if soup.find(oncontextmenu=True):
            return -1

        # Check 3: Search within all <script> tags for relevant JS patterns
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                # Look for 'addEventListener' for contextmenu or 'event.button == 2'
                if re.search(r'contextmenu|event\.button\s*==\s*2', script.string, re.IGNORECASE):
                    return -1

        return 1

    except requests.RequestException as e:
        return 0

# --- Example Usage ---

# A legitimate site that is unlikely to have this feature
# legit_url = "https://www.wikipedia.org"
# print(f"Checking '{legit_url}': {check_for_disabled_right_click(legit_url)}")

# # A test URL that points to a page known to disable right-click for demonstration
# # (This is a benign test site)
# suspicious_url = "https://www.dynamicdrive.com/dynamicindex9/noright.htm"
# print(f"Checking '{suspicious_url}': {check_for_disabled_right_click(suspicious_url)}")


# --- Example Usage ---

# Example of a legitimate site (likely 0 or 1 redirect)
# url1 = "http://google.com" # Often redirects from http to https

# # Example of a shortened URL (guaranteed redirect)
# url2 = "https://t.co/bYVq6nRGBw" # Twitter's URL shortener

# # Forcing a multi-redirect chain for demonstration
# # httpstat.us is a site for testing HTTP status codes
# # This URL will redirect 4 times: 301 -> 302 -> 307 -> 308 -> 200
# url3 = "https://httpstat.us/301?location=https://httpstat.us/302?location=https://httpstat.us/307?location=https://httpstat.us/308?location=https://httpstat.us/200"


# print(f"Classification for '{url1}': {check_website_forwarding(url1)}\n")
# print(f"Classification for '{url2}': {check_website_forwarding(url2)}\n")
# print(f"Classification for '{url3}': {check_website_forwarding(url3)}\n")

def check_anchor_urls(page_url):
    try:
        # Fetch webpage
        response = requests.get(page_url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
    except Exception as e:
        return 0 

    anchors = soup.find_all("a", href=True)
    if not anchors:
        return 0

    total = len(anchors)
    suspicious = 0

    # Extract domain of the main page
    main_domain = urlparse(page_url).netloc

    for a in anchors:
        href = a.get("href").strip().lower()

        # Case 1: anchor does not link to a webpage
        if href in ["#", "#content", "#skip", "javascript:void(0)"]:
            suspicious += 1
            continue

        # Case 2: different domain
        if href.startswith("http"):
            anchor_domain = urlparse(href).netloc
            if anchor_domain and anchor_domain != main_domain:
                suspicious += 1

    percent = (suspicious / total) * 100

    # Apply rule
    if percent < 31:
        return 1
    elif 31 <= percent <= 67:
        return 0
    else:
        return -1

def get_main_domain(domain):
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])  # e.g. github.com from assets.github.com
    return domain

def request_url_feature(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        domain = urlparse(url).netloc
        main_domain = get_main_domain(domain)
        total = 0
        external = 0

        tags = ['img', 'video', 'audio', 'script', 'link', 'iframe']
        for tag in tags:
            for resource in soup.find_all(tag):
                src = resource.get('src') or resource.get('href')
                if src:
                    total += 1
                    full_url = urljoin(url, src)
                    res_domain = urlparse(full_url).netloc
                    if res_domain:
                        res_main = get_main_domain(res_domain)
                        if res_main != main_domain:
                            external += 1

        if total == 0:
            return 0

        percent_external = (external / total) * 100

        # Classification based on the same rule
        if percent_external < 22:
            return 1
        elif 22 <= percent_external <= 61:
            return 0
        else:
            return -1

        
    except Exception as e:
        return 0
    
def check_meta_script_link_links(url):
    try:
        # Fetch the webpage
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Get the domain of the main page
        main_domain = urlparse(url).netloc

        # Collect all link URLs from <meta>, <script>, and <link> tags
        links = []

        # <meta> tags (look for 'content' attributes with URLs)
        for meta in soup.find_all('meta'):
            content = meta.get('content')
            if content and ('http' in content or 'https' in content):
                links.append(content)

        # <script> tags (look for 'src')
        for script in soup.find_all('script', src=True):
            links.append(script['src'])

        # <link> tags (look for 'href')
        for link in soup.find_all('link', href=True):
            links.append(link['href'])

        total_links = len(links)
        if total_links == 0:
            
            return 0

        # Count how many links are external
        external_links = 0
        for l in links:
            domain = urlparse(l).netloc
            if domain and main_domain not in domain:
                external_links += 1

        # Calculate percentage of external links
        percentage = (external_links / total_links) * 100

        # Apply the rule
        if percentage < 17:
            return 1
        elif 17 <= percentage <= 81:
            return 0
        else:
            return -1

    except Exception as e:
        return 0

def get_domain_name(url):
    """Extracts the domain name from a URL."""
    try:
        # Extracts the 'netloc' part (e.g., www.example.com)
        domain = urlparse(url).netloc
        # Removes 'www.' prefix for consistent comparison
        if domain.startswith('www.'):
            return domain[4:]
        return domain
    except:
        return ""

def analyze_sfh(url):
    """
    Analyzes the Server Form Handlers (SFHs) of all forms on a given webpage.

    Args:
        url (str): The URL of the webpage to analyze.

    Returns:
        A list of classifications for each form found.
    """

    # print(f"\nAnalyzing URL: {url}\n{'='*40}")

    # Get the domain of the base URL for comparison
    base_domain = get_domain_name(url)
    if not base_domain:
        return 0

    try:
        # Fetch the HTML content of the page
        response = requests.get(url, timeout=10)
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

    except requests.exceptions.RequestException as e:
        return 0

    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')

    if not forms:
        return 0

    # Analyze each form found on the page
    for i, form in enumerate(forms, 1):
        action = form.get('action')
        status = ""

        # Rule 1: Check if SFH is empty or "about:blank"
        if not action or action.strip().lower() == "about:blank":
            return -1

        else:
            # Create an absolute URL for the form action
            action_url = urljoin(url, action)
            action_domain = get_domain_name(action_url)

            # Rule 2: Check if SFH refers to a different domain
            if action_domain and action_domain != base_domain:
                return 0

            # Rule 3: Otherwise, it's legitimate
            else:
                return 1


# ----------------------------- Single URL -----------------------------
def classify_url(url, tranco_file="tranco.csv", blacklist_file="openphish.csv"):
    bl_set = load_blacklist(blacklist_file)
    url_for_req = url if url.startswith(("http://","https://")) else "http://" + url
    host = urlparse(url_for_req).netloc
    features = {
        "having_IP_Address":having_ip_address(url),
        "URL_Length":url_length(url),
        "Shortining_Service":is_shortened_url(url),
        "having_At_Symbol":have_at_symbol(url),
        "double_slash_redirecting":double_slash(url),
        "Prefix_Suffix":have_hyphen(url),
        "having_Sub_Domain":check_subdomains(url),
        "SSLfinal_State":check_https_legitimacy(url),
        "Domain_registeration_length":check_domain_registration_length(url),
        "Favicon":check_favicon(url),
        "port":check_non_standard_port(url),
        "HTTPS_token":check_http_token_in_domain(url),
        "Request_URL":request_url_feature(url),
        "URL_of_Anchor":check_anchor_urls(url),
        "Links_in_tags":check_meta_script_link_links(url),
        "SFH":analyze_sfh(url),
        "Submitting_to_email":0,
        "Abnormal_URL":check_abnormal_url(url),
        "Redirect":check_website_forwarding(url),
        "on_mouseover":check_for_status_bar_spoofing(url),
        "RightClick":check_for_disabled_right_click(url),
        "popUpWidnow":0,
        "Iframe":0,
        "age_of_domain": check_domain_age(host),
        "DNSRecord": check_dns_record(host),
        "web_traffic": check_traffic_rank(host, tranco_file),
        "Page_Rank": check_pagerank(None),
        "Google_Index": check_google_index(True),
        "Links_pointing_to_page": check_external_links(url_for_req),
        "Statistical_report": check_blacklists(host, bl_set)
    }
    return features

# ----------------------------- Script -----------------------------
if __name__ == "__main__":
    url = input("Enter a URL: ").strip()
    features = classify_url(url)
    print("\nFeatures Dictionary:")
    print(features)



