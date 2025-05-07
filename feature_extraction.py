import re
import pandas as pd
import numpy as np
import socket
import requests
import whois
import tldextract
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime
import time


def extract_features(url):
    features = {}

    # 1. Have_IP
    ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', url)
    features["Have_IP"] = 1 if ip_match else 0

    # 2. Have_At
    features["Have_At"] = 1 if "@" in url else 0

    # 3. URL_Length
    features["URL_Length"] = len(url)

    # 4. URL_Depth (number of path segments)
    path = urlparse(url).path
    features["URL_Depth"] = path.count('/')

    # 5. Redirection (presence of '//', excluding protocol)
    features["Redirection"] = 1 if url.count('//') > 1 else 0

    # 6. https_Domain (contains https in domain name)
    domain = urlparse(url).netloc
    features["https_Domain"] = 1 if 'https' in domain else 0

    # 7. TinyURL (shorteners)
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|budurl\.com|ping\.fm|post\.ly|just\.as|bkite\.com|snurl\.com|lnkd\.in|db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.ly|u\.bb|yourls\.org|prettylinkpro\.com|viralurl\.com|vur\.me|0rz\.tw|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net"
    features["TinyURL"] = 1 if re.search(shortening_services, url) else 0

    # 8. Prefix/Suffix (using '-' in domain)
    features["Prefix_Suffix"] = 1 if '-' in domain else 0

    # 9. DNS_Record
    try:
        socket.gethostbyname(domain)
        features["DNS_Record"] = 1
    except:
        features["DNS_Record"] = 0

    # 10. Web_Traffic (simulate Alexa check using try/except)
    try:
        response = requests.get(f"https://www.alexa.com/siteinfo/{domain}", timeout=5)
        features["Web_Traffic"] = 1 if response.status_code == 200 else 0
    except:
        features["Web_Traffic"] = 0

    # 11. Domain_Age & 12. Domain_End
    try:
        whois_info = whois.whois(domain)
        creation_date = whois_info.creation_date
        expiration_date = whois_info.expiration_date
        if isinstance(creation_date, list): creation_date = creation_date[0]
        if isinstance(expiration_date, list): expiration_date = expiration_date[0]
        domain_age = (datetime.now() - creation_date).days if creation_date else -1
        domain_end = (expiration_date - datetime.now()).days if expiration_date else -1
        features["Domain_Age"] = domain_age
        features["Domain_End"] = domain_end
    except:
        features["Domain_Age"] = -1
        features["Domain_End"] = -1

    # 13. iFrame
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        features["iFrame"] = 1 if soup.find_all('iframe') else 0
    except:
        features["iFrame"] = 0

    # 14. Mouse_Over (e.g., using JS to hide destination)
    features["Mouse_Over"] = 1 if re.search(r"onmouseover\s*=\s*['\"]?window\.status", url, re.IGNORECASE) else 0

    # 15. Right_Click Disabled
    features["Right_Click"] = 1 if re.search(r"event.button\s*==\s*2", url, re.IGNORECASE) else 0

    # 16. Web_Forwards (check if multiple redirects)
    try:
        session = requests.Session()
        response = session.get(url, timeout=5, allow_redirects=True)
        features["Web_Forwards"] = 1 if len(response.history) > 2 else 0
    except:
        features["Web_Forwards"] = 0

    # 17. Suspicious_Words (sensitive words in URL)
    suspicious_words = ['secure', 'account', 'update', 'login', 'free', 'verify', 'bank',
                        'password', 'bonus', 'lucky']
    features["Suspicious_Words"] = 1 if any(word in url.lower() for word in suspicious_words) else 0

    features["Suspicious_Patterns"] = 0
    suspicious_pattern_list = [
        r'\d{4,}',  # Many numbers in domain
        r'[0-9a-f]{32}',  # MD5-like hash
        r'(secure|login|account|banking|update|verify|signin|security|bonus).*\.',  # Security keywords in wrong place
        r'\.(xyz|tk|ml|ga|cf|gq|pw)$',  # Common abuse TLDs
        r'([a-zA-Z0-9])\1{5,}',  # Character repetition
        r'[^a-zA-Z0-9-.]',  # Special characters in domain
        r'(-[a-zA-Z0-9]+){3,}'  # Excessive hyphens
    ]
    for pattern in suspicious_pattern_list:
        if re.search(pattern, url):
            features["Suspicious_Patterns"] += 1

            # 19. Have_Currency
    features["Have_Currency"] = int(bool(re.search(r'[₦$€£¥₹₽]', url)))

    # 18. GoogleIndex (whether URL is indexed)
    try:
        query = f"https://www.google.com/search?q=site:{url}"
        headers = {'User-Agent': 'Mozilla/5.0'}
        resp = requests.get(query, headers=headers, timeout=5)
        features["GoogleIndex"] = 1 if "did not match any documents" not in resp.text else 0
    except:
        features["GoogleIndex"] = 0

    return features
