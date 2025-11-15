# extract_features.py
import re
import ipaddress
from urllib.parse import urlsplit

def extract_features(url: str) -> dict:
    s = (url or "").strip()
    sp = urlsplit(s)
    scheme = (sp.scheme or "").lower()
    host = (sp.hostname or "").lower()
    domain = host[4:] if host.startswith("www.") else host

    # IsDomainIP
    is_ip = False
    try:
        if domain:
            ipaddress.ip_address(domain)
            is_ip = True
    except Exception:
        is_ip = False

    parts = domain.split(".") if domain else []
    tld = parts[-1] if parts else ""
    no_of_sub = max(len(parts) - 2, 0)

    url_len = len(s)
    letters = sum(c.isalpha() for c in s)
    digits  = sum(c.isdigit() for c in s)
    n_eq    = s.count("=")
    n_q     = s.count("?")
    n_amp   = s.count("&")
    n_other = sum(1 for c in s if not c.isalnum() and c not in {"=","?","&"})
    special_ratio = (sum(1 for c in s if not c.isalnum())/url_len) if url_len else 0

    pct_enc   = len(re.findall(r"%[0-9A-Fa-f]{2}", s))
    hex_chunks= len(re.findall(r"(?<![A-Za-z0-9])[0-9A-Fa-f]{8,}(?![A-Za-z0-9])", s))
    obf_chars = pct_enc + hex_chunks + s.count("@")
    has_obf   = int(obf_chars > 0)
    obf_ratio = (obf_chars/url_len) if url_len else 0

    max_run, cur, prev = 0, 0, None
    for ch in s:
        cur = (cur + 1) if ch == prev else 1
        prev = ch
        if cur > max_run: max_run = cur
    cont_rate = (max_run/url_len) if url_len else 0

    return {
        # URL-only features (numeric)
        "URLLength": url_len,
        "DomainLength": len(domain),
        "IsDomainIP": int(is_ip),
        "TLDLength": len(tld),
        "NoOfSubDomain": no_of_sub,
        "IsHTTPS": int(scheme == "https"),
        "NoOfEqualsInURL": n_eq,
        "NoOfQMarkInURL": n_q,
        "NoOfAmpersandInURL": n_amp,
        "NoOfOtherSpecialCharsInURL": n_other,
        "SpacialCharRatioInURL": special_ratio,
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": (letters/url_len) if url_len else 0.0,
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": (digits/url_len) if url_len else 0.0,
        "HasObfuscation": has_obf,
        "NoOfObfuscatedChar": obf_chars,
        "ObfuscationRatio": obf_ratio,
        "CharContinuationRate": cont_rate,

        # placeholders cho feature thu thập từ nội dung trang
        "URLSimilarityIndex": None, "TLDLegitimateProb": None, "URLCharProb": None,
        "LineOfCode": None, "LargestLineLength": None, "HasTitle": None,
        "DomainTitleMatchScore": None, "URLTitleMatchScore": None, "HasFavicon": None,
        "Robots": None, "IsResponsive": None, "NoOfURLRedirect": None,
        "NoOfSelfRedirect": None, "HasDescription": None, "NoOfPopup": None,
        "NoOfiFrame": None, "HasExternalFormSubmit": None, "HasSocialNet": None,
        "HasSubmitButton": None, "HasHiddenFields": None, "HasPasswordField": None,
        "HasCopyrightInfo": None, "NoOfImage": None, "NoOfCSS": None,
        "NoOfJS": None, "NoOfSelfRef": None, "NoOfEmptyRef": None, "NoOfExternalRef": None,
    }
