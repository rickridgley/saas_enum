import random
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from typing import Tuple, List

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36 Edg/96.0.1054.62",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Safari/537.36",
]


def clean_text_for_search(text: str) -> str:
    """Clean and normalize text for searching."""
    if not text:
        return ""

    text = re.sub(r"\s+", " ", text.strip())
    text = re.sub(r"&[a-zA-Z0-9]+;", " ", text)
    text = re.sub(r"[^\w\s\-.]", " ", text)
    return text.lower()


def extract_contextual_snippets(text: str, search_term: str, context_chars: int = 100) -> List[str]:
    """Extract contextual snippets around search term matches."""
    if not text or not search_term:
        return []

    text_lower = text.lower()
    search_lower = search_term.lower()
    snippets = []
    start = 0
    while True:
        pos = text_lower.find(search_lower, start)
        if pos == -1:
            break
        context_start = max(0, pos - context_chars)
        context_end = min(len(text), pos + len(search_term) + context_chars)
        snippet = text[context_start:context_end].strip()
        snippet = re.sub(r"\s+", " ", snippet)
        if context_start > 0:
            snippet = "..." + snippet
        if context_end < len(text):
            snippet = snippet + "..."
        snippets.append(snippet)
        start = pos + 1
    return snippets[:5]


def analyze_webpage_content(short_name: str, soup: BeautifulSoup, page_text: str, final_url: str, result: dict) -> Tuple[bool, List[str], str]:
    """Analyze webpage content for company name references and context."""
    evidence = []
    url_match_only = False
    content_match = False

    short_name_clean = clean_text_for_search(short_name)
    page_text_clean = clean_text_for_search(page_text)

    parsed_url = urlparse(final_url)
    url_domain = parsed_url.netloc.lower()
    url_path = parsed_url.path.lower()

    # Check for SSO redirect patterns
    sso_patterns = [
        "identity-provider-select",
        "federation/auth/login",
        "saml2",
        "oauth2",
        "openid",
        "login/identity",
        "sso",
        "single-sign-on"
    ]
    
    for pattern in sso_patterns:
        if pattern in final_url.lower():
            evidence.append("SSO redirect detected")
            content_match = True
            break

    if short_name_clean in url_domain:
        url_match_only = True
        if url_domain.startswith(short_name_clean + "."):
            evidence.append("Exact subdomain match in URL")
        else:
            evidence.append("Partial domain match in URL")

    if short_name_clean in url_path:
        url_match_only = True
        evidence.append("Short name found in URL path")

    if soup.title:
        title_text = clean_text_for_search(soup.title.get_text())
        if short_name_clean in title_text:
            content_match = True
            title_words = title_text.split()
            if short_name_clean in title_words:
                evidence.append("Exact word match in page title")
            else:
                evidence.append("Substring match in page title")

    for meta in soup.find_all("meta"):
        for attr in ["content", "name", "property"]:
            meta_value = meta.get(attr, "")
            if meta_value and short_name_clean in clean_text_for_search(meta_value):
                content_match = True
                evidence.append(f"Found in meta {attr}")
                break

    if short_name_clean in page_text_clean:
        content_match = True
        occurrences = page_text_clean.count(short_name_clean)
        evidence.append(f"Found {occurrences} occurrence(s) in body text")

    forms = soup.find_all("form")
    if forms:
        for form in forms:
            action = form.get("action", "")
            if short_name_clean in clean_text_for_search(action):
                content_match = True
                evidence.append("Short name in form action")
                break

    for img in soup.find_all("img"):
        alt_text = img.get("alt", "")
        src = img.get("src", "")
        if short_name_clean in clean_text_for_search(alt_text) or short_name_clean in clean_text_for_search(src):
            content_match = True
            evidence.append("Short name in image/logo reference")
            break

    error_indicators = [
        "page not found",
        "404",
        "error",
        "not available",
        "coming soon",
        "under construction",
        "maintenance",
        "temporarily unavailable",
    ]

    for indicator in error_indicators:
        if indicator in page_text_clean:
            evidence.append(f"Error page detected: {indicator}")
            break

    result["web_check"]["evidence"] = evidence

    if content_match:
        return True, evidence, "strong"
    elif url_match_only:
        return True, evidence, "weak"
    else:
        return False, evidence, "none"


def check_webpage_content(url: str, short_name: str, result: dict, timeout: int = 10) -> Tuple[bool, str, str, str]:
    """Enhanced webpage content checking with improved parsing."""
    try:
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
        final_url = resp.url
        if resp.status_code != 200:
            return False, f"HTTP Error: {resp.status_code}", final_url, "none"

        soup = BeautifulSoup(resp.text, "html.parser")
        page_text = soup.get_text()

        reference_found, evidence, match_strength = analyze_webpage_content(short_name, soup, page_text, final_url, result)

        if soup.title:
            result["web_check"]["page_title"] = soup.title.get_text().strip()

        snippets = extract_contextual_snippets(page_text, short_name)
        result["web_check"]["text_snippets"] = snippets
        result["web_check"]["match_strength"] = match_strength

        if evidence:
            details_str = " | ".join(evidence[:5])
        else:
            details_str = "No specific indicators found"

        result["web_check"]["has_forms"] = bool(soup.find_all("form"))
        result["web_check"]["word_count"] = len(page_text.split())
        result["web_check"]["html_excerpt"] = soup.prettify()[:1500]

        return reference_found, details_str, final_url, match_strength
    except requests.RequestException as e:
        return False, f"Request error: {str(e)}", url, "none"
    except Exception as e:
        return False, f"Error checking webpage: {str(e)}", url, "none"
