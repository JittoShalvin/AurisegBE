# scanner.py
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup


def fetch_url(url: str, timeout: int = 10):
    """
    Fetch a URL and return (response, error_message).
    SSL verification is enabled by default; set verify=False
    only in controlled lab environments if needed.
    """
    try:
        resp = requests.get(url, timeout=timeout, verify=True)
        return resp, None
    except Exception as e:
        return None, str(e)


def extract_links(html: str, base_url: str):
    """Return a list of absolute URLs found in anchor tags."""
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for a in soup.find_all("a", href=True):
        full = urljoin(base_url, a["href"])
        links.add(full)
    return sorted(links)


def extract_forms(html: str, base_url: str):
    """
    Extract forms with method, action and inputs.
    Returns a list of dicts:
    { action, method, inputs: [{name, type}] }
    """
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = (form.get("method") or "GET").upper()
        action_url = urljoin(base_url, action)

        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            ftype = inp.get("type") or inp.name
            if name:
                inputs.append({"name": name, "type": ftype})

        forms.append(
            {
                "action": action_url,
                "method": method,
                "inputs": inputs,
            }
        )
    return forms


def extract_params(links, forms):
    """
    Collect parameter names from:
    - query strings in links
    - form input names
    """
    param_names = set()

    for link in links:
        parsed = urlparse(link)
        query = parse_qs(parsed.query)
        for name in query.keys():
            param_names.add(name)

    for form in forms:
        for inp in form.get("inputs", []):
            param_names.add(inp["name"])

    return sorted(param_names)


def get_cookies_and_headers(response: requests.Response):
    """Return cookies and headers as plain dicts."""
    cookies = {c.name: c.value for c in response.cookies}
    headers = dict(response.headers)
    return cookies, headers


def scan_target(url: str):
    """
    Orchestrator: fetch page + extract links, forms, params, cookies, headers.
    Returns (scan_data_dict, error_message).
    """
    resp, error = fetch_url(url)
    if error:
        return None, error

    html = resp.text
    links = extract_links(html, resp.url)
    forms = extract_forms(html, resp.url)
    params = extract_params(links, forms)
    cookies, headers = get_cookies_and_headers(resp)

    data = {
        "final_url": resp.url,
        "status_code": resp.status_code,
        "links": links,
        "forms": forms,
        "params": params,
        "cookies": cookies,
        "headers": headers,
    }
    return data, None
