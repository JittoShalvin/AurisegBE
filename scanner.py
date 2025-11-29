# backend/scanner.py
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup




def extract_links(html: str, base_url: str):
    soup = BeautifulSoup(html, "html.parser")
    links = set()

    for a in soup.find_all("a", href=True):
        full = urljoin(base_url, a["href"])
        links.add(full)

    return list(links)


def extract_forms(html: str, base_url: str):
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

        forms.append({
            "action": action_url,
            "method": method,
            "inputs": inputs
        })

    return forms


def extract_params(links, forms):
    params = set()

    for link in links:
        parsed = urlparse(link)
        query = parse_qs(parsed.query)
        for name in query.keys():
            params.add(name)

    for form in forms:
        for i in form["inputs"]:
            params.add(i["name"])

    return sorted(params)


def get_cookies_and_headers(response):
    cookies = {c.name: c.value for c in response.cookies}
    headers = dict(response.headers)
    return cookies, headers


def scan_target(url: str):
    resp, err = fetch_url(url)
    if err:
        return None, err

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
        "headers": headers
    }

    return data, None
