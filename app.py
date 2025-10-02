#!/usr/bin/env python3
"""
generate_csp.py

A script that spiders a target website, identifies external resource loads,
categorizes them into CSP directives, and generates CSP headers in both
IIS web.config and JSON formats.

Author: Ryan Wilson 
"""

import argparse
import requests
import re
import os
import json
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from collections import defaultdict
from time import sleep

visited = set()

def fetch_html(url):
    """
    Fetch the HTML content of a given URL.

    Args:
        url (str): Target URL to fetch.

    Returns:
        str or None: HTML content if successful, else None.
    """
    try:
        response = requests.get(url, timeout=15)
        if response.ok:
            return response.text
    except Exception as e:
        print(f"[!] Failed to fetch {url}: {e}")
    return None

def extract_internal_links(html, base_url, domain):
    """
    Extract all internal links from HTML that belong to the same domain.

    Args:
        html (str): HTML content.
        base_url (str): Original page URL.
        domain (str): Base domain to match against.

    Returns:
        set: A set of internal URLs found.
    """
    internal_links = set()
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe']):
        attr = 'href' if tag.name in ['a', 'link'] else 'src'
        link = tag.get(attr)
        if link:
            full_url = urljoin(base_url, link)
            parsed = urlparse(full_url)
            if parsed.netloc == domain:
                cleaned = parsed.scheme + "://" + parsed.netloc + parsed.path
                internal_links.add(cleaned)
    return internal_links

def extract_external_urls(html, base_domain):
    """
    Identify external resource URLs from HTML that do not belong to base domain.

    Args:
        html (str): HTML content.
        base_domain (str): Domain to exclude.

    Returns:
        set: External URLs found in the HTML.
    """
    urls = set()
    for match in re.findall(r'https?://[^\s"\'<>]+', html):
        parsed = urlparse(match)
        if parsed.netloc and base_domain not in parsed.netloc:
            urls.add(match)
    return urls

def categorize_resource(url):
    """
    Determine which CSP directive an external URL belongs to.

    Args:
        url (str): URL to classify.

    Returns:
        str: CSP directive name (e.g., 'script-src').
    """
    if re.search(r'\.js(\?|$)', url):
        return 'script-src'
    elif re.search(r'\.css(\?|$)', url):
        return 'style-src'
    elif re.search(r'\.(woff2?|ttf|otf)(\?|$)', url):
        return 'font-src'
    elif re.search(r'\.(jpg|jpeg|png|gif|svg|webp)(\?|$)', url):
        return 'img-src'
    elif re.search(r'\.json(\?|$)', url):
        return 'connect-src'
    else:
        return 'default-src'

def build_csp(urls):
    """
    Build a dictionary of CSP directives based on categorized URLs.

    Args:
        urls (set): Set of external URLs.

    Returns:
        dict: Dictionary of CSP directives and their associated domains.
    """
    csp = defaultdict(set)
    for url in urls:
        directive = categorize_resource(url)
        domain = urlparse(url).netloc
        csp[directive].add(domain)
    for directive in csp:
        csp[directive].add("'self'")
    return {k: sorted(list(v)) for k, v in csp.items()}

def write_json(csp_dict, filename):
    """
    Write the CSP policy to a JSON file.

    Args:
        csp_dict (dict): CSP dictionary.
        filename (str): Output path for JSON file.
    """
    with open(filename, 'w') as f:
        json.dump(csp_dict, f, indent=2)

def write_web_config(csp_dict, filename):
    """
    Write the CSP header in IIS-compatible web.config format.

    Args:
        csp_dict (dict): CSP policy.
        filename (str): Output path for web.config file.
    """
    csp_string = ' '.join(f"{k} {' '.join(v)};" for k, v in csp_dict.items())
    config = f"""<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
        <add name="Content-Security-Policy" value="{csp_string}" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>"""
    with open(filename, 'w') as f:
        f.write(config)

def spider_and_audit(base_url, max_pages=25):
    """
    Spider the target website and collect external resource loads.

    Args:
        base_url (str): URL to start scanning from.
        max_pages (int): Max number of internal pages to spider.

    Returns:
        dict: Final categorized CSP policy.
    """
    parsed = urlparse(base_url)
    domain = parsed.netloc
    queue = [base_url]
    external_urls = set()

    print(f"[+] Starting scan on: {base_url} (max {max_pages} pages)")

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        print(f"  - Fetching: {url}")
        html = fetch_html(url)
        if not html:
            continue
        external = extract_external_urls(html, domain)
        internal = extract_internal_links(html, base_url, domain)
        external_urls.update(external)
        queue.extend(internal - visited)
        sleep(0.5)  # Polite delay to avoid hammering the server

    return build_csp(external_urls)

def main():
    """
    Parse arguments and launch the CSP generator.
    """
    parser = argparse.ArgumentParser(description="Generate a CSP policy from scanned URLs")
    parser.add_argument("--url", required=True, help="Base URL to scan (e.g., https://example.com)")
    parser.add_argument("--output-dir", default="./csp_results", help="Directory to store results")
    parser.add_argument("--max-pages", type=int, default=25, help="Max pages to spider (default: 25)")
    args = parser.parse_args()

    csp = spider_and_audit(args.url, args.max_pages)
    os.makedirs(args.output_dir, exist_ok=True)
    json_path = os.path.join(args.output_dir, "csp_policy.json")
    webconfig_path = os.path.join(args.output_dir, "web.config")

    write_json(csp, json_path)
    write_web_config(csp, webconfig_path)

    print(f"\n[✓] CSP policy written to:")
    print(f"    - {json_path}")
    print(f"    - {webconfig_path}")
    print("\n[✓] Domains by directive:")
    for k, v in csp.items():
        print(f"  {k}: {', '.join(v)}")

if __name__ == "__main__":
    main()

