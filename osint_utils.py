import asyncio
import logging
import re
import socket
from io import BytesIO
from urllib.parse import urljoin

import aiohttp
import dns.resolver
import shodan
from PIL import Image
from PIL.ExifTags import TAGS

# Regex for finding email addresses
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

# Regex for finding social media links
SOCIAL_REGEX = {
    'linkedin': re.compile(r'https?://(?:www\.)?linkedin\.com/(?:in|company)/[a-zA-Z0-9_-]+/?'),
    'twitter': re.compile(r'https?://(?:www\.)?twitter\.com/[a-zA-Z0-9_]{1,15}/?'),
    'github': re.compile(r'https?://(?:www\.)?github\.com/[a-zA-Z0-9_-]+/?'),
    'facebook': re.compile(r'https?://(?:www\.)?facebook\.com/[a-zA-Z0-9._-]+/?'),
}

# Regex for finding API paths in JS files
JS_PATH_REGEX = re.compile(r'["\'](/api/|/v[1-9]/|/wp-json/|/graphql)[a-zA-Z0-9/_-]*["\']')

async def get_dns_records(domain):
    """Fetches common DNS records for a domain."""
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
    resolver = dns.resolver.Resolver()
    for record_type in record_types:
        try:
            answers = await resolver.resolve_async(domain, record_type)
            records[record_type] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            records[record_type] = []
        except Exception as e:
            logging.warning(f"DNS query for {record_type} failed for {domain}: {e}")
            records[record_type] = []
    return records

async def query_wayback_machine(session, domain):
    """Fetches known URLs from the Wayback Machine via AlienVault's OTX."""
    logging.info(f"Querying Wayback Machine for {domain}...")
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=1000"
    try:
        async with session.get(url, timeout=20) as response:
            if response.status == 200:
                data = await response.json()
                return [entry['url'] for entry in data.get('url_list', [])]
    except Exception as e:
        logging.warning(f"Wayback Machine query failed: {e}")
    return []

async def query_shodan(api_key, domain):
    """Queries Shodan for information about the domain's IP address."""
    if not api_key:
        return {"error": "Shodan API key not configured."}
    logging.info(f"Querying Shodan for {domain}...")
    try:
        ip_address = socket.gethostbyname(domain)
        api = shodan.Shodan(api_key)
        host_info = api.host(ip_address)
        return {
            "ip": host_info.get('ip_str'),
            "organization": host_info.get('org'),
            "os": host_info.get('os'),
            "ports": host_info.get('ports'),
            "hostnames": host_info.get('hostnames'),
            "location": {
                "city": host_info.get('city'),
                "country": host_info.get('country_name'),
            },
            "vulnerabilities": host_info.get('vulns', [])
        }
    except shodan.APIError as e:
        logging.error(f"Shodan API error: {e}")
        return {"error": str(e)}
    except Exception as e:
        logging.error(f"Shodan query failed: {e}")
        return {"error": "Failed to resolve domain or query Shodan."}

async def analyze_js_file(session, js_url):
    """Downloads a JS file and scans for interesting paths."""
    try:
        async with session.get(js_url, timeout=15) as response:
            if response.status == 200:
                content = await response.text()
                return list(set(JS_PATH_REGEX.findall(content)))
    except Exception as e:
        logging.debug(f"Failed to analyze JS file {js_url}: {e}")
    return []

async def find_and_analyze_js(soup, base_url, session):
    """Finds all JS files on a page and analyzes them."""
    js_files = [urljoin(base_url, script['src']) for script in soup.find_all('script', src=True)]
    analysis_results = {}
    
    tasks = [analyze_js_file(session, url) for url in js_files]
    results = await asyncio.gather(*tasks)
    
    for url, paths in zip(js_files, results):
        if paths:
            analysis_results[url] = paths
            
    return analysis_results

# Other functions (extract_contacts_and_socials, get_image_exif, etc.) remain the same
async def extract_contacts_and_socials(html_content, base_url):
    emails = set(EMAIL_REGEX.findall(html_content))
    social_links = {p: list(set(r.findall(html_content))) for p, r in SOCIAL_REGEX.items() if r.search(html_content)}
    return {"emails": list(emails), "social_links": social_links}

async def get_image_exif(session, image_url):
    try:
        async with session.get(image_url, timeout=10) as response:
            if response.status != 200: return None
            image = Image.open(BytesIO(await response.read()))
            exif_data = image._getexif()
            if not exif_data: return None
            return {TAGS.get(tag_id, tag_id): str(value) for tag_id, value in exif_data.items()}
    except Exception: return None

async def find_and_process_images(soup, base_url, session):
    urls = [urljoin(base_url, img['src']) for img in soup.find_all('img', src=True)][:5]
    results = await asyncio.gather(*[get_image_exif(session, url) for url in urls])
    return {url: exif for url, exif in zip(urls, results) if exif}

async def check_interesting_files(session, base_url):
    found = {}
    for f in ['security.txt', 'humans.txt']:
        url = urljoin(base_url, f"/.well-known/{f}" if f == 'security.txt' else f"/{f}")
        try:
            async with session.head(url, timeout=5, allow_redirects=True) as r:
                if r.status == 200: found[f] = str(r.url)
        except Exception: pass
    return found
