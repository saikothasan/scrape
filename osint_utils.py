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

# Regexes
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
SOCIAL_REGEX = {
    'linkedin': re.compile(r'https?://(?:www\.)?linkedin\.com/(?:in|company)/[a-zA-Z0-9_-]+/?'),
    'twitter': re.compile(r'https?://(?:www\.)?twitter\.com/[a-zA-Z0-9_]{1,15}/?'),
    'github': re.compile(r'https?://(?:www\.)?github\.com/[a-zA-Z0-9_-]+/?'),
}
JS_PATH_REGEX = re.compile(r'["\'](/api/|/v[1-9]/|/wp-json/|/graphql)[a-zA-Z0-9/_-]*["\']')
CLOUD_BUCKET_REGEX = {
    's3': re.compile(r'https?://[a-zA-Z0-9.-]+\.s3\.[a-zA-Z0-9.-]+\.amazonaws\.com/[^"\']+'),
    'azure': re.compile(r'https?://[a-zA-Z0-9]+\.blob\.core\.windows\.net/[^"\']+'),
    'gcp': re.compile(r'https?://storage\.googleapis\.com/[a-zA-Z0-9.-]+/[^"\']+')
}

def find_cloud_buckets(html_content):
    """Finds potential cloud storage URLs in HTML."""
    buckets = {}
    for provider, pattern in CLOUD_BUCKET_REGEX.items():
        found = list(set(pattern.findall(html_content)))
        if found:
            buckets[provider] = found
    return buckets

# All other OSINT functions remain the same
async def get_dns_records(domain):
    records = {}
    for r_type in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']:
        try:
            answers = await dns.resolver.resolve_async(domain, r_type)
            records[r_type] = [str(r) for r in answers]
        except Exception:
            records[r_type] = []
    return records

async def query_wayback_machine(session, domain):
    logging.info(f"Querying Wayback Machine for {domain}...")
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=1000"
    try:
        async with session.get(url, timeout=20) as r:
            if r.status == 200:
                data = await r.json()
                return [entry['url'] for entry in data.get('url_list', [])]
    except Exception as e:
        logging.warning(f"Wayback Machine query failed: {e}")
    return []

async def query_shodan(api_key, domain):
    if not api_key: return {"error": "Shodan API key not configured."}
    logging.info(f"Querying Shodan for {domain}...")
    try:
        ip = socket.gethostbyname(domain)
        api = shodan.Shodan(api_key)
        host = api.host(ip)
        return {k: host.get(k) for k in ['ip_str', 'org', 'os', 'ports', 'hostnames', 'location', 'vulns']}
    except Exception as e:
        return {"error": str(e)}

async def analyze_js_file(session, js_url):
    try:
        async with session.get(js_url, timeout=15) as r:
            if r.status == 200:
                return list(set(JS_PATH_REGEX.findall(await r.text())))
    except Exception: pass
    return []

async def find_and_analyze_js(soup, base_url, session):
    urls = [urljoin(base_url, s['src']) for s in soup.find_all('script', src=True)]
    results = await asyncio.gather(*[analyze_js_file(session, url) for url in urls])
    return {url: paths for url, paths in zip(urls, results) if paths}

async def extract_contacts_and_socials(html_content, base_url):
    emails = set(EMAIL_REGEX.findall(html_content))
    socials = {p: list(set(r.findall(html_content))) for p, r in SOCIAL_REGEX.items() if r.search(html_content)}
    return {"emails": list(emails), "social_links": socials}

async def get_image_exif(session, image_url):
    try:
        async with session.get(image_url, timeout=10) as r:
            if r.status != 200: return None
            img = Image.open(BytesIO(await r.read()))
            exif = img._getexif()
            return {TAGS.get(t, t): str(v) for t, v in exif.items()} if exif else None
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
