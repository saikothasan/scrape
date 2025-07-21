import argparse
import asyncio
import configparser
import json
import logging
import os
import random
import re
import time
from collections import deque
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

import aiohttp
import extruct
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from fake_useragent import UserAgent
from langdetect import detect, LangDetectException
from playwright.async_api import async_playwright, Error as PlaywrightError
from playwright_stealth import stealth_async
from pydantic import BaseModel, ValidationError, HttpUrl
from tldextract import extract

from captcha_solver import CaptchaSolver
from database import Database
from osint_utils import (extract_contacts_and_socials, find_and_process_images,
                         check_interesting_files, get_dns_records, query_wayback_machine,
                         query_shodan, find_and_analyze_js)
from tech_fingerprinter import TechFingerprinter

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
scraper_logger = logging.getLogger('scraper')

load_dotenv()
COMMAND_FILE = 'command.json'

# --- Data Validation Models ---
class ScrapedItem(BaseModel):
    url: HttpUrl
    title: str
    text_content: str
    status_code: int
    language: str | None = None
    structured_data: str | None = None
    technologies: str | None = None
    emails: str | None = None
    social_links: str | None = None
    image_metadata: str | None = None
    interesting_files: str | None = None
    js_analysis: str | None = None

class DomainOsintData(BaseModel):
    domain: str
    dns_records: str
    shodan_info: str

class AdvancedWebScraper:
    def __init__(self, config):
        self.config = config
        self.base_url = config.get('main', 'start_url')
        self.domain = extract(self.base_url).registered_domain
        self.database_file = config.get('main', 'database_file')
        self.max_concurrent_tasks = config.getint('main', 'tasks')
        self.delay_min = config.getfloat('main', 'delay_min', fallback=1.0)
        self.delay_max = config.getfloat('main', 'delay_max', fallback=3.0)
        
        self.url_queue = asyncio.Queue()
        self.visited_urls = set()
        self.lock = asyncio.Lock()
        
        self.user_agent = UserAgent()
        self.robot_parser = self._setup_robot_parser()
        
        self.resume_crawl = config.getboolean('main', 'resume_crawl', fallback=False)
        self.visited_urls_file = f"{self.database_file.rsplit('.', 1)[0]}.visited.json"
        self.queue_file = f"{self.database_file.rsplit('.', 1)[0]}.queue.txt"
        self.status_file = 'status.json'

        self.start_time = time.time()
        self.crawled_count = 0
        self.http_status_codes = {}
        self.recent_logs = deque(maxlen=50)
        self.status = "Initializing"
        self.should_stop = False

        self.db = Database(self.database_file)
        captcha_api_key = config.get('captcha', 'api_key', fallback=None)
        self.captcha_solver = CaptchaSolver(captcha_api_key) if captcha_api_key else None
        self.fingerprinter = TechFingerprinter()

        self.proxies = self._load_proxies()
        self.proxy_index = 0
        self.custom_headers = self._load_custom_headers()

        self._load_crawling_rules()
        self._load_retry_settings()
        self._load_osint_settings()

        self._initialize_state()
        self._setup_log_capture()

    def _load_osint_settings(self):
        self.osint_config = self.config['osint'] if 'osint' in self.config else {}
        self.shodan_api_key = self.osint_config.get('shodan_api_key', fallback=None)

    async def _run_domain_osint(self):
        """Performs OSINT tasks that apply to the entire domain."""
        scraper_logger.info(f"--- Starting Domain-Level OSINT for {self.domain} ---")
        
        dns_records, shodan_info = {}, {}
        
        if self.osint_config.getboolean('dns_recon', False):
            dns_records = await get_dns_records(self.domain)
            
        if self.osint_config.getboolean('shodan_recon', False) and self.shodan_api_key:
            shodan_info = await query_shodan(self.shodan_api_key, self.domain)
        
        osint_data = DomainOsintData(
            domain=self.domain,
            dns_records=json.dumps(dns_records),
            shodan_info=json.dumps(shodan_info)
        )
        await asyncio.to_thread(self.db.insert_osint_data, osint_data)
        scraper_logger.info("--- Domain-Level OSINT Complete ---")

    async def _parse_page(self, url, html_content, status_code, headers, http_session):
        soup = BeautifulSoup(html_content, 'lxml')
        
        # Basic parsing
        exclude_selectors = self.config.get('parser', 'exclude_selectors', fallback='').strip()
        if exclude_selectors:
            for selector in exclude_selectors.split(','):
                for tag in soup.select(selector.strip()):
                    tag.decompose()
        text = soup.get_text(separator=' ', strip=True)
        title = soup.title.string.strip() if soup.title else "No Title"
        
        # Language and Structured Data
        language = detect(text) if self.config.getboolean('parser', 'detect_language', fallback=True) and text else None
        structured_data = extruct.extract(html_content, base_url=url) if self.config.getboolean('parser', 'extract_structured_data', fallback=True) else {}
        
        # OSINT Analysis
        technologies, emails, social_links, image_metadata, interesting_files, js_analysis = {}, {}, {}, {}, {}, {}
        if self.osint_config.getboolean('fingerprint_tech', False):
            technologies = self.fingerprinter.analyze(url, html_content, headers)
        if self.osint_config.getboolean('extract_contacts', False):
            contacts = await extract_contacts_and_socials(html_content, url)
            emails, social_links = contacts['emails'], contacts['social_links']
        if self.osint_config.getboolean('analyze_images', False):
            image_metadata = await find_and_process_images(soup, url, http_session)
        if self.osint_config.getboolean('find_hidden_files', False):
            interesting_files = await check_interesting_files(http_session, url)
        if self.osint_config.getboolean('analyze_js', False):
            js_analysis = await find_and_analyze_js(soup, url, http_session)

        # Save to DB
        try:
            item = ScrapedItem(
                url=url, title=title, text_content=text, status_code=status_code, language=language,
                structured_data=json.dumps({k: v for k, v in structured_data.items() if v}),
                technologies=json.dumps(technologies), emails=json.dumps(emails),
                social_links=json.dumps(social_links), image_metadata=json.dumps(image_metadata),
                interesting_files=json.dumps(interesting_files), js_analysis=json.dumps(js_analysis)
            )
            await asyncio.to_thread(self.db.insert_item, item)
        except ValidationError as e:
            scraper_logger.warning(f"Data validation failed for {url}: {e}")
        
        # Link discovery
        links_to_add = []
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(self.base_url, href).split('#')[0]
            is_valid, reason = self._is_valid_url(full_url)
            if is_valid:
                links_to_add.append(full_url)
            elif reason not in ["Invalid scheme", "External domain"]:
                scraper_logger.debug(f"Skipped URL {full_url}: {reason}")
        
        pagination_links = set()
        if self.pagination_selectors:
            for selector in self.pagination_selectors:
                for link in soup.select(selector):
                    href = link.get('href')
                    if href:
                        full_url = urljoin(self.base_url, href).split('#')[0]
                        if self._is_valid_url(full_url)[0]:
                            pagination_links.add(full_url)
        
        async with self.lock:
            for link_url in pagination_links:
                if link_url not in self.visited_urls:
                    self.visited_urls.add(link_url)
                    await self.url_queue.put(link_url)
            for link_url in links_to_add:
                if link_url not in self.visited_urls:
                    self.visited_urls.add(link_url)
                    await self.url_queue.put(link_url)

    async def _worker(self, browser):
        proxy_config = None
        proxy_str = self._get_proxy()
        if proxy_str:
            proxy_config = {"server": proxy_str}
        
        fingerprint_cfg = self.config['fingerprint']
        locale = fingerprint_cfg.get('locale', fallback=None)
        timezone_id = fingerprint_cfg.get('timezone_id', fallback=None)
        geo_lat = fingerprint_cfg.getfloat('geolocation_lat', fallback=None)
        geo_lon = fingerprint_cfg.getfloat('geolocation_lon', fallback=None)
        geolocation = {'latitude': geo_lat, 'longitude': geo_lon} if geo_lat and geo_lon else None
        
        width, height = random.choice([(1920, 1080), (1366, 768), (1440, 900), (1536, 864)])
        viewport = {'width': width, 'height': height}

        context = await browser.new_context(
            user_agent=self.user_agent.random,
            viewport=viewport,
            locale=locale,
            timezone_id=timezone_id,
            geolocation=geolocation,
            permissions=['geolocation'] if geolocation else [],
            proxy=proxy_config,
            extra_http_headers=self.custom_headers
        )

        if self.config.getboolean('behavior', 'canvas_spoofing', fallback=True):
            await context.add_init_script(path='canvas_spoof.js')

        await stealth_async(context)
        
        last_url = self.base_url
        async with aiohttp.ClientSession(headers={'User-Agent': self.user_agent.random}) as http_session:
            try:
                while not self.should_stop and not (self.status == "Finished" and self.url_queue.empty()):
                    try:
                        url = await asyncio.wait_for(self.url_queue.get(), timeout=1.0)
                    except asyncio.TimeoutError:
                        continue
                    
                    scraper_logger.info(f"Worker {asyncio.current_task().get_name()}: Crawling {url}")
                    html, status, headers = await self._get_page_content(context, url, referer=last_url)
                    
                    async with self.lock:
                        self.http_status_codes[status] = self.http_status_codes.get(status, 0) + 1

                    if html:
                        await self._parse_page(url, html, status, headers, http_session)
                    
                    async with self.lock:
                        self.crawled_count += 1
                    
                    self.url_queue.task_done()
                    last_url = url
                    await asyncio.sleep(random.uniform(self.delay_min, self.delay_max))
            finally:
                await context.close()
    
    async def run(self):
        self.status = "Running"
        if os.path.exists(COMMAND_FILE): os.remove(COMMAND_FILE)
        
        # Run domain-level OSINT once at the start
        await self._run_domain_osint()

        updater_task = asyncio.create_task(self._periodic_updater())
        
        async with aiohttp.ClientSession(headers={'User-Agent': self.user_agent.random}) as http_session:
            if self.osint_config.getboolean('wayback_discovery', False):
                wayback_urls = await query_wayback_machine(http_session, self.domain)
                async with self.lock:
                    for url in wayback_urls:
                        if self._is_valid_url(url)[0] and url not in self.visited_urls:
                            self.visited_urls.add(url)
                            await self.url_queue.put(url)
                scraper_logger.info(f"Added {len(wayback_urls)} URLs from Wayback Machine.")

        await self._parse_sitemap()
            
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            
            if self.config.has_section('login'):
                login_context = await browser.new_context(user_agent=self.user_agent.random)
                await stealth_async(login_context)
                try:
                    await self._login(login_context)
                except Exception as e:
                    scraper_logger.error(f"Aborting due to login failure: {e}")
                    self.should_stop = True
                finally:
                    await login_context.close()

            if not self.should_stop:
                scraper_logger.info(f"Starting crawl of {self.base_url} with {self.max_concurrent_tasks} tasks.")
                tasks = [asyncio.create_task(self._worker(browser), name=f"Worker-{i+1}") for i in range(self.max_concurrent_tasks)]
                
                try:
                    while not self.should_stop:
                        if self.url_queue.empty():
                            await asyncio.sleep(10)
                            if self.url_queue.empty():
                                self.status = "Finished"; break
                        await asyncio.sleep(1)
                except KeyboardInterrupt:
                    self.status = "Stopped"
                
                if self.should_stop: self.status = "Stopped"
                
                scraper_logger.info(f"Scraper {self.status}. Shutting down tasks...")
                for task in tasks: task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
            
            await browser.close()

        updater_task.cancel()
        self.db.close()
        scraper_logger.info("Scraper has shut down.")

    def _load_proxies(self): return []
    def _get_proxy(self): return None
    def _load_custom_headers(self): return {}
    def _load_crawling_rules(self): self.whitelist_patterns, self.blacklist_patterns, self.pagination_selectors = [], [], []
    def _load_retry_settings(self): self.max_retries, self.initial_backoff = 3, 2.0
    def _setup_log_capture(self): pass
    def _initialize_state(self): self.url_queue.put_nowait(self.base_url)
    async def _periodic_updater(self): pass
    def _setup_robot_parser(self): return RobotFileParser()
    async def _parse_sitemap(self): pass
    def _is_valid_url(self, url): return True, "Valid"
    async def _get_page_content(self, context, url, referer=None): return "<html></html>", 200, {}
    async def _human_like_interaction(self, page): pass
    async def _login(self, context): pass
    async def _handle_captcha_if_present(self, page): pass
