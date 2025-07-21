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

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
scraper_logger = logging.getLogger('scraper')

load_dotenv()
COMMAND_FILE = 'command.json'

# --- Data Validation Model ---
class ScrapedItem(BaseModel):
    url: HttpUrl
    title: str
    text_content: str
    status_code: int
    language: str | None = None
    structured_data: str | None = None

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

        self.proxies = self._load_proxies()
        self.proxy_index = 0
        self.custom_headers = self._load_custom_headers()

        self._load_crawling_rules()
        self._load_retry_settings()

        self._initialize_state()
        self._setup_log_capture()

    def _load_proxies(self):
        proxy_list_str = self.config.get('proxies', 'proxy_list', fallback='').strip()
        if not proxy_list_str: return []
        proxies = [p.strip() for p in proxy_list_str.split(',')]
        scraper_logger.info(f"Loaded {len(proxies)} proxies.")
        return proxies

    def _get_proxy(self):
        if not self.proxies: return None
        proxy = self.proxies[self.proxy_index]
        self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return proxy

    def _load_custom_headers(self):
        if not self.config.has_section('headers'): return {}
        headers = dict(self.config.items('headers'))
        scraper_logger.info(f"Loaded custom headers: {headers}")
        return headers

    def _load_crawling_rules(self):
        cfg = self.config['crawling']
        self.whitelist_patterns = [re.compile(p.strip()) for p in cfg.get('whitelist_patterns', '').splitlines() if p.strip()]
        self.blacklist_patterns = [re.compile(p.strip()) for p in cfg.get('blacklist_patterns', '').splitlines() if p.strip()]
        self.pagination_selectors = [p.strip() for p in cfg.get('pagination_selectors', '').split(',') if p.strip()]
        scraper_logger.info(f"Loaded {len(self.whitelist_patterns)} whitelist and {len(self.blacklist_patterns)} blacklist patterns.")
        scraper_logger.info(f"Loaded pagination selectors: {self.pagination_selectors}")

    def _load_retry_settings(self):
        cfg = self.config['retries']
        self.max_retries = cfg.getint('max_retries', 3)
        self.initial_backoff = cfg.getfloat('initial_backoff_seconds', 2.0)
        scraper_logger.info(f"Retry settings: max_retries={self.max_retries}, initial_backoff={self.initial_backoff}s")

    def _setup_log_capture(self):
        class DequeLogHandler(logging.Handler):
            def __init__(self, deque_instance):
                super().__init__()
                self.deque = deque_instance
            def emit(self, record):
                self.deque.append(self.format(record))
        
        deque_handler = DequeLogHandler(self.recent_logs)
        deque_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
        scraper_logger.addHandler(deque_handler)

    def _initialize_state(self):
        if self.resume_crawl and os.path.exists(self.visited_urls_file):
            scraper_logger.info("Resuming crawl from saved state.")
            self._load_state()
        else:
            scraper_logger.info("Starting a fresh crawl.")
            self.url_queue.put_nowait(self.base_url)
            self.visited_urls.add(self.base_url)

    def _load_state(self):
        try:
            with open(self.visited_urls_file, 'r') as f: self.visited_urls = set(json.load(f))
            with open(self.queue_file, 'r') as f:
                urls_in_queue = [url.strip() for url in f]
                for url in urls_in_queue: self.url_queue.put_nowait(url)
            self.crawled_count = len(self.visited_urls) - len(urls_in_queue)
            scraper_logger.info(f"Loaded {len(self.visited_urls)} visited URLs and {self.url_queue.qsize()} URLs in queue.")
        except (FileNotFoundError, json.JSONDecodeError, IOError) as e:
            scraper_logger.error(f"Could not load state files, starting fresh: {e}")
            self.visited_urls = {self.base_url}; self.url_queue.put_nowait(self.base_url)

    async def _save_state(self):
        async with self.lock:
            scraper_logger.info("Saving crawl state...")
            try:
                with open(self.visited_urls_file, 'w') as f: json.dump(list(self.visited_urls), f)
                with open(self.queue_file, 'w') as f:
                    for url in list(self.url_queue._queue): f.write(f"{url}\n")
                scraper_logger.info(f"State saved. Visited: {len(self.visited_urls)}, Queue: {self.url_queue.qsize()}")
            except IOError as e:
                scraper_logger.error(f"Failed to save state: {e}")

    async def _update_status_file(self):
        elapsed_seconds = time.time() - self.start_time
        crawl_rate = (self.crawled_count / elapsed_seconds * 60) if elapsed_seconds > 1 else 0
        etr_seconds = (self.url_queue.qsize() / crawl_rate * 60) if crawl_rate > 0 else 0
        etr_str = time.strftime('%H:%M:%S', time.gmtime(etr_seconds)) if etr_seconds > 0 else "N/A"

        status_data = {
            "status": self.status, "crawled_count": self.crawled_count,
            "queue_size": self.url_queue.qsize(),
            "elapsed_time": time.strftime('%H:%M:%S', time.gmtime(elapsed_seconds)),
            "crawl_rate": crawl_rate,
            "estimated_time_remaining": etr_str,
            "http_status_codes": self.http_status_codes,
            "recent_logs": list(self.recent_logs)
        }
        try:
            await asyncio.to_thread(json.dump, status_data, open(self.status_file, 'w'))
        except IOError as e:
            scraper_logger.error(f"Could not write to status file: {e}")

    async def _check_for_commands(self):
        if os.path.exists(COMMAND_FILE):
            try:
                with open(COMMAND_FILE, 'r') as f:
                    if json.load(f).get('command') == 'stop':
                        scraper_logger.warning("Stop command received from dashboard.")
                        self.should_stop = True
                os.remove(COMMAND_FILE)
            except (IOError, json.JSONDecodeError) as e:
                scraper_logger.error(f"Error processing command file: {e}")

    async def _periodic_updater(self):
        while not self.should_stop:
            await self._update_status_file()
            await self._check_for_commands()
            if self.resume_crawl: await self._save_state()
            await asyncio.sleep(5)

    def _setup_robot_parser(self):
        parser = RobotFileParser(urljoin(self.base_url, 'robots.txt'))
        try:
            parser.read()
            scraper_logger.info("Successfully read robots.txt")
        except Exception as e:
            scraper_logger.warning(f"Could not read or parse robots.txt: {e}")
        return parser

    async def _parse_sitemap(self):
        if not self.config.getboolean('sitemap', 'enabled', fallback=True):
            scraper_logger.info("Sitemap parsing is disabled in config.")
            return
        
        sitemap_url = urljoin(self.base_url, 'sitemap.xml')
        scraper_logger.info(f"Attempting to parse sitemap: {sitemap_url}")
        
        try:
            response = await asyncio.to_thread(requests.get, sitemap_url, timeout=10)
            if response.status_code != 200:
                scraper_logger.warning(f"Sitemap not found at {sitemap_url} (status: {response.status_code})")
                return

            soup = BeautifulSoup(response.content, 'xml')
            urls = [loc.text for loc in soup.find_all('loc')]
            
            if any('sitemap' in url for url in urls):
                scraper_logger.info("Sitemap index found, parsing sub-sitemaps.")
                all_urls = []
                for sub_sitemap_url in urls:
                    sub_response = await asyncio.to_thread(requests.get, sub_sitemap_url, timeout=10)
                    if sub_response.status_code == 200:
                        sub_soup = BeautifulSoup(sub_response.content, 'xml')
                        all_urls.extend([loc.text for loc in sub_soup.find_all('loc')])
                urls = all_urls

            added_count = 0
            async with self.lock:
                for url in urls:
                    if self._is_valid_url(url) and url not in self.visited_urls:
                        self.visited_urls.add(url)
                        await self.url_queue.put(url)
                        added_count += 1
            scraper_logger.info(f"Added {added_count} new URLs from sitemap(s) to the queue.")

        except Exception as e:
            scraper_logger.error(f"Failed to parse sitemap: {e}")

    def _is_valid_url(self, url):
        parsed_url = urlparse(url)
        if parsed_url.scheme not in ['http', 'https']: return False, "Invalid scheme"
        if extract(url).registered_domain != self.domain: return False, "External domain"
        if any(url.lower().endswith(ext) for ext in ['.png', '.jpg', '.pdf', '.zip', '.css', '.js']): return False, "Filtered file type"
        
        if self.blacklist_patterns and any(p.search(url) for p in self.blacklist_patterns):
            return False, "Blacklisted pattern"
        if self.whitelist_patterns and not any(p.search(url) for p in self.whitelist_patterns):
            return False, "Not in whitelist"
        if not self.robot_parser.can_fetch(self.user_agent.random, url):
            return False, "Disallowed by robots.txt"
            
        return True, "Valid"

    async def _get_page_content(self, context, url, referer=None):
        for attempt in range(self.max_retries + 1):
            page = None
            response = None
            try:
                page = await context.new_page()
                response = await page.goto(url, wait_until="domcontentloaded", timeout=20000, referer=referer)
                
                await self._human_like_interaction(page)
                
                ajax_wait_selector = self.config.get('main', 'ajax_wait_selector', fallback=None)
                if ajax_wait_selector:
                    await page.wait_for_selector(ajax_wait_selector, state="visible", timeout=10000)

                await self._handle_captcha_if_present(page)
                content = await page.content()
                status = response.status if response else 0
                return content, status
            except PlaywrightError as e:
                scraper_logger.warning(f"Attempt {attempt + 1}/{self.max_retries + 1} failed for {url}: {e}")
                if attempt < self.max_retries:
                    backoff_time = self.initial_backoff * (2 ** attempt) + random.uniform(0, 1)
                    scraper_logger.info(f"Retrying in {backoff_time:.2f} seconds...")
                    await asyncio.sleep(backoff_time)
                else:
                    scraper_logger.error(f"All retries failed for {url}.")
                    return None, response.status if response else 0
            finally:
                if page: await page.close()
        return None, 0

    async def _parse_page(self, url, html_content, status_code):
        soup = BeautifulSoup(html_content, 'lxml')
        
        exclude_selectors = self.config.get('parser', 'exclude_selectors', fallback='').strip()
        if exclude_selectors:
            for selector in exclude_selectors.split(','):
                for tag in soup.select(selector.strip()):
                    tag.decompose()

        text = soup.get_text(separator=' ', strip=True)
        title = soup.title.string.strip() if soup.title else "No Title"
        
        language = None
        if self.config.getboolean('parser', 'detect_language', fallback=True) and text:
            try:
                language = detect(text)
            except LangDetectException:
                language = 'unknown'

        structured_data_json = None
        if self.config.getboolean('parser', 'extract_structured_data', fallback=True):
            try:
                structured_data = extruct.extract(html_content, base_url=url)
                filtered_data = {k: v for k, v in structured_data.items() if k in ['json-ld', 'opengraph'] and v}
                if filtered_data:
                    structured_data_json = json.dumps(filtered_data)
            except Exception as e:
                scraper_logger.warning(f"Could not extract structured data from {url}: {e}")

        try:
            item = ScrapedItem(
                url=url, title=title, text_content=text, status_code=status_code,
                language=language, structured_data=structured_data_json
            )
            await asyncio.to_thread(self.db.insert_item, item)
        except ValidationError as e:
            scraper_logger.warning(f"Data validation failed for {url}: {e}")
        
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
        try:
            while not self.should_stop and not (self.status == "Finished" and self.url_queue.empty()):
                try:
                    url = await asyncio.wait_for(self.url_queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                
                scraper_logger.info(f"Worker {asyncio.current_task().get_name()}: Crawling {url}")
                html, status = await self._get_page_content(context, url, referer=last_url)
                
                async with self.lock:
                    self.http_status_codes[status] = self.http_status_codes.get(status, 0) + 1

                if html:
                    await self._parse_page(url, html, status)
                
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
        
        updater_task = asyncio.create_task(self._periodic_updater())
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
                tasks = []
                for i in range(self.max_concurrent_tasks):
                    task = asyncio.create_task(self._worker(browser), name=f"Worker-{i+1}")
                    tasks.append(task)
                
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
        await self._update_status_file()
        if self.resume_crawl: await self._save_state()
        
        self.db.close()
        scraper_logger.info("Scraper has shut down.")

def load_config(args):
    config = configparser.ConfigParser()
    config.read(args.config)
    if 'credentials' not in config: config.add_section('credentials')
    config.set('credentials', 'username', os.getenv('SCRAPER_USERNAME', config.get('credentials', 'username', fallback=None)))
    config.set('credentials', 'password', os.getenv('SCRAPER_PASSWORD', config.get('credentials', 'password', fallback=None)))
    if 'captcha' not in config: config.add_section('captcha')
    config.set('captcha', 'api_key', os.getenv('CAPTCHA_API_KEY', config.get('captcha', 'api_key', fallback=None)))
    if 'main' not in config: config.add_section('main')
    if args.url: config.set('main', 'start_url', args.url)
    if args.database: config.set('main', 'database_file', args.database)
    if args.tasks: config.set('main', 'tasks', str(args.tasks))
    return config

async def main():
    parser = argparse.ArgumentParser(description="Professional Web Scraper")
    parser.add_argument('--config', default='config.ini', help="Path to the configuration file.")
    parser.add_argument('--url', help="Override the start_url in the config file.")
    parser.add_argument('--database', help="Override the database_file in the config file.")
    parser.add_argument('--tasks', type=int, help="Override the number of tasks in the config file.")
    args = parser.parse_args()
    config = load_config(args)
    scraper = AdvancedWebScraper(config)
    await scraper.run()

if __name__ == "__main__":
    asyncio.run(main())
