# Advanced Web Scraper & OSINT Framework

This is a professional-grade, enterprise-level framework for web scraping, Open Source Intelligence (OSINT) gathering, and security reconnaissance. It combines a powerful, stealthy web crawler with a suite of tools used by cybersecurity professionals to provide a comprehensive analysis of any web target.

The framework is built around a resilient, asynchronous Python core and features a real-time web dashboard for monitoring and data analysis.

![Dashboard Screenshot](https://user-images.githubusercontent.com/12345/placeholder.png) <!-- Placeholder for a real screenshot -->

---

## Key Features

The framework is divided into several key functional areas:

### 🕷️ Core Scraping & Crawling
- **Recursive Crawling**: Discovers and crawls all internal links on a website.
- **JavaScript Rendering**: Uses Playwright to handle dynamic, JS-heavy sites and Single-Page Applications (SPAs).
- **Comprehensive Text Extraction**: Parses and cleans all readable text from pages, excluding specified elements like navs and footers.
- **Sitemap & Wayback Machine Discovery**: Accelerates URL discovery by parsing `sitemap.xml` and querying the Internet Archive.
- **Resilient State Management**: Can pause and resume crawls, saving queue and visited URLs to disk.

### 🛡️ Anti-Detection & Stealth
- **User-Agent Rotation**: Uses a vast list of real-world User-Agents for every request.
- **Proxy Rotation**: Supports a list of proxies to distribute traffic.
- **Human-like Behavior**: Simulates random delays, mouse movements, and scrolling to mimic a real user.
- **Canvas Fingerprint Spoofing**: Injects a script to modify canvas rendering, a common vector for browser fingerprinting.
- **Playwright-Stealth Integration**: Applies various patches to the headless browser to avoid detection.

### 🕵️ Open Source Intelligence (OSINT)
- **Technology Fingerprinting**: Identifies the target's tech stack (CMS, frameworks, analytics) using Wappalyzer.
- **Contact & Social Media Scraping**: Extracts email addresses and social media links from page content.
- **Image EXIF Analysis**: Downloads images and extracts metadata (geolocation, camera info, etc.).
- **Hidden File Discovery**: Checks for common sensitive files like `security.txt` and `humans.txt`.
- **DNS Reconnaissance**: Fetches `A`, `MX`, `NS`, and `TXT` records to map domain infrastructure.
- **Shodan Integration**: Queries Shodan's database for server information, open ports, and known vulnerabilities.
- **Cloud Asset Discovery**: Scans for publicly exposed S3 buckets, Azure Blobs, and GCP Storage URLs.

### 🎯 Active Reconnaissance
- **Subdomain Enumeration**: Performs DNS brute-forcing with a wordlist to find hidden subdomains.
- **Directory & File Brute-Forcing**: Searches for unlinked content like admin panels, backups, and API endpoints.
- **URL Parameter Analysis**: Discovers and catalogs all URL parameters, providing a target list for security testing (e.g., for SQLi, XSS).

### 📊 Dashboard & Reporting
- **Real-Time Monitoring**: A Flask-based web dashboard to monitor status, crawl rate, logs, and more.
- **Interactive Data Tables**: Search, sort, and paginate through all scraped data.
- **Detailed OSINT Views**: Dedicated panels for viewing DNS records, Shodan data, and reconnaissance findings.
- **Customizable CSV Export**: Export selected data columns to a CSV file for external analysis.

---

## Architecture

- **Backend**: Asynchronous Python application using `asyncio` and `Playwright` for crawling.
- **Web Dashboard**: `Flask` server providing a REST API and serving a Bootstrap 5 frontend.
- **Database**: `SQLite` for robust data storage of scraped content, OSINT findings, and recon results.
- **Configuration**: Managed through a comprehensive `config.ini` file and a `.env` file for secrets.

---

## Setup and Installation

**Prerequisites**: Python 3.10+

1.  **Set up a Virtual Environment** (Recommended):
    \`\`\`bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    \`\`\`

2.  **Install Dependencies**:
    \`\`\`bash
    pip install -r requirements.txt
    \`\`\`

3.  **Install Playwright Browsers**:
    This is a one-time setup to download the necessary browser binaries.
    \`\`\`bash
    playwright install
    \`\`\`

4.  **Configure the Scraper**:
    - Rename `config.ini.template` to `config.ini`.
    - Open `config.ini` and set the `start_url` under the `[main]` section to your target website.
    - Review other settings, especially the wordlist paths in the `[recon]` section.

5.  **Set up Environment Variables**:
    - Rename `.env.template` to `.env`.
    - Open `.env` and add your API keys and credentials. This is the secure way to handle secrets.
    ```dotenv
    # For 2Captcha service
    CAPTCHA_API_KEY="your_2captcha_api_key"
    # For Shodan integration
    SHODAN_API_KEY="your_shodan_api_key"
    # For websites requiring login
    SCRAPER_USERNAME="your_login_username"
    SCRAPER_PASSWORD="your_login_password"
    \`\`\`

---

## Usage

The framework consists of two main components: the scraper and the dashboard. They should be run in separate terminals.

1.  **Run the Scraper**:
    This will start the crawling and reconnaissance process based on your `config.ini`.
    \`\`\`bash
    python scraper.py
    \`\`\`

2.  **Run the Dashboard**:
    This will start the web server for monitoring the scraper's progress.
    \`\`\`bash
    python dashboard.py
    \`\`\`
    Navigate to `http://127.0.0.1:5000` in your web browser to view the dashboard.

---

## Configuration (`config.ini`)

The `config.ini` file is the primary control center for the scraper.

| Section      | Key                    | Description                                                              |
|--------------|------------------------|--------------------------------------------------------------------------|
| **[main]**   | `start_url`            | The initial URL to begin the crawl.                                      |
|              | `database_file`        | Path to the SQLite database file.                                        |
|              | `tasks`                | Number of concurrent browser instances to run.                           |
|              | `delay_min`/`delay_max`| Random delay range (in seconds) between requests.                        |
|              | `resume_crawl`         | `true` to resume a stopped crawl, `false` to start fresh.                |
| **[osint]**  | `*_recon`/`*_discovery`| `true`/`false` toggles for various OSINT modules.                        |
|              | `shodan_api_key`       | Your Shodan API key (can also be set in `.env`).                         |
| **[recon]**  | `*_enum`/`*_bruteforce`| `true`/`false` toggles for active recon modules.                         |
|              | `*_wordlist`           | Path to the wordlists for subdomain and directory brute-forcing.         |
| **[login]**  | `login_url`            | The URL of the login page.                                               |
|              | `*_selector`           | CSS selectors for username/password fields and submit/success elements.  |
| **[fingerprint]**| `locale`, `timezone_id`| Spoof browser locale and timezone.                                   |
|              | `geolocation_*`        | Spoof GPS coordinates.                                                   |
| **[proxies]**| `proxy_list`           | Comma-separated list of proxies (`http://user:pass@host:port`).          |

---

## ⚠️ Ethical Use Disclaimer

This tool is designed for professional and educational purposes only. It is intended for use in authorized security assessments, penetration testing, and legitimate data collection scenarios.

**Users are solely responsible for their actions.** Using this tool against websites without prior mutual consent is illegal in many jurisdictions. The developers assume no liability and are not responsible for any misuse or damage caused by this program. Always respect the `robots.txt` file of a website and its Terms of Service.

---

## Project Structure

\`\`\`
.
├── canvas_spoof.js         # Script for anti-fingerprinting
├── captcha_solver.py       # Handles 2Captcha integration
├── config.ini.template     # Template for configuration
├── dashboard.py            # Flask web dashboard
├── database.py             # SQLite database handler
├── export.py               # CSV export utility
├── osint_utils.py          # OSINT data gathering functions
├── recon_tools.py          # Active reconnaissance functions
├── README.md               # This file
├── requirements.txt        # Python dependencies
├── scraper.py              # The main scraper application
├── tech_fingerprinter.py   # Wappalyzer integration
├── templates/
│   └── index.html          # HTML for the web dashboard
└── wordlists/
    ├── directories-small.txt # Wordlist for directory brute-forcing
    └── subdomains-small.txt  # Wordlist for subdomain enumeration
