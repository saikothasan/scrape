import asyncio
import logging
from urllib.parse import urljoin

async def enumerate_subdomains(domain, wordlist_path, session):
    """
    Performs DNS brute-force to find valid subdomains.
    """
    logging.info(f"Starting subdomain enumeration for {domain} using {wordlist_path}")
    found_subdomains = []
    try:
        with open(wordlist_path, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logging.error(f"Subdomain wordlist not found at: {wordlist_path}")
        return []

    async def check_subdomain(sub):
        target = f"http://{sub}.{domain}"
        try:
            async with session.head(target, timeout=5, allow_redirects=False) as response:
                if response.status < 500: # Consider any non-server-error response as potentially valid
                    logging.info(f"Found subdomain: {target} (Status: {response.status})")
                    return (target, response.status)
        except asyncio.TimeoutError:
            pass
        except Exception: # Catches connection errors etc.
            pass
        return None

    tasks = [check_subdomain(sub) for sub in subdomains]
    results = await asyncio.gather(*tasks)
    
    found_subdomains = [res for res in results if res]
    logging.info(f"Subdomain enumeration finished. Found {len(found_subdomains)} subdomains.")
    return found_subdomains

async def brute_force_directories(base_url, wordlist_path, session):
    """
    Brute-forces common directory and file names.
    """
    logging.info(f"Starting content discovery on {base_url} using {wordlist_path}")
    found_paths = []
    try:
        with open(wordlist_path, 'r') as f:
            paths = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logging.error(f"Directory wordlist not found at: {wordlist_path}")
        return []

    async def check_path(path):
        target = urljoin(base_url, path)
        try:
            async with session.head(target, timeout=5, allow_redirects=False) as response:
                if response.status != 404:
                    logging.info(f"Found content: {target} (Status: {response.status})")
                    return (target, response.status)
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass
        return None

    tasks = [check_path(path) for path in paths]
    results = await asyncio.gather(*tasks)
    
    found_paths = [res for res in results if res]
    logging.info(f"Content discovery finished. Found {len(found_paths)} paths.")
    return found_paths
