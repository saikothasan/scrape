import logging
from Wappalyzer import Wappalyzer, WebPage

class TechFingerprinter:
    """
    Uses Wappalyzer to detect technologies used by a web page.
    """
    def __init__(self):
        try:
            self.wappalyzer = Wappalyzer.latest()
            logging.info("Wappalyzer initialized successfully.")
        except Exception as e:
            logging.error(f"Failed to initialize Wappalyzer: {e}")
            self.wappalyzer = None

    def analyze(self, url, html, headers):
        """
        Analyzes a webpage to identify its technology stack.

        Args:
            url (str): The URL of the webpage.
            html (str): The HTML content of the page.
            headers (dict): The response headers.

        Returns:
            dict: A dictionary of detected technologies and their categories.
        """
        if not self.wappalyzer:
            return {}
            
        try:
            webpage = WebPage(url, html, headers)
            tech_info = self.wappalyzer.analyze_with_categories(webpage)
            return tech_info
        except Exception as e:
            logging.warning(f"Wappalyzer analysis failed for {url}: {e}")
            return {}
