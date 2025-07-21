import asyncio
import logging
from twocaptcha import TwoCaptcha
from twocaptcha.api import ApiException

class CaptchaSolver:
    """
    Handles CAPTCHA solving by integrating with the 2Captcha service.
    """
    def __init__(self, api_key):
        if not api_key:
            raise ValueError("2Captcha API key is required.")
        self.api_key = api_key
        self.solver = TwoCaptcha(api_key)
        logging.info("CaptchaSolver initialized with 2Captcha.")

    async def solve_recaptcha_v2(self, page, captcha_selector):
        """
        Solves a reCAPTCHA v2 found on the page.
        """
        logging.warning(f"CAPTCHA detected on page: {page.url}")
        
        try:
            captcha_element = page.locator(captcha_selector)
            if not await captcha_element.is_visible():
                logging.info("CAPTCHA element not visible, skipping solve.")
                return False
                
            site_key = await captcha_element.get_attribute('data-sitekey')
            if not site_key:
                logging.error("Could not find 'data-sitekey' on CAPTCHA element.")
                return False

            logging.info(f"Found site key: {site_key}. Sending to 2Captcha...")

            def solve_sync():
                return self.solver.recaptcha(sitekey=site_key, url=page.url)
            
            result = await asyncio.to_thread(solve_sync)
            
            token = result.get('code')
            if not token:
                logging.error("2Captcha did not return a solution token.")
                return False
            
            logging.info("Received CAPTCHA solution token from 2Captcha.")

            injection_script = f"""
            document.getElementById('g-recaptcha-response').innerHTML = '{token}';
            """
            await page.evaluate(injection_script)
            
            logging.info("Successfully injected CAPTCHA token into the page.")
            return True

        except ApiException as e:
            logging.error(f"2Captcha API error: {e}")
            return False
        except Exception as e:
            logging.error(f"An unexpected error occurred during CAPTCHA solving: {e}")
            return False
