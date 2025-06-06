import whois
import socket
import requests
import re
import dns.resolver
import json
import time
import os
import logging
import datetime
import argparse
import subprocess
import string
import validators
from requests.exceptions import RequestException, Timeout
from dns.exception import DNSException
from dotenv import load_dotenv
from pygments import highlight, lexers, formatters

# Φόρτωση μεταβλητών περιβάλλοντος από .env
load_dotenv()

# ANSI κωδικοί χρωμάτων ανά επίπεδο λογαρισμού
LOG_COLORS = {
    'DEBUG': '\033[36m',    # Κυανό
    'INFO': '\033[32m',     # Πράσινο
    'WARNING': '\033[33m',  # Κίτρινο
    'ERROR': '\033[31m',    # Κόκκινο
    'CRITICAL': '\033[41m', # Κόκκινο φόντο
}
RESET_COLOR = '\033[0m'

class ColorfulFormatter(logging.Formatter):
    def format(self, record):
        log_color = LOG_COLORS.get(record.levelname, RESET_COLOR)
        levelname_colored = f"{log_color}{record.levelname}{RESET_COLOR}"
        formatted = super().format(record)
        return formatted.replace(record.levelname, levelname_colored)

# Ρύθμιση logger με χρώματα
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)
for handler in logging.root.handlers:
    handler.setFormatter(ColorfulFormatter('[%(asctime)s] %(levelname)s - %(message)s', '%Y-%m-%d %H:%M:%S'))

def requests_get_with_retry(url, headers=None, timeout=5, retries=3, backoff=1):
    for attempt in range(1, retries + 1):
        try:
            logger.debug(f"Requesting URL: {url} (Attempt {attempt})")
            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()
            logger.info(f"Successful request to {url} on attempt {attempt}")
            return response
        except Timeout:
            logger.warning(f"Timeout on {url}, attempt {attempt} of {retries}")
        except RequestException as e:
            logger.error(f"Request error on {url}, attempt {attempt} of {retries}: {e}")
        if attempt < retries:
            sleep_time = backoff * attempt
            logger.debug(f"Sleeping {sleep_time}s before retry")
            time.sleep(sleep_time)
    logger.error(f"Failed to get response from {url} after {retries} attempts")
    return None

def validate_domain(domain):
    return validators.domain(domain)

def validate_username(username):
    pattern = r"^[a-zA-Z0-9._-]{3,30}$"
    return re.match(pattern, username) is not None

def get_whois(domain):
    try:
        w = whois.whois(domain)
        logger.info(f"WHOIS lookup successful for {domain} (python-whois)")
        return w
    except Exception as e:
        logger.warning(f"python-whois failed for {domain}: {e}")
        try:
            output = subprocess.check_output(['whois', domain], text=True, timeout=10)
            logger.info(f"WHOIS lookup successful for {domain} (system whois)")
            return output
        except Exception as e2:
            logger.error(f"System whois command failed for {domain}: {e2}")
            return f"WHOIS lookup failed: {e2}"

def get_dns_records(domain, timeout=5):
    records = {}
    try:
        logger.debug(f"Resolving A record for {domain}")
        records['A'] = socket.gethostbyname(domain)
    except socket.gaierror:
        logger.warning(f"Failed to resolve A record for {domain}")
        records['A'] = None

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    for record_type in ['MX', 'NS', 'TXT']:
        try:
            logger.debug(f"Resolving {record_type} records for {domain}")
            answers = resolver.resolve(domain, record_type)
            records[record_type] = [str(r) for r in answers]
        except (DNSException, Exception) as e:
            logger.warning(f"Failed to resolve {record_type} records for {domain}: {e}")
            records[record_type] = []

    records['SPF'] = [txt for txt in records.get('TXT', []) if 'v=spf1' in txt.lower()]
    try:
        dkim_selector = 'default'
        dkim_domain = f"{dkim_selector}._domainkey.{domain}"
        logger.debug(f"Resolving DKIM TXT records for {dkim_domain}")
        dkim_records = resolver.resolve(dkim_domain, 'TXT')
        records['DKIM'] = [r.to_text() for r in dkim_records]
    except (DNSException, Exception) as e:
        logger.warning(f"Failed to resolve DKIM records for {domain}: {e}")
        records['DKIM'] = []

    return records

def geoip_lookup(ip):
    url = f"https://ipinfo.io/{ip}/json"
    response = requests_get_with_retry(url, timeout=5)
    if response:
        try:
            data = response.json()
            return {
                'IP': ip,
                'City': data.get('city'),
                'Region': data.get('region'),
                'Country': data.get('country'),
                'Org': data.get('org'),
                'Loc': data.get('loc'),
                'Postal': data.get('postal')
            }
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in GeoIP response for IP {ip}")
            return {"Error": "Invalid JSON in GeoIP response"}
    else:
        logger.error(f"GeoIP lookup failed for IP {ip} after retries")
    return {"Error": "GeoIP lookup failed after retries"}

def search_social_media(username):
    platforms = {
        "Twitter": f"https://twitter.com/{username}",
        "GitHub": f"https://github.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "Facebook": f"https://www.facebook.com/{username}"
    }
    found = {}
    headers = {'User-Agent': 'Mozilla/5.0'}
    for platform, url in platforms.items():
        response = requests_get_with_retry(url, headers=headers)
        if response and response.status_code == 200:
            found[platform] = url
            logger.info(f"Found {platform} profile for {username}")
    return found

def reverse_image_search_url(image_url):
    return f"https://www.google.com/searchbyimage?image_url={image_url}"

def haveibeenpwned_check(account):
    api_key = os.getenv("HIBP_API_KEY")
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
    headers = {'User-Agent': 'OSINT-Script'}
    if api_key:
        headers['hibp-api-key'] = api_key
    else:
        logger.warning("HIBP API key not found in environment")
        return ["HIBP API key not found in environment"]

    response = requests_get_with_retry(url, headers=headers, timeout=10, retries=3, backoff=2)
    if response:
        if response.status_code == 200:
            try:
                breaches = response.json()
                logger.info(f"HIBP breaches found for {account}: {len(breaches)}")
                return [b['Name'] for b in breaches]
            except Exception as e:
                logger.error(f"Error parsing HIBP response: {e}")
                return [f"Error parsing HIBP response: {e}"]
        elif response.status_code == 404:
            logger.info(f"No breaches found for {account}")
            return []
        logger.error(f"Error {response.status_code} from HaveIBeenPwned for {account}")
        return [f"Error {response.status_code} from HaveIBeenPwned"]
    logger.error(f"Failed to retrieve HaveIBeenPwned data after retries for {account}")
    return ["Failed to retrieve HaveIBeenPwned data after retries"]

def hunterio_email_search(domain):
    api_key = os.getenv("HUNTER_API_KEY")
    if not api_key:
        logger.warning("Hunter.io API key not set in environment")
        return ["Hunter.io API key not set in environment"]

    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
    response = requests_get_with_retry(url, timeout=10, retries=3, backoff=2)
    if response:
        try:
            data = response.json()
            emails = [e['value'] for e in data.get('data', {}).get('emails', [])]
            logger.info(f"Hunter.io found {len(emails)} emails for {domain}")
            return emails
        except Exception as e:
            logger.error(f"Error parsing Hunter.io response: {e}")
            return [f"Error parsing Hunter.io response: {e}"]
    logger.error(f"Failed to retrieve Hunter.io data after retries for {domain}")
    return [f"Failed to retrieve Hunter.io data after retries"]

def censys_search(domain):
    return f"https://search.censys.io/certificates?q={domain}"

def sanitize_filename(filename):
    valid_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
    cleaned = ''.join(c for c in filename if c in valid_chars)
    cleaned = cleaned.strip().replace(' ', '_')
    if not cleaned:
        return "output.json"
    if not cleaned.endswith('.json'):
        cleaned += '.json'
    return cleaned
    

def json_serial(obj):
    if isinstance(obj, datetime.datetime) or isinstance(obj, datetime.date):
        return obj.isoformat()
    raise TypeError("Type not serializable")

def main():
    parser = argparse.ArgumentParser(description="OSINT Tool")
    parser.add_argument("target", help="Domain or username")
    parser.add_argument("--image", help="Optional image URL for reverse image search", default=None)
    parser.add_argument("--output", help="Output filename", default=None)
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    target = args.target.strip()
    img_url = args.image

    raw_filename = args.output or f"osint_results_{target.replace(' ', '_')}.json"
    filename = sanitize_filename(raw_filename)
    logger.debug(f"Output filename sanitized: {filename}")

    try:
        if validate_domain(target):
            target_type = 'domain'
            logger.info(f"Target {target} detected as domain")
        elif validate_username(target):
            target_type = 'username'
            logger.info(f"Target {target} detected as username")
        else:
            raise ValueError("Invalid domain or username format")

        results = {'type': target_type}

        if target_type == 'domain':
            results['whois'] = get_whois(target)
            results['dns'] = get_dns_records(target)
            ip = results['dns'].get('A')
            if ip:
                results['geoip'] = geoip_lookup(ip)
            results['hunter_emails'] = hunterio_email_search(target)
            results['censys_certificates_url'] = censys_search(target)
        else:
            results['social_media'] = search_social_media(target)
            results['haveibeenpwned'] = haveibeenpwned_check(target)

        if img_url:
            results['reverse_image_search_url'] = reverse_image_search_url(img_url)

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4, default=json_serial)

        json_str = json.dumps(results, indent=4, ensure_ascii=False, default=json_serial)
        colorful_json = highlight(json_str, lexers.JsonLexer(), formatters.TerminalFormatter())
        print(colorful_json)
        logger.info(f"Results saved to {filename}")

    except Exception as e:
        logger.error(f"Fatal error: {e}")

if __name__ == "__main__":
    main()
