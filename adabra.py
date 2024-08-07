import argparse
import requests
import tldextract
from urllib.parse import urlparse
import socket
import ssl
import dns.resolver
import dns.query
import dns.zone
import dns.exception
import time
import os
import re
import subprocess
from bs4 import BeautifulSoup
from ipwhois import IPWhois
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

# ANSI escape codes for colored text
YELLOW_BOLD = "\033[1;33m"
RESET = "\033[0m"

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

def extract_domain(url):
    parsed_url = urlparse(url)
    domain = tldextract.extract(parsed_url.netloc)
    return f"{domain.domain}.{domain.suffix}"

def normalize_input(input_str):
    parsed_url = urlparse(input_str)
    if parsed_url.scheme in ('http', 'https'):
        netloc = parsed_url.netloc
        path = parsed_url.path
        if ':' in netloc:
            domain, port = netloc.split(':')
            return domain, port, path
        else:
            return netloc, None, path
    else:
        if ':' in input_str:
            domain, port = input_str.split(':')
            return domain, port, ''
        else:
            return input_str, None, ''

def fetch_url(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
    
    try:
        start_time = time.time()
        response = requests.get(url, headers=headers)
        end_time = time.time()
        response.raise_for_status()
        
        logger.info(f"\n{YELLOW_BOLD}HTTP Request Information:{RESET}")
        logger.info(f"  Request Method: GET")
        logger.info(f"  URL: {url}")
        logger.info(f"  Status Code: {response.status_code}")
        logger.info(f"  Response Time: {end_time - start_time:.2f} seconds")
        logger.info(f"  Request Headers: {response.request.headers}")
        
        logger.info(f"\n{YELLOW_BOLD}All Response Headers:{RESET}")
        for header, value in response.headers.items():
            if 'http://' in value or 'https://' in value:
                urls = re.findall(r'(https?://\S+)', value)
                for url in urls:
                    logger.info(f"  {header}: {url}")
            else:
                logger.info(f"  {header}: {value}")
        
        return response
    
    except requests.RequestException as e:
        logger.error(f"Error fetching the URL: {e}")
        return None

def analyze_meta_tags(response):
    try:
        soup = BeautifulSoup(response.text, 'html.parser')
        meta_tags = soup.find_all('meta')
        meta_info = []
        for tag in meta_tags:
            name = tag.get('name', '')
            property = tag.get('property', '')
            content = tag.get('content', '')
            meta_info.append({
                'name': name,
                'property': property,
                'content': content
            })
        return meta_info

    except Exception as e:
        logger.error(f"Error analyzing meta tags: {e}")
        return None

def analyze_ssl_tls(domain, port=443):
    try:
        # SSL/TLS Analysis
        context = ssl.create_default_context()
        with socket.create_connection((domain, port)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                
                logger.info(f"\n{YELLOW_BOLD}SSL/TLS Protocol:{RESET} {protocol}")
                logger.info(f"{YELLOW_BOLD}SSL/TLS Certificate:{RESET}")
                for key, value in cert.items():
                    logger.info(f"  {key}: {value}")

    except Exception as e:
        logger.error(f"Error analyzing SSL/TLS: {e}")

def analyze_security_headers(response):
    try:
        headers = response.headers
        security_headers = {
            'Content-Security-Policy': headers.get('Content-Security-Policy'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
            'X-Frame-Options': headers.get('X-Frame-Options'),
            'X-XSS-Protection': headers.get('X-XSS-Protection')
        }
        
        logger.info(f"\n{YELLOW_BOLD}Security Headers:{RESET}")
        for header in sorted(security_headers.keys()):
            value = security_headers[header]
            if value:
                logger.info(f"  {header}:")
                if 'http://' in value or 'https://' in value:
                    urls = re.findall(r'(https?://\S+)', value)
                    for url in urls:
                        logger.info(f"    {url}")
                else:
                    logger.info(f"    {value}")

    except Exception as e:
        logger.error(f"Error fetching security headers: {e}")

def server_info(url):
    try:
        response = requests.head(url)
        response.raise_for_status()
        
        server_headers = {
            'Server': response.headers.get('Server', 'Unknown'),
            'Powered-By': response.headers.get('X-Powered-By', 'Unknown'),
            'Framework': response.headers.get('X-Framework', 'Unknown'),
            'Backend Server': response.headers.get('X-Backend-Server', 'Unknown'),
        }
        
        logger.info(f"\n{YELLOW_BOLD}Server Information:{RESET}")
        for header, value in server_headers.items():
            if value != 'Unknown':
                logger.info(f"  {header}: {value}")

    except requests.RequestException as e:
        logger.error(f"Error fetching server info: {e}")

def page_content_analysis(response):
    try:
        soup = BeautifulSoup(response.text, 'html.parser')
        text = soup.get_text()
        word_count = len(text.split())
        logger.info(f"\n{YELLOW_BOLD}Page Content Analysis:{RESET}")
        logger.info(f"  Word Count: {word_count}")
        logger.info(f"  Page Length: {len(response.text)} bytes")

    except Exception as e:
        logger.error(f"Error analyzing page content: {e}")

def performance_info(url):
    try:
        start_time = time.time()
        response = requests.get(url)
        end_time = time.time()
        load_time = end_time - start_time
        logger.info(f"\n{YELLOW_BOLD}Performance Information:{RESET}")
        logger.info(f"  Page Load Time: {load_time:.2f} seconds")
        logger.info(f"  Content Size: {len(response.content)} bytes")

    except requests.RequestException as e:
        logger.error(f"Error fetching performance info: {e}")

def dns_info(domain):
    try:
        logger.info(f"\n{YELLOW_BOLD}DNS Information for:{RESET} {domain}")
        
        ns_records = []
        
        # Get DNS records
        with ThreadPoolExecutor() as executor:
            future_to_record = {
                executor.submit(dns.resolver.resolve, domain, 'A'): 'A',
                executor.submit(dns.resolver.resolve, domain, 'MX'): 'MX',
                executor.submit(dns.resolver.resolve, domain, 'NS'): 'NS',
                executor.submit(dns.resolver.resolve, domain, 'TXT'): 'TXT'
            }
            for future in as_completed(future_to_record):
                record_type = future_to_record[future]
                try:
                    answers = future.result()
                    for rdata in answers:
                        if record_type == 'A':
                            ip_address = rdata.address
                            logger.info(f"  A Record: {ip_address}")
                            # Fetch ASN information for the IP address
                            obj = IPWhois(ip_address)
                            res = obj.lookup_rdap()
                            asn = res['asn']
                            asn_country_code = res['asn_country_code']
                            asn_description = res['asn_description']
                            logger.info(f"  ASN: {asn}")
                            logger.info(f"  ASN Country Code: {asn_country_code}")
                            logger.info(f"  ASN Description: {asn_description}")
                            # Retrieve unique IP prefixes
                            unique_prefixes = get_unique_ip_prefixes(asn)
                            if unique_prefixes:
                                logger.info(f"  Unique IP Prefixes:")
                                for prefix in unique_prefixes:
                                    logger.info(f"    {prefix}")
                            else:
                                logger.info("  No IP prefixes found.")
                        elif record_type == 'MX':
                            logger.info(f"  MX Record: {rdata.exchange}")
                        elif record_type == 'NS':
                            ns_records.append(rdata.target.to_text())
                            logger.info(f"  NS Record: {rdata.target}")
                        elif record_type == 'TXT':
                            logger.info(f"  TXT Record: {rdata.to_text()}")
                except dns.resolver.NoAnswer:
                    logger.info(f"  No {record_type} Record found.")
        
        try:
            z = dns.zone.from_xfr(dns.query.xfr(domain, '127.0.0.1'))
            for name, node in z.nodes.items():
                logger.info(f"  Zone Transfer: {name} -> {node.to_text()}")
        except dns.exception.DNSException as e:
            logger.info(f"  Zone Transfer Failed: {e}")

    except Exception as e:
        logger.error(f"Error fetching DNS information: {e}")

def protocol_info(domain):
    try:
        logger.info(f"\n{YELLOW_BOLD}Protocol Information for:{RESET} {domain}")
        protocols = {
            'TCP': 80,
            'HTTPS': 443,
            'DNS': 53,
            'SSH': 22
        }
        
        with ThreadPoolExecutor() as executor:
            future_to_protocol = {
                executor.submit(check_protocol, domain, port): proto for proto, port in protocols.items()
            }
            for future in as_completed(future_to_protocol):
                protocol = future_to_protocol[future]
                result = future.result()
                logger.info(f"  {protocol} Protocol: {result}")

    except Exception as e:
        logger.error(f"Error fetching protocol information: {e}")

def check_protocol(domain, port):
    try:
        if port == 53:  # DNS uses UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(b'', (domain, port))
            sock.close()
            return "reachable"
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((domain, port))
            sock.close()
            return "open"
    except (socket.timeout, socket.error):
        return "closed or not reachable"

def detect_technology(response):
    try:
        soup = BeautifulSoup(response.text, 'html.parser')
        headers = response.headers
        
        x_powered_by = headers.get('X-Powered-By', '')
        server_header = headers.get('Server', '')
        
        cms = None
        programming_language = None
        framework = None
        
        cms_patterns = {
            'wordpress': ['wp-content', 'wp-admin', 'wp-includes'],
            'joomla': ['/joomla/', 'joomla'],
            'drupal': ['drupal', 'sites/default'],
            'magento': ['magento', 'catalog/product']
        }
        
        for cms_name, patterns in cms_patterns.items():
            if any(pattern in response.text.lower() for pattern in patterns):
                cms = cms_name.capitalize()
                break
        
        language_patterns = {
            'php': ['php'],
            'asp.net': ['asp.net'],
            'python': ['python'],
            'ruby': ['ruby'],
            'node.js': ['node.js']
        }
        
        for language, patterns in language_patterns.items():
            if any(pattern in x_powered_by.lower() or pattern in server_header.lower() for pattern in patterns):
                programming_language = language.capitalize()
                break
        
        framework_patterns = {
            'django': ['django'],
            'flask': ['flask'],
            'rails': ['rails'],
            'laravel': ['laravel']
        }
        
        for framework_name, patterns in framework_patterns.items():
            if any(pattern in response.text.lower() for pattern in patterns):
                framework = framework_name.capitalize()
                break
        
        logger.info(f"\n{YELLOW_BOLD}Technology Detection:{RESET}")
        if cms:
            logger.info(f"  CMS Detected: {cms}")
        else:
            logger.info("  CMS Detected: None detected")
        
        if programming_language:
            logger.info(f"  Programming Language: {programming_language}")
        else:
            logger.info("  Programming Language: None detected")
        
        if framework:
            logger.info(f"  Framework: {framework}")
        else:
            logger.info("  Framework: None detected")

    except Exception as e:
        logger.error(f"Error detecting technology: {e}")

def detect_os_ttl(domain):
    try:
        logger.info(f"\n{YELLOW_BOLD}OS Detection based on TTL:{RESET}")
        response = os.system(f"ping -c 1 {domain}")
        ttl = None
        
        if response == 0:
            result = os.popen(f"ping -c 1 {domain}").read()
            ttl = re.search(r'ttl=(\d+)', result)
            if ttl:
                ttl = int(ttl.group(1))
                
                if ttl <= 64:
                    logger.info("  Likely OS: Linux")
                elif ttl <= 128:
                    logger.info("  Likely OS: Windows")
                else:
                    logger.info("  OS: Unknown based on TTL")
            else:
                logger.info("  TTL value not found.")
        else:
            logger.info("  Ping failed.")
    
    except Exception as e:
        logger.error(f"Error detecting OS based on TTL: {e}")

def check_http_https_status(domain):
    http_url = f"http://{domain}"
    https_url = f"https://{domain}"

    def check_status(url):
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return "UP"
            else:
                return "DOWN"
        except requests.RequestException:
            return "DOWN"

    logger.info(f"\n{YELLOW_BOLD}HTTP/HTTPS Status Check:{RESET}")
    http_status = check_status(http_url)
    https_status = check_status(https_url)

    logger.info(f"  HTTP Status: {http_status}")
    logger.info(f"  HTTPS Status: {https_status}")

def get_unique_ip_prefixes(as_number):
    command = ['whois', '-h', 'whois.radb.net', '--', f'-i origin AS{as_number}']
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        output = result.stdout
        prefixes = re.findall(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+', output)
        unique_prefixes = set(prefixes)
        return unique_prefixes
    
    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing whois command: {e}")
        return set()

def main(input_str, link=False, asn=False):
    domain, port, path = normalize_input(input_str)
    logger.info(f"\n{YELLOW_BOLD}Analyzing Input:{RESET} {input_str}")

    if link:
        logger.info(f"\n{YELLOW_BOLD}Link Extraction:{RESET}")
        response = fetch_url(f"http://{domain}")
        if response:
            soup = BeautifulSoup(response.text, 'html.parser')
            links = set()
            for tag in soup.find_all('a', href=True):
                link = tag.get('href')
                if link.startswith('http'):
                    links.add(link)
            if links:
                for link in links:
                    logger.info(f"  {link}")
            else:
                logger.info("  No links found.")
        return

    if asn:
        try:
            ip_addresses = socket.gethostbyname_ex(domain)[2]
            for ip_address in ip_addresses:
                obj = IPWhois(ip_address)
                res = obj.lookup_rdap()
                asn = res['asn']
                logger.info(f"\n{YELLOW_BOLD}ASN Whois for IP {ip_address}:{RESET}")
                logger.info(f"  ASN: {asn}")
                unique_prefixes = get_unique_ip_prefixes(asn)
                if unique_prefixes:
                    logger.info("  Unique IP Prefixes:")
                    for prefix in unique_prefixes:
                        logger.info(f"    {prefix}")
                else:
                    logger.info("  No IP prefixes found.")
        except Exception as e:
            logger.error(f"Error fetching ASN information: {e}")
        return

    if port:
        logger.info(f"  Port: {port}")
    
    if path:
        logger.info(f"  Path: {path}")

    server_info(f"http://{domain}")  # Assuming default HTTP for server info
    
    domain_name = extract_domain(f"http://{domain}")
    logger.info(f"\n{YELLOW_BOLD}Domain:{RESET} {domain_name}")
    
    dns_info(domain_name)
    protocol_info(domain_name)
    check_http_https_status(domain)
    
    url = f"http://{domain}"  # Use default scheme for URL fetching
    response = fetch_url(url)
    
    if response:
        meta_tags_info = analyze_meta_tags(response)
        if meta_tags_info is not None:
            logger.info(f"\n{YELLOW_BOLD}Meta Tags Information:{RESET}")
            for meta in meta_tags_info:
                logger.info(f"  Name: {meta['name']}, Property: {meta['property']}, Content: {meta['content']}")
        else:
            logger.info("Failed to retrieve or parse meta tags.")
        
        analyze_ssl_tls(domain, int(port) if port else 443)
        analyze_security_headers(response)
        page_content_analysis(response)
        performance_info(url)
        detect_technology(response)
    else:
        logger.info("Failed to fetch the URL.")
    
    detect_os_ttl(domain)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze a given URL, IP, or domain.")
    parser.add_argument('-u', '--url', type=str, required=True, help="The URL, IP, or domain to analyze")
    parser.add_argument('--link', action='store_true', help="Extract and display all links from the provided URL")
    parser.add_argument('--asn', action='store_true', help="Display ASN information for the provided domain")
    args = parser.parse_args()
    
    main(args.url, link=args.link, asn=args.asn)
