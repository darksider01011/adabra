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

# ANSI escape codes for yellow bold text
YELLOW_BOLD = "\033[1;33m"
RESET = "\033[0m"

def extract_domain(url):
    parsed_url = urlparse(url)
    domain = tldextract.extract(parsed_url.netloc)
    return f"{domain.domain}.{domain.suffix}"

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
        
        print(f"\n{YELLOW_BOLD}HTTP Request Information:{RESET}")
        print(f"  Request Method: GET")
        print(f"  URL: {url}")
        print(f"  Status Code: {response.status_code}")
        print(f"  Response Time: {end_time - start_time:.2f} seconds")
        print(f"  Request Headers: {response.request.headers}")
        
        print(f"\n{YELLOW_BOLD}All Response Headers:{RESET}")
        for header, value in response.headers.items():
            print(f"  {header}: {value}")
        
        return response
    
    except requests.RequestException as e:
        print(f"Error fetching the URL: {e}")
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
        print(f"Error analyzing meta tags: {e}")
        return None

def analyze_ssl_tls(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        # Find IP address
        ip_address = socket.gethostbyname(hostname)
        print(f"\n{YELLOW_BOLD}IP Address:{RESET} {ip_address}")
        
        # SSL/TLS Analysis
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                
                print(f"\n{YELLOW_BOLD}SSL/TLS Protocol:{RESET} {protocol}")
                print(f"{YELLOW_BOLD}SSL/TLS Certificate:{RESET}")
                for key, value in cert.items():
                    print(f"  {key}: {value}")

    except Exception as e:
        print(f"Error analyzing SSL/TLS: {e}")

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
        
        print(f"\n{YELLOW_BOLD}Security Headers:{RESET}")
        for header, value in security_headers.items():
            print(f"  {header}: {value}")

    except Exception as e:
        print(f"Error fetching security headers: {e}")

def server_info(url):
    try:
        response = requests.head(url)
        response.raise_for_status()
        
        # Categorize server headers
        server_headers = {
            'Server': response.headers.get('Server', 'Unknown'),
            'Powered-By': response.headers.get('X-Powered-By', 'Unknown'),
            'Framework': response.headers.get('X-Framework', 'Unknown'),
            'Backend Server': response.headers.get('X-Backend-Server', 'Unknown'),
        }
        
        print(f"\n{YELLOW_BOLD}Server Information:{RESET}")
        for header, value in server_headers.items():
            if value != 'Unknown':
                print(f"  {header}: {value}")

    except requests.RequestException as e:
        print(f"Error fetching server info: {e}")

def page_content_analysis(response):
    try:
        soup = BeautifulSoup(response.text, 'html.parser')
        text = soup.get_text()
        word_count = len(text.split())
        print(f"\n{YELLOW_BOLD}Page Content Analysis:{RESET}")
        print(f"  Word Count: {word_count}")
        print(f"  Page Length: {len(response.text)} bytes")

    except Exception as e:
        print(f"Error analyzing page content: {e}")

def performance_info(url):
    try:
        start_time = time.time()
        response = requests.get(url)
        end_time = time.time()
        load_time = end_time - start_time
        print(f"\n{YELLOW_BOLD}Performance Information:{RESET}")
        print(f"  Page Load Time: {load_time:.2f} seconds")
        print(f"  Content Size: {len(response.content)} bytes")

    except requests.RequestException as e:
        print(f"Error fetching performance info: {e}")

def dns_info(domain):
    try:
        print(f"\n{YELLOW_BOLD}DNS Information for:{RESET} {domain}")
        
        ns_records = []
        
        # Get DNS records
        try:
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                ip_address = rdata.address
                print(f"  A Record: {ip_address}")
                
                # Fetch ASN information for the IP address
                obj = IPWhois(ip_address)
                res = obj.lookup_rdap()
                asn = res['asn']
                asn_country_code = res['asn_country_code']
                asn_description = res['asn_description']
                print(f"  ASN: {asn}")
                print(f"  ASN Country Code: {asn_country_code}")
                print(f"  ASN Description: {asn_description}")
                
                # Retrieve unique IP prefixes
                unique_prefixes = get_unique_ip_prefixes(asn)
                if unique_prefixes:
                    print(f"  Unique IP Prefixes:")
                    for prefix in unique_prefixes:
                        print(f"    {prefix}")
                else:
                    print("  No IP prefixes found.")
                
        except dns.resolver.NoAnswer:
            print("  No A Record found.")
        
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                print(f"  MX Record: {rdata.exchange}")
        except dns.resolver.NoAnswer:
            print("  No MX Record found.")
        
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            for rdata in answers:
                ns_records.append(rdata.target.to_text())
                print(f"  NS Record: {rdata.target}")
        except dns.resolver.NoAnswer:
            print("  No NS Record found.")
        
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                print(f"  TXT Record: {rdata.to_text()}")
        except dns.resolver.NoAnswer:
            print("  No TXT Record found.")
        
        # Use NS records for Zone Transfer checks
        for ns in ns_records:
            print(f"\n{YELLOW_BOLD}DNS Zone Transfer Check using NS server:{RESET} {ns}")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain))
                print("  Zone Transfer Successful:")
                for name, node in zone.nodes.items():
                    print(f"    {name.to_text()}: {node.to_text(zone)}")
            except (dns.exception.DNSException, Exception) as e:
                print(f"  Zone Transfer Failed: {e}")

    except Exception as e:
        print(f"Error fetching DNS information: {e}")

def protocol_info(domain):
    try:
        print(f"\n{YELLOW_BOLD}Protocol Information for:{RESET} {domain}")
        protocols = {
            'TCP': 80,
            'HTTPS': 443,
            'DNS': 53,
            'SSH': 22
        }
        
        for proto, port in protocols.items():
            try:
                if proto == 'DNS':
                    # DNS Protocol Check
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(1)
                    sock.sendto(b'', (domain, port))
                    sock.close()
                    print(f"  {proto} Protocol: Port {port} is reachable")
                else:
                    # TCP/UDP checks
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    if port:
                        sock.connect((domain, port))
                        sock.close()
                        print(f"  {proto} Protocol: Port {port} is open")
                    else:
                        print(f"  {proto} Protocol: Port {port} is not applicable")
            except (socket.timeout, socket.error):
                print(f"  {proto} Protocol: Port {port} is closed or not reachable")

    except Exception as e:
        print(f"Error fetching protocol information: {e}")

def detect_technology(response):
    try:
        soup = BeautifulSoup(response.text, 'html.parser')
        headers = response.headers
        
        x_powered_by = headers.get('X-Powered-By', '')
        server_header = headers.get('Server', '')
        
        cms = None
        programming_language = None
        framework = None
        
        # Detecting CMS
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
        
        # Detecting Programming Language
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
        
        # Detecting Framework
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
        
        print(f"\n{YELLOW_BOLD}Technology Detection:{RESET}")
        if cms:
            print(f"  CMS Detected: {cms}")
        else:
            print("  CMS Detected: None detected")
        
        if programming_language:
            print(f"  Programming Language: {programming_language}")
        else:
            print("  Programming Language: None detected")
        
        if framework:
            print(f"  Framework: {framework}")
        else:
            print("  Framework: None detected")

    except Exception as e:
        print(f"Error detecting technology: {e}")

def detect_os_ttl(domain):
    try:
        print(f"\n{YELLOW_BOLD}OS Detection based on TTL:{RESET}")
        response = os.system(f"ping -c 1 {domain}")
        ttl = None
        
        if response == 0:
            result = os.popen(f"ping -c 1 {domain}").read()
            ttl = re.search(r'ttl=(\d+)', result)
            if ttl:
                ttl = int(ttl.group(1))
                
                if ttl <= 64:
                    print("  Likely OS: Linux")
                elif ttl <= 128:
                    print("  Likely OS: Windows")
                else:
                    print("  OS: Unknown based on TTL")
            else:
                print("  TTL value not found.")
        else:
            print("  Ping failed.")
    
    except Exception as e:
        print(f"Error detecting OS based on TTL: {e}")

def check_http_https_status(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

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

    print(f"\n{YELLOW_BOLD}HTTP/HTTPS Status Check:{RESET}")
    http_status = check_status(http_url)
    https_status = check_status(https_url)

    print(f"  HTTP Status: {http_status}")
    print(f"  HTTPS Status: {https_status}")

def get_unique_ip_prefixes(as_number):
    command = ['whois', '-h', 'whois.radb.net', '--', f'-i origin AS{as_number}']
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        output = result.stdout
        prefixes = re.findall(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+', output)
        unique_prefixes = set(prefixes)
        return unique_prefixes
    
    except subprocess.CalledProcessError as e:
        print(f"Error executing whois command: {e}")
        return set()

def main(url):
    print(f"\n{YELLOW_BOLD}Analyzing URL:{RESET} {url}")
    
    server_info(url)  # Fetch and display server information first
    
    domain = extract_domain(url)
    print(f"\n{YELLOW_BOLD}Domain:{RESET} {domain}")
    
    dns_info(domain)  # DNS information and zone transfer check
    protocol_info(domain)
    check_http_https_status(url)  # Check HTTP and HTTPS status
    
    response = fetch_url(url)
    
    if response:
        meta_tags_info = analyze_meta_tags(response)
        if meta_tags_info is not None:
            print(f"\n{YELLOW_BOLD}Meta Tags Information:{RESET}")
            for meta in meta_tags_info:
                print(f"  Name: {meta['name']}, Property: {meta['property']}, Content: {meta['content']}")
        else:
            print("Failed to retrieve or parse meta tags.")
        
        analyze_ssl_tls(url)
        analyze_security_headers(response)
        page_content_analysis(response)
        performance_info(url)
        detect_technology(response)
    else:
        print("Failed to fetch the URL.")
    
    detect_os_ttl(domain)
    
    # ASN and IP prefixes analysis
    try:
        # Get ASN using IPWhois
        ip_address = socket.gethostbyname(domain)
        obj = IPWhois(ip_address)
        res = obj.lookup_rdap()
        asn = res['asn']
        
        print(f"\n{YELLOW_BOLD}ASN Whois:{RESET}")
        print(f"  ASN: {asn}")
        unique_prefixes = get_unique_ip_prefixes(asn)
        if unique_prefixes:
            print("  Unique IP Prefixes:")
            for prefix in unique_prefixes:
                print(f"    {prefix}")
        else:
            print("  No IP prefixes found.")
            
    except Exception as e:
        print(f"Error fetching ASN information: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze a given URL.")
    parser.add_argument('-u', '--url', type=str, required=True, help="The URL to analyze")
    args = parser.parse_args()
    
    main(args.url)
