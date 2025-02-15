import requests
import re
import ipaddress
import threading
import queue
from bs4 import BeautifulSoup
import argparse
import asyncio
import httpx
import ssl

# Known Cloud Providers (You can expand this list)
CLOUD_PROVIDERS = {
    "AS16509": "Amazon",
    "AS15169": "Google",
    "AS8075": "Microsoft",
    "AS13335": "Akamai",
    "AS3209": "Cloudflare",
}

# Define output files
ASN_FILE = "asn.txt"
CIDR_FILE = "cidrs.txt"
IP_FILE = "ips.txt"
LIVE_HOSTS_FILE = "live_hosts.txt"

# Number of worker threads
NUM_WORKERS = 20

# Create a custom SSL context that allows self-signed certificates
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

async def check_ip(ip, client, semaphore):
    """Asynchronously check if an IP is accessible via HTTP/HTTPS"""
    async with semaphore:
        urls = [f'https://{ip}', f'http://{ip}']  # Check both HTTP and HTTPS
        for url in urls:
            try:
                response = await client.get(url, timeout=5)
                if 200 <= response.status_code <= 405:
                    with open(LIVE_HOSTS_FILE, "a") as f:
                        f.write(f"{url}\n")
                    return url
            except (httpx.RequestError, ssl.SSLError) as e:
                # Log SSL errors but continue
                if "SSL" in str(e):
                    print(f"[!] SSL error for {url}: {e}")
                pass  # Ignore other errors (timeouts, unreachable hosts)
    return None

async def scan_live_hosts():
    """Scan live hosts using httpx for HTTP/HTTPS accessibility"""
    live_hosts = []

    with open(IP_FILE, "r") as f:
        ip_list = [line.strip() for line in f.readlines()]

    if not ip_list:
        print("[-] No IPs found to scan.")
        return

    print(f"[*] Scanning {len(ip_list)} IPs for live hosts...")

    semaphore = asyncio.Semaphore(NUM_WORKERS)  # Limit to NUM_WORKERS concurrent requests
    async with httpx.AsyncClient(verify=ssl_context) as client:
        tasks = []
        for ip in ip_list:
            tasks.append(check_ip(ip, client, semaphore))
        
        # Run all tasks concurrently
        await asyncio.gather(*tasks)

    print(f"[*] Live host scan completed.")

def get_asn(domain):
    """Find ASN for a given domain using bgp.he.net"""
    url = f"https://bgp.he.net/dns/{domain}"
    headers = {"User-Agent": "Mozilla/5.0"}
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print(f"[!] Failed to fetch ASN data for {domain}.")
        return []

    soup = BeautifulSoup(response.text, "html.parser")
    asn_list = set()

    for link in soup.find_all("a", href=True):
        if "/AS" in link["href"]:
            asn = re.search(r"AS(\d+)", link["href"])
            if asn:
                asn_list.add(asn.group(1))

    return list(asn_list)

def get_cidrs(asn):
    """Fetch CIDR ranges from bgp.he.net for a given ASN"""
    url = f"https://bgp.he.net/AS{asn}"
    headers = {"User-Agent": "Mozilla/5.0"}
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print(f"[!] Failed to fetch CIDRs for ASN {asn}")
        return []

    cidrs = re.findall(r"\d+\.\d+\.\d+\.\d+/\d+", response.text)
    return list(set(cidrs))

def expand_cidr_worker(q):
    """Worker function to expand CIDR ranges"""
    while not q.empty():
        cidr = q.get()
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
            if network.is_private or network.is_reserved:
                print(f"[!] Skipping private/reserved CIDR: {cidr}")
                continue
            with open(IP_FILE, "a") as f:
                for ip in network:
                    f.write(f"{ip}\n")
        except Exception as e:
            print(f"[!] Error processing {cidr}: {e}")
        q.task_done()

def process_domain(domain):
    print(f"[*] Processing domain {domain}...")

    print(f"[*] Finding ASN for {domain}...")
    asns = get_asn(domain)
    if not asns:
        print(f"[!] No ASN found for {domain}.")
        return

    cidr_queue = queue.Queue()

    for asn in asns:
        print(f"[*] Processing ASN {asn}...")

        # Check if ASN belongs to a cloud provider
        if asn in CLOUD_PROVIDERS:
            print(f"[!] {CLOUD_PROVIDERS[asn]} detected. Skipping CIDRs from this ASN...")
            continue  # Skip this ASN

        print(f"[*] Fetching CIDRs for ASN {asn}...")
        cidrs = get_cidrs(asn)
        print(f"[*] Found {len(cidrs)} CIDR ranges.")

        for cidr in cidrs:
            cidr_queue.put(cidr)

    print("[*] Expanding CIDRs to IPs using workers...")
    threads = []
    for _ in range(NUM_WORKERS):
        t = threading.Thread(target=expand_cidr_worker, args=(cidr_queue,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("[*] Scanning for live hosts...")
    asyncio.run(scan_live_hosts())  # Use async scan to check HTTP/HTTPS

    print(f"[+] Done for {domain}. Check the output files:")
    print(f"    - ASN: {ASN_FILE}")
    print(f"    - CIDRs: {CIDR_FILE}")
    print(f"    - All IPs: {IP_FILE}")
    print(f"    - Live Hosts: {LIVE_HOSTS_FILE}")

def main(domains):
    if isinstance(domains, str):
        # Read domains from a file if the argument is a file path
        with open(domains, "r") as file:
            domains = [line.strip() for line in file.readlines() if line.strip()]
            
    for domain in domains:
        process_domain(domain)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find ASN, CIDRs, and Live Hosts from a Domain or List of Domains")
    parser.add_argument("-d", "--domain", help="Target domain (e.g., example.com)")
    parser.add_argument("-l", "--list", help="File containing list of domains (one per line)", type=str)
    
    args = parser.parse_args()
    
    if args.domain:
        # Single domain
        main([args.domain])
    elif args.list:
        # List of domains from file
        main(args.list)
    else:
        print("Please provide a domain using -d or a list of domains using -l.")
