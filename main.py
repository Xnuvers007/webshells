import subprocess, sys
from sys import platform
try:
    import dns, socket, time, random, jsbeautifier, re, requests
    from urllib.parse import urlparse, urljoin
    from bs4 import BeautifulSoup
except (ImportError, ModuleNotFoundError):
    if platform == 'win32':
        command = ["pip", "install", "-r", "requirements.txt"]
        install = subprocess.call(command, stderr=subprocess.STDOUT, shell=True)
    elif platform == 'linux' or platform == 'linux2' or platform == 'posix':
        try:
            root = input("Do you want to install the requirements as root? [y/n]: ")
            if root == "y" or root == "Y":
                command = ["sudo", "pip3", "install", "-r", "requirements.txt"]
                install = subprocess.call(command, stderr=subprocess.STDOUT, shell=True)
            elif root == "n" or root == "N":
                command = ["pip3", "install", "-r", "requirements.txt"]
                install = subprocess.call(command, stderr=subprocess.STDOUT, shell=True)
            else:
                print("Invalid input!")
        except (Exception):
            print("ERROR: Invalid input")
            sys.exit(1)
    else:
        print("ERROR: Invalid platform")
        sys.exit(1)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone14,3; U; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/19A346 Safari/602.1",
    "Mozilla/5.0 (iPhone13,2; U; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/15E148 Safari/602.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A5370a Safari/604.1",
    "Mozilla/5.0 (Apple-iPhone7C2/1202.466; U; CPU like Mac OS X; en) AppleWebKit/420+ (KHTML, like Gecko) Version/3.0 Mobile/1A543 Safari/419.3",
    "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.188",
    # Add more user agents here
]

def fetch_url_content(url):
    try:
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        response = requests.get(url, headers=headers)
        try:
            server_name = response.headers["Server"]
            # kukis = response.headers["Set-Cookie"]
            print(f"Server: {server_name}")
            print(f"Status code: {response.status_code}")
            print(f"Cookie: {response.headers['Set-Cookie']}")
            print(f"Content-Type: {response.headers['Content-Type']}")
            print(f"Date: {response.headers['Date']}")
            print(f"x-frame-options: {response.headers['X-Frame-Options']}")
            print(f"X-XSS-Protection: {response.headers['X-XSS-Protection']}")
        except (Exception, KeyError):
            pass
        response.raise_for_status()  # Check for HTTP errors
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching content from {url}: {e}")
        return None

def find_potential_webshells(content):
    # Regular expressions to match common webshell signatures
    webshell_signatures = [
        r"eval\s*\(",
        r"exec\s*\(",
        r"base64_decode\s*\(",
        r"system\s*\(",
        r"passthru\s*\(",
        r"shell_exec\s*\(",
        r"proc_open\s*\(",
        r"popen\s*\(",
        r"pcntl_exec\s*\(",
        r"assert\s*\(",
        r"create_function\s*\(",
        # r"include\s*\(",
        # r"require\s*\(",
        # r"include_once\s*\(",
        # r"require_once\s*\(",
        # r"call_user_func\s*\(",
        # r"call_user_func_array\s*\(",
        r"preg_replace\s*\(\s*['\"][\s\S]*['\"],\s*['\"][\s\S]*['\"]\s*\.\s*['\"][\s\S]*['\"]\s*,\s*['\"][\s\S]*['\"]\s*\)"

    ]

    # Additional patterns for detecting webshells
    additional_patterns = [
        r"(?P<func>echo|print|print_r)\s*\(\s*\$_(GET|POST|REQUEST)",
        r"(?P<func>preg_replace|preg_filter)\s*\(\s*['\"]/@e['\"],",
        r"(?P<func>ob_start)\s*\(\s*['\"]@{10,}"
    ]

    found_webshells = []
    for signature in webshell_signatures:
        if re.search(signature, content):
            found_webshells.append(signature)

    for pattern in additional_patterns:
        matches = re.finditer(pattern, content)
        for match in matches:
            found_webshells.append(match.group())

    return found_webshells

def find_potential_backdoors(content):
    # Regular expression to match suspicious PHP file extensions
    suspicious_extensions = [
        r"\.php\d?",
        r"\.phtml",
        r"\.phps",
        r"\.php3?",
        r"\.inc",
        r"\.cgi",
        r"\.asp",
        r"\.aspx",
        r"\.jsp",
        r"\.cfm",
        r"\.pl",
        r"\.sh",
        r"\.py",
        r"\.PhP",
        r"\.php",
        # add it more what you want
    ]

    found_backdoors = []
    for extension in suspicious_extensions:
        pattern = r'<\?(?:php)?[^<]+(?:' + extension + r')\b'
        if re.search(pattern, content, re.IGNORECASE):
            found_backdoors.append(extension)

    return found_backdoors

def parse_javascript_code(code):
    # Add more advanced JavaScript parsing techniques here
    beautified_code = jsbeautifier.beautify(code)
    # Implement parsing logic to look for suspicious patterns in the JavaScript code
    return beautified_code

def save_to_file(filename, data):
    with open(filename, "w") as file:
        file.write(data)

def find_potential_obfuscated_php_webshells(content):
    obfuscated_patterns = [
        r"chr\(\d+\)",
        r"chr\(\d+\s*\.\.\s*\d+\)",
        r"chr\(\d+\s*\.\.\s*\d+\s*\.\.\s*\d+\)",
        r"chr\(\d+\s*\.\.\s*\d+\s*\.\.\s*\d+\s*\.\.\s*\d+\)",
        r"chr\(\d+\s*\.\.\s*\d+\s*\.\.\s*\d+\s*\.\.\s*\d+\s*\.\.\s*\d+\)",
        r"base64_decode\([\"'][\w\+/=]+[\"']\)",
        r"gzinflate\([\"'][\w\+/=]+[\"']\)",
        r"gzuncompress\([\"'][\w\+/=]+[\"']\)",
        r"gzdecode\([\"'][\w\+/=]+[\"']\)",
        r"str_rot13\([\"'][\w\+/=]+[\"']\)",
        r"strrev\([\"'][\w\+/=]+[\"']\)",
        r"base64_decode\s*(\$_(?:GET|POST|REQUEST)\[.*\])",
        r"gzinflate\s*(\$_(?:GET|POST|REQUEST)\[.*\])",
        r"gzuncompress\s*(\$_(?:GET|POST|REQUEST)\[.*\])",
        r"gzdecode\s*(\$_(?:GET|POST|REQUEST)\[.*\])",
        r"str_rot13\s*(\$_(?:GET|POST|REQUEST)\[.*\])",
        r"strrev\s*(\$_(?:GET|POST|REQUEST)\[.*\])",
        r"base64_decode\s*\(\s*['\"][\w\+/=]+['\"]\s*\)",
        r"gzinflate\s*\(\s*['\"][\w\+/=]+['\"]\s*\)",
        r"gzuncompress\s*\(\s*['\"][\w\+/=]+['\"]\s*\)",
        r"gzdecode\s*\(\s*['\"][\w\+/=]+['\"]\s*\)",
        r"str_rot13\s*\(\s*['\"][\w\+/=]+['\"]\s*\)",
        r"strrev\s*\(\s*['\"][\w\+/=]+['\"]\s*\)",
        r"base64_decode\s*\(\s*\$_(?:GET|POST|REQUEST)\[.*\]\s*\)",
        r"gzinflate\s*\(\s*\$_(?:GET|POST|REQUEST)\[.*\]\s*\)",
        r"gzuncompress\s*\(\s*\$_(?:GET|POST|REQUEST)\[.*\]\s*\)",
        r"gzdecode\s*\(\s*\$_(?:GET|POST|REQUEST)\[.*\]\s*\)",
        r"str_rot13\s*\(\s*\$_(?:GET|POST|REQUEST)\[.*\]\s*\)",
        r"strrev\s*\(\s*\$_(?:GET|POST|REQUEST)\[.*\]\s*\)",
        r"base64_decode\s*\(",
        r"eval\s*\(\s*base64_decode\s*\(",
        r"eval\s*\(\s*str_rot13\s*\(",
        r"eval\s*\(\s*gzinflate\s*\(",
        r"eval\s*\(\s*gzuncompress\s*\(",
        r"eval\s*\(\s*gzdecode\s*\(",
        r"eval\s*\(\s*strrev\s*\(",
        r"eval\s*\(\s*str_rot13\s*\("
    ]

    found_webshells = []
    try:
        for pattern in obfuscated_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                found_webshells.append(pattern)
    except:
        for pattern in obfuscated_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                found_webshells.append(match.group())

    return found_webshells


def find_potential_obfuscated_js_webshells(content):
    obfuscated_patterns = [
        r"String\.fromCharCode\((?:\s*0x[0-9a-fA-F]+,?)+\)",
        r"String\.fromCharCode\((?:\s*\d+,?)+\)",
        r"eval(String\.fromCharCode\((?:\s*0x[0-9a-fA-F]+,?)+\))",
        r"eval(String\.fromCharCode\((?:\s*\d+,?)+\))",
        r"eval\(String\.fromCharCode\((?:\s*0x[0-9a-fA-F]+,?)+\)\)",
        r"eval\(String\.fromCharCode\((?:\s*\d+,?)+\)\)",
        r"eval\s*\(",
        r"new\s+Function\s*\("
        r"unescape\s*\(",
        r"escape\s*\("
    ]

    found_webshells = []
    try:
        for pattern in obfuscated_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                found_webshells.append(pattern)
    except:
        for pattern in obfuscated_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                found_webshells.append(match.group())

    return found_webshells

def scan_for_webshells(url):
    content = fetch_url_content(url)
    if content is None:
        return

    potential_webshells = find_potential_webshells(content)
    potential_backdoors = find_potential_backdoors(content)
    potential_obfuscated_php_webshells = find_potential_obfuscated_php_webshells(content)
    potential_obfuscated_js_webshells = find_potential_obfuscated_js_webshells(content)

    alerts = []
    webshells_found = []  # Store the URLs where potential webshells are found

    if potential_webshells:
        alert = f"Potential webshells/backdoors found in {url}:\n"
        for webshell in potential_webshells:
            matches = re.finditer(webshell, content)
            for match in matches:
                location = match.start()
                context_start = max(0, location - 50)
                context_end = min(len(content), location + 50)
                context = content[context_start:context_end]
                alert += f" - {webshell} (Location: {location})\n"
                alert += f"   Context: {context}\n"

                # Save the URL where the webshell is found
                webshells_found.append(url)
        alerts.append(alert)

    if potential_backdoors:
        alert = f"Potential backdoor file extensions found in {url}:\n"
        for extension in potential_backdoors:
            matches = re.finditer(extension, content, re.IGNORECASE)
            for match in matches:
                location = match.start()
                context_start = max(0, location - 50)
                context_end = min(len(content), location + 50)
                context = content[context_start:context_end]
                alert += f" - {extension} (Location: {location})\n"
                alert += f"   Context: {context}\n"
        alerts.append(alert)

    if potential_obfuscated_php_webshells:
        alert = f"Potential obfuscated PHP webshells found in {url}:\n"
        for pattern in potential_obfuscated_php_webshells:
            alert += f" - {pattern}\n"
        alerts.append(alert)

    if potential_obfuscated_js_webshells:
        alert = f"Potential obfuscated JavaScript webshells found in {url}:\n"
        for pattern in potential_obfuscated_js_webshells:
            alert += f" - {pattern}\n"
        alerts.append(alert)

    # Extract and analyze linked JavaScript files
    javascript_links = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', content)
    for js_link in javascript_links:
        js_content = fetch_url_content(js_link)
        if js_content:
            parsed_js_code = parse_javascript_code(js_content)
            potential_js_webshells = find_potential_webshells(parsed_js_code)
            if potential_js_webshells:
                alert = f"Potential webshells/backdoors in JavaScript: {js_link}\n"
                for webshell in potential_js_webshells:
                    matches = re.finditer(webshell, parsed_js_code)
                    for match in matches:
                        location = match.start()
                        context_start = max(0, location - 50)
                        context_end = min(len(parsed_js_code), location + 50)
                        context = parsed_js_code[context_start:context_end]
                        alert += f" - {webshell} (Location: {location})\n"
                        alert += f"   Context: {context}\n"

                        # Save the URL where the webshell is found
                        webshells_found.append(js_link)
                alerts.append(alert)

    if alerts:
        print("\n".join(alerts))

    if webshells_found:
        print("\nURLs with potential webshells/backdoors:")
        print("\n".join(webshells_found))

    save_option = input("Do you want to save the scan results to a file? (y/n): ").lower()
    # if save_option == "yes" or save_option == "Y" or save_option == "y":
    # if save_option in ["yes", "y"]:
    if re.search(r"[yY]|yes|Yes|YES", save_option):
        file_name = input("Enter the file name (e.g., YourURL.txt): ")
        save_to_file(file_name, "\n\n".join(alerts + webshells_found))
        print(f"Scan results saved to '{file_name}'.")

def deep_scan_website_for_webshells(url):
    print(f"Deep scanning {url} for webshells/backdoors...")
    visited_urls = set()

    def recursive_scan(url):
        if url in visited_urls:
            return

        visited_urls.add(url)
        scan_for_webshells(url)

        # Extract subdomains and scan them
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        subdomains = [f"{subdomain}.{parsed_url.netloc}" for subdomain in get_subdomains(parsed_url.netloc)]
        for subdomain in subdomains:
            subdomain_url = f"{parsed_url.scheme}://{subdomain}"
            scan_for_webshells(subdomain_url)

        # Extract paths and scan them
        paths = get_paths(url)
        for path in paths:
            path_url = urljoin(base_url, path)
            scan_for_webshells(path_url)

    def get_subdomains(domain):
        try:
            answers = dns.resolver.resolve(domain, 'A')
            subdomains = [rdata.to_text() for rdata in answers]
        except:
            subdomains = [f"{subdomain}.{domain}" for subdomain in socket.gethostbyname_ex(domain)[1]]
        return subdomains

    def get_paths(url):
        paths = []
        content = fetch_url_content(url)
        if content:
            soup = BeautifulSoup(content, "html.parser")
            links = soup.find_all("a")
            for link in links:
                href = link.get("href")
                if href:
                    full_url = urljoin(url, href)
                    paths.append(full_url)
        return paths

    recursive_scan(url)

if __name__ == "__main__":
    __author__ = "Xnuvers007"
    __version__ = "3.1.5"
    __description__ = "Deep scan a website for webshells/backdoors, Created by Xnuvers007.\nThis code script will check the website for backdoors or web shells by checking the Javascript and PHP code. whether it is obfuscated or not. Javascript has malicious code such as clickjacking, cross-site scripting (XSS), and RCE. just like PHP, but PHP is much stronger if malicious code is inserted." 
    __timescan__ = time.strftime("%d-%m-%Y %H:%M:%S")
    banner = f"""
+-+-+-+-+-+-+-+-+-+-+
|X|n|u|v|e|r|s|0|0|7|
+-+-+-+-+-+-+-+-+-+-+
author: {__author__}
version: {__version__}
Github: https://github.com/Xnuvers007
Description: {__description__}
Time: {__timescan__}
"""
    try:
        website_url = input("Enter the URL of the website to scan: ")
    except:
        # exit in 3 seconds
        for i in range(3, 0, -1):
            print(f"Exiting in {i} seconds...")
            time.sleep(1)
        exit()
    deep_scan_website_for_webshells(website_url)
