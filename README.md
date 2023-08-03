# Usage (Penggunaan)

linux/termux = <code>python3 main.py</code> <br />
windows = ```python main.py```

![GAMBARANNYA](https://github.com/Xnuvers007/webshells/assets/62522733/3a6be194-a486-4188-915f-ba32bcece6e3)

# English
# webshells Scanner
The provided code is a Python script that performs a deep scan on a given website to detect potential webshells and backdoors. The script checks both JavaScript and PHP code for suspicious patterns, whether obfuscated or not. It provides information about the server, status code, cookies, content type, date, X-Frame-Options, and X-XSS-Protection headers of the website.

Here is a brief description of the main components of the script:

1. Package Imports:
   - The script imports necessary modules such as `subprocess`, `sys`, `dns`, `socket`, `time`, `random`, `jsbeautifier`, `re`, `requests`, `urlparse`, `urljoin`, and `BeautifulSoup` for URL parsing and web content analysis.

2. User Agents:
   - A list of different user agents is defined to simulate various user agents when making HTTP requests.

3. Function Definitions:
   - `fetch_url_content(url)`: Fetches the content of a given URL, prints some information about the response headers, and returns the text content.
   - `find_potential_webshells(content)`: Scans the given content for potential webshell signatures and additional suspicious patterns, returning a list of matches.
   - `find_potential_backdoors(content)`: Scans the given content for potential PHP backdoor file extensions and returns a list of matches.
   - `parse_javascript_code(code)`: Beautifies and parses JavaScript code to identify suspicious patterns, although the detailed parsing logic is yet to be implemented.
   - `save_to_file(filename, data)`: Saves the given data into a file with the specified filename.

4. Scan Functions:
   - `find_potential_obfuscated_php_webshells(content)`: Scans the given content for potential obfuscated PHP webshell patterns and returns a list of matches.
   - `find_potential_obfuscated_js_webshells(content)`: Scans the given content for potential obfuscated JavaScript webshell patterns and returns a list of matches.
   - `scan_for_webshells(url)`: Performs a webshell scan on the provided URL by fetching its content, scanning for potential webshells, backdoors, obfuscated PHP webshells, and obfuscated JavaScript webshells, and printing the results.

5. Deep Scan Function:
   - `deep_scan_website_for_webshells(url)`: Performs a deep scan on the provided URL, recursively scanning subdomains and paths for potential webshells using the `scan_for_webshells` function.

6. Main Execution:
   - The script prompts the user to enter the URL of the website to scan, and then initiates the deep scan using `deep_scan_website_for_webshells`. The script also displays information about the author, version, description, and timestamp.

Note: The script includes error handling for potential import errors and handles platform-specific package installations (e.g., on Windows and Linux). The script also saves the scan results to a file if the user chooses to do so.

Overall, this script is designed to help website administrators and security professionals detect potential security threats within their websites and take appropriate actions to remove any malicious code or vulnerabilities.

# Indonesia
# pemindai webshells

Kode yang disediakan adalah skrip Python yang melakukan pemindaian mendalam pada situs web tertentu untuk mendeteksi potensi webshells dan pintu belakang. Skrip ini memeriksa kode JavaScript dan PHP untuk mencari pola yang mencurigakan, baik yang dikaburkan atau tidak. Skrip ini menyediakan informasi tentang server, kode status, cookie, jenis konten, tanggal, X-Frame-Options, dan header X-XSS-Protection pada situs web.

Berikut ini adalah penjelasan singkat tentang komponen utama skrip:

1. Impor Paket:
   - Skrip mengimpor modul-modul yang diperlukan seperti `subprocess`, `sys`, `dns`, `socket`, `time`, `random`, `jsbeautifier`, `re`, `request`, `urlparse`, `urljoin`, dan `BeautifulSoup` untuk penguraian URL dan analisis konten web.

2. Agen Pengguna:
   - Daftar agen pengguna yang berbeda didefinisikan untuk mensimulasikan berbagai agen pengguna saat membuat permintaan HTTP.

3. Definisi Fungsi:
   - `fetch_url_content(url)`: Mengambil konten dari URL yang diberikan, mencetak beberapa informasi tentang header respons, dan mengembalikan konten teks.
   - `find_potential_webshells(content)`: Memindai konten yang diberikan untuk mencari tanda tangan webshell potensial dan pola tambahan yang mencurigakan, mengembalikan daftar kecocokan.
   - `find_potential_backdoors(content)`: Memindai konten yang diberikan untuk mencari potensi ekstensi file pintu belakang PHP dan mengembalikan daftar kecocokan.
   - `parsing_javascript_code(kode)`: Mempercantik dan mem-parsing kode JavaScript untuk mengidentifikasi pola yang mencurigakan, meskipun logika penguraian yang terperinci belum diimplementasikan.
   - `save_to_file(nama_file, data)`: Menyimpan data yang diberikan ke dalam file dengan nama file yang ditentukan.

4. Fungsi Pemindaian:
   - `find_potential_obfuscated_php_webshells(content)`: Memindai konten yang diberikan untuk mencari potensi pola webshell PHP yang dikaburkan dan mengembalikan daftar kecocokan.
   - `find_potential_obfuscated_js_webshells(content)`: Memindai konten yang diberikan untuk mencari potensi pola webshell JavaScript yang dikaburkan dan mengembalikan daftar kecocokan.
   - `scan_for_webshells(url)`: Melakukan pemindaian webshell pada URL yang disediakan dengan mengambil kontennya, memindai potensi webshell, pintu belakang, webshell PHP yang dikaburkan, dan webshell JavaScript yang dikaburkan, dan mencetak hasilnya.

5. Fungsi Pemindaian Mendalam:
   - `deep_scan_website_for_webshells(url)`: Melakukan pemindaian mendalam pada URL yang disediakan, secara rekursif memindai subdomain dan jalur untuk webshell potensial menggunakan fungsi `scan_for_webshells`.

6. Eksekusi Utama:
   - Skrip meminta pengguna untuk memasukkan URL situs web yang akan dipindai, lalu memulai pemindaian mendalam menggunakan `deep_scan_website_for_webshells`. Skrip ini juga menampilkan informasi tentang pembuat, versi, deskripsi, dan stempel waktu.

Catatan: Skrip ini mencakup penanganan kesalahan untuk potensi kesalahan impor dan menangani instalasi paket khusus platform (misalnya, pada Windows dan Linux). Skrip ini juga menyimpan hasil pemindaian ke sebuah file jika pengguna memilih untuk melakukannya.

Secara keseluruhan, skrip ini dirancang untuk membantu administrator situs web dan profesional keamanan mendeteksi potensi ancaman keamanan di dalam situs web mereka dan mengambil tindakan yang tepat untuk menghapus kode berbahaya atau kerentanan.
