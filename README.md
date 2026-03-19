<div align="center">

# 🔥 scan4xss

**Fast Async Browser-Based XSS Scanner**

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)
![Playwright](https://img.shields.io/badge/Playwright-Chromium-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

*Uses a real Chromium browser to detect actual JavaScript execution - not regex, not guessing.*

 **Author:** hkmj · [www.hemanthkumarmj.com](https://www.hemanthkumarmj.com)

</div>

---

## 📸 Preview

```
╭──────────────────────────────────────────────────────────────╮
│  scan4xss - Fast Async Browser-Based XSS Scanner             │
│  ⚡ Detects real JavaScript execution using Playwright      --
│  Author: hkmj  |  www.hemanthkumarmj.com                     │
╰──────────────────────────────────────────────────────────────╯

Checking URL reachability...
[!] Unreachable - skipping: https://dead-site.com/page?id=1

[+] Mode    : URL list  urls.txt
[+] Targets : 2
[+] Payloads: 106
[+] Total   : 212 tests
[+] Threads : 15

Scanning... ████████████████░░░░  80%  0:01:42

🔥 XSS FOUND  via dialog
  URL    : http://site.com/page?id=<script>alert('XSS_a3f9c1b2')<%2Fscript>
  Payload: <script>alert('XSS_a3f9c1b2')</script>
  Token  : XSS_a3f9c1b2

🔥 XSS FOUND  via dom-body
  URL    : http://site.com/page?id=<svg%2Fonload%3Dalert('XSS_7bc2d3e4')>
  Payload: <svg/onload=alert('XSS_7bc2d3e4')>
  Token  : XSS_7bc2d3e4

────────────────────────────────────────────────────────────────
Scan complete.  Vulnerabilities: 2   Skipped: 1
  ↳ skipped: https://dead-site.com/page?id=1
────────────────────────────────────────────────────────────────

✔ HTML Report : report.html
✔ JSON Report : report.json
```

---

## ✨ Features

| Feature | Detail |
|---|---|
| 🌐 **Real browser** | Chromium via Playwright - actual JS execution, not pattern matching |
| 🎯 **Unique token per test** | UUID token per scan - eliminates false positives from site's own alerts |
| 🔍 **4 detection methods** | `dialog` · `dom-title` · `cookie` · `dom-body` |
| 🔗 **Single URL or list** | `-u` for one URL, `-l` for a file of URLs |
| 🌐 **Smart URL injection** | Injects payload into every query param individually |
| ⚠️ **Unreachable URL detection** | Checks reachability before scanning - skips and reports dead URLs |
| 🧵 **`--threads` flag** | Tune concurrency at runtime (default: 15) |
| ⛔ **Clean Ctrl+C** | Saves partial results to HTML + JSON before exit |
| 📄 **HTML + JSON reports** | Both generated after every scan automatically |
| 🔒 **SSL error handling** | `ignore_https_errors=True` - handles broken certs on bug bounty targets |
| 🖨️ **No duplicate output** | `asyncio.Lock()` prevents same finding printing twice |
| 🎨 **Rich terminal UI** | Progress bar, colored output via `rich` |

---

## 📦 Installation

```bash
# 1. Clone
git clone https://github.com/hkmj/scan4xss.git
cd scan4xss

# 2. Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install Playwright browser (one time setup)
playwright install chromium
```

**requirements.txt**
```
playwright
rich
```

---

## 🚀 Usage

### Single URL
```bash
python scan4xss.py -u "http://site.com/page?id=1" payloads.txt
```

### List of URLs from file
```bash
python scan4xss.py -l urls.txt payloads.txt
```

### Custom threads and output name
```bash
python scan4xss.py -l urls.txt payloads.txt --threads 20 --output my_scan
```

### Custom page load timeout
```bash
python scan4xss.py -u "http://site.com/?q=1" payloads.txt --timeout 15
```

### Help
```bash
python scan4xss.py -h
```

---

## ⚙️ CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `-u URL` | - | Single target URL |
| `-l FILE` | - | File with target URLs, one per line |
| `payloads` | required | File with XSS payloads, one per line |
| `--threads N` | `15` | Concurrent browser tabs |
| `--output NAME` | `report` | Output filename without extension |
| `--timeout SEC` | `10` | Page load timeout in seconds |

> `-u` and `-l` are mutually exclusive - use one or the other, not both.

---

## 📝 Input File Format

**urls.txt** - one URL per line:
```
https://testphp.vulnweb.com/listproducts.php?cat=1
http://site.com/search?q=hello&page=1
http://a-plussoft.com/en/products.php?id=
http://site.com/page
```

Supported URL formats:

| URL type | What scan4xss does |
|---|---|
| `?id=1&name=hello` | Injects payload into each param separately |
| `?id=` (empty value) | Extracts key `id`, injects payload |
| No query string | Appends `?q=<payload>` |

---

**payloads.txt** - use `XSS_TOKEN` as a placeholder:
```
<script>alert('XSS_TOKEN')</script>
<img src=x onerror=alert('XSS_TOKEN')>
"><svg/onload=alert('XSS_TOKEN')>
'><script>alert('XSS_TOKEN')</script>
<body onload=alert('XSS_TOKEN')>
<iframe src=javascript:alert('XSS_TOKEN')>
```

> `XSS_TOKEN` is replaced with a unique UUID value per test.
> If your payload doesn't contain `XSS_TOKEN`, a silent DOM title marker is appended automatically.

---

## 🔍 How Detection Works

scan4xss uses **4 detection methods** in order for every test:

```
Payload injected into URL param
           │
           ▼
  1. dialog     →  alert/confirm/prompt fires with our token?
           │
           ▼
  2. dom-title  →  document.title contains our marker?
           │
           ▼
  3. cookie     →  document.cookie contains our marker?
           │
           ▼
  4. dom-body   →  marker visible in rendered page body?
           │
           ▼
     VULNERABLE ✓  or  SAFE ✗
```

**Why unique tokens eliminate false positives:**
- Site shows its own `alert()` on page load → **not flagged** (our token won't be in the message)
- Our payload executes and calls `alert('XSS_a3f9c1')` → **flagged** (token matches)

---

## 📁 Output

After every scan, two report files are generated:

**report.html** - dark-themed table with clickable URLs, payload used, and detection method

**report.json**
```json
{
  "generated": "2025-03-20T14:32:11",
  "total_vulnerable": 2,
  "total_skipped": 1,
  "skipped_urls": ["https://dead-site.com/page?id=1"],
  "results": [
    {
      "url": "http://site.com/page?id=1",
      "test_url": "http://site.com/page?id=<script>...",
      "payload": "<script>alert('XSS_a3f9c1')</script>",
      "token": "XSS_a3f9c1",
      "method": "dialog",
      "status": "VULNERABLE",
      "found_at": "2025-03-20T14:31:05"
    }
  ]
}
```

---

## 🗂️ Project Structure

```
scan4xss/
├── scan4xss.py          # Main scanner (single file)
├── requirements.txt    # Python dependencies
├── README.md           # This file
├── LICENSE             # MIT License
├── urls.txt            # Your target URLs
└── payloads.txt        # Your XSS payloads
```

---

## ⚠️ Disclaimer

> This tool is intended for **authorized security testing, bug bounty programs, and educational purposes only.**
>
> Do **not** use this tool against systems you do not own or have explicit written permission to test. Unauthorized scanning may violate computer crime laws in your jurisdiction (e.g. CFAA, Computer Misuse Act, IT Act 2000).
>
> The author is not responsible for any misuse or damage caused by this tool.

---

## 🤝 Contributing

PRs and issues welcome! Ideas for future versions:

- [ ] Blind XSS support with callback server
- [ ] POST parameter injection
- [ ] Proxy support (`--proxy http://127.0.0.1:8080`)
- [ ] Rate limiting (`--delay 0.5`)
- [ ] Slack / Discord webhook alerts on find
- [ ] DOM source and sink analysis

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for full details.

---

<div align="center">

Made with ❤️ by **hkmj** · [hemanthkumarmj.com](https://www.hemanthkumarmj.com)

If this helped you find a bug, give it a ⭐

</div>
