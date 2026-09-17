# 👁 PhantomEye

> AI-Powered OSINT Intelligence Framework 
> Reconnaissance. Intelligence. Precision.

```
  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗███████╗██╗   ██╗███████╗
  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║██╔════╝╚██╗ ██╔╝██╔════╝
  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║█████╗   ╚████╔╝ █████╗
  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║██╔══╝    ╚██╔╝  ██╔══╝
  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║███████╗   ██║   ███████╗
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚══════╝
```

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-cyan.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux-purple.svg)](https://www.kali.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Powered by Claude](https://img.shields.io/badge/AI-Claude%20claude--sonnet--4-20250514-orange.svg)](https://anthropic.com)

---

## ✨ Features

| Module | Capability |
|--------|-----------|
| 👤 Username | Enumerate a username across 30+ platforms concurrently |
| 📧 Email | HaveIBeenPwned breach check, Gravatar footprint, domain validation |
| 🌐 IP | Geolocation, ASN, reverse DNS, AbuseIPDB score, optional Shodan scan |
| 🔍 Domain | WHOIS, DNS records, SSL certificate, HTTP headers, tech fingerprinting, subdomain enum |
| 📱 Phone | Carrier lookup, region analysis, line type, OSINT dork generation |
| 🤖 AI Analyst | Claude-powered intelligence synthesis with actionable reports |
| 💾 Persistence | SQLite session history, JSON & HTML report export |

---

## 🚀 Installation (Kali Linux)

```bash

git clone https://github.com/AmanPanda24/phantomeye.git
cd phantomeye

chmod +x install.sh
sudo ./install.sh
```

### Manual Install

```bash
git clone https://github.com/AmanPanda24/phantomeye.git
cd phantomeye

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
pip install -e .

python -m phantomeye.cli --help

phantomeye --help


---

## ⚙️ Configuration

   bash

phantomeye config --anthropic-key sk-ant-...


phantomeye config --hibp-key YOUR_HIBP_KEY          # haveibeenpwned.com
phantomeye config --shodan-key YOUR_SHODAN_KEY       # shodan.io
phantomeye config --hunter-key YOUR_HUNTER_KEY       # hunter.io
phantomeye config --numverify-key YOUR_NUMVERIFY_KEY # numverify.com


phantomeye config --show


Environment variables are also supported:
   bash
export ANTHROPIC_API_KEY="sk-ant-..."
export HIBP_API_KEY="..."
export SHODAN_API_KEY="..."
```

Config is stored at `~/.phantomeye/config.json`.

---

## 📖 Usage

### Username Enumeration

   bash
# Basic scan
phantomeye username johndoe

# With HTML report + AI analysis
phantomeye username johndoe --output html

# Both JSON and HTML, skip AI
phantomeye username johndoe --output both --no-ai

# Custom timeout (seconds per request)
phantomeye username johndoe --timeout 15


### Email OSINT

   bash
phantomeye email target@example.com
phantomeye email target@example.com --output html


  What it checks:
- Format validation
- MX records & domain reachability
- Disposable email detection
- HaveIBeenPwned breach lookup
- Hunter.io email verification
- Gravatar profile footprint

### IP Reconnaissance

  bash
# Basic IP recon
phantomeye ip 8.8.8.8

# With Shodan scan (requires Shodan API key)
phantomeye ip 8.8.8.8 --shodan

# Hostname (auto-resolves to IP)
phantomeye ip evil.example.com


What it checks:**
- ipinfo.io geolocation
- ip-api.com (continent, city, ISP, ASN)
- Reverse DNS
- AbuseIPDB confidence score
- Shodan open ports & services (optional)

### Domain Recon

   bash
# Full domain investigation
phantomeye domain example.com

# With subdomain enumeration
phantomeye domain example.com --subdomains

# Generate HTML report
phantomeye domain example.com --output html --subdomains


What it checks:
- WHOIS registration data
- DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA)
- SSL certificate details & SAN domains
- HTTP security headers
- Technology fingerprinting (CMS, CDN, frameworks, analytics)
- Redirect chain analysis
- Subdomain brute force (50 common names)

### Phone OSINT

   bash

phantomeye phone +918976534234

phantomeye phone +917898098745


What it checks:
- Number format validation
- Country, carrier, line type (via phonenumbers library)
- Region description
- NumVerify API lookup
- OSINT dork URL generation

### Session History

bash

phantomeye history

phantomeye history --limit 50


---

## 📊 Output Formats

| Format | Location |
|--------|----------|
| Rich terminal | Always displayed in the console |
| JSON | `~/.phantomeye/reports/phantomeye_<type>_<target>_<ts>.json` |
| HTML | `~/.phantomeye/reports/phantomeye_<type>_<target>_<ts>.html` |

HTML reports include:
- Dark-themed interface
- AI intelligence analysis
- Full raw OSINT data with syntax highlighting

---

## 🤖 AI Analysis

PhantomEye uses Claude claude-sonnet-4-20250514 to transform raw OSINT data into actionable intelligence reports.

Each AI report includes:
- Intelligence Summary — Top findings at a glance
- Pattern Analysis — What the data reveals about the target
- Risk Assessment — Threat indicators and concerns
- Recommended Next Steps — Specific follow-up actions

To enable AI analysis, set your Anthropic API key:
```bash
phantomeye config --anthropic-key sk-ant-YOUR_KEY
```

Use `--no-ai` to skip AI analysis on any command.

---
## 🏗️ Project Structure

```text
phantomeye/
├── phantomeye/
│   ├── __init__.py
│   ├── cli.py                  # Click CLI entry point
│   ├── banner.py               # ASCII art banner
│   ├── config.py               # Config manager (~/.phantomeye/config.json)
│   │
│   ├── modules/
│   │   ├── username_recon.py   # 30+ platform concurrent scanner
│   │   ├── email_recon.py      # HIBP + Hunter + Gravatar
│   │   ├── ip_recon.py         # Geo + ASN + Shodan
│   │   ├── domain_recon.py     # WHOIS + DNS + SSL + tech FP
│   │   ├── phone_recon.py      # Carrier + region + dorks
│   │   └── ai_analyst.py       # Claude API integration
│   │
│   └── utils/
│       ├── database.py          # SQLite session persistence
│       └── reporter.py          # JSON + HTML report generator
│
├── requirements.txt
├── setup.py
├── install.sh                  # Kali Linux one-command installer
└── README.md
```

## 🔑 API Keys Reference

| Service | Free Tier | Get Key |
|---------|-----------|---------|
| **Anthropic** (AI) | Pay-as-you-go | [console.anthropic.com](https://console.anthropic.com) |
| **HaveIBeenPwned** | $3.50/month | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) |
| **Shodan** | Limited free | [shodan.io](https://shodan.io) |
| **Hunter.io** | 25 req/month | [hunter.io](https://hunter.io) |
| **NumVerify** | 250 req/month | [numverify.com](https://numverify.com) |
| **ipinfo.io** | 50k req/month | No key needed |
| **ip-api.com** | 45 req/min | No key needed |
| **Gravatar** | Unlimited | No key needed |

---

## ⚠️ Legal Disclaimer

**PhantomEye is designed for authorized security research, penetration testing, and legitimate OSINT investigations only.**

- Only use PhantomEye against systems and individuals you have **explicit permission** to investigate
- Comply with all applicable laws in your jurisdiction
- The developers are not responsible for misuse of this tool
- OSINT is legal — unauthorized system access is not

---

## 🤝 Contributing

Contributions welcome! To add a new platform to username recon, simply add it to the `PLATFORMS` dictionary in `phantomeye/modules/username_recon.py`:

   python
"NewPlatform": {
    "url": "https://newplatform.com/{}",
    "check": "status",   # or "text"
    "code": 200,         # expected status code
    # "needle": "text",  # if check == "text"
},


---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---
