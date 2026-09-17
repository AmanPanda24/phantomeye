"""
PhantomEye — Domain Recon Module
WHOIS, DNS records, SSL certificate, HTTP headers, technology fingerprinting,
subdomain enumeration, and redirect chain analysis.
"""

import ssl
import socket
import json
import re
from typing import Optional, List
from datetime import datetime

import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    )
}

COMMON_SUBDOMAINS = [
    "www", "mail", "smtp", "pop", "imap", "ftp", "ns1", "ns2",
    "dev", "staging", "api", "cdn", "static", "assets", "admin",
    "cpanel", "webmail", "blog", "shop", "store", "vpn", "remote",
    "test", "demo", "beta", "portal", "dashboard", "status", "support",
    "docs", "wiki", "git", "gitlab", "jenkins", "jira", "confluence",
    "m", "mobile", "app", "web", "secure", "login", "auth",
]

TECH_SIGNATURES = {
    "X-Powered-By": {
        r"PHP": "PHP",
        r"ASP\.NET": "ASP.NET",
        r"Express": "Express.js",
        r"Next\.js": "Next.js",
    },
    "Server": {
        r"nginx": "Nginx",
        r"Apache": "Apache",
        r"cloudflare": "Cloudflare",
        r"LiteSpeed": "LiteSpeed",
        r"Microsoft-IIS": "IIS",
        r"Caddy": "Caddy",
    },
    "Via": {r"cloudflare": "Cloudflare CDN"},
    "CF-Ray": {r".*": "Cloudflare"},
    "X-Vercel-Id": {r".*": "Vercel"},
    "X-Amz-Cf-Id": {r".*": "AWS CloudFront"},
    "X-GitHub-Request-Id": {r".*": "GitHub Pages"},
    "X-Fastly-Request-ID": {r".*": "Fastly CDN"},
}

BODY_SIGNATURES = {
    r"wp-content|wp-includes": "WordPress",
    r"Powered by Joomla": "Joomla",
    r"drupal\.js|Drupal\.settings": "Drupal",
    r"shopify\.com": "Shopify",
    r"squarespace\.com": "Squarespace",
    r"wix\.com": "Wix",
    r"webflow\.io": "Webflow",
    r"gtag\(|google-analytics\.com": "Google Analytics",
    r"fbq\(|connect\.facebook\.net": "Facebook Pixel",
    r"react\.development|__REACT": "React",
    r"ng-version|angular\.min\.js": "Angular",
    r"vue\.runtime|__VUE__": "Vue.js",
    r"next\.js|__NEXT_DATA__": "Next.js",
    r"nuxt\.js|__nuxt": "Nuxt.js",
    r"stripe\.com/v3": "Stripe",
    r"recaptcha": "Google reCAPTCHA",
}


class DomainRecon:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(HEADERS)

    def _whois(self, domain: str) -> dict:
        try:
            import whois as pythonwhois
            w = pythonwhois.whois(domain)
            creation = w.creation_date
            expiry   = w.expiration_date
            updated  = w.updated_date

            def normalise_date(d):
                if isinstance(d, list):
                    d = d[0]
                return d.isoformat() if isinstance(d, datetime) else str(d) if d else None

            return {
                "registrar":     w.registrar,
                "whois_server":  w.whois_server,
                "created":       normalise_date(creation),
                "expires":       normalise_date(expiry),
                "updated":       normalise_date(updated),
                "name_servers":  [ns.lower() for ns in (w.name_servers or [])] if w.name_servers else [],
                "status":        w.status if isinstance(w.status, list) else [w.status],
                "dnssec":        w.dnssec,
                "registrant_org": getattr(w, "org", None),
                "registrant_country": getattr(w, "country", None),
            }
        except ImportError:
            return {"error": "python-whois not installed. Run: pip install python-whois"}
        except Exception as e:
            return {"error": str(e)}

    def _dns_records(self, domain: str) -> dict:
        records: dict = {}
        try:
            import dns.resolver

            record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                    records[rtype] = [str(r) for r in answers]
                except Exception:
                    records[rtype] = []
        except ImportError:
            # Fallback: basic A record via socket
            try:
                ip = socket.gethostbyname(domain)
                records["A"] = [ip]
                records["note"] = "Install dnspython for full DNS enumeration"
            except Exception:
                records["error"] = "DNS resolution failed"

        return records

    def _ssl_cert(self, domain: str) -> dict:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.create_connection((domain, 443), timeout=10),
                server_hostname=domain,
            ) as s:
                cert = s.getpeercert()

            san_list = []
            for (key, val) in cert.get("subjectAltName", []):
                if key == "DNS":
                    san_list.append(val)

            def parse_cert_date(d: str) -> str:
                try:
                    return datetime.strptime(d, "%b %d %H:%M:%S %Y %Z").isoformat()
                except Exception:
                    return d

            return {
                "subject":      dict(x[0] for x in cert.get("subject", [])),
                "issuer":       dict(x[0] for x in cert.get("issuer", [])),
                "version":      cert.get("version"),
                "serial_number":cert.get("serialNumber"),
                "not_before":   parse_cert_date(cert.get("notBefore", "")),
                "not_after":    parse_cert_date(cert.get("notAfter", "")),
                "san_domains":  san_list,
                "san_count":    len(san_list),
            }
        except ssl.SSLError as e:
            return {"error": f"SSL error: {e}"}
        except Exception as e:
            return {"error": str(e)}

    def _http_probe(self, domain: str) -> dict:
        result: dict = {"headers": {}, "technologies": [], "redirect_chain": [], "status_code": None}
        for scheme in ("https", "http"):
            try:
                resp = self.session.get(
                    f"{scheme}://{domain}",
                    timeout=15,
                    allow_redirects=True,
                )
                result["status_code"]    = resp.status_code
                result["final_url"]      = resp.url
                result["headers"]        = dict(resp.headers)
                result["redirect_chain"] = [r.url for r in resp.history]
                result["content_length"] = len(resp.content)

                # Technology fingerprint
                tech = set()
                for header, patterns in TECH_SIGNATURES.items():
                    hval = resp.headers.get(header, "")
                    for pat, name in patterns.items():
                        if re.search(pat, hval, re.I):
                            tech.add(name)

                body = resp.text[:50_000]  # first 50k chars
                for pat, name in BODY_SIGNATURES.items():
                    if re.search(pat, body, re.I):
                        tech.add(name)

                result["technologies"] = sorted(tech)
                break
            except Exception:
                continue

        return result

    def _enumerate_subdomains(self, domain: str) -> dict:
        found = []
        for sub in COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                found.append({"subdomain": fqdn, "ip": ip})
            except Exception:
                continue
        return {"found": found, "checked": len(COMMON_SUBDOMAINS)}

    def run(self, domain: str, enumerate_subdomains: bool = False) -> dict:
        # Strip protocol if given
        domain = re.sub(r"^https?://", "", domain).split("/")[0]
        results: dict = {"target": domain}

        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                      console=console, transient=True) as prog:
            t = prog.add_task("WHOIS lookup…", total=None)

            results["whois"] = self._whois(domain)

            prog.update(t, description="DNS records…")
            results["dns"] = self._dns_records(domain)

            prog.update(t, description="SSL certificate…")
            results["ssl"] = self._ssl_cert(domain)

            prog.update(t, description="HTTP probe & tech fingerprint…")
            results["http"] = self._http_probe(domain)

            if enumerate_subdomains:
                prog.update(t, description="Subdomain enumeration…")
                results["subdomains"] = self._enumerate_subdomains(domain)

        return results
