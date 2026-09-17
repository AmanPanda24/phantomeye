"""
PhantomEye — Email Recon Module
HaveIBeenPwned breach check, email format validation,
disposable email detection, and social footprint.
"""

import re
import time
import socket
from typing import Optional

import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "throwaway.email", "yopmail.com", "sharklasers.com", "guerrillamailblock.com",
    "fakeinbox.com", "dispostable.com", "trashmail.com", "trashmail.io",
    "spamgourmet.com", "spamgourmet.net", "maildrop.cc", "burnermail.io",
}

HEADERS = {"User-Agent": "PhantomEye-OSINT/1.0"}


class EmailRecon:
    def __init__(self, hibp_key: str = "", hunter_key: str = ""):
        self.hibp_key   = hibp_key
        self.hunter_key = hunter_key
        self.session = requests.Session()
        self.session.headers.update(HEADERS)

    def _validate_format(self, email: str) -> dict:
        pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
        return {"valid_format": bool(re.match(pattern, email))}

    def _get_domain_info(self, domain: str) -> dict:
        info: dict = {"domain": domain}

        # MX record check
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, "MX")
            info["mx_records"] = [str(r.exchange).rstrip(".") for r in answers]
            info["has_mx"] = True
        except Exception:
            info["mx_records"] = []
            info["has_mx"] = False

        # Disposable check
        info["is_disposable"] = domain.lower() in DISPOSABLE_DOMAINS

        # A record / reachability
        try:
            ip = socket.gethostbyname(domain)
            info["resolved_ip"] = ip
            info["domain_reachable"] = True
        except Exception:
            info["resolved_ip"] = None
            info["domain_reachable"] = False

        return info

    def _check_hibp(self, email: str) -> dict:
        if not self.hibp_key:
            return {"error": "No HIBP API key configured. Run: phantomeye config --hibp-key KEY"}

        headers = {
            "hibp-api-key": self.hibp_key,
            "User-Agent": "PhantomEye-OSINT/1.0",
        }
        try:
            resp = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers=headers,
                timeout=15,
            )
            if resp.status_code == 200:
                breaches = resp.json()
                return {
                    "found_in_breaches": True,
                    "breach_count": len(breaches),
                    "breaches": [
                        {
                            "name": b.get("Name"),
                            "date": b.get("BreachDate"),
                            "pwn_count": b.get("PwnCount"),
                            "data_classes": b.get("DataClasses", []),
                        }
                        for b in breaches
                    ],
                }
            elif resp.status_code == 404:
                return {"found_in_breaches": False, "breach_count": 0, "breaches": []}
            elif resp.status_code == 429:
                return {"error": "Rate limited by HIBP — wait 1 minute and retry"}
            else:
                return {"error": f"HIBP returned HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def _check_hunter(self, email: str) -> dict:
        if not self.hunter_key:
            return {"error": "No Hunter.io API key configured"}
        try:
            resp = requests.get(
                "https://api.hunter.io/v2/email-verifier",
                params={"email": email, "api_key": self.hunter_key},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "status":      data.get("status"),
                    "score":       data.get("score"),
                    "regexp":      data.get("regexp"),
                    "gibberish":   data.get("gibberish"),
                    "disposable":  data.get("disposable"),
                    "webmail":     data.get("webmail"),
                    "mx_records":  data.get("mx_records"),
                    "smtp_server": data.get("smtp_server"),
                    "smtp_check":  data.get("smtp_check"),
                    "accept_all":  data.get("accept_all"),
                    "sources":     [s.get("uri") for s in data.get("sources", [])],
                }
            return {"error": f"Hunter returned HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def _social_footprint(self, email: str) -> dict:
        """Check if email is referenced on Gravatar and similar public services."""
        import hashlib
        email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
        gravatar_url = f"https://www.gravatar.com/{email_hash}.json"

        result: dict = {"gravatar": {}}
        try:
            resp = requests.get(gravatar_url, timeout=10)
            if resp.status_code == 200:
                entry = resp.json().get("entry", [{}])[0]
                result["gravatar"] = {
                    "profile_found": True,
                    "display_name": entry.get("displayName"),
                    "profile_url":  entry.get("profileUrl"),
                    "thumbnail":    entry.get("thumbnailUrl"),
                    "location":     entry.get("currentLocation"),
                    "about_me":     entry.get("aboutMe"),
                    "urls":         [u.get("value") for u in entry.get("urls", [])],
                }
            else:
                result["gravatar"] = {"profile_found": False}
        except Exception:
            result["gravatar"] = {"profile_found": False}

        return result

    def run(self, email: str) -> dict:
        results: dict = {"target": email}

        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                      console=console, transient=True) as prog:
            t = prog.add_task("Validating email format…", total=None)

            results["validation"]    = self._validate_format(email)
            domain = email.split("@")[-1] if "@" in email else ""

            prog.update(t, description="Checking domain…")
            results["domain_info"]   = self._get_domain_info(domain)

            prog.update(t, description="Checking HaveIBeenPwned…")
            results["hibp"]          = self._check_hibp(email)
            time.sleep(1.5)                        # HIBP rate limit courtesy delay

            prog.update(t, description="Checking Hunter.io…")
            results["hunter"]        = self._check_hunter(email)

            prog.update(t, description="Checking social footprint…")
            results["social"]        = self._social_footprint(email)

        return results
