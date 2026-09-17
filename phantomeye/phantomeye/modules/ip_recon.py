"""
PhantomEye — IP Recon Module
Geolocation, ASN lookup, reverse DNS, abuse score, and optional Shodan scan.
"""

import socket
import ipaddress
from typing import Optional

import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

HEADERS = {"User-Agent": "PhantomEye-OSINT/1.0"}


class IPRecon:
    def __init__(self, shodan_key: Optional[str] = None):
        self.shodan_key = shodan_key
        self.session = requests.Session()
        self.session.headers.update(HEADERS)

    def _is_valid_ip(self, ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _is_private(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def _ipinfo(self, ip: str) -> dict:
        try:
            resp = self.session.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "ip":           data.get("ip"),
                    "hostname":     data.get("hostname"),
                    "city":         data.get("city"),
                    "region":       data.get("region"),
                    "country":      data.get("country"),
                    "location":     data.get("loc"),
                    "org":          data.get("org"),
                    "postal":       data.get("postal"),
                    "timezone":     data.get("timezone"),
                }
            return {"error": f"ipinfo.io returned {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def _ipapi(self, ip: str) -> dict:
        try:
            resp = self.session.get(
                f"http://ip-api.com/json/{ip}",
                params={
                    "fields": "status,message,continent,country,regionName,city,"
                              "zip,lat,lon,isp,org,as,asname,reverse,mobile,"
                              "proxy,hosting,query"
                },
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "continent":   data.get("continent"),
                        "country":     data.get("country"),
                        "region":      data.get("regionName"),
                        "city":        data.get("city"),
                        "zip":         data.get("zip"),
                        "latitude":    data.get("lat"),
                        "longitude":   data.get("lon"),
                        "isp":         data.get("isp"),
                        "organization":data.get("org"),
                        "asn":         data.get("as"),
                        "asn_name":    data.get("asname"),
                        "reverse_dns": data.get("reverse"),
                        "is_mobile":   data.get("mobile"),
                        "is_proxy":    data.get("proxy"),
                        "is_hosting":  data.get("hosting"),
                    }
                return {"error": data.get("message", "Unknown error")}
            return {"error": f"ip-api.com returned {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def _abuse_score(self, ip: str) -> dict:
        """Free tier: 1000 req/day without API key for basic check."""
        try:
            resp = self.session.get(
                f"https://api.abuseipdb.com/api/v2/check",
                headers={"Key": "free", "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10,
            )
            # Without a key we still get limited data
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "abuse_score":      data.get("abuseConfidenceScore"),
                    "total_reports":    data.get("totalReports"),
                    "last_reported_at": data.get("lastReportedAt"),
                    "is_whitelisted":   data.get("isWhitelisted"),
                    "usage_type":       data.get("usageType"),
                    "isp":              data.get("isp"),
                    "domain":           data.get("domain"),
                }
            return {"note": "AbuseIPDB requires an API key for full results"}
        except Exception as e:
            return {"error": str(e)}

    def _reverse_dns(self, ip: str) -> dict:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return {"hostname": hostname}
        except Exception:
            return {"hostname": None}

    def _shodan_scan(self, ip: str) -> dict:
        if not self.shodan_key:
            return {"error": "No Shodan API key configured"}
        try:
            resp = self.session.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": self.shodan_key},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "ports":         data.get("ports", []),
                    "hostnames":     data.get("hostnames", []),
                    "os":            data.get("os"),
                    "tags":          data.get("tags", []),
                    "vulns":         list(data.get("vulns", {}).keys()),
                    "last_update":   data.get("last_update"),
                    "country_name":  data.get("country_name"),
                    "city":          data.get("city"),
                    "services": [
                        {
                            "port":    s.get("port"),
                            "proto":   s.get("transport"),
                            "product": s.get("product"),
                            "version": s.get("version"),
                            "cpe":     s.get("cpe"),
                        }
                        for s in data.get("data", [])
                    ],
                }
            elif resp.status_code == 404:
                return {"note": "No Shodan data for this IP"}
            return {"error": f"Shodan returned {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def run(self, ip: str) -> dict:
        results: dict = {"target": ip}

        if not self._is_valid_ip(ip):
            # Try resolving as hostname
            try:
                resolved = socket.gethostbyname(ip)
                results["resolution"] = {"hostname": ip, "resolved_ip": resolved}
                ip = resolved
            except Exception:
                results["error"] = f"'{ip}' is not a valid IP address and could not be resolved"
                return results

        if self._is_private(ip):
            results["note"] = "Private/reserved IP address — limited OSINT available"

        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                      console=console, transient=True) as prog:
            t = prog.add_task("Querying ipinfo.io…", total=None)

            results["ipinfo"]     = self._ipinfo(ip)

            prog.update(t, description="Querying ip-api.com…")
            results["geolocation"] = self._ipapi(ip)

            prog.update(t, description="Checking reverse DNS…")
            results["reverse_dns"] = self._reverse_dns(ip)

            prog.update(t, description="Checking AbuseIPDB…")
            results["abuse"]      = self._abuse_score(ip)

            if self.shodan_key:
                prog.update(t, description="Running Shodan scan…")
                results["shodan"] = self._shodan_scan(ip)

        return results
