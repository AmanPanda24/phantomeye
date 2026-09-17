"""
PhantomEye — Phone Recon Module
Carrier lookup, number validation, region info, and OSINT presence.
"""

import re
from typing import Optional

import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

HEADERS = {"User-Agent": "PhantomEye-OSINT/1.0"}

CC_MAP = {
    "1":  "United States / Canada",
    "7":  "Russia / Kazakhstan",
    "20": "Egypt",
    "27": "South Africa",
    "30": "Greece",
    "31": "Netherlands",
    "32": "Belgium",
    "33": "France",
    "34": "Spain",
    "36": "Hungary",
    "39": "Italy",
    "40": "Romania",
    "41": "Switzerland",
    "43": "Austria",
    "44": "United Kingdom",
    "45": "Denmark",
    "46": "Sweden",
    "47": "Norway",
    "48": "Poland",
    "49": "Germany",
    "51": "Peru",
    "52": "Mexico",
    "54": "Argentina",
    "55": "Brazil",
    "56": "Chile",
    "57": "Colombia",
    "58": "Venezuela",
    "60": "Malaysia",
    "61": "Australia",
    "62": "Indonesia",
    "63": "Philippines",
    "64": "New Zealand",
    "65": "Singapore",
    "66": "Thailand",
    "81": "Japan",
    "82": "South Korea",
    "84": "Vietnam",
    "86": "China",
    "90": "Turkey",
    "91": "India",
    "92": "Pakistan",
    "93": "Afghanistan",
    "94": "Sri Lanka",
    "95": "Myanmar",
    "98": "Iran",
    "212": "Morocco",
    "213": "Algeria",
    "216": "Tunisia",
    "218": "Libya",
    "220": "Gambia",
    "221": "Senegal",
    "234": "Nigeria",
    "254": "Kenya",
    "255": "Tanzania",
    "256": "Uganda",
    "263": "Zimbabwe",
    "966": "Saudi Arabia",
    "971": "UAE",
    "972": "Israel",
    "974": "Qatar",
    "975": "Bhutan",
    "977": "Nepal",
}


class PhoneRecon:
    def __init__(self, numverify_key: str = ""):
        self.numverify_key = numverify_key
        self.session = requests.Session()
        self.session.headers.update(HEADERS)

    def _parse_number(self, number: str) -> dict:
        # Remove all non-digit characters except leading +
        cleaned = re.sub(r"[^\d+]", "", number)
        is_international = cleaned.startswith("+")
        digits_only = cleaned.lstrip("+")

        country = None
        calling_code = None

        if is_international:
            # Try 1, 2, and 3-digit calling codes
            for length in (3, 2, 1):
                code = digits_only[:length]
                if code in CC_MAP:
                    calling_code = code
                    country = CC_MAP[code]
                    break

        return {
            "original":         number,
            "cleaned":          cleaned,
            "is_international": is_international,
            "digits_only":      digits_only,
            "digit_count":      len(digits_only),
            "calling_code":     calling_code,
            "country":          country,
            "format_e164":      f"+{digits_only}" if is_international else None,
        }

    def _phonenumbers_parse(self, number: str) -> dict:
        try:
            import phonenumbers
            from phonenumbers import geocoder, carrier, timezone

            try:
                parsed = phonenumbers.parse(number, None)
            except Exception:
                # Try with + prefix
                parsed = phonenumbers.parse(f"+{number.lstrip('+')}", None)

            is_valid   = phonenumbers.is_valid_number(parsed)
            is_possible = phonenumbers.is_possible_number(parsed)

            region = phonenumbers.region_code_for_number(parsed)

            return {
                "is_valid":    is_valid,
                "is_possible": is_possible,
                "country_code": parsed.country_code,
                "national_number": str(parsed.national_number),
                "region":      region,
                "description": geocoder.description_for_number(parsed, "en"),
                "carrier":     carrier.name_for_number(parsed, "en"),
                "timezones":   list(timezone.time_zones_for_number(parsed)),
                "format_national":     phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
                "format_international": phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "format_e164":         phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.E164),
                "number_type": str(phonenumbers.number_type(parsed)).split(".")[-1],
            }
        except ImportError:
            return {"note": "Install phonenumbers for richer data: pip install phonenumbers"}
        except Exception as e:
            return {"error": str(e)}

    def _numverify(self, number: str) -> dict:
        if not self.numverify_key:
            return {"note": "No NumVerify API key configured — add with: phantomeye config --numverify-key KEY"}
        try:
            resp = self.session.get(
                "http://apilayer.net/api/validate",
                params={
                    "access_key": self.numverify_key,
                    "number":     number,
                    "country_code": "",
                    "format": 1,
                },
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "valid":           data.get("valid"),
                    "number":          data.get("number"),
                    "local_format":    data.get("local_format"),
                    "international_format": data.get("international_format"),
                    "country_prefix":  data.get("country_prefix"),
                    "country_code":    data.get("country_code"),
                    "country_name":    data.get("country_name"),
                    "location":        data.get("location"),
                    "carrier":         data.get("carrier"),
                    "line_type":       data.get("line_type"),
                }
            return {"error": f"NumVerify returned {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def _osint_dorks(self, number: str) -> dict:
        """Generate Google dork URLs for manual investigation."""
        e164 = number if number.startswith("+") else f"+{number}"
        national = re.sub(r"[^\d]", "", number)

        dorks = {
            "google_exact":     f"https://www.google.com/search?q=%22{e164}%22",
            "google_national":  f"https://www.google.com/search?q=%22{national}%22",
            "truecaller":       f"https://www.truecaller.com/search/{e164.lstrip('+')}",
            "eyecon":           f"https://eyecon.me/phone-lookup/{national}",
            "sync_me":          f"https://sync.me/search/?number={e164}",
            "numlookup":        f"https://www.numlookup.com/{national}",
            "whitepages":       f"https://www.whitepages.com/phone/{national}",
        }
        return {"dorks": dorks, "note": "Open these URLs in a browser for manual OSINT"}

    def run(self, number: str) -> dict:
        results: dict = {"target": number}

        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                      console=console, transient=True) as prog:
            t = prog.add_task("Parsing number…", total=None)

            results["basic_parse"]    = self._parse_number(number)

            prog.update(t, description="Running phonenumbers analysis…")
            results["phonenumbers"]   = self._phonenumbers_parse(number)

            prog.update(t, description="NumVerify API lookup…")
            results["numverify"]      = self._numverify(number)

            prog.update(t, description="Generating OSINT dorks…")
            results["osint_dorks"]    = self._osint_dorks(number)

        return results
