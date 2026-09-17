"""
PhantomEye — Username Recon Module
Checks username availability / existence across 30+ platforms.
"""

import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

console = Console()

# "reliable": True  -> a plain HTTP status check (200 vs 404) is trustworthy for this
#                      site. It actually differentiates real vs fake usernames.
# "reliable": False -> the site is known to return the SAME status code (usually 200,
#                      sometimes 403/429) whether or not the username exists, because
#                      it either serves a JS single-page-app shell or blocks bots
#                      uniformly. Checking status alone here gives a false FOUND or a
#                      false NOT FOUND for every single username, which is exactly the
#                      "same result no matter what I type" bug. These are reported as
#                      UNCERTAIN instead of guessed at.
PLATFORMS = {
    "GitHub":        {"url": "https://github.com/{}", "check": "status", "code": 200, "reliable": True},
    "GitLab":        {"url": "https://gitlab.com/{}", "check": "status", "code": 200, "reliable": True},
    "Twitter/X":     {"url": "https://twitter.com/{}", "check": "status", "code": 200, "reliable": False},
    "Instagram":     {"url": "https://www.instagram.com/{}/", "check": "status", "code": 200, "reliable": False},
    "Reddit":        {"url": "https://www.reddit.com/user/{}/", "check": "status", "code": 200, "reliable": True},
    "TikTok":        {"url": "https://www.tiktok.com/@{}", "check": "status", "code": 200, "reliable": False},
    "YouTube":       {"url": "https://www.youtube.com/@{}", "check": "status", "code": 200, "reliable": False},
    "LinkedIn":      {"url": "https://www.linkedin.com/in/{}", "check": "status", "code": 200, "reliable": False},
    "Pinterest":     {"url": "https://www.pinterest.com/{}", "check": "status", "code": 200, "reliable": True},
    "Twitch":        {"url": "https://www.twitch.tv/{}", "check": "status", "code": 200, "reliable": False},
    "Steam":         {"url": "https://steamcommunity.com/id/{}", "check": "text", "needle": "steamcommunity.com/id/", "reliable": True},
    "Keybase":       {"url": "https://keybase.io/{}", "check": "status", "code": 200, "reliable": True},
    "HackerNews":    {"url": "https://news.ycombinator.com/user?id={}", "check": "text", "needle": "user?id=", "reliable": True},
    "Dev.to":        {"url": "https://dev.to/{}", "check": "status", "code": 200, "reliable": True},
    "Medium":        {"url": "https://medium.com/@{}", "check": "status", "code": 200, "reliable": True},
    "Bitbucket":     {"url": "https://bitbucket.org/{}", "check": "status", "code": 200, "reliable": True},
    "Codepen":       {"url": "https://codepen.io/{}", "check": "status", "code": 200, "reliable": True},
    "TryHackMe":     {"url": "https://tryhackme.com/p/{}", "check": "status", "code": 200, "reliable": True},
    "Replit":        {"url": "https://replit.com/@{}", "check": "status", "code": 200, "reliable": True},
    "Mastodon":      {"url": "https://mastodon.social/@{}", "check": "status", "code": 200, "reliable": True},
    "Telegram":      {"url": "https://t.me/{}", "check": "status", "code": 200, "reliable": False},
    "Pastebin":      {"url": "https://pastebin.com/u/{}", "check": "text", "needle": "pastebin.com/u/", "reliable": True},
    "VK":            {"url": "https://vk.com/{}", "check": "status", "code": 200, "reliable": False},
    "Flickr":        {"url": "https://www.flickr.com/people/{}", "check": "status", "code": 200, "reliable": True},
    "Behance":       {"url": "https://www.behance.net/{}", "check": "status", "code": 200, "reliable": True},
    "Dribbble":      {"url": "https://dribbble.com/{}", "check": "status", "code": 200, "reliable": True},
    "Soundcloud":    {"url": "https://soundcloud.com/{}", "check": "status", "code": 200, "reliable": True},
    "Spotify":       {"url": "https://open.spotify.com/user/{}", "check": "status", "code": 200, "reliable": True},
    "Npmjs":         {"url": "https://www.npmjs.com/~{}", "check": "status", "code": 200, "reliable": False},
    "PyPI":          {"url": "https://pypi.org/user/{}/", "check": "status", "code": 200, "reliable": False},
    "DockerHub":     {"url": "https://hub.docker.com/u/{}", "check": "status", "code": 200, "reliable": True},
    # "HackTheBox" was removed: its URL never contained the username
    # ("https://app.hackthebox.com/profile/overview" was a constant, hardcoded string),
    # so it returned the exact same status for literally every target — a plain bug,
    # not a site-reliability issue. HTB profiles are keyed by numeric ID, not
    # username, so there's no simple per-username URL to check here.
}

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    )
}

# Fingerprints of bot-blocking / challenge pages served by common WAFs and CDNs.
# When we see one of these in the body, the status code (often 200) tells us
# nothing about whether the username exists — we were blocked, not answered.
BLOCK_MARKERS = (
    "client challenge", "just a moment", "attention required",
    "enable javascript and cookies", "captcha", "access denied",
    "request unsuccessful", "perimeterx", "datadome", "cf-browser-verification",
)


@dataclass
class PlatformResult:
    platform: str
    status: str            # "found" | "not_found" | "uncertain"
    url: str
    status_code: Optional[int] = None
    error: Optional[str] = None

    @property
    def found(self) -> bool:
        # kept for backwards compatibility with any code checking .found
        return self.status == "found"


class UsernameRecon:
    def __init__(self, timeout: int = 10, max_workers: int = 15):
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.headers.update(HEADERS)

    def _check_platform(self, username: str, platform: str, cfg: dict) -> PlatformResult:
        url = cfg["url"].format(username)
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            code = resp.status_code

            # Detect bot-blocking / challenge pages regardless of status code —
            # this is what silently broke npm and PyPI: they returned a real-looking
            # status (403, or 200 with a JS challenge body) for EVERY username.
            body_lower = resp.text[:5000].lower() if resp.text else ""
            blocked = any(marker in body_lower for marker in BLOCK_MARKERS)

            if blocked or code == 429:
                status = "uncertain"
            elif not cfg.get("reliable", True):
                # Known-unreliable platform (SPA shell, uniform bot response, etc.):
                # don't claim a confident found/not-found, since the signal doesn't
                # actually vary with the username. Surface it honestly instead of
                # guessing wrong every time.
                status = "uncertain"
            elif cfg["check"] == "status":
                if code == cfg["code"]:
                    status = "found"
                elif code == 404:
                    status = "not_found"
                else:
                    status = "uncertain"
            else:  # text needle
                if code == 404:
                    status = "not_found"
                elif code == 200 and cfg["needle"] in resp.text:
                    status = "found"
                elif code == 200:
                    status = "not_found"
                else:
                    status = "uncertain"

            return PlatformResult(platform=platform, status=status, url=url, status_code=code)
        except requests.exceptions.Timeout:
            return PlatformResult(platform=platform, status="uncertain", url=url, error="timeout")
        except requests.exceptions.ConnectionError:
            return PlatformResult(platform=platform, status="uncertain", url=url, error="connection error")
        except Exception as e:
            return PlatformResult(platform=platform, status="uncertain", url=url, error=str(e))

    def run(self, username: str) -> dict:
        results: dict = {"target": username, "platforms": {}}

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(f"[cyan]Scanning {len(PLATFORMS)} platforms…", total=len(PLATFORMS))

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {
                    executor.submit(self._check_platform, username, name, cfg): name
                    for name, cfg in PLATFORMS.items()
                }
                for future in as_completed(futures):
                    res: PlatformResult = future.result()
                    results["platforms"][res.platform] = {
                        "status": res.status,          # "found" | "not_found" | "uncertain"
                        "found": res.found,             # back-compat convenience flag
                        "url": res.url,
                        "status_code": res.status_code,
                        "error": res.error,
                    }
                    progress.advance(task)

        found_count = sum(1 for d in results["platforms"].values() if d["status"] == "found")
        not_found_count = sum(1 for d in results["platforms"].values() if d["status"] == "not_found")
        uncertain_count = sum(1 for d in results["platforms"].values() if d["status"] == "uncertain")
        results["summary"] = {
            "total_platforms": len(PLATFORMS),
            "found": found_count,
            "not_found": not_found_count,
            "uncertain": uncertain_count,
        }
        return results
