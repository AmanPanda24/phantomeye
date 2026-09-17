"""
PhantomEye configuration manager.
Stores API keys and settings in ~/.phantomeye/config.json
"""

import json
import os
from pathlib import Path
from dataclasses import dataclass, asdict, field
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

CONFIG_DIR  = Path.home() / ".phantomeye"
CONFIG_FILE = CONFIG_DIR / "config.json"


@dataclass
class Config:
    anthropic_api_key: str = ""
    hibp_api_key:      str = ""
    shodan_api_key:    str = ""
    hunter_api_key:    str = ""
    numverify_api_key: str = ""
    request_delay:    float = 1.0     # seconds between requests
    max_threads:       int = 10
    reports_dir:       str = str(Path.home() / ".phantomeye" / "reports")
    db_path:           str = str(Path.home() / ".phantomeye" / "phantomeye.db")

    @classmethod
    def load(cls) -> "Config":
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        Path(cls().reports_dir).mkdir(parents=True, exist_ok=True)

        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    data = json.load(f)
                return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
            except Exception:
                pass

        obj = cls()
        obj.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY", "")
        obj.hibp_api_key      = os.getenv("HIBP_API_KEY", "")
        obj.shodan_api_key    = os.getenv("SHODAN_API_KEY", "")
        obj.hunter_api_key    = os.getenv("HUNTER_API_KEY", "")
        obj.numverify_api_key = os.getenv("NUMVERIFY_API_KEY", "")
        return obj

    def save(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            json.dump(asdict(self), f, indent=2)

    def display(self):
        table = Table(title="PhantomEye Configuration", box=box.ROUNDED, border_style="cyan")
        table.add_column("Setting", style="bold cyan")
        table.add_column("Value")

        def mask(s: str) -> str:
            return s[:4] + "***" + s[-4:] if len(s) > 10 else ("SET" if s else "[dim]NOT SET[/dim]")

        table.add_row("Anthropic API key",  mask(self.anthropic_api_key))
        table.add_row("HIBP API key",       mask(self.hibp_api_key))
        table.add_row("Shodan API key",     mask(self.shodan_api_key))
        table.add_row("Hunter API key",     mask(self.hunter_api_key))
        table.add_row("NumVerify API key",  mask(self.numverify_api_key))
        table.add_row("Request delay",      f"{self.request_delay}s")
        table.add_row("Max threads",        str(self.max_threads))
        table.add_row("Reports directory",  self.reports_dir)
        table.add_row("Database path",      self.db_path)

        console.print(table)
