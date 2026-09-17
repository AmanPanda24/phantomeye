"""
PhantomEye — AI-Powered OSINT Intelligence Framework
Main CLI entry point
"""

import click
import sys
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

from .banner import print_banner
from .config import Config
from .modules.username_recon import UsernameRecon
from .modules.email_recon import EmailRecon
from .modules.ip_recon import IPRecon
from .modules.domain_recon import DomainRecon
from .modules.phone_recon import PhoneRecon
from .modules.ai_analyst import AIAnalyst
from .utils.database import Database
from .utils.reporter import Reporter

console = Console()

@click.group(invoke_without_command=True)
@click.option("--version", is_flag=True, help="Show version and exit")
@click.pass_context
def cli(ctx, version):
    """
    \b
    PhantomEye — AI-Powered OSINT Intelligence Framework
    Reconnaissance. Intelligence. Precision.
    """
    if version:
        console.print("[bold cyan]PhantomEye[/bold cyan] v1.0.0")
        sys.exit(0)
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print(ctx.get_help())

@cli.command("username")
@click.argument("target")
@click.option("--output", "-o", type=click.Choice(["json", "html", "both"]), default="json",
              help="Output format")
@click.option("--no-ai", is_flag=True, help="Skip AI analysis")
@click.option("--timeout", default=10, help="Request timeout in seconds (default: 10)")
def username_cmd(target, output, no_ai, timeout):
    """Enumerate a username across 30+ platforms."""
    print_banner()
    console.rule(f"[bold cyan]Username Recon → [yellow]{target}[/yellow]")

    cfg = Config.load()
    db = Database()
    session_id = db.new_session("username", target)

    recon = UsernameRecon(timeout=timeout)
    results = recon.run(target)
    db.save_results(session_id, results)

    _display_username_results(target, results)

    ai_summary = None
    if not no_ai and cfg.anthropic_api_key:
        console.rule("[bold magenta]AI Analysis")
        analyst = AIAnalyst(api_key=cfg.anthropic_api_key)
        ai_summary = analyst.analyse(
            target_type="username",
            target=target,
            data=results
        )
        console.print(Panel(ai_summary, title="[bold magenta]PhantomEye AI Insight",
                            border_style="magenta"))

    reporter = Reporter(session_id=session_id, target=target, target_type="username")
    reporter.save(results, ai_summary, output)
    db.close()

@cli.command("email")
@click.argument("target")
@click.option("--output", "-o", type=click.Choice(["json", "html", "both"]), default="json")
@click.option("--no-ai", is_flag=True)
def email_cmd(target, output, no_ai):
    """Investigate an email address (HIBP, reputation, social presence)."""
    print_banner()
    console.rule(f"[bold cyan]Email Recon → [yellow]{target}[/yellow]")

    cfg = Config.load()
    db = Database()
    session_id = db.new_session("email", target)

    recon = EmailRecon(hibp_key=cfg.hibp_api_key, hunter_key=cfg.hunter_api_key)
    results = recon.run(target)
    db.save_results(session_id, results)

    _display_generic_results(results)

    ai_summary = None
    if not no_ai and cfg.anthropic_api_key:
        console.rule("[bold magenta]AI Analysis")
        analyst = AIAnalyst(api_key=cfg.anthropic_api_key)
        ai_summary = analyst.analyse(target_type="email", target=target, data=results)
        console.print(Panel(ai_summary, title="[bold magenta]PhantomEye AI Insight",
                            border_style="magenta"))

    Reporter(session_id, target, "email").save(results, ai_summary, output)
    db.close()

@cli.command("ip")
@click.argument("target")
@click.option("--output", "-o", type=click.Choice(["json", "html", "both"]), default="json")
@click.option("--no-ai", is_flag=True)
@click.option("--shodan", is_flag=True, help="Include Shodan scan (requires API key)")
def ip_cmd(target, output, no_ai, shodan):
    """Geolocate and fingerprint an IP address."""
    print_banner()
    console.rule(f"[bold cyan]IP Recon → [yellow]{target}[/yellow]")

    cfg = Config.load()
    db = Database()
    session_id = db.new_session("ip", target)

    recon = IPRecon(shodan_key=cfg.shodan_api_key if shodan else None)
    results = recon.run(target)
    db.save_results(session_id, results)

    _display_generic_results(results)

    ai_summary = None
    if not no_ai and cfg.anthropic_api_key:
        console.rule("[bold magenta]AI Analysis")
        analyst = AIAnalyst(api_key=cfg.anthropic_api_key)
        ai_summary = analyst.analyse(target_type="ip", target=target, data=results)
        console.print(Panel(ai_summary, title="[bold magenta]PhantomEye AI Insight",
                            border_style="magenta"))

    Reporter(session_id, target, "ip").save(results, ai_summary, output)
    db.close()

@cli.command("domain")
@click.argument("target")
@click.option("--output", "-o", type=click.Choice(["json", "html", "both"]), default="json")
@click.option("--no-ai", is_flag=True)
@click.option("--subdomains", is_flag=True, help="Enable subdomain enumeration")
def domain_cmd(target, output, no_ai, subdomains):
    """WHOIS, DNS, SSL, and technology fingerprint a domain."""
    print_banner()
    console.rule(f"[bold cyan]Domain Recon → [yellow]{target}[/yellow]")

    cfg = Config.load()
    db = Database()
    session_id = db.new_session("domain", target)

    recon = DomainRecon()
    results = recon.run(target, enumerate_subdomains=subdomains)
    db.save_results(session_id, results)

    _display_generic_results(results)

    ai_summary = None
    if not no_ai and cfg.anthropic_api_key:
        console.rule("[bold magenta]AI Analysis")
        analyst = AIAnalyst(api_key=cfg.anthropic_api_key)
        ai_summary = analyst.analyse(target_type="domain", target=target, data=results)
        console.print(Panel(ai_summary, title="[bold magenta]PhantomEye AI Insight",
                            border_style="magenta"))

    Reporter(session_id, target, "domain").save(results, ai_summary, output)
    db.close()

@cli.command("phone")
@click.argument("target")
@click.option("--output", "-o", type=click.Choice(["json", "html", "both"]), default="json")
@click.option("--no-ai", is_flag=True)
def phone_cmd(target, output, no_ai):
    """Investigate a phone number (carrier, region, OSINT presence)."""
    print_banner()
    console.rule(f"[bold cyan]Phone Recon → [yellow]{target}[/yellow]")

    cfg = Config.load()
    db = Database()
    session_id = db.new_session("phone", target)

    recon = PhoneRecon(numverify_key=cfg.numverify_api_key)
    results = recon.run(target)
    db.save_results(session_id, results)

    _display_generic_results(results)

    ai_summary = None
    if not no_ai and cfg.anthropic_api_key:
        console.rule("[bold magenta]AI Analysis")
        analyst = AIAnalyst(api_key=cfg.anthropic_api_key)
        ai_summary = analyst.analyse(target_type="phone", target=target, data=results)
        console.print(Panel(ai_summary, title="[bold magenta]PhantomEye AI Insight",
                            border_style="magenta"))

    Reporter(session_id, target, "phone").save(results, ai_summary, output)
    db.close()

@cli.command("history")
@click.option("--limit", default=20, help="Number of sessions to display")
def history_cmd(limit):
    """List past recon sessions from the local database."""
    db = Database()
    sessions = db.list_sessions(limit)
    db.close()

    table = Table(title="Session History", box=box.ROUNDED, border_style="cyan")
    table.add_column("ID", style="dim")
    table.add_column("Type", style="bold cyan")
    table.add_column("Target", style="yellow")
    table.add_column("Timestamp", style="dim")

    for s in sessions:
        table.add_row(str(s["id"]), s["target_type"], s["target"], s["created_at"])

    console.print(table)

@cli.command("config")
@click.option("--anthropic-key", help="Set Anthropic API key")
@click.option("--hibp-key", help="Set HaveIBeenPwned API key")
@click.option("--shodan-key", help="Set Shodan API key")
@click.option("--hunter-key", help="Set Hunter.io API key")
@click.option("--numverify-key", help="Set NumVerify API key")
@click.option("--show", is_flag=True, help="Show current configuration")
def config_cmd(anthropic_key, hibp_key, shodan_key, hunter_key, numverify_key, show):
    """Manage PhantomEye API keys and settings."""
    cfg = Config.load()

    if show:
        cfg.display()
        return

    if anthropic_key:
        cfg.anthropic_api_key = anthropic_key
    if hibp_key:
        cfg.hibp_api_key = hibp_key
    if shodan_key:
        cfg.shodan_api_key = shodan_key
    if hunter_key:
        cfg.hunter_api_key = hunter_key
    if numverify_key:
        cfg.numverify_api_key = numverify_key

    cfg.save()
    console.print("[bold green]✓[/bold green] Configuration saved.")

def _display_username_results(target: str, results: dict):
    platforms = results.get("platforms", {})
    found = [p for p, d in platforms.items() if d.get("status") == "found"]
    not_found = [p for p, d in platforms.items() if d.get("status") == "not_found"]
    uncertain = [p for p, d in platforms.items() if d.get("status") == "uncertain"]

    table = Table(title=f"Username: {target}", box=box.ROUNDED, border_style="cyan")
    table.add_column("Platform", style="bold")
    table.add_column("Status")
    table.add_column("URL", style="dim")

    status_labels = {
        "found":     "[bold green]FOUND[/bold green]",
        "not_found": "[dim]NOT FOUND[/dim]",
        "uncertain": "[yellow]UNCERTAIN (blocked/unreliable)[/yellow]",
    }

    for platform, data in platforms.items():
        status = status_labels.get(data.get("status"), "[dim]NOT FOUND[/dim]")
        url = data.get("url", "—")
        table.add_row(platform, status, url)

    console.print(table)
    console.print(f"\n[bold green]Found:[/bold green] {len(found)}  "
                  f"[dim]Not found:[/dim] {len(not_found)}  "
                  f"[yellow]Uncertain:[/yellow] {len(uncertain)}")
    if uncertain:
        console.print(
            "[dim]Uncertain = the platform blocks automated requests or serves the "
            "same page regardless of username, so its result can't be trusted. "
            "Check those manually.[/dim]"
        )


def _display_generic_results(results: dict):
    for section, data in results.items():
        if not data or not isinstance(data, dict):
            continue
        table = Table(title=section.replace("_", " ").title(),
                      box=box.SIMPLE_HEAVY, border_style="cyan")
        table.add_column("Field", style="bold cyan", no_wrap=True)
        table.add_column("Value")
        for k, v in data.items():
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v) if v else "—"
            table.add_row(str(k).replace("_", " "), str(v) if v else "—")
        console.print(table)


def main():
    cli()


if __name__ == "__main__":
    main()
