#!/usr/bin/env python3
"""
scan4xss - Fast Async Browser-Based XSS Scanner
Author : hkmj
Website: www.hemanthkumarmj.com
"""

import asyncio
import json
import signal
import sys
import uuid
import html
import argparse
from datetime import datetime
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from playwright.async_api import async_playwright, TimeoutError as PWTimeout
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TimeElapsedColumn

console = Console()

# ── Global state ──
# NOTE: _print_lock is created inside main() after the event loop starts.
#       Creating asyncio.Lock() at module level causes the overlap bug.
results     = []
_print_lock = None
_skipped    = []     # unreachable URLs logged here
TIMEOUT     = 10000
_SHUTDOWN   = None   # asyncio.Event — created inside main()


# ──────────────────────────────────────────────
# Banner
# ──────────────────────────────────────────────
def show_banner():
    banner = """
                                                   .o                                 
                                                 .d88                                 
     .oooo.o  .ooooo.   .oooo.   ooo. .oo.     .d'888   oooo    ooo  .oooo.o  .oooo.o 
    d88(  "8 d88' `"Y8 `P  )88b  `888P"hkmj  .d'  888    `88b..8P'  d88(  "8 d88(  "8 
    `"hkmj.  888        .oP"888   888   888  88ooo888oo    hkmj'    `"hkmj.  `"hkmj.  
    o.  )88b 888   .o8 d8(  888   888   888       888    .o8"'88b   o.  )88b o.  )88b 
    8""888P' `Y8bod8P' `hkmj""8o o888o o888o     o888o  o88'   888o 8""888P' 8""888P' 
                                                                                      
                                                                                                                                                                            
"""

    console.print(Panel.fit(
        f"[bold cyan]{banner}[/bold cyan]\n"
        "[green]⚡ Fast Async Browser-Based XSS Scanner[/green]\n"
        "[green]⚡ Detects real JavaScript execution using Playwright[/green]\n\n"
        "[yellow]Author:[/yellow] hkmj\n"
        "[blue]www.hemanthkumarmj.com[/blue]",
        border_style="bright_magenta"
    ))


# ──────────────────────────────────────────────
# File loader
# ──────────────────────────────────────────────
def load_file(path: str) -> list:
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [x.strip() for x in f if x.strip()]
        if not lines:
            console.print(f"[red][-] File is empty: {path}[/red]")
            sys.exit(1)
        return lines
    except FileNotFoundError:
        console.print(f"[red][-] File not found: {path}[/red]")
        sys.exit(1)


# ──────────────────────────────────────────────
# URL reachability check
# ──────────────────────────────────────────────
async def is_reachable(url: str, context) -> bool:
    """
    Opens the URL in a temporary page.
    Returns True if page loads (even with errors).
    Returns False on timeout or connection failure.
    """
    page = await context.new_page()
    try:
        await page.goto(url, timeout=8000, wait_until="domcontentloaded")
        return True
    except PWTimeout:
        return False
    except Exception as exc:
        msg = str(exc).lower()
        if any(x in msg for x in ("net::err", "connection", "refused", "not resolve")):
            return False
        return True   # other errors (e.g. HTTP 404) = reachable but error page
    finally:
        try:
            await page.close()
        except Exception:
            pass


# ──────────────────────────────────────────────
# URL builder
# Handles:
#   ?id=1    → injects into each param
#   ?id=     → extracts key, injects value
#   no query → appends ?q=payload
# ──────────────────────────────────────────────
def build_urls(url: str, payload: str) -> list:
    p  = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    built = []

    if not p.query:
        new_qs = {"q": [payload]}
        built.append(urlunparse(p._replace(query=urlencode(new_qs, doseq=True))))
        return built

    if not qs:
        # ?id= style — empty value
        key = p.query.split("=")[0] if "=" in p.query else "q"
        new_qs = {key: [payload]}
        built.append(urlunparse(p._replace(query=urlencode(new_qs, doseq=True))))
        return built

    for key in qs:
        new_qs      = {k: v[:] for k, v in qs.items()}
        new_qs[key] = [payload]
        built.append(urlunparse(p._replace(query=urlencode(new_qs, doseq=True))))

    return built


# ──────────────────────────────────────────────
# Scan worker
# ──────────────────────────────────────────────
async def scan_worker(sem, context, url, payload, progress, task_id):
    async with sem:
        if _SHUTDOWN.is_set():
            progress.update(task_id, advance=1)
            return

        token  = uuid.uuid4().hex[:12]
        marker = f"XSS_{token}"

        if "XSS_TOKEN" in payload:
            final_payload = payload.replace("XSS_TOKEN", marker)
        else:
            final_payload = f"{payload}<script>document.title='{marker}'</script>"

        for test_url in build_urls(url, final_payload):
            if _SHUTDOWN.is_set():
                break

            page      = await context.new_page()
            triggered = False
            method    = None

            # ── Detection 1: dialog ──
            async def on_dialog(dialog):
                nonlocal triggered, method
                try:
                    if marker in dialog.message or not dialog.message:
                        triggered = True
                        method    = "dialog"
                    await dialog.dismiss()
                except Exception:
                    pass

            page.on("dialog", on_dialog)

            try:
                await page.goto(
                    test_url, timeout=TIMEOUT, wait_until="domcontentloaded"
                )
                await page.wait_for_timeout(1500)

                # ── Detection 2: DOM title ──
                if not triggered:
                    try:
                        if marker in await page.title():
                            triggered = True
                            method    = "dom-title"
                    except Exception:
                        pass

                # ── Detection 3: cookie ──
                if not triggered:
                    try:
                        for c in await context.cookies():
                            if marker in c.get("value", ""):
                                triggered = True
                                method    = "cookie"
                                break
                    except Exception:
                        pass

                # ── Detection 4: body text ──
                if not triggered:
                    try:
                        if marker in await page.inner_text("body"):
                            triggered = True
                            method    = "dom-body"
                    except Exception:
                        pass

            except Exception:
                pass  # nav / timeout — already handled by reachability check

            # ── Print result — lock ensures one thread at a time ──
            if triggered:
                async with _print_lock:
                    already = any(r["test_url"] == test_url for r in results)
                    if not already:
                        results.append({
                            "url":      url,
                            "test_url": test_url,
                            "payload":  final_payload,
                            "token":    marker,
                            "method":   method,
                            "status":   "VULNERABLE",
                            "found_at": datetime.now().isoformat(),
                        })
                        # Print as one atomic block — no interleaving possible
                        console.print(
                            f"\n[bold red]🔥 XSS FOUND[/bold red]  "
                            f"[dim]via {method}[/dim]\n"
                            f"  [cyan]URL    :[/cyan] {test_url}\n"
                            f"  [yellow]Payload:[/yellow] {final_payload}\n"
                            f"  [green]Token  :[/green] {marker}\n"
                        )

            try:
                await page.close()
            except Exception:
                pass

        progress.update(task_id, advance=1)


# ──────────────────────────────────────────────
# Reports
# ──────────────────────────────────────────────
def generate_html_report(output: str):
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = ""
    for r in results:
        rows += f"""
        <tr>
            <td><a href="{html.escape(r['test_url'])}" target="_blank">{html.escape(r['test_url'])}</a></td>
            <td>{html.escape(r['payload'])}</td>
            <td>{html.escape(r.get('method','?'))}</td>
            <td style="color:#f87171">{r['status']}</td>
        </tr>"""

    skipped_rows = ""
    for s in _skipped:
        skipped_rows += f"<tr><td>{html.escape(s)}</td></tr>"

    page = f"""<!DOCTYPE html>
<html>
<head>
    <title>scan4xss — XSS Report</title>
    <meta charset="utf-8">
    <style>
        * {{ box-sizing:border-box; margin:0; padding:0; }}
        body  {{ background:#0f172a; color:#e2e8f0; font-family:monospace; padding:2rem; }}
        h1    {{ color:#22c55e; margin-bottom:.4rem; }}
        h2    {{ color:#94a3b8; font-size:1rem; margin:2rem 0 .5rem; }}
        p     {{ color:#94a3b8; margin-bottom:1.5rem; font-size:.85rem; }}
        .badge {{ display:inline-block; background:#1e293b; color:#f87171;
                  border:1px solid #f87171; padding:.2rem .8rem;
                  border-radius:4px; font-size:.85rem; margin-bottom:1.5rem; }}
        .skip  {{ display:inline-block; background:#1e293b; color:#facc15;
                  border:1px solid #facc15; padding:.2rem .8rem;
                  border-radius:4px; font-size:.85rem; margin:0 0 1rem .5rem; }}
        table  {{ width:100%; border-collapse:collapse; margin-bottom:2rem; }}
        th, td {{ border:1px solid #1e293b; padding:.7rem 1rem; text-align:left; }}
        th     {{ background:#1e293b; color:#94a3b8; font-size:.82rem; }}
        tr:hover td {{ background:#1e293b88; }}
        a {{ color:#38bdf8; text-decoration:none; }}
        a:hover {{ text-decoration:underline; }}
        .none {{ color:#64748b; text-align:center; padding:2rem; }}
    </style>
</head>
<body>
    <h1>🔥 scan4xss — XSS Report</h1>
    <p>Generated: {now}</p>
    <span class="badge">{len(results)} Vulnerabilities Found</span>
    {"<span class='skip'>" + str(len(_skipped)) + " Unreachable URLs Skipped</span>" if _skipped else ""}

    <table>
        <thead>
            <tr><th>Test URL</th><th>Payload</th><th>Method</th><th>Status</th></tr>
        </thead>
        <tbody>
            {"<tr><td colspan='4' class='none'>No vulnerabilities found.</td></tr>" if not results else rows}
        </tbody>
    </table>

    {"<h2>⚠️ Unreachable / Skipped URLs</h2><table><thead><tr><th>URL</th></tr></thead><tbody>" + skipped_rows + "</tbody></table>" if _skipped else ""}
</body>
</html>"""

    with open(output, "w", encoding="utf-8") as f:
        f.write(page)
    console.print(f"[bold green]✔ HTML Report : {output}[/bold green]")


def generate_json_report(output: str):
    with open(output, "w", encoding="utf-8") as f:
        json.dump({
            "generated":          datetime.now().isoformat(),
            "total_vulnerable":   len(results),
            "total_skipped":      len(_skipped),
            "skipped_urls":       _skipped,
            "results":            results,
        }, f, indent=2)
    console.print(f"[bold green]✔ JSON Report : {output}[/bold green]")


def save_and_exit(html_out, json_out):
    console.print("\n[yellow][!] Interrupted — saving partial results ...[/yellow]")
    generate_html_report(html_out)
    generate_json_report(json_out)
    sys.exit(0)


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
async def main():
    global _print_lock, _SHUTDOWN, TIMEOUT

    # ── Create lock + shutdown event HERE inside the running event loop ──
    _print_lock = asyncio.Lock()
    _SHUTDOWN   = asyncio.Event()

    parser = argparse.ArgumentParser(
        prog="scan4xss",
        description=(
            "scan4xss — Fast Async Browser-Based XSS Scanner\n"
            "Author: hkmj | www.hemanthkumarmj.com"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
─────────────────────────────────────────────
USAGE EXAMPLES
─────────────────────────────────────────────
  Single URL:
    python scan4xss.py -u "http://site.com/page?id=1" payloads.txt

  URL list file:
    python scan4xss.py -l urls.txt payloads.txt

  Custom threads & output:
    python scan4xss.py -l urls.txt payloads.txt --threads 20 --output my_scan

  Custom timeout:
    python scan4xss.py -u "http://site.com/?q=1" payloads.txt --timeout 15

─────────────────────────────────────────────
PAYLOAD TIP
─────────────────────────────────────────────
  Use XSS_TOKEN as a placeholder in payloads:
    <script>alert('XSS_TOKEN')</script>
    <img src=x onerror=alert('XSS_TOKEN')>

  The scanner replaces XSS_TOKEN with a unique value per test.

─────────────────────────────────────────────
DETECTION METHODS
─────────────────────────────────────────────
  dialog    →  alert/confirm/prompt triggered with token
  dom-title →  document.title contains marker
  cookie    →  document.cookie contains marker
  dom-body  →  marker rendered in page body
─────────────────────────────────────────────
        """
    )

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-u", "--url",  metavar="URL",  help='Single target URL e.g. "http://site.com/page?id=1"')
    target_group.add_argument("-l", "--list", metavar="FILE", help="File with target URLs, one per line")

    parser.add_argument("payloads",           help="File with XSS payloads, one per line")
    parser.add_argument("--threads", type=int, default=15, metavar="N",    help="Concurrent tabs (default: 15)")
    parser.add_argument("--output",  default="report",    metavar="NAME",  help="Output filename without extension (default: report)")
    parser.add_argument("--timeout", type=int, default=10, metavar="SEC",  help="Page load timeout seconds (default: 10)")

    args     = parser.parse_args()
    TIMEOUT  = args.timeout * 1000
    html_out = f"{args.output}.html"
    json_out = f"{args.output}.json"

    show_banner()

    urls     = [args.url.strip()] if args.url else load_file(args.list)
    payloads = load_file(args.payloads)

    mode_label = "Single URL" if args.url else f"URL list  [cyan]{args.list}[/cyan]"
    console.print(f"[green][+] Mode    :[/green] {mode_label}")
    console.print(f"[green][+] Targets :[/green] {len(urls)}")
    console.print(f"[green][+] Payloads:[/green] {len(payloads)}")
    console.print(f"[green][+] Threads :[/green] {args.threads}")
    console.print(f"[green][+] Payloads:[/green] [cyan]{args.payloads}[/cyan]\n")

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: save_and_exit(html_out, json_out))
        except NotImplementedError:
            pass

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True,
                java_script_enabled=True,
            )

            # ── Reachability check — done before scanning ──
            console.print("[dim]Checking URL reachability...[/dim]")
            reachable_urls = []
            for url in urls:
                if await is_reachable(url, context):
                    reachable_urls.append(url)
                else:
                    _skipped.append(url)
                    console.print(f"[yellow][!] Unreachable — skipping: {url}[/yellow]")

            if not reachable_urls:
                console.print("[red][-] No reachable URLs found. Exiting.[/red]")
                await browser.close()
                return

            if _skipped:
                console.print(
                    f"\n[yellow][!] {len(_skipped)} URL(s) skipped, "
                    f"{len(reachable_urls)} URL(s) will be scanned.[/yellow]\n"
                )

            total = len(reachable_urls) * len(payloads)
            console.print(f"[green][+] Total   :[/green] {total} tests\n")

            sem = asyncio.Semaphore(args.threads)

            with Progress(
                "[progress.description]{task.description}",
                BarColumn(),
                "[progress.percentage]{task.percentage:>3.0f}%",
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task_id = progress.add_task("[cyan]Scanning...", total=total)

                tasks = [
                    scan_worker(sem, context, url, payload, progress, task_id)
                    for url in reachable_urls
                    for payload in payloads
                ]
                await asyncio.gather(*tasks)

            await browser.close()

    except KeyboardInterrupt:
        save_and_exit(html_out, json_out)

    # ── Summary ──
    console.print(f"\n[bold]{'─' * 60}[/bold]")
    console.print(
        f"[bold green]Scan complete.[/bold green]  "
        f"Vulnerabilities: [bold red]{len(results)}[/bold red]  "
        f"Skipped: [bold yellow]{len(_skipped)}[/bold yellow]"
    )
    if _skipped:
        for s in _skipped:
            console.print(f"  [yellow]↳ skipped:[/yellow] {s}")
    console.print(f"[bold]{'─' * 60}[/bold]\n")

    generate_html_report(html_out)
    generate_json_report(json_out)


if __name__ == "__main__":
    asyncio.run(main())
