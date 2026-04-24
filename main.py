"""
main.py - WifiShield: WiFi Security Auditor
Based on Lecture 7 (Chapter 11: Hacking Wireless Networks) and
Lecture 8 (Gaining Access: Exploitation).

Run with: python main.py
Requires: pip install rich jinja2
"""

import sys
import os
import time

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.text import Text
    from rich import box
    from rich.columns import Columns
    from rich.rule import Rule
    from rich.prompt import Prompt, Confirm
except ImportError:
    print("Please install dependencies: pip install rich jinja2")
    sys.exit(1)

# Add modules path
sys.path.insert(0, os.path.dirname(__file__))

from modules.scanner import scan_networks
from modules.encryption_audit import audit_encryption
from modules.ssid_checker import check_ssid, check_broadcast
from modules.wps_detector import detect_wps
from modules.mac_auditor import audit_mac_addresses, load_whitelist, save_whitelist, get_connected_devices
from modules.hidden_network_detector import detect_hidden_networks
from modules.scorer import score_all_networks
from modules.report_gen import generate_report, open_report

console = Console()

BANNER = r"""
 __        ___  __ _   ____  _     _      _     _
 \ \      / (_)/ _(_) / ___|| |__ (_) ___| | __| |
  \ \ /\ / /| | |_| | \___ \| '_ \| |/ _ \ |/ _` |
   \ V  V / | |  _| |  ___) | | | | |  __/ | (_| |
    \_/\_/  |_|_| |_| |____/|_| |_|_|\___|_|\__,_|
"""


def show_banner():
    console.print(
        Panel(
            f"[bold blue]{BANNER}[/bold blue]\n"
            "[dim]WiFi Security Auditor — Based on Lecture 7: Chapter 11 & Lecture 8[/dim]\n"
            "[dim]Concepts: WEP/TKIP/WPA2-AES, Default SSIDs (Table 11-1), WPS, MAC Filtering[/dim]",
            border_style="blue",
            padding=(1, 4)
        )
    )


def run_scan() -> tuple:
    """Run all scanning and analysis modules."""
    console.print()
    console.print(Rule("[bold cyan]Running Security Audit[/bold cyan]"))
    console.print()

    steps = [
        ("Scanning nearby access points (netsh wlan)...", "AP Scan"),
        ("Checking encryption protocols (WEP/TKIP/WPA2)...", "Encryption"),
        ("Checking SSID broadcast & default SSIDs...", "SSID Check"),
        ("Detecting WPS vulnerability...", "WPS Detect"),
        ("Detecting hidden/cloaked networks...", "Hidden Nets"),
        ("Scanning network devices (ARP table)...", "MAC Audit"),
        ("Calculating security scores...", "Scoring"),
    ]

    with Progress(
        SpinnerColumn(spinner_name="dots", style="bold blue"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30, style="blue", complete_style="green"),
        TextColumn("[green]{task.fields[status]}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("Initializing...", total=len(steps), status="")

        # Step 1: Scan
        progress.update(task, description=steps[0][0], status="")
        networks = scan_networks()
        time.sleep(0.5)
        progress.advance(task)

        # Step 2: Encryption audit
        progress.update(task, description=steps[1][0], status=f"{len(networks)} APs found")
        networks = audit_encryption(networks)
        time.sleep(0.3)
        progress.advance(task)

        # Step 3: SSID checks
        progress.update(task, description=steps[2][0], status="")
        networks = check_ssid(networks)
        networks = check_broadcast(networks)
        time.sleep(0.3)
        progress.advance(task)

        # Step 4: WPS
        progress.update(task, description=steps[3][0], status="")
        networks = detect_wps(networks)
        time.sleep(0.3)
        progress.advance(task)

        # Step 5: Hidden networks
        progress.update(task, description=steps[4][0], status="")
        hidden_audit = detect_hidden_networks()
        time.sleep(0.5)
        progress.advance(task)

        # Step 6: MAC audit
        progress.update(task, description=steps[5][0], status="")
        mac_audit = audit_mac_addresses()
        time.sleep(0.3)
        progress.advance(task)

        # Step 7: Score
        progress.update(task, description=steps[6][0], status="")
        networks = score_all_networks(networks)
        time.sleep(0.3)
        progress.advance(task)

    console.print(f"  [bold green]✓[/bold green] Scan complete — [bold]{len(networks)}[/bold] networks | [cyan]{hidden_audit['total_detected']}[/cyan] hidden detected")
    console.print()
    return networks, mac_audit, hidden_audit


def display_results(networks: list, mac_audit: dict, hidden_audit: dict):
    """Display results in rich terminal tables."""

    # ── AP Table ──────────────────────────────────
    console.print(Rule("[bold]📡 Wireless Network Security Audit[/bold]"))
    console.print()

    if not networks:
        console.print("[yellow]  No networks found. Make sure WiFi is enabled.[/yellow]")
    else:
        table = Table(
            box=box.ROUNDED,
            border_style="dim blue",
            show_header=True,
            header_style="bold cyan",
            padding=(0, 1)
        )
        table.add_column("SSID", style="bold white", min_width=20)
        table.add_column("BSSID", style="dim", min_width=17)
        table.add_column("Ch", justify="center", style="cyan")
        table.add_column("Signal", justify="center")
        table.add_column("Security", min_width=20)
        table.add_column("Enc Risk", justify="center")
        table.add_column("Score", justify="center")
        table.add_column("Issues", min_width=18)

        for ap in sorted(networks, key=lambda x: x.get('security_score', {}).get('score', 50)):
            score_obj = ap.get('security_score', {})
            score = score_obj.get('score', 0)
            risk = ap.get('encryption_risk', 'UNKNOWN')

            # Color coding
            if score < 30:
                score_str = f"[bold red]{score}[/bold red]"
            elif score < 55:
                score_str = f"[bold yellow]{score}[/bold yellow]"
            elif score < 80:
                score_str = f"[bold orange1]{score}[/bold orange1]"
            else:
                score_str = f"[bold green]{score}[/bold green]"

            risk_colors = {
                'CRITICAL': '[bold red]CRITICAL[/bold red]',
                'MEDIUM': '[bold yellow]MEDIUM[/bold yellow]',
                'SAFE': '[bold green]SAFE[/bold green]',
                'UNKNOWN': '[dim]UNKNOWN[/dim]'
            }
            risk_str = risk_colors.get(risk, risk)

            # Issues summary
            issues = []
            if ap.get('is_default_ssid'):
                issues.append('[yellow]Default SSID[/yellow]')
            if ap.get('wps_enabled'):
                issues.append('[red]WPS![/red]')
            if risk == 'CRITICAL':
                issues.append('[red]WEP/Open[/red]')
            elif risk == 'MEDIUM':
                issues.append('[yellow]TKIP[/yellow]')

            table.add_row(
                ap.get('ssid', 'Hidden') or 'Hidden',
                ap.get('bssid', 'N/A'),
                str(ap.get('channel', '?')),
                f"{ap.get('signal_bars', '')} {ap.get('signal', 0)}%",
                f"{ap.get('security', '?')} / {ap.get('encryption', '?')}",
                risk_str,
                score_str,
                ', '.join(issues) if issues else '[green]Clean[/green]'
            )

        console.print(table)

    # ── Hidden Networks Section ───────────────────────────
    console.print()
    console.print(Rule("[bold cyan]🔭 Hidden Network Detection (Cloaked SSID)[/bold cyan]"))
    console.print()
    console.print(f"  [dim]{hidden_audit.get('lecture_note', '')}[/dim]")
    console.print()

    hidden_list = hidden_audit.get('hidden', [])
    if hidden_list:
        h_table = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", padding=(0, 1))
        h_table.add_column("BSSID", style="cyan")
        h_table.add_column("Channel")
        h_table.add_column("Signal")
        h_table.add_column("Auth")
        h_table.add_column("Detection Method", style="dim")
        for h in hidden_list:
            h_table.add_row(
                h.get('bssid', 'N/A'),
                str(h.get('channel', '?')),
                str(h.get('signal', '?')) + '%',
                h.get('auth', 'Unknown'),
                h.get('detection_method', 'passive scan')
            )
        console.print(h_table)
        console.print(f"  [yellow]⚠[/yellow] [dim]{hidden_audit.get('attacker_note', '')}[/dim]")
    else:
        console.print("  [dim]No hidden networks detected in passive scan.[/dim]")
        console.print("  [dim]Note: Active probing (Kismet-style) may detect additional cloaked APs.[/dim]")

    # ── MAC Audit ─────────────────────────────────────────
    console.print()
    console.print(Rule("[bold]🔐 Network Device Audit (MAC Whitelist)[/bold]"))
    console.print()
    console.print(f"  [dim]{mac_audit.get('lecture_note', '')}[/dim]")
    console.print()

    devices_all = (
        mac_audit.get('authorized', []) +
        mac_audit.get('unauthorized', []) +
        mac_audit.get('unknown_status', [])
    )

    if devices_all:
        mac_table = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", padding=(0, 1))
        mac_table.add_column("IP Address", style="cyan")
        mac_table.add_column("MAC Address", style="dim")
        mac_table.add_column("Type")
        mac_table.add_column("Status")

        for d in mac_audit.get('authorized', []):
            mac_table.add_row(d['ip'], d['mac'], d['type'], '[green]✅ Authorized[/green]')
        for d in mac_audit.get('unauthorized', []):
            mac_table.add_row(d['ip'], d['mac'], d['type'], '[bold red]⛔ UNAUTHORIZED[/bold red]')
        for d in mac_audit.get('unknown_status', []):
            mac_table.add_row(d['ip'], d['mac'], d['type'], '[yellow]⚠ No whitelist defined[/yellow]')

        console.print(mac_table)
    else:
        console.print("  [dim]No devices found in ARP table.[/dim]")


def manage_whitelist():
    """Interactive MAC whitelist manager."""
    console.print()
    console.print(Rule("[bold]🔐 MAC Whitelist Manager[/bold]"))
    console.print()
    console.print("[dim]  Based on Lecture 7 Countermeasures: 'Allow only predetermined MAC addresses to access the WLAN'[/dim]")
    console.print()

    whitelist = load_whitelist()
    devices = get_connected_devices()

    console.print(f"  [bold]Current whitelist:[/bold] {len(whitelist)} entries")
    if whitelist:
        for mac in whitelist:
            console.print(f"    [green]✅ {mac}[/green]")
    else:
        console.print("  [yellow]  No whitelist defined yet.[/yellow]")

    console.print()
    console.print("  [bold]Devices currently on your network:[/bold]")
    for d in devices:
        if 'error' not in d:
            in_wl = d['mac'] in whitelist
            status = "[green]✅ whitelisted[/green]" if in_wl else "[yellow]not whitelisted[/yellow]"
            console.print(f"    {d['ip']}  {d['mac']}  — {status}")

    console.print()
    add = Confirm.ask("  Would you like to add a MAC to the whitelist?", default=False)
    if add:
        new_mac = Prompt.ask("  Enter MAC address (format: AA:BB:CC:DD:EE:FF)")
        new_mac = new_mac.upper().strip()
        if new_mac not in whitelist:
            whitelist.append(new_mac)
            save_whitelist(whitelist)
            console.print(f"  [green]✅ Added {new_mac} to whitelist.[/green]")
        else:
            console.print(f"  [yellow]  Already in whitelist.[/yellow]")


def main_menu():
    show_banner()
    console.print()

    while True:
        console.print(Panel(
            "[bold cyan]1[/bold cyan]  Run Full Security Audit\n"
            "[bold cyan]2[/bold cyan]  Manage MAC Whitelist\n"
            "[bold cyan]3[/bold cyan]  Generate HTML Report\n"
            "[bold cyan]4[/bold cyan]  Exit",
            title="[bold]Main Menu[/bold]",
            border_style="dim blue",
            padding=(1, 4)
        ))
        console.print()

        choice = Prompt.ask("  [bold cyan]Select option[/bold cyan]", choices=["1", "2", "3", "4"], default="1")

        if choice == "1":
            networks, mac_audit, hidden_audit = run_scan()
            display_results(networks, mac_audit, hidden_audit)

            console.print()
            if Confirm.ask("  Generate HTML report?", default=True):
                report_path = generate_report(networks, mac_audit, hidden_audit)
                console.print(f"\n  [bold green]✅ Report saved:[/bold green] {report_path}")
                open_report(report_path)

        elif choice == "2":
            manage_whitelist()

        elif choice == "3":
            console.print("  [yellow]Running quick scan to generate report...[/yellow]")
            networks, mac_audit, hidden_audit = run_scan()
            report_path = generate_report(networks, mac_audit, hidden_audit)
            console.print(f"\n  [bold green]✅ Report saved:[/bold green] {report_path}")
            open_report(report_path)

        elif choice == "4":
            console.print("\n  [dim]Goodbye. Stay secure.[/dim]\n")
            sys.exit(0)

        console.print()


if __name__ == '__main__':
    main_menu()
