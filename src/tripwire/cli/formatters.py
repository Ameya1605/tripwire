"""Rich terminal formatting and visualization components for Tripwire CLI."""

import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from tripwire.models.report import DiffResult, RiskSeverity, AuditSummary

# Ensure UTF-8 output encoding on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console(safe_box=True)


def print_banner():
    """Prints the Tripwire CLI header banner."""
    banner_text = Text()
    banner_text.append("[+] TRIPWIRE ", style="bold bright_cyan")
    banner_text.append("| Differential Dynamic Behavioral Analysis (DDBA)\n", style="bold white")
    banner_text.append("Supply Chain Security • Zero Code Inspection • Differential Normalization", style="dim cyan")
    console.print(Panel(banner_text, border_style="cyan", box=box.ROUNDED))


def render_diff_result(res: DiffResult):
    """Renders a comprehensive Rich terminal report for a package diff."""
    # 1. Verdict & Risk Header
    if res.verdict == "BLOCK":
        header_style = "bold white on red"
        badge = "[BLOCKED] HIGH RISK MALICIOUS MUTATION"
    elif res.verdict == "WARN":
        header_style = "bold black on yellow"
        badge = "[WARNING] SUSPICIOUS BEHAVIOR DETECTED"
    else:
        header_style = "bold white on green"
        badge = "[PASSED] BEHAVIOR VERIFIED SAFE"

    console.print()
    console.print(
        Panel(
            f"Package: [bold white]{res.package_name}[/] | [dim]{res.old_version}[/] -> [bold cyan]{res.new_version}[/]\n"
            f"Risk Score: [bold]{res.risk_score}/10.0[/] ({res.severity.value}) | Verdict: [bold]{res.verdict}[/]\n"
            f"[italic]{res.executive_summary}[/]",
            title=f"[{header_style}] {badge} [/{header_style}]",
            border_style="red" if res.verdict == "BLOCK" else ("yellow" if res.verdict == "WARN" else "green"),
            box=box.ROUNDED,
        )
    )

    # 2. Honeytoken Breaches (if any)
    if res.honeytoken_trips:
        console.print()
        console.print("[!] [bold red]CRITICAL: SYNTHETIC CANARY HONEYTOKENS BREACHED[/]")
        ht_table = Table(box=box.HEAVY_EDGE, border_style="red", show_header=True, header_style="bold red")
        ht_table.add_column("Token Type", style="bold white", width=12)
        ht_table.add_column("Decoy Asset Target", style="cyan", width=25)
        ht_table.add_column("Attributed Process", style="yellow", width=20)
        ht_table.add_column("Breach Evidence", style="white")

        for trip in res.honeytoken_trips:
            ht_table.add_row(
                trip.token_type,
                trip.accessed_target,
                f"{trip.process_binary} (PID {trip.pid})",
                trip.evidence_snippet,
            )
        console.print(ht_table)

    # 3. Behavioral Deltas Table
    if res.deltas:
        console.print()
        console.print("[*] [bold cyan]BEHAVIORAL DELTA ANOMALIES (vs BASELINE)[/]")
        delta_table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold bright_white")
        delta_table.add_column("Category", style="bold cyan", width=10)
        delta_table.add_column("Severity", width=10)
        delta_table.add_column("Anomaly Description", width=36)
        delta_table.add_column("Baseline (Old)", style="dim", width=20)
        delta_table.add_column("Observed (New)", style="yellow", width=24)
        delta_table.add_column("MITRE ATT&CK", style="magenta", width=12)

        for d in res.deltas:
            # Color severity
            if d.severity == RiskSeverity.CRITICAL:
                sev_style = "[bold white on red]CRIT[/]"
            elif d.severity == RiskSeverity.HIGH:
                sev_style = "[bold red]HIGH[/]"
            elif d.severity == RiskSeverity.MEDIUM:
                sev_style = "[yellow]MED[/]"
            else:
                sev_style = "[blue]LOW[/]"

            mitre = d.mitre_attack_id or "-"
            delta_table.add_row(
                d.category.upper(),
                sev_style,
                d.summary,
                d.old_state or "-",
                d.new_state or "-",
                mitre,
            )
        console.print(delta_table)

    # 4. Statistical Metrics Box
    console.print()
    metrics_text = Text()
    metrics_text.append(f"* Baseline Syscalls: {res.old_syscall_count:,}   ", style="dim")
    metrics_text.append(f"* Candidate Syscalls: {res.new_syscall_count:,}   ", style="dim")
    pct_filtered = 0.0
    if (res.old_syscall_count + res.new_syscall_count) > 0:
        pct_filtered = round((res.raw_delta_noise_filtered / (res.old_syscall_count + res.new_syscall_count)) * 100, 1)
    metrics_text.append(f"* Noise Filtered: {res.raw_delta_noise_filtered:,} events ({pct_filtered}%)   ", style="bold green")
    metrics_text.append(f"* Isolated Deltas: {res.meaningful_anomalies_count}", style="bold cyan")
    console.print(Panel(metrics_text, title="[dim]Empirical Normalization Telemetry[/dim]", box=box.HORIZONTALS))


def render_audit_summary(audit: AuditSummary):
    """Renders a summary table for package-lock.json audits."""
    console.print()
    console.print(Panel(f"Audit Manifest: [bold cyan]{audit.manifest_path}[/]", box=box.ROUNDED))

    summary_table = Table(box=box.ROUNDED, show_header=True, header_style="bold white")
    summary_table.add_column("Dependency", style="bold cyan")
    summary_table.add_column("Transition", style="dim")
    summary_table.add_column("Risk Score", justify="right")
    summary_table.add_column("Verdict", justify="center")
    summary_table.add_column("Key Behavioral Finding")

    for pkg in audit.packages:
        if pkg.diff_result:
            dr = pkg.diff_result
            verdict_style = "[bold green]PASS[/]" if dr.verdict == "PASS" else ("[bold yellow]WARN[/]" if dr.verdict == "WARN" else "[bold red]BLOCK[/]")
            finding = dr.deltas[0].summary if dr.deltas else "Clean - Matches Baseline"
            summary_table.add_row(
                pkg.package_name,
                f"{pkg.old_version} -> {pkg.new_version}",
                f"{dr.risk_score}/10",
                verdict_style,
                finding,
            )
        else:
            summary_table.add_row(pkg.package_name, f"{pkg.old_version} -> {pkg.new_version}", "-", "[dim]SKIPPED[/]", pkg.error_message or "-")

    console.print(summary_table)
    console.print(
        f"\n[bold]Total Scanned:[/] {audit.total_packages_checked} | "
        f"[green]Clean:[/] {audit.clean_packages} | "
        f"[yellow]Warn:[/] {audit.warn_packages} | "
        f"[red]Blocked:[/] {audit.blocked_packages}\n"
    )
