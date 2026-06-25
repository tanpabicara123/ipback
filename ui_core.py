from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich import box

console = Console()

def get_latency_color(val):
    if val <= 90: return "green"
    elif val <= 170: return "yellow"
    else: return "red"

def draw_main_menu():
    console.clear()
    menu_text = (
        " [bold green]1.[/bold green] Local Scanner\n"
        " [bold yellow]2.[/bold yellow] IP Tracker\n"
        " [bold magenta]3.[/bold magenta] Internet Health Check\n"
        " [bold blue]4.[/bold blue] OSINT Target Analyzer (DNS & Traceroute)\n"
        " [bold red]0.[/bold red] Keluar"
    )
    menu_panel = Panel(
        menu_text,
        title="[bold cyan]IP TOOLS - PYTHON EDITION[/bold cyan]",
        subtitle="[dim]Pilih salah satu opsi[/dim]",
        expand=False,
        box=box.ROUNDED,
        border_style="cyan"
    )
    console.print(menu_panel)

def draw_scan_results(results, my_ip):
    console.print(f"\n[bold green]📍 IP Lokal Anda:[/bold green] {my_ip}")
    console.print(f"[bold cyan]📊 Total Perangkat Terhubung:[/bold cyan] {len(results)}\n")

    table = Table(title="[bold magenta]Hasil Pemindaian Jaringan[/bold magenta]", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Status",     justify="center", style="bold green", min_width=6)
    table.add_column("IP Address", justify="center", style="cyan",       min_width=15)
    table.add_column("Latency",    justify="center",                     min_width=10)

    for row in results:
        ip   = row[0]
        lat  = row[1]
        ttl  = row[2]
        hint = row[3]

        color   = get_latency_color(lat)
        ttl_str = str(ttl) if ttl is not None else "-"

        table.add_row(
            "● UP",
            ip,
            f"[{color}]{lat:.2f} ms[/{color}]"
        )
        table.add_row(
            "",
            f"[dim]Hint: {hint} ({ttl_str})[/dim]",
            ""
        )

    console.print(Align.center(table))

def draw_tracker_results(current_ips, new_ips, gone_ips, last_time, my_ip):
    console.print(f"\n[bold green]📍 IP Lokal Anda:[/bold green] {my_ip}")
    console.print(f"[bold cyan]📈 Status Jaringan:[/bold cyan] {len(current_ips)} Perangkat terhubung.")

    sorted_current = sorted(list(current_ips), key=lambda x: int(x.split('.')[3]))
    current_text = "\n".join([f"[cyan]●[/cyan] {ip}" for ip in sorted_current]) if sorted_current else "[dim]Tidak ada perangkat[/dim]"
    p_current = Panel(current_text, title="[bold cyan]Daftar Perangkat Saat Ini[/bold cyan]", expand=False, box=box.ROUNDED, border_style="cyan")

    new_text = "\n".join([f"[green]●[/green] {ip}" for ip in new_ips]) if new_ips else "[dim]Tidak ada perangkat baru[/dim]"
    p_new = Panel(new_text, title="[bold green]Baru / Masuk[/bold green]", expand=False, box=box.ROUNDED, border_style="green")

    gone_text = "\n".join([f"[red]●[/red] {ip}" for ip in gone_ips]) if gone_ips else "[dim]Tidak ada perangkat keluar[/dim]"
    p_gone = Panel(gone_text, title="[bold red]Terputus / Keluar[/bold red]", expand=False, box=box.ROUNDED, border_style="red")

    console.print("\n")
    console.print(p_current)
    console.print(p_new)
    console.print(p_gone)

    console.print(f"\n[yellow]🕒 Log Terakhir:[/yellow] {last_time}")
    console.print("\n[dim]----------------------------------------[/dim]")

def draw_health_submenu(targets):
    console.clear()
    target_list = "\n".join([f"  [cyan]➜[/cyan] {t}" for t in targets])
    if not targets:
        target_list = "  [dim](Tidak ada target server, silakan edit file!)[/dim]"

    menu_text = (
        f"[bold yellow]Target Server Saat Ini ({len(targets)} Server):[/bold yellow]\n"
        f"{target_list}\n\n"
        " [bold green]1.[/bold green] Mulai Ping & Packet Loss Test\n"
        " [bold cyan]2.[/bold cyan] Mulai Speedtest (Bandwidth Download & Upload)\n"
        " [bold yellow]3.[/bold yellow] Edit Target Server (via Nano)\n"
        " [bold red]0.[/bold red] Kembali ke Menu Utama"
    )
    panel = Panel(menu_text, title="[bold magenta]🌐 Internet Health Check[/bold magenta]", expand=False, box=box.ROUNDED, border_style="magenta")
    console.print(panel)

def draw_health_results(results):
    table = Table(title="[bold magenta]Laporan Kualitas Jaringan Global[/bold magenta]", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Target Server", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Packet Loss", justify="center")
    table.add_column("Rata-rata Ping", justify="center")

    total_loss, total_ping, valid_pings = 0, 0, 0

    for res in results:
        target = res['target']
        loss   = res['loss']
        ping   = res['ping']

        loss_str = f"[green]{loss}%[/green]" if loss == 0 else (f"[yellow]{loss}%[/yellow]" if loss < 100 else f"[red]{loss}%[/red]")

        if loss == 100:
            status_str = "[bold red]DOWN / RTO[/bold red]"
            ping_str   = "[dim]-[/dim]"
        else:
            status_str = "[bold green]UP[/bold green]"
            color      = get_latency_color(ping)
            ping_str   = f"[{color}]{ping:.2f} ms[/{color}]"
            total_ping += ping
            valid_pings += 1

        total_loss += loss
        table.add_row(target, status_str, loss_str, ping_str)

    console.print("\n")
    console.print(Align.center(table))

    avg_total_loss = (total_loss / len(results)) if results else 100
    avg_total_ping = (total_ping / valid_pings) if valid_pings > 0 else 0

    if avg_total_loss == 100:
        health, desc, border = "[bold red]TERPUTUS (Offline)[/bold red]", "Koneksi ISP mati total atau tidak ada akses internet.", "red"
    elif avg_total_loss == 0 and avg_total_ping > 120:
        health, desc, border = "[bold yellow]TIDAK STABIL (Ping Tinggi)[/bold yellow]", "Tidak ada packet loss, tapi rata-rata ping terlalu lambat (>120ms).", "yellow"
    elif avg_total_loss > 25 and avg_total_ping < 50:
        health, desc, border = "[bold yellow]TIDAK STABIL (Loss Parah)[/bold yellow]", "Ping cepat, tapi terlalu banyak paket yang hilang (>25%).", "yellow"
    elif avg_total_loss > 25:
        health, desc, border = "[bold yellow]TIDAK STABIL (Gangguan)[/bold yellow]", "Koneksi buruk dengan packet loss sangat tinggi.", "yellow"
    elif avg_total_loss > 15 and avg_total_ping < 50:
        health, desc, border = "[bold cyan]BAIK (Normal)[/bold cyan]", "Ada packet loss, tapi koneksi tertolong karena ping sangat cepat (<50ms).", "cyan"
    elif avg_total_loss > 15:
        health, desc, border = "[bold yellow]TIDAK STABIL (Loss Sedang)[/bold yellow]", "Packet loss di atas 15% dengan ping yang lambat. Koneksi tidak stabil.", "yellow"
    elif avg_total_loss == 0 and avg_total_ping < 50:
        health, desc, border = "[bold green]SANGAT BAIK[/bold green]", "Koneksi sempurna. 0% Loss dan ping sangat cepat.", "green"
    else:
        health, desc, border = "[bold cyan]BAIK (Normal)[/bold cyan]", "Koneksi internet berjalan normal dan stabil.", "cyan"

    conclusion = Panel(
        f"Kualitas Internet : {health}\nCatatan           : [dim]{desc}[/dim]",
        title="[bold]Kesimpulan Akhir[/bold]",
        box=box.ROUNDED,
        border_style=border,
        expand=False
    )
    console.print("\n")
    console.print(Align.center(conclusion))

def draw_speedtest_results(results):
    dl_results = results.get("download_results", [])
    ul_results = results.get("upload_results",   [])
    avg_dl     = results.get("avg_download",     0.0)
    avg_ul     = results.get("avg_upload",       0.0)
    ping_ms    = results.get("ping",             0.0)

    table = Table(
        title="[bold cyan]Hasil Uji Kecepatan Bandwidth[/bold cyan]",
        box=box.ROUNDED, header_style="bold magenta"
    )
    table.add_column("Provider",  style="cyan",   justify="left",  min_width=12)
    table.add_column("Download",  justify="right", min_width=12)
    table.add_column("Upload",    justify="right", min_width=12)

    for i in range(max(len(dl_results), len(ul_results))):
        dl = dl_results[i] if i < len(dl_results) else {}
        ul = ul_results[i] if i < len(ul_results) else {}

        provider = dl.get("provider") or ul.get("provider") or "-"

        if dl.get("error"):
            dl_str = "[red]✖ Gagal[/red]"
        else:
            dl_mbps = dl.get("mbps", 0.0)
            dl_col  = "green" if dl_mbps >= 10 else ("yellow" if dl_mbps >= 5 else "red")
            dl_str  = f"[{dl_col}]{dl_mbps:.2f} Mbps[/{dl_col}]"

        if ul.get("error"):
            ul_str = "[red]✖ Gagal[/red]"
        else:
            ul_mbps = ul.get("mbps", 0.0)
            ul_col  = "green" if ul_mbps >= 5 else ("yellow" if ul_mbps >= 2 else "red")
            ul_str  = f"[{ul_col}]{ul_mbps:.2f} Mbps[/{ul_col}]"

        table.add_row(provider, dl_str, ul_str)

    table.add_section()
    avg_dl_col = "green" if avg_dl >= 10 else ("yellow" if avg_dl >= 5 else "red")
    avg_ul_col = "green" if avg_ul >= 5  else ("yellow" if avg_ul >= 2 else "red")
    table.add_row(
        "[bold white]Rata-rata[/bold white]",
        f"[bold {avg_dl_col}]{avg_dl:.2f} Mbps[/bold {avg_dl_col}]",
        f"[bold {avg_ul_col}]{avg_ul:.2f} Mbps[/bold {avg_ul_col}]"
    )

    console.print("\n")
    console.print(Align.center(table))

    ping_color = "green" if ping_ms <= 50 else ("yellow" if ping_ms <= 100 else "red")
    ping_panel = Panel(
        f" [bold]Ping ke Cloudflare:[/bold] [{ping_color}]{ping_ms:.2f} ms[/{ping_color}]",
        expand=False,
        border_style=ping_color
    )
    console.print(Align.center(ping_panel))

# ================= OSINT Display Functions =================

def draw_osint_results(results):
    domain  = results.get("domain", "")
    ips     = results.get("ips",    [])
    geo     = results.get("geo",    {})
    ssl_i   = results.get("ssl",   {})
    dns_i   = results.get("dns",   {})
    whois_i = results.get("whois", {})
    http_i  = results.get("http",  {})
    risk_i  = results.get("risk",  {})
    trace   = results.get("trace",  "")
    is_ip   = results.get("is_ip", False)

    console.print(f"\n[bold magenta]{'='*10} Hasil Analisis OSINT: {domain} {'='*10}[/bold magenta]")

    # --- Panel 1: IP Address ---
    ip_text = "\n".join([f" [green]➜[/green] {ip}" for ip in ips]) if ips else "[red]Tidak ada IP ditemukan / Resolusi gagal.[/red]"
    console.print(Panel(ip_text, title="[bold cyan]📡 Daftar IP Address[/bold cyan]", border_style="cyan", expand=False))

    # --- Panel 2: GeoIP ---
    if geo and geo.get("status") == "success":
        geo_text = (
            f" [bold]ISP/ASN  :[/bold] {geo.get('isp', 'N/A')} ({geo.get('as', 'N/A')})\n"
            f" [bold]Lokasi   :[/bold] {geo.get('city', 'N/A')}, {geo.get('regionName', 'N/A')}, {geo.get('country', 'N/A')}\n"
            f" [bold]Koordinat:[/bold] {geo.get('lat', 'N/A')}, {geo.get('lon', 'N/A')}"
        )
        console.print(Panel(geo_text, title="[bold yellow]🌍 GeoIP & Identitas Server[/bold yellow]", border_style="yellow", expand=False))

    # --- Panel 3: SSL Certificate ---
    if ssl_i.get("error"):
        ssl_text = f"[red]⚠  {ssl_i['error']}[/red]"
    else:
        status_map = {
            "valid":   f"[bold green]✔ Valid[/bold green] ({ssl_i.get('days_left', 0)} hari lagi)",
            "warning": f"[bold yellow]⚠ Segera Renew[/bold yellow] ({ssl_i.get('days_left', 0)} hari lagi)",
            "expired": f"[bold red]✖ EXPIRED[/bold red] ({abs(ssl_i.get('days_left', 0))} hari lalu)"
        }
        ssl_status = status_map.get(ssl_i.get("status", ""), "[dim]N/A[/dim]")
        sans_str   = ", ".join(ssl_i.get("sans", [])) if ssl_i.get("sans") else "[dim]N/A[/dim]"
        ssl_text = (
            f" [bold]Status     :[/bold] {ssl_status}\n"
            f" [bold]Issued To  :[/bold] {ssl_i.get('issued_to', 'N/A')}\n"
            f" [bold]Issuer     :[/bold] {ssl_i.get('issuer', 'N/A')}\n"
            f" [bold]Berlaku    :[/bold] {ssl_i.get('not_before', 'N/A')} s/d {ssl_i.get('not_after', 'N/A')}\n"
            f" [bold]SANs       :[/bold] {sans_str}"
        )
    ssl_border = {"valid": "green", "warning": "yellow", "expired": "red", "error": "red"}.get(ssl_i.get("status", "error"), "red")
    console.print(Panel(ssl_text, title="[bold cyan]🔒 SSL Certificate Inspector[/bold cyan]", border_style=ssl_border, expand=False))

    # --- Panel 4: DNS Records ---
    # Kalau mode IP, DNS sengaja dilewati — tampilkan info ringkas, bukan error merah
    if is_ip:
        console.print(Panel(
            "[dim]DNS lookup dilewati — input adalah IP address.[/dim]",
            title="[bold magenta]🔎 DNS Deep Lookup[/bold magenta]",
            border_style="dim", expand=False
        ))
    elif dns_i.get("error"):
        console.print(Panel(
            f"[red]{dns_i['error']}[/red]",
            title="[bold magenta]🔎 DNS Deep Lookup[/bold magenta]",
            border_style="red", expand=False
        ))
    else:
        dns_lines = []
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
            recs = dns_i.get(rtype, [])
            if recs:
                dns_lines.append(f" [bold cyan][{rtype}][/bold cyan]")
                for r in recs:
                    display = r[:65] + "..." if len(r) > 65 else r
                    dns_lines.append(f"   [dim]➜[/dim] {display}")
        spf_str   = "[green]Ada ✔[/green]"      if dns_i.get("spf")   else "[red]Tidak ada ✖[/red]"
        dmarc_str = "[green]Ada ✔[/green]"      if dns_i.get("dmarc") else "[red]Tidak ada ✖[/red]"
        dns_lines.append(f"\n [bold]SPF  :[/bold] {spf_str}   [bold]DMARC:[/bold] {dmarc_str}")
        dns_text = "\n".join(dns_lines) if dns_lines else "[dim]Tidak ada record ditemukan.[/dim]"
        console.print(Panel(dns_text, title="[bold magenta]🔎 DNS Deep Lookup[/bold magenta]", border_style="magenta", expand=False))

    # --- Panel 5: WHOIS ---
    # FIX: Tampilan berbeda untuk mode IP vs Domain
    if whois_i.get("error"):
        whois_text  = f"[red]{whois_i['error']}[/red]"
        whois_title = "[bold yellow]📋 WHOIS[/bold yellow]"
    elif is_ip:
        # Mode IP — tampilkan org / cidr / rir / abuse
        whois_text = (
            f" [bold]Organisasi :[/bold] {whois_i.get('org',     'N/A')}\n"
            f" [bold]Negara     :[/bold] {whois_i.get('country', 'N/A')}\n"
            f" [bold]CIDR/Range :[/bold] {whois_i.get('cidr',    'N/A')}\n"
            f" [bold]RIR        :[/bold] {whois_i.get('rir',     'N/A')}\n"
            f" [bold]Abuse      :[/bold] {whois_i.get('abuse',   'N/A')}\n"
            f" [bold]Sumber     :[/bold] [dim]{whois_i.get('source', 'N/A')}[/dim]"
        )
        whois_title = "[bold yellow]📋 WHOIS IP Info[/bold yellow]"
    else:
        # Mode Domain — tampilkan registrar / owner / dates / age
        age       = whois_i.get("domain_age")
        age_str   = f"{age} tahun" if age is not None else "N/A"
        age_color = "green" if (age and age >= 5) else ("yellow" if (age and age >= 1) else "red")
        whois_text = (
            f" [bold]Registrar  :[/bold] {whois_i.get('registrar',  'N/A')}\n"
            f" [bold]Owner      :[/bold] {whois_i.get('owner',      'N/A')}\n"
            f" [bold]Negara     :[/bold] {whois_i.get('country',    'N/A')}\n"
            f" [bold]Registered :[/bold] {whois_i.get('registered', 'N/A')}\n"
            f" [bold]Expires    :[/bold] {whois_i.get('expires',    'N/A')}\n"
            f" [bold]Usia Domain:[/bold] [{age_color}]{age_str}[/{age_color}]\n"
            f" [bold]Sumber     :[/bold] [dim]{whois_i.get('source', 'N/A')}[/dim]"
        )
        whois_title = "[bold yellow]📋 WHOIS Lookup[/bold yellow]"

    console.print(Panel(whois_text, title=whois_title, border_style="yellow", expand=False))

    # --- Panel 6: HTTP Header Fingerprinting ---
    if http_i.get("error"):
        http_text = f"[red]{http_i['error']}[/red]"
    else:
        cdn     = http_i.get("cdn")
        cdn_str = f"[bold green]{cdn}[/bold green]" if cdn else "[dim]Tidak terdeteksi[/dim]"
        sec     = http_i.get("security_headers", {})
        sec_lines = []
        for hname, hval in sec.items():
            marker = "[green]✔[/green]" if hval else "[red]✖[/red]"
            sec_lines.append(f"   {marker} {hname}")
        http_text = (
            f" [bold]Server     :[/bold] {http_i.get('server', '-')}\n"
            f" [bold]Powered By :[/bold] {http_i.get('powered_by', '-')}\n"
            f" [bold]CDN / WAF  :[/bold] {cdn_str}\n"
            f" [bold]Security Headers:[/bold]\n"
            + "\n".join(sec_lines)
        )
    console.print(Panel(http_text, title="[bold green]🌐 HTTP Header Fingerprinting[/bold green]", border_style="green", expand=False))

    # --- Panel 7: Traceroute ---
    trace_display = trace.strip() if trace.strip() else "[dim]Tidak tersedia.[/dim]"
    console.print(Panel(trace_display, title="[bold green]🗺  Jalur Rute Jaringan (Traceroute)[/bold green]", border_style="green", expand=False))

    # --- Panel 8: Risk Verdict ---
    draw_risk_verdict(risk_i)


def draw_risk_verdict(risk_i):
    if not risk_i:
        return

    risk_level = risk_i.get("risk_level", "N/A")
    risk_color = risk_i.get("risk_color", "white")
    risk_emoji = risk_i.get("risk_emoji", "")
    risk_score = risk_i.get("risk_score", 0)
    issues     = risk_i.get("issues",    [])
    positives  = risk_i.get("positives", [])

    lines = [f" Tingkat Risiko : [{risk_color}]{risk_emoji} {risk_level}[/{risk_color}]  [dim](Score: {risk_score})[/dim]\n"]

    if positives:
        lines.append(" [bold green]✔ Positif:[/bold green]")
        for p in positives:
            lines.append(f"   [green]+[/green] {p}")

    if issues:
        lines.append("\n [bold red]✖ Perhatian:[/bold red]")
        for i in issues:
            lines.append(f"   [red]![/red] {i}")

    verdict_text = "\n".join(lines)
    console.print(Panel(
        verdict_text,
        title=f"[bold {risk_color}]⚡ Risk Verdict[/bold {risk_color}]",
        border_style=risk_color,
        expand=False
    ))


def draw_export_prompt():
    console.print("\n[bold cyan]💾 Export Hasil OSINT?[/bold cyan]")
    console.print("   [bold green]1.[/bold green] Export ke JSON")
    console.print("   [bold yellow]2.[/bold yellow] Export ke TXT")
    console.print("   [bold red]0.[/bold red] Lewati / Tidak export")

    choice = input("\n ➜ Pilih format export [1/2/0]: ").strip()

    if choice == '1':
        return 'json'
    elif choice == '2':
        return 'txt'
    else:
        return None


def draw_export_success(filepath):
    console.print(f"\n[bold green]✅ Hasil berhasil disimpan ke:[/bold green]")
    console.print(f"   [cyan]{filepath}[/cyan]")


def draw_exit():
    console.print("\n[bold green]Terima kasih telah menggunakan tools ini! 🚀[/bold green]\n")
