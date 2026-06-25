import socket
import asyncio
import os
import re
import json
import ssl
import time
import urllib.request
from datetime import datetime
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from ui_core import console

LOG_FILE     = os.path.expanduser("~/.iptracker_log")
TIME_FILE    = os.path.expanduser("~/.iptracker_time")
TARGETS_FILE = os.path.expanduser("~/.iptracker_targets.txt")
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
EXPORTS_DIR  = os.path.join(SCRIPT_DIR, "exports")

def get_my_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

# ================= Logika Local Scanner =================

def parse_ttl(output):
    """Extract TTL value dari output ping dan return device hint.

    Menggunakan normalisasi ke initial TTL terdekat untuk mengurangi
    false detection akibat TTL yang sudah berkurang di tiap hop.
    Standard initial TTL: 64 (Linux/Android/macOS), 128 (Windows), 255 (Router/IoT)
    """
    try:
        match = re.search(r'ttl=(\d+)', output, re.IGNORECASE)
        if match:
            ttl_received = int(match.group(1))

            # Normalisasi ke initial TTL terdekat dari atas
            standard_ttls = [64, 128, 255]
            initial_ttl = min(
                (s for s in standard_ttls if s >= ttl_received),
                default=255
            )

            if initial_ttl == 255:
                return ttl_received, "🔀 Kemungkinan Router/Switch"
            elif initial_ttl == 128:
                return ttl_received, "💻 Kemungkinan Windows"
            else:
                return ttl_received, "📱 Kemungkinan Android/Linux"
    except Exception:
        pass
    return None, "❓ Unknown"

async def get_hostname(ip):
    """Resolve hostname via reverse DNS. Return '-' jika gagal."""
    try:
        result = await asyncio.to_thread(socket.gethostbyaddr, ip)
        hostname = result[0]
        return hostname[:30] + ".." if len(hostname) > 30 else hostname
    except Exception:
        return "-"

async def async_ping_ip(ip):
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "1", "-W", "1", ip,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await proc.communicate()
        if proc.returncode == 0:
            output = stdout.decode()
            start = output.find("time=")
            if start != -1:
                end = output.find(" ms", start)
                time_val = float(output[start+5:end])
                ttl, hint = parse_ttl(output)
                return (ip, time_val, ttl, hint)
        return None
    except Exception:
        return None

async def safe_ping(ip, sem, progress, task_id):
    async with sem:
        result = await async_ping_ip(ip)
        progress.advance(task_id)
        return result

async def run_scan_async(prefix):
    found = []
    ips_to_scan = [f"{prefix}.{i}" for i in range(1, 255)]
    sem = asyncio.Semaphore(25)

    with Progress(
        SpinnerColumn(spinner_name="dots", style="cyan"),
        TextColumn("[bold yellow]Scanning...[/bold yellow]"),
        BarColumn(bar_width=40, style="cyan", complete_style="green"),
        TextColumn("[cyan]({task.completed}/{task.total})[/cyan]"),
        console=console
    ) as progress:
        task_id = progress.add_task("ping", total=len(ips_to_scan))
        tasks = [safe_ping(ip, sem, progress, task_id) for ip in ips_to_scan]
        results = await asyncio.gather(*tasks)
        for result in results:
            if result is not None:
                found.append(result)

    found.sort(key=lambda x: int(x[0].split('.')[3]))
    return found

# ================= Logika Health Check & Speedtest =================

def load_targets():
    if not os.path.exists(TARGETS_FILE):
        default_targets = ["8.8.8.8", "1.1.1.1", "facebook.com", "google.com"]
        with open(TARGETS_FILE, "w") as f:
            f.write("\n".join(default_targets))
    with open(TARGETS_FILE, "r") as f:
        targets = [line.strip() for line in f.read().splitlines() if line.strip()]
    return targets

async def async_wan_ping(target):
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "4", "-W", "1", target,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode('utf-8', errors='ignore')

        packet_loss = 100
        loss_match = re.search(r'(\d+)%\s*packet\s*loss', output)
        if loss_match:
            packet_loss = int(loss_match.group(1))

        avg_ping = 0.0
        if packet_loss < 100:
            ping_match = re.search(r'=\s*[\d\.]+/(?P<avg>[\d\.]+)/', output)
            if ping_match:
                avg_ping = float(ping_match.group('avg'))

        return {"target": target, "loss": packet_loss, "ping": avg_ping}
    except Exception:
        return {"target": target, "loss": 100, "ping": 0.0}

async def run_health_check_async(targets):
    results = []
    with Progress(
        SpinnerColumn(spinner_name="line", style="magenta"),
        TextColumn("[bold magenta]Menguji kestabilan koneksi global (Mohon tunggu 4 detik)...[/bold magenta]"),
        console=console
    ) as progress:
        progress.add_task("wait", total=None)
        tasks = [async_wan_ping(t) for t in targets]
        results = await asyncio.gather(*tasks)
    return results

# URL Provider Speedtest
_CF_DL_URL = "https://speed.cloudflare.com/__down?bytes=10000000"
_CF_UL_URL = "https://speed.cloudflare.com/__up"
_LS_DL_URL = "https://librespeed.snt.utwente.nl/backend/garbage.php?ckSize=10"
_LS_UL_URL = "https://librespeed.snt.utwente.nl/backend/empty.php"

async def _test_download(url, label):
    """Download 10MB dari provider, return kecepatan dalam Mbps."""
    try:
        def do_download():
            req = urllib.request.Request(url, headers={
                'User-Agent':    'Mozilla/5.0 (Linux; Android 10)',
                'Cache-Control': 'no-cache'
            })
            start = time.time()
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
            elapsed = time.time() - start
            size = len(data)
            if elapsed > 0 and size > 0:
                return (size * 8) / (elapsed * 1_000_000)
            return 0.0

        mbps = await asyncio.to_thread(do_download)
        return {"provider": label, "mbps": round(mbps, 2), "error": None}
    except Exception as e:
        return {"provider": label, "mbps": 0.0, "error": str(e)[:60]}

async def _test_upload(url, label):
    """Upload 10MB ke provider, return kecepatan dalam Mbps."""
    try:
        def do_upload():
            # 1MB random diulang 10x — lebih cepat dari os.urandom(10MB)
            # tapi tetap tidak bisa dikompresi server
            chunk = os.urandom(1_000_000)
            data  = chunk * 10
            req = urllib.request.Request(url, data=data, headers={
                'User-Agent':     'Mozilla/5.0 (Linux; Android 10)',
                'Content-Type':   'application/octet-stream',
                'Content-Length': str(len(data)),
                'Cache-Control':  'no-cache'
            })
            start = time.time()
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp.read()
            elapsed = time.time() - start
            if elapsed > 0:
                return (len(data) * 8) / (elapsed * 1_000_000)
            return 0.0

        mbps = await asyncio.to_thread(do_upload)
        return {"provider": label, "mbps": round(mbps, 2), "error": None}
    except Exception as e:
        return {"provider": label, "mbps": 0.0, "error": str(e)[:60]}

async def run_speedtest_async():
    """
    Speed test Opsi B: Cloudflare + LibreSpeed (snt.utwente.nl).
    Download & Upload tiap provider jalan paralel via asyncio.gather.
    Hasil akhir dirata-rata hanya dari provider yang sukses.
    File tidak disimpan ke storage — semua masuk RAM lalu dibuang.
    """
    # Download Test — kedua provider paralel
    console.print(" [bold cyan][ ⬇ ][/bold cyan] [cyan]Menguji Download (Cloudflare + LibreSpeed)...[/cyan]")
    dl_cf, dl_ls = await asyncio.gather(
        _test_download(_CF_DL_URL, "Cloudflare"),
        _test_download(_LS_DL_URL, "LibreSpeed"),
    )
    console.print(" [bold green][ ✔ ][/bold green] [cyan]Download Test (Selesai)[/cyan]")

    # Upload Test — kedua provider paralel
    console.print(" [bold yellow][ ⬆ ][/bold yellow] [yellow]Menguji Upload (Cloudflare + LibreSpeed)...[/yellow]")
    ul_cf, ul_ls = await asyncio.gather(
        _test_upload(_CF_UL_URL, "Cloudflare"),
        _test_upload(_LS_UL_URL, "LibreSpeed"),
    )
    console.print(" [bold green][ ✔ ][/bold green] [yellow]Upload Test (Selesai)[/yellow]")

    # Ping ke Cloudflare sebagai referensi
    console.print(" [bold magenta][ ◎ ][/bold magenta] [magenta]Mengukur Ping...[/magenta]")
    ping_result = await async_wan_ping("speed.cloudflare.com")
    ping_ms = ping_result.get("ping", 0.0)
    console.print(" [bold green][ ✔ ][/bold green] [magenta]Ping (Selesai)[/magenta]")

    # Rata-rata hanya dari provider yang berhasil
    dl_valid = [r for r in [dl_cf, dl_ls] if not r["error"] and r["mbps"] > 0]
    ul_valid = [r for r in [ul_cf, ul_ls] if not r["error"] and r["mbps"] > 0]

    avg_dl = round(sum(r["mbps"] for r in dl_valid) / len(dl_valid), 2) if dl_valid else 0.0
    avg_ul = round(sum(r["mbps"] for r in ul_valid) / len(ul_valid), 2) if ul_valid else 0.0

    return {
        "download_results": [dl_cf, dl_ls],
        "upload_results":   [ul_cf, ul_ls],
        "avg_download":     avg_dl,
        "avg_upload":       avg_ul,
        "ping":             ping_ms,
    }

# ================= OSINT: Helper — Deteksi IP vs Domain =================

def is_ip_address(target):
    """Return True jika target adalah IPv4 address yang valid."""
    try:
        socket.inet_pton(socket.AF_INET, target)
        return True
    except socket.error:
        return False

# ================= OSINT: SSL Inspector =================

async def get_ssl_info(target, is_ip=False):
    """
    Coba koneksi SSL ke port 443.
    is_ip=True → pesan error lebih kontekstual, tidak ada penalty di risk verdict.
    """
    try:
        context = ssl.create_default_context()

        def fetch_ssl():
            with socket.create_connection((target, 443), timeout=5) as sock:
                # Untuk IP, server_hostname tidak di-set agar tidak strict SNI check
                sni = None if is_ip else target
                with context.wrap_socket(sock, server_hostname=sni) as ssock:
                    return ssock.getpeercert()

        cert = await asyncio.to_thread(fetch_ssl)

        subject = dict(x[0] for x in cert.get('subject', []))
        issuer  = dict(x[0] for x in cert.get('issuer', []))

        not_after_ts  = ssl.cert_time_to_seconds(cert.get('notAfter', ''))
        not_before_ts = ssl.cert_time_to_seconds(cert.get('notBefore', ''))

        not_after_dt  = datetime.utcfromtimestamp(not_after_ts)
        not_before_dt = datetime.utcfromtimestamp(not_before_ts)

        days_left = (not_after_dt - datetime.utcnow()).days

        sans = []
        if 'subjectAltName' in cert:
            sans = [v for k, v in cert['subjectAltName'] if k == 'DNS'][:5]

        if days_left < 0:
            status = "expired"
        elif days_left <= 30:
            status = "warning"
        else:
            status = "valid"

        return {
            "issued_to":  subject.get('commonName', 'N/A'),
            "issuer":     issuer.get('organizationName', 'N/A'),
            "not_before": not_before_dt.strftime('%Y-%m-%d'),
            "not_after":  not_after_dt.strftime('%Y-%m-%d'),
            "days_left":  days_left,
            "sans":       sans,
            "status":     status,
            "is_ip":      is_ip,
            "error":      None
        }
    except (ConnectionRefusedError, OSError):
        msg = "Port 443 tidak terbuka (wajar untuk IP publik)" if is_ip else "Port 443 tidak terbuka (tidak support HTTPS)"
        return {"error": msg, "status": "error", "is_ip": is_ip,
                "issued_to": "N/A", "issuer": "N/A", "days_left": 0, "sans": []}
    except ssl.SSLError as e:
        msg = f"SSL Error (IP tidak support HTTPS langsung): {str(e)[:50]}" if is_ip else f"SSL Error: {str(e)[:60]}"
        return {"error": msg, "status": "error", "is_ip": is_ip,
                "issued_to": "N/A", "issuer": "N/A", "days_left": 0, "sans": []}
    except Exception as e:
        return {"error": str(e)[:60], "status": "error", "is_ip": is_ip,
                "issued_to": "N/A", "issuer": "N/A", "days_left": 0, "sans": []}

# ================= OSINT: DNS Deep Lookup =================

async def get_dns_records(domain):
    results = {
        "A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [],
        "spf": False, "dmarc": False, "error": None
    }

    try:
        import dns.resolver
    except ImportError:
        results["error"] = "Library 'dnspython' belum terinstall.\nKetik: pip install dnspython"
        return results

    def fetch_record(rtype):
        try:
            answers = dns.resolver.resolve(domain, rtype)
            if rtype == 'MX':
                return [f"{str(r.exchange).rstrip('.')} (priority {r.preference})" for r in answers]
            elif rtype == 'TXT':
                return [b''.join(r.strings).decode('utf-8', errors='ignore') for r in answers]
            else:
                return [r.to_text() for r in answers]
        except Exception:
            return []

    for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
        results[rtype] = await asyncio.to_thread(fetch_record, rtype)

    results['spf']   = any('v=spf1' in txt.lower() for txt in results.get('TXT', []))

    def fetch_dmarc():
        try:
            dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            return True
        except Exception:
            return False

    results['dmarc'] = await asyncio.to_thread(fetch_dmarc)
    return results

# ================= OSINT: WHOIS Lookup (Hybrid: whois CLI → RDAP fallback) =================
# Untuk domain : whois CLI dulu, fallback ke rdap.org jika CLI gagal/kosong
# Untuk IP     : whois CLI untuk info org/netname/CIDR dari RIR (ARIN/APNIC/RIPE)

def _parse_whois_domain(raw):
    """Parse plain-text whois output untuk domain. Return dict field penting."""

    def _find(patterns, text):
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
            if m:
                val = m.group(1).strip()
                if val and val.lower() not in ('n/a', 'redacted for privacy',
                                                'data protected', 'not disclosed'):
                    return val
        return "N/A"

    registrar  = _find([
        r'Registrar:\s*(.+)',
        r'registrar:\s*(.+)',
        r'Registrar Name:\s*(.+)',
    ], raw)

    owner = _find([
        r'Registrant Organization:\s*(.+)',
        r'Registrant Name:\s*(.+)',
        r'registrant:\s*(.+)',
        r'owner:\s*(.+)',
        r'Organisation:\s*(.+)',
    ], raw)

    country = _find([
        r'Registrant Country:\s*(.+)',
        r'country:\s*(.+)',
        r'Country:\s*(.+)',
    ], raw)

    # Cari tanggal creation — multi format
    registered = _find([
        r'Creation Date:\s*(.+)',
        r'created:\s*(.+)',
        r'Created On:\s*(.+)',
        r'Registration Date:\s*(.+)',
        r'Domain Registration Date:\s*(.+)',
    ], raw)

    # Normalisasi tanggal ke YYYY-MM-DD
    if registered != "N/A":
        registered = registered[:10].replace('/', '-')

    expires = _find([
        r'Registry Expiry Date:\s*(.+)',
        r'Expiry Date:\s*(.+)',
        r'Expiration Date:\s*(.+)',
        r'expires:\s*(.+)',
        r'Registrar Registration Expiration Date:\s*(.+)',
    ], raw)

    if expires != "N/A":
        expires = expires[:10].replace('/', '-')

    # Hitung domain age
    domain_age = None
    if registered != "N/A":
        try:
            reg_dt     = datetime.strptime(registered[:10], '%Y-%m-%d')
            domain_age = (datetime.utcnow() - reg_dt).days // 365
        except Exception:
            pass

    return {
        "registrar":  registrar,
        "registered": registered,
        "expires":    expires,
        "owner":      owner,
        "country":    country,
        "domain_age": domain_age,
        "error":      None,
        "source":     "whois CLI"
    }

def _parse_whois_ip(raw):
    """Parse plain-text whois output untuk IP address. Return dict field penting."""

    def _find(patterns, text):
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
            if m:
                val = m.group(1).strip()
                if val:
                    return val
        return "N/A"

    org = _find([
        r'OrgName:\s*(.+)',
        r'org-name:\s*(.+)',
        r'organisation:\s*(.+)',
        r'Organization:\s*(.+)',
        r'owner:\s*(.+)',
        r'NetName:\s*(.+)',
    ], raw)

    country = _find([
        r'Country:\s*(.+)',
        r'country:\s*(.+)',
    ], raw)

    cidr = _find([
        r'CIDR:\s*(.+)',
        r'inetnum:\s*(.+)',
        r'NetRange:\s*(.+)',
    ], raw)

    # Cari RIR dari whois server yang merespons
    rir = "N/A"
    for name in ('ARIN', 'APNIC', 'RIPE', 'LACNIC', 'AFRINIC'):
        if name.lower() in raw.lower():
            rir = name
            break

    # Abuse contact
    abuse = _find([
        r'OrgAbuseEmail:\s*(.+)',
        r'abuse-mailbox:\s*(.+)',
        r'Abuse contact:\s*(.+)',
    ], raw)

    return {
        "org":     org,
        "country": country,
        "cidr":    cidr,
        "rir":     rir,
        "abuse":   abuse,
        "error":   None,
        "source":  "whois CLI"
    }

async def _whois_cli(target):
    """Jalankan whois command via subprocess. Return raw output atau None jika gagal."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "whois", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await proc.communicate()
        raw = stdout.decode('utf-8', errors='ignore').strip()
        # Anggap gagal kalau output terlalu pendek atau ada pesan error umum
        if len(raw) < 100 or "no match" in raw.lower() or "not found" in raw.lower():
            return None
        return raw
    except FileNotFoundError:
        return None
    except Exception:
        return None

async def _rdap_fallback_domain(domain):
    """Fallback ke rdap.org untuk domain jika whois CLI gagal."""
    try:
        def fetch_rdap():
            req = urllib.request.Request(
                f"https://rdap.org/domain/{domain}",
                headers={'User-Agent': 'Mozilla/5.0 (Linux; Android 10)',
                         'Accept': 'application/rdap+json'}
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                return json.loads(resp.read().decode())

        data = await asyncio.to_thread(fetch_rdap)

        registrar = "N/A"
        owner     = "N/A"
        country   = "N/A"
        for entity in data.get('entities', []):
            roles = entity.get('roles', [])
            vcard = entity.get('vcardArray', [None, []])[1]
            name  = "N/A"
            for field in vcard:
                if field[0] == 'fn':
                    name = field[3]
                    break
            if 'registrar' in roles:
                registrar = name
            if 'registrant' in roles:
                owner = name
                for field in vcard:
                    if field[0] == 'adr':
                        adr_val = field[3]
                        if isinstance(adr_val, list) and len(adr_val) >= 7:
                            country = adr_val[6] or "N/A"
                        break

        registered = "N/A"
        expires    = "N/A"
        for event in data.get('events', []):
            action = event.get('eventAction', '')
            date   = event.get('eventDate', '')[:10]
            if action == 'registration':
                registered = date
            elif action == 'expiration':
                expires = date

        domain_age = None
        if registered != "N/A":
            try:
                reg_dt     = datetime.strptime(registered, '%Y-%m-%d')
                domain_age = (datetime.utcnow() - reg_dt).days // 365
            except Exception:
                pass

        return {
            "registrar":  registrar,
            "registered": registered,
            "expires":    expires,
            "owner":      owner,
            "country":    country,
            "domain_age": domain_age,
            "error":      None,
            "source":     "RDAP"
        }

    except urllib.error.HTTPError as e:
        return {"error": f"RDAP tidak tersedia (HTTP {e.code})",
                "registrar": "N/A", "registered": "N/A", "expires": "N/A",
                "owner": "N/A", "country": "N/A", "domain_age": None, "source": "RDAP"}
    except Exception as e:
        return {"error": f"WHOIS/RDAP gagal: {str(e)[:80]}",
                "registrar": "N/A", "registered": "N/A", "expires": "N/A",
                "owner": "N/A", "country": "N/A", "domain_age": None, "source": "RDAP"}

async def get_whois_info(target, is_ip=False):
    """
    Hybrid WHOIS lookup:
    - Domain : whois CLI → parse → fallback RDAP jika hasil kosong
    - IP     : whois CLI → parse info org/CIDR/RIR
    """
    raw = await _whois_cli(target)

    if is_ip:
        # Mode IP — ambil info organisasi dari whois CLI
        if raw:
            return _parse_whois_ip(raw)
        return {
            "org": "N/A", "country": "N/A", "cidr": "N/A",
            "rir": "N/A", "abuse": "N/A",
            "error": "whois CLI tidak tersedia. Ketik: pkg install whois",
            "source": "whois CLI"
        }
    else:
        # Mode Domain — whois CLI dulu
        if raw:
            parsed = _parse_whois_domain(raw)
            # Cek apakah field penting berhasil diisi
            has_data = any(
                parsed.get(f, "N/A") != "N/A"
                for f in ("registrar", "registered", "owner")
            )
            if has_data:
                return parsed
            # Hasil CLI ada tapi semua field kosong → fallback RDAP
            console.print(" [bold yellow][ ↩ ][/bold yellow] [yellow]whois CLI hasilnya kosong, coba RDAP...[/yellow]")

        # Fallback ke RDAP
        return await _rdap_fallback_domain(target)

# ================= OSINT: HTTP Header Fingerprinting =================
# FIX: Coba HTTP dulu sebelum HTTPS — Cloudflare lebih sering blokir HTTPS bot.
#      Timeout dinaikkan dari 5 ke 8 detik untuk toleransi jaringan seluler.

async def get_http_headers(target):
    try:
        def fetch_headers():
            for scheme in ('http', 'https'):
                try:
                    req = urllib.request.Request(
                        f"{scheme}://{target}",
                        headers={'User-Agent': 'Mozilla/5.0 (Linux; Android 10)'}
                    )
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        return dict(resp.headers)
                except Exception:
                    continue
            raise Exception("Koneksi ke target gagal (HTTP & HTTPS timeout/blokir)")

        headers = await asyncio.to_thread(fetch_headers)
        h = {k.lower(): v for k, v in headers.items()}

        server     = h.get('server', '-')
        powered_by = h.get('x-powered-by', '-')

        security_headers = {
            'X-Frame-Options':         'x-frame-options' in h,
            'Strict-Transport-Sec':    'strict-transport-security' in h,
            'Content-Security-Policy': 'content-security-policy' in h,
            'X-Content-Type-Options':  'x-content-type-options' in h,
        }

        cdn = None
        srv = server.lower()
        if 'cloudflare' in srv:
            cdn = 'Cloudflare'
        elif 'cloudfront' in srv or 'x-amz-cf-id' in h:
            cdn = 'AWS CloudFront'
        elif 'akamai' in srv or 'x-akamai-transformed' in h:
            cdn = 'Akamai'
        elif 'fastly' in h.get('x-served-by', '').lower() or 'fastly' in srv:
            cdn = 'Fastly'
        elif 'x-sucuri-id' in h:
            cdn = 'Sucuri'

        return {
            "server":           server,
            "powered_by":       powered_by,
            "security_headers": security_headers,
            "cdn":              cdn,
            "error":            None
        }
    except Exception as e:
        return {"error": str(e)[:80], "server": "-", "powered_by": "-",
                "security_headers": {}, "cdn": None}

# ================= OSINT: Risk Verdict Calculation (Weighted) =================
# IMPROVED: Sistem scoring berbobot — tiap faktor punya nilai risiko berbeda.
# SSL expired/missing jauh lebih kritikal dibanding tidak ada CDN.
#
# Tabel bobot risiko:
#   SSL Expired          → skor 40  (kritikal, data bisa dicuri / MITM)
#   SSL Warning (<30hr)  → skor 20  (urgent tapi masih hidup)
#   SSL Error/Missing    → skor 30  (tidak ada enkripsi sama sekali)
#   Tidak ada SPF        → skor 15  (rawan email spoofing)
#   Tidak ada DMARC      → skor 10  (pelengkap SPF, lebih rendah)
#   Missing sec headers  → skor 5 per header (max 20)
#   Domain sangat baru   → skor 20  (< 1 tahun, high phishing risk)
#   Tidak ada CDN/WAF    → skor 5   (opsional, bukan kritikal)
#
# Catatan: jika is_ip=True, SSL error/missing TIDAK diberi penalty
#
# Threshold level:
#   score >= 50  → HIGH
#   score >= 20  → MEDIUM
#   score < 20   → LOW

def calculate_risk_verdict(ssl_info, dns_info, whois_info, http_info, target, is_ip=False):
    issues    = []
    positives = []
    score     = 0

    # --- SSL ---
    ssl_status = ssl_info.get('status') if ssl_info else 'error'
    if ssl_status == 'expired':
        score += 40
        issues.append(f"SSL Expired ({abs(ssl_info.get('days_left', 0))} hari lalu) ⚠ KRITIKAL")
    elif ssl_status == 'warning':
        score += 20
        issues.append(f"SSL mau expired ({ssl_info.get('days_left', 0)} hari lagi)")
    elif ssl_status == 'error':
        if is_ip:
            # SSL gagal di IP itu wajar — tidak dikasih penalty
            issues.append("SSL via IP tidak tersedia (wajar, bukan indikator risiko)")
        else:
            score += 30
            issues.append("SSL tidak terdeteksi / tidak ada HTTPS")
    else:
        positives.append(f"SSL Valid ({ssl_info.get('days_left', 0)} hari lagi)")

    # --- CDN / WAF ---
    cdn = http_info.get('cdn') if http_info and not http_info.get('error') else None
    if cdn:
        positives.append(f"CDN/WAF: {cdn}")
    else:
        score += 5
        issues.append("Tidak ada CDN/WAF terdeteksi")

    # --- DNS Email Security — hanya relevan untuk domain ---
    if not is_ip and dns_info and not dns_info.get('error'):
        if dns_info.get('spf'):
            positives.append("SPF Configured")
        else:
            score += 15
            issues.append("Tidak ada SPF (rawan email spoofing)")
        if dns_info.get('dmarc'):
            positives.append("DMARC Configured")
        else:
            score += 10
            issues.append("Tidak ada DMARC")

    # --- HTTP Security Headers ---
    if http_info and not http_info.get('error'):
        sec     = http_info.get('security_headers', {})
        missing = sum(1 for v in sec.values() if not v)
        if missing == 0:
            positives.append("Security Headers lengkap")
        else:
            score += missing * 5
            issues.append(f"{missing} Security Header tidak ada")

    # --- Domain Age — hanya relevan untuk domain ---
    if not is_ip and whois_info and not whois_info.get('error'):
        age = whois_info.get('domain_age')
        if age is not None:
            if age < 1:
                score += 20
                issues.append("Domain sangat baru (< 1 tahun) — waspadai phishing")
            elif age >= 5:
                positives.append(f"Domain sudah lama ({age} tahun)")

    # --- Tentukan Risk Level ---
    if score >= 50:
        risk_level, risk_color, risk_emoji = "HIGH",   "red",    "🔴"
    elif score >= 20:
        risk_level, risk_color, risk_emoji = "MEDIUM", "yellow", "🟡"
    else:
        risk_level, risk_color, risk_emoji = "LOW",    "green",  "🟢"

    return {
        "domain":     target,
        "issues":     issues,
        "positives":  positives,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "risk_emoji": risk_emoji,
        "risk_score": score,
        "cdn":        cdn
    }

# ================= OSINT: Main Recon Function =================

async def run_osint_recon_async(target):
    """
    Main OSINT recon. Auto-detect apakah target adalah IP atau domain.
    Flow berbeda:
      Domain → DNS resolution, SSL, DNS records, WHOIS domain, HTTP, Traceroute, Risk
      IP     → GeoIP langsung, SSL (optional), WHOIS IP (org/CIDR), HTTP, Traceroute, Risk
    """
    is_ip = is_ip_address(target)

    results = {
        "domain": target,
        "ips":    [],
        "geo":    {},
        "ssl":    {},
        "dns":    {},
        "whois":  {},
        "http":   {},
        "risk":   {},
        "trace":  "",
        "is_ip":  is_ip
    }

    label = "IP" if is_ip else "Domain"

    with console.status(
        f"[bold cyan]Memulai rekon OSINT untuk {label}: {target}...[/bold cyan]",
        spinner="dots"
    ) as status:

        if is_ip:
            # ── Mode IP ──────────────────────────────────────────────
            results["ips"] = [target]
            console.print(f" [bold cyan][ ℹ ][/bold cyan] [cyan]Target adalah IP address — mode IP aktif[/cyan]")

            # Tahap 1: GeoIP langsung pakai IP target
            status.update(f"[bold yellow]Melacak identitas IP {target}...[/bold yellow]")
            try:
                def fetch_geo_ip():
                    req = urllib.request.Request(
                        f"http://ip-api.com/json/{target}",
                        headers={'User-Agent': 'Mozilla/5.0'}
                    )
                    with urllib.request.urlopen(req, timeout=5) as response:
                        return json.loads(response.read().decode())
                results["geo"] = await asyncio.to_thread(fetch_geo_ip)
                console.print(" [bold green][ ✔ ][/bold green] [yellow]Pelacakan GeoIP & ASN (Selesai)[/yellow]")
            except Exception:
                results["geo"] = {"status": "fail"}
                console.print(" [bold red][ ✖ ][/bold red] [yellow]Gagal menarik data GeoIP[/yellow]")

            # Tahap 2: SSL (opsional untuk IP)
            status.update(f"[bold cyan]Mencoba SSL di port 443 {target}...[/bold cyan]")
            results["ssl"] = await get_ssl_info(target, is_ip=True)
            if results["ssl"].get("error"):
                console.print(f" [bold yellow][ ~ ][/bold yellow] [cyan]SSL: {results['ssl']['error']}[/cyan]")
            else:
                console.print(" [bold green][ ✔ ][/bold green] [cyan]SSL Certificate Inspector (Selesai)[/cyan]")

            # Tahap 3: DNS records — skip untuk IP
            results["dns"] = {"error": "DNS lookup tidak relevan untuk IP address", "skipped": True}
            console.print(" [bold dim][ - ][/bold dim] [dim]DNS Deep Lookup dilewati (input adalah IP)[/dim]")

            # Tahap 4: WHOIS IP — org/CIDR/RIR
            status.update(f"[bold yellow]Mengambil info registrasi IP {target}...[/bold yellow]")
            results["whois"] = await get_whois_info(target, is_ip=True)
            if results["whois"].get("error"):
                console.print(f" [bold red][ ✖ ][/bold red] [yellow]WHOIS IP: {results['whois']['error']}[/yellow]")
            else:
                src = results["whois"].get("source", "whois CLI")
                console.print(f" [bold green][ ✔ ][/bold green] [yellow]WHOIS IP via {src} (Selesai)[/yellow]")

        else:
            # ── Mode Domain ───────────────────────────────────────────
            # Tahap 1: DNS Resolution
            status.update(f"[bold cyan]Resolusi DNS {target}...[/bold cyan]")
            try:
                _, _, ip_list = await asyncio.to_thread(socket.gethostbyname_ex, target)
                results["ips"] = ip_list
                console.print(" [bold green][ ✔ ][/bold green] [cyan]Resolusi DNS IP (Selesai)[/cyan]")
            except Exception as e:
                results["ips"] = []
                console.print(f" [bold red][ ✖ ][/bold red] [cyan]Gagal menemukan IP: {e}[/cyan]")

            # Tahap 2: GeoIP dari IP hasil resolusi
            if results["ips"]:
                primary_ip = results["ips"][0]
                status.update(f"[bold yellow]Melacak identitas server {primary_ip}...[/bold yellow]")
                try:
                    def fetch_geo():
                        req = urllib.request.Request(
                            f"http://ip-api.com/json/{primary_ip}",
                            headers={'User-Agent': 'Mozilla/5.0'}
                        )
                        with urllib.request.urlopen(req, timeout=5) as response:
                            return json.loads(response.read().decode())
                    results["geo"] = await asyncio.to_thread(fetch_geo)
                    console.print(" [bold green][ ✔ ][/bold green] [yellow]Pelacakan GeoIP & ASN (Selesai)[/yellow]")
                except Exception:
                    results["geo"] = {"status": "fail"}
                    console.print(" [bold red][ ✖ ][/bold red] [yellow]Gagal menarik data GeoIP[/yellow]")

            # Tahap 3: SSL Inspector
            status.update(f"[bold cyan]Memeriksa SSL Certificate {target}...[/bold cyan]")
            results["ssl"] = await get_ssl_info(target, is_ip=False)
            if results["ssl"].get("error"):
                console.print(f" [bold red][ ✖ ][/bold red] [cyan]SSL: {results['ssl']['error']}[/cyan]")
            else:
                console.print(" [bold green][ ✔ ][/bold green] [cyan]SSL Certificate Inspector (Selesai)[/cyan]")

            # Tahap 4: DNS Deep Lookup
            status.update(f"[bold magenta]Menggali DNS Records {target}...[/bold magenta]")
            results["dns"] = await get_dns_records(target)
            if results["dns"].get("error"):
                first_line = results['dns']['error'].split('\n')[0]
                console.print(f" [bold red][ ✖ ][/bold red] [magenta]DNS: {first_line}[/magenta]")
            else:
                console.print(" [bold green][ ✔ ][/bold green] [magenta]DNS Deep Lookup (Selesai)[/magenta]")

            # Tahap 5: WHOIS Domain (hybrid CLI → RDAP)
            status.update(f"[bold yellow]Mengambil data WHOIS {target}...[/bold yellow]")
            results["whois"] = await get_whois_info(target, is_ip=False)
            if results["whois"].get("error"):
                first_line = results['whois']['error'].split('\n')[0]
                console.print(f" [bold red][ ✖ ][/bold red] [yellow]WHOIS: {first_line}[/yellow]")
            else:
                src = results["whois"].get("source", "")
                console.print(f" [bold green][ ✔ ][/bold green] [yellow]WHOIS via {src} (Selesai)[/yellow]")

        # ── Tahap bersama (domain & IP) ───────────────────────────────

        # HTTP Header Fingerprinting
        status.update(f"[bold green]Membaca HTTP Headers {target}...[/bold green]")
        results["http"] = await get_http_headers(target)
        if results["http"].get("error"):
            console.print(f" [bold red][ ✖ ][/bold red] [green]HTTP: {results['http']['error']}[/green]")
        else:
            console.print(" [bold green][ ✔ ][/bold green] [green]HTTP Header Fingerprinting (Selesai)[/green]")

        # Traceroute
        status.update(f"[bold magenta]Traceroute ke {target} (maks 15 hop)...[/bold magenta]")
        try:
            proc = await asyncio.create_subprocess_exec(
                "traceroute", "-m", "15", "-w", "1", target,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
            )
            stdout, _ = await proc.communicate()
            trace_output = stdout.decode('utf-8', errors='ignore')
            if "not found" in trace_output.lower() or proc.returncode == 127:
                results["trace"] = "Perintah traceroute belum diinstall di Termux.\nSilakan ketik: pkg install traceroute"
            else:
                results["trace"] = trace_output
                console.print(" [bold green][ ✔ ][/bold green] [magenta]Pemetaan rute jaringan (Selesai)[/magenta]")
        except FileNotFoundError:
            results["trace"] = "Perintah traceroute belum diinstall di Termux.\nSilakan ketik: pkg install traceroute"
            console.print(" [bold red][ ✖ ][/bold red] [magenta]Traceroute tidak ditemukan![/magenta]")
        except Exception as e:
            results["trace"] = f"Traceroute error: {e}"

        # Risk Verdict
        status.update("[bold white]Menghitung Risk Verdict...[/bold white]")
        results["risk"] = calculate_risk_verdict(
            results["ssl"], results["dns"],
            results["whois"], results["http"],
            target, is_ip=is_ip
        )
        console.print(" [bold green][ ✔ ][/bold green] [bold white]Kalkulasi Risk Verdict (Selesai)[/bold white]")

    return results

# ================= OSINT: Export Functions =================

def _ensure_exports_dir():
    if not os.path.exists(EXPORTS_DIR):
        os.makedirs(EXPORTS_DIR)

def check_export_limit():
    _ensure_exports_dir()
    files = [f for f in os.listdir(EXPORTS_DIR) if f.startswith("osint_")]
    if len(files) >= 20:
        console.print(f"\n[bold yellow]⚠️  Ada {len(files)} file export di folder exports/[/bold yellow]")
        confirm = input(" Hapus semua file lama? [y/N]: ").strip().lower()
        if confirm == 'y':
            for f in files:
                os.remove(os.path.join(EXPORTS_DIR, f))
            console.print("[bold green]✅ File lama dihapus.[/bold green]")

def export_osint_results(results, target, fmt):
    _ensure_exports_dir()

    is_ip   = results.get("is_ip", False)
    safe_t  = re.sub(r'[^\w\-.]', '_', target)
    date_str = datetime.now().strftime("%Y-%m-%d")
    filename = f"osint_{safe_t}_{date_str}.{fmt}"
    filepath = os.path.join(EXPORTS_DIR, filename)

    ssl_i   = results.get("ssl",   {})
    dns_i   = results.get("dns",   {})
    whois_i = results.get("whois", {})
    http_i  = results.get("http",  {})
    risk_i  = results.get("risk",  {})
    geo_i   = results.get("geo",   {})

    if fmt == 'json':
        # Bangun whois section sesuai mode
        if is_ip:
            whois_section = {
                "org":    whois_i.get("org",     "N/A"),
                "country": whois_i.get("country", "N/A"),
                "cidr":   whois_i.get("cidr",    "N/A"),
                "rir":    whois_i.get("rir",      "N/A"),
                "abuse":  whois_i.get("abuse",    "N/A"),
                "source": whois_i.get("source",   "N/A"),
            }
        else:
            whois_section = {
                "registrar":        whois_i.get("registrar",  "N/A"),
                "registered":       whois_i.get("registered", "N/A"),
                "expires":          whois_i.get("expires",    "N/A"),
                "owner":            whois_i.get("owner",      "N/A"),
                "country":          whois_i.get("country",    "N/A"),
                "domain_age_tahun": whois_i.get("domain_age", None),
                "source":           whois_i.get("source",     "N/A"),
            }

        export_data = {
            "target":       target,
            "type":         "IP" if is_ip else "Domain",
            "tanggal":      datetime.now().strftime("%d %b %Y, %H:%M WIB"),
            "ip_addresses": results.get("ips", []),
            "geoip": {
                "isp":    geo_i.get("isp",    "N/A"),
                "as":     geo_i.get("as",     "N/A"),
                "kota":   geo_i.get("city",   "N/A"),
                "negara": geo_i.get("country","N/A"),
            },
            "ssl": {
                "issued_to":      ssl_i.get("issued_to",  "N/A"),
                "issuer":         ssl_i.get("issuer",     "N/A"),
                "berlaku_dari":   ssl_i.get("not_before", "N/A"),
                "berlaku_sampai": ssl_i.get("not_after",  "N/A"),
                "sisa_hari":      ssl_i.get("days_left",  0),
                "status":         ssl_i.get("status",     "N/A"),
                "sans":           ssl_i.get("sans",       []),
            },
            "dns":          {"skipped": True} if is_ip else {
                "A":     dns_i.get("A",    []),
                "AAAA":  dns_i.get("AAAA", []),
                "MX":    dns_i.get("MX",   []),
                "NS":    dns_i.get("NS",   []),
                "TXT":   dns_i.get("TXT",  []),
                "spf":   dns_i.get("spf",   False),
                "dmarc": dns_i.get("dmarc", False),
            },
            "whois": whois_section,
            "http_headers": {
                "server":           http_i.get("server",     "-"),
                "powered_by":       http_i.get("powered_by", "-"),
                "cdn_waf":          http_i.get("cdn",        None),
                "security_headers": http_i.get("security_headers", {}),
            },
            "risk_verdict": {
                "risk_level": risk_i.get("risk_level", "N/A"),
                "risk_score": risk_i.get("risk_score", 0),
                "issues":     risk_i.get("issues",    []),
                "positives":  risk_i.get("positives", []),
            },
            "traceroute": results.get("trace", ""),
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

    elif fmt == 'txt':
        sep   = "=" * 45
        lines = []
        lines.append(sep)
        lines.append(f"  HASIL OSINT: {target} ({'IP' if is_ip else 'Domain'})")
        lines.append(f"  Tanggal: {datetime.now().strftime('%d %b %Y, %H:%M WIB')}")
        lines.append(sep)
        lines.append("")

        lines.append("[IP Address]")
        for ip in results.get("ips", []):
            lines.append(f"  -> {ip}")
        lines.append("")

        if geo_i.get("status") == "success":
            lines.append("[GeoIP & ASN]")
            lines.append(f"  ISP/ASN : {geo_i.get('isp', 'N/A')} ({geo_i.get('as', 'N/A')})")
            lines.append(f"  Lokasi  : {geo_i.get('city', 'N/A')}, {geo_i.get('country', 'N/A')}")
            lines.append("")

        lines.append("[SSL Certificate]")
        if ssl_i.get("error"):
            lines.append(f"  Info: {ssl_i['error']}")
        else:
            status_map = {
                "valid":   f"Valid ({ssl_i.get('days_left', 0)} hari lagi)",
                "warning": f"Warning - Segera Renew ({ssl_i.get('days_left', 0)} hari lagi)",
                "expired": f"EXPIRED ({abs(ssl_i.get('days_left', 0))} hari lalu)"
            }
            lines.append(f"  Issued to : {ssl_i.get('issued_to', 'N/A')}")
            lines.append(f"  Issuer    : {ssl_i.get('issuer', 'N/A')}")
            lines.append(f"  Berlaku   : {ssl_i.get('not_before', 'N/A')}")
            lines.append(f"  Expires   : {ssl_i.get('not_after', 'N/A')}")
            lines.append(f"  Status    : {status_map.get(ssl_i.get('status', ''), 'N/A')}")
            if ssl_i.get("sans"):
                lines.append(f"  SANs      : {', '.join(ssl_i['sans'])}")
        lines.append("")

        if is_ip:
            lines.append("[DNS Records]")
            lines.append("  (Dilewati — input adalah IP address)")
            lines.append("")

            lines.append("[WHOIS IP]")
            if whois_i.get("error"):
                lines.append(f"  Error: {whois_i['error']}")
            else:
                lines.append(f"  Organisasi : {whois_i.get('org',     'N/A')}")
                lines.append(f"  Negara     : {whois_i.get('country', 'N/A')}")
                lines.append(f"  CIDR/Range : {whois_i.get('cidr',    'N/A')}")
                lines.append(f"  RIR        : {whois_i.get('rir',     'N/A')}")
                lines.append(f"  Abuse      : {whois_i.get('abuse',   'N/A')}")
                lines.append(f"  Sumber     : {whois_i.get('source',  'N/A')}")
        else:
            lines.append("[DNS Records]")
            if dns_i.get("error"):
                lines.append(f"  Error: {dns_i['error']}")
            else:
                for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
                    recs = dns_i.get(rtype, [])
                    if recs:
                        lines.append(f"  [{rtype}]")
                        for r in recs:
                            display = r[:70] + "..." if len(r) > 70 else r
                            lines.append(f"    -> {display}")
                lines.append(f"  SPF   : {'Ada' if dns_i.get('spf') else 'Tidak ada'}")
                lines.append(f"  DMARC : {'Ada' if dns_i.get('dmarc') else 'Tidak ada'}")
            lines.append("")

            lines.append("[WHOIS Domain]")
            if whois_i.get("error"):
                lines.append(f"  Error: {whois_i['error']}")
            else:
                lines.append(f"  Registrar  : {whois_i.get('registrar',  'N/A')}")
                lines.append(f"  Registered : {whois_i.get('registered', 'N/A')}")
                lines.append(f"  Expires    : {whois_i.get('expires',    'N/A')}")
                lines.append(f"  Owner      : {whois_i.get('owner',      'N/A')}")
                lines.append(f"  Sumber     : {whois_i.get('source',     'N/A')}")
                age = whois_i.get('domain_age')
                if age is not None:
                    lines.append(f"  Domain Age : {age} tahun")
        lines.append("")

        lines.append("[HTTP Headers]")
        if http_i.get("error"):
            lines.append(f"  Error: {http_i['error']}")
        else:
            lines.append(f"  Server   : {http_i.get('server', '-')}")
            lines.append(f"  Tech     : {http_i.get('powered_by', '-')}")
            cdn = http_i.get('cdn')
            lines.append(f"  CDN/WAF  : {cdn if cdn else 'Tidak terdeteksi'}")
            sec = http_i.get('security_headers', {})
            for hname, hval in sec.items():
                lines.append(f"  {hname:25}: {'Ada' if hval else 'Tidak ada'}")
        lines.append("")

        lines.append("[Risk Verdict]")
        lines.append(f"  Level : {risk_i.get('risk_emoji', '')} {risk_i.get('risk_level', 'N/A')} (Score: {risk_i.get('risk_score', 0)})")
        for p in risk_i.get("positives", []):
            lines.append(f"  [+] {p}")
        for i in risk_i.get("issues", []):
            lines.append(f"  [!] {i}")
        lines.append("")

        lines.append("[Traceroute]")
        lines.append(results.get("trace", "Tidak tersedia"))
        lines.append("")
        lines.append(sep)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    return filepath
