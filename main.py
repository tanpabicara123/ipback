import asyncio
import os
from datetime import datetime
import ui_core
import net_core

async def main():
    my_ip = net_core.get_my_ip()
    if not my_ip:
        ui_core.console.print("[bold red]Error: Tidak bisa mendeteksi IP. Pastikan Wi-Fi atau Data seluler aktif![/bold red]")
        return
    prefix = ".".join(my_ip.split('.')[:3])

    while True:
        ui_core.draw_main_menu()
        choice = input("\n ➜ Pilih menu [1/2/3/4/0]: ")

        if choice == '1':
            ui_core.console.print("\n")
            results = await net_core.run_scan_async(prefix)

            ui_core.draw_scan_results(results, my_ip)

            # Ambil hanya IP dari tuple (ip, lat, ttl, hint, hostname)
            ip_list = [r[0] for r in results]
            with open(net_core.LOG_FILE, "w") as f:
                f.write("\n".join(ip_list))
            with open(net_core.TIME_FILE, "w") as f:
                f.write(datetime.now().strftime("%d %b %Y, %H:%M WIB"))

            ui_core.console.print("\n[dim]----------------------------------------[/dim]")
            input(" Tekan [ENTER] untuk kembali ke menu...")

        elif choice == '2':
            ui_core.console.print("\n")

            old_ips = set()
            if os.path.exists(net_core.LOG_FILE):
                with open(net_core.LOG_FILE, "r") as f:
                    old_ips = set(f.read().splitlines())

            results     = await net_core.run_scan_async(prefix)
            # Ambil hanya IP dari tuple (ip, lat, ttl, hint, hostname)
            current_ips = {r[0] for r in results}

            last_time = "Belum ada log"
            if os.path.exists(net_core.TIME_FILE):
                with open(net_core.TIME_FILE, "r") as f:
                    last_time = f.read()

            new_ips  = current_ips - old_ips
            gone_ips = old_ips - current_ips

            ui_core.draw_tracker_results(current_ips, new_ips, gone_ips, last_time, my_ip)

            with open(net_core.LOG_FILE, "w") as f:
                f.write("\n".join(current_ips))
            with open(net_core.TIME_FILE, "w") as f:
                f.write(datetime.now().strftime("%d %b %Y, %H:%M WIB"))

            input(" Tekan [ENTER] untuk kembali ke menu...")

        elif choice == '3':
            while True:
                targets = net_core.load_targets()
                ui_core.draw_health_submenu(targets)

                sub_choice = input("\n ➜ Pilih opsi [1/2/3/0]: ")

                if sub_choice == '1':
                    ui_core.console.print("\n")
                    if not targets:
                        ui_core.console.print("[bold red]Target kosong! Silakan edit file terlebih dahulu.[/bold red]")
                    else:
                        health_results = await net_core.run_health_check_async(targets)
                        ui_core.draw_health_results(health_results)

                    ui_core.console.print("\n[dim]----------------------------------------[/dim]")
                    input(" Tekan [ENTER] untuk kembali...")

                elif sub_choice == '2':
                    ui_core.console.print("\n")
                    try:
                        speedtest_results = await net_core.run_speedtest_async()
                        ui_core.draw_speedtest_results(speedtest_results)
                    except ImportError:
                        ui_core.console.print("[bold red]Error: Library 'speedtest-cli' belum terinstall.[/bold red]")
                        ui_core.console.print("Silakan tutup skrip ini (Ctrl+C) dan ketik perintah: [yellow]pip install speedtest-cli[/yellow]")
                    except Exception as e:
                        ui_core.console.print(f"\n[bold red]Ups, terjadi kegagalan saat Speedtest: {e}[/bold red]")
                        ui_core.console.print("[dim]Pastikan koneksi internet aktif.[/dim]")

                    ui_core.console.print("\n[dim]----------------------------------------[/dim]")
                    input(" Tekan [ENTER] untuk kembali...")

                elif sub_choice == '3':
                    os.system(f"nano {net_core.TARGETS_FILE}")

                elif sub_choice == '0':
                    break

        elif choice == '4':
            ui_core.console.print("\n")
            target_domain = input(" ➜ Masukkan Domain / IP Target (contoh: google.com atau 8.8.8.8): ").strip()

            if not target_domain:
                ui_core.console.print("[bold red]Target tidak boleh kosong![/bold red]")
                ui_core.console.print("\n[dim]----------------------------------------[/dim]")
                input(" Tekan [ENTER] untuk kembali ke menu...")
            else:
                # Jalankan rekon OSINT
                osint_results = await net_core.run_osint_recon_async(target_domain)

                # Tampilkan semua hasil terlebih dahulu
                ui_core.draw_osint_results(osint_results)

                ui_core.console.print("\n[dim]----------------------------------------[/dim]")

                # Setelah hasil tampil, baru tanya export
                net_core.check_export_limit()
                export_fmt = ui_core.draw_export_prompt()

                if export_fmt:
                    try:
                        filepath = net_core.export_osint_results(osint_results, target_domain, export_fmt)
                        ui_core.draw_export_success(filepath)
                    except Exception as e:
                        ui_core.console.print(f"[bold red]Gagal export: {e}[/bold red]")
                else:
                    ui_core.console.print("[dim]Export dilewati.[/dim]")

                ui_core.console.print("\n[dim]----------------------------------------[/dim]")
                input(" Tekan [ENTER] untuk kembali ke menu...")

        elif choice == '0':
            ui_core.draw_exit()
            break

if __name__ == "__main__":
    try:
        if os.system("command -v nano > /dev/null 2>&1") != 0:
            print("Perhatian: Editor 'nano' belum terinstall. Ketik 'pkg install nano' di Termux nanti.")
        asyncio.run(main())
    except KeyboardInterrupt:
        ui_core.draw_exit()
