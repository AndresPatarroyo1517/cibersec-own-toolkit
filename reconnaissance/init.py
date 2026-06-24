#!/usr/bin/env python3
"""
CyberSec Toolkit - Reconnaissance Module Entry Point.
Provides unified CLI access to all reconnaissance modules.

Uso:
    python -m reconnaissance.init discover --range 192.168.1.0/24 --methods icmp,syn --output hosts.json
    python -m reconnaissance.init portscan --target 192.168.1.1 --ports 1-1000 --mode syn
    python -m reconnaissance.init subenum --domain example.com --wordlist subdomains.txt --crtsh
    python -m reconnaissance.init webfinger --url https://example.com
    python -m reconnaissance.init fullscan --target 192.168.1.0/24 --output report.html
    python -m reconnaissance.init history
    python -m reconnaissance.init init

Or directly:
    python reconnaissance/init.py portscan --target scanme.nmap.org --ports 22,80,443
"""
import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional

# Add project root to path so 'utilities' and 'reconnaissance' modules resolve correctly
_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from reconnaissance.host_discovery import HostDiscoverer
from reconnaissance.port_scanner import PortScanner, parse_port_range
from reconnaissance.subdomain_enum import SubdomainEnumerator
from reconnaissance.web_fingerprint import WebFingerprinter
from utilities.save_results import save_results
from utilities.database import save_scan_record, get_scan_history, init_db
from utilities.report_generator import generate_report

# Suppress SSL warnings
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass

VERSION = "1.0.0"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('recon')


def print_banner():
    banner = """
    ╔══════════════════════════════════════════════════════════╗
    ║           CyberSec Toolkit - Reconnaissance Suite        ║
    ║                    Network & Web Recon                   ║
    ║                       v1.0.0                             ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print(banner)


def cmd_discover(args):
    """Módulo 1.1: Host Discovery - ARP/ICMP/SYN scan over CIDR range."""
    logger.info("=" * 60)
    logger.info("HOST DISCOVERY - Módulo 1.1")
    logger.info("=" * 60)

    allowed = {'arp', 'icmp', 'syn'}
    methods = [m.strip().lower() for m in args.methods.split(',') if m.strip()]
    invalid = set(methods) - allowed
    if invalid:
        logger.error(f"Métodos inválidos: {invalid}. Permitidos: {allowed}")
        return 1

    start_time = time.time()

    try:
        discoverer = HostDiscoverer(args.range)
        results = discoverer.discover(methods, max_workers=args.workers)
        stats = discoverer.get_statistics()
    except ValueError as e:
        logger.error(f"Error: {e}")
        return 1
    except PermissionError:
        logger.error("Privilegios insuficientes. Ejecuta con sudo para ARP/SYN")
        return 1
    except KeyboardInterrupt:
        logger.warning("\nEscaneo interrumpido por usuario")
        return 130
    except Exception as e:
        logger.error(f"Error inesperado: {e}", exc_info=args.verbose)
        return 1

    duration = time.time() - start_time

    # Output
    if args.output:
        base_path = args.output.rsplit('.', 1)[0] if '.' in args.output else args.output
        save_results(results, 'json', base_path, stats, logger)

    # Save to database
    save_scan_record('host_discovery', args.range, stats, results, duration)

    print(f"\n✅ Host Discovery completado en {duration:.2f}s")
    print(f"   Hosts encontrados: {len(results)}")
    for host in results:
        method = host.get('método', host.get('method', '?'))
        latency = host.get('latencia_ms', host.get('latency_ms', '?'))
        mac = host.get('mac', '')
        mac_str = f" [{mac}]" if mac else ""
        print(f"   ├─ {host['ip']} (vía {method}, {latency}ms{mac_str})")

    return 0


def cmd_portscan(args):
    """Módulo 1.2: Port Scanner with Service Detection - TCP Connect/SYN/UDP."""
    logger.info("=" * 60)
    logger.info("PORT SCANNER - Módulo 1.2")
    logger.info("=" * 60)

    start_time = time.time()

    try:
        ports = parse_port_range(args.ports)
    except ValueError as e:
        logger.error(f"Error parseando puertos: {e}")
        return 1

    try:
        scanner = PortScanner(args.target)
        results = scanner.scan(
            ports=ports,
            mode=args.mode,
            max_workers=args.workers,
            show_closed=args.show_closed
        )
        stats = scanner.get_statistics()
    except ValueError as e:
        logger.error(f"Error: {e}")
        return 1
    except PermissionError as e:
        logger.error(f"Error de permisos: {e}")
        return 1
    except KeyboardInterrupt:
        logger.warning("\nEscaneo interrumpido por usuario")
        return 130
    except Exception as e:
        logger.error(f"Error inesperado: {e}", exc_info=args.verbose)
        return 1

    duration = time.time() - start_time

    if args.output:
        base_path = args.output.rsplit('.', 1)[0] if '.' in args.output else args.output
        save_results(results, 'json', base_path, stats, logger)

    save_scan_record('port_scan', args.target, stats, results, duration)

    open_ports = [p for p in results.get('ports', []) if p.get('state') == 'open']
    print(f"\n✅ Port Scan completado en {duration:.2f}s")
    print(f"   Puertos abiertos: {len(open_ports)}/{len(ports)}")
    for p in open_ports:
        version = f" {p['version']}" if p.get('version') else ""
        banner = p.get('banner', '')[:60]
        banner_str = f" [{banner}]" if banner else ""
        print(f"   ├─ {p['port']}/tcp OPEN - {p['service']}{version}{banner_str}")

    return 0


def cmd_subenum(args):
    """Módulo 1.3: Subdomain Enumeration - DNS brute, crt.sh, AXFR, HTTP check."""
    logger.info("=" * 60)
    logger.info("SUBDOMAIN ENUMERATION - Módulo 1.3")
    logger.info("=" * 60)

    start_time = time.time()

    wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                wordlist = [line.strip() for line in f if line.strip()]
            logger.info(f"Wordlist cargada: {len(wordlist)} subdominios")
        except FileNotFoundError:
            logger.error(f"Wordlist no encontrada: {args.wordlist}")
            return 1

    enumerator = SubdomainEnumerator(args.domain, wordlist=wordlist)

    try:
        results = enumerator.enumerate(
            use_crtsh=not args.no_crtsh,
            use_axfr=not args.no_axfr,
            http_check=not args.no_http,
            max_workers=args.workers
        )
        stats = enumerator.get_statistics()
    except KeyboardInterrupt:
        logger.warning("\nEnumeración interrumpida por usuario")
        return 130
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=args.verbose)
        return 1

    duration = time.time() - start_time

    if args.output:
        base_path = args.output.rsplit('.', 1)[0] if '.' in args.output else args.output
        save_results(results, 'json', base_path, stats, logger)

    save_scan_record('subdomain_enum', args.domain, stats, results, duration)

    print(f"\n✅ Subdomain Enumeration completada en {duration:.2f}s")
    print(f"   Subdominios encontrados: {len(results)}")
    for sub in results[:30]:
        title = sub.get('http_title', sub.get('https_title', ''))
        title_str = f" [{title[:40]}]" if title else ""
        status = sub.get('http_status', sub.get('https_status', '?'))
        print(f"   ├─ {sub['subdomain']} -> {sub.get('ip', '?')} ({status}){title_str}")
    if len(results) > 30:
        print(f"   └─ ... y {len(results) - 30} más (ver --output)")

    return 0


def cmd_webfinger(args):
    """Módulo 1.4: Web Technology Fingerprinting."""
    logger.info("=" * 60)
    logger.info("WEB FINGERPRINTING - Módulo 1.4")
    logger.info("=" * 60)

    start_time = time.time()

    fingerprinter = WebFingerprinter(args.url)

    try:
        results = fingerprinter.fingerprint(probe_paths=not args.no_probe)
        stats = fingerprinter.get_statistics()
    except KeyboardInterrupt:
        logger.warning("\nFingerprinting interrumpido por usuario")
        return 130
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=args.verbose)
        return 1

    duration = time.time() - start_time

    if args.output:
        base_path = args.output.rsplit('.', 1)[0] if '.' in args.output else args.output
        save_results(results, 'json', base_path, stats, logger)

    save_scan_record('web_fingerprint', args.url, stats, results, duration)

    print(f"\n✅ Web Fingerprinting completado en {duration:.2f}s")
    print(f"   URL: {results.get('url', args.url)}")
    print(f"   Servidor: {results.get('server', 'N/A')}")
    print(f"   WAF: {results.get('waf', 'No detectado')}")
    print(f"   CMS: {results.get('cms', 'No detectado')}")
    print(f"   Frameworks: {', '.join(results.get('frameworks', [])) or 'Ninguno'}")
    print(f"   Tecnologías: {len(results.get('technologies', []))}")

    interesting = results.get('interesting_paths', [])
    if interesting:
        print(f"   Paths interesantes encontrados:")
        for p in interesting:
            print(f"     ├─ {p['path']} -> {p['status']}")

    return 0


def cmd_fullscan(args):
    """
    Módulo 1.5: Full Scan - Ejecuta todos los módulos en orden y genera reporte HTML.
    1. Host discovery on CIDR
    2. Port scan on discovered hosts
    3. Web fingerprinting on discovered HTTP(S) services
    """
    logger.info("=" * 60)
    logger.info("FULL SCAN - Módulo 1.5")
    logger.info("=" * 60)

    start_time = time.time()
    all_results: Dict[str, any] = {}

    target = args.target
    output_path = args.output or f"reports/fullscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

    # ── Step 1: Host Discovery ──
    logger.info("\n[1/3] Host Discovery en progreso...")
    methods = ['icmp', 'syn']
    try:
        discoverer = HostDiscoverer(target)
        hosts = discoverer.discover(methods, max_workers=args.workers)
        all_results['host_discovery'] = hosts
        logger.info(f"   → {len(hosts)} hosts activos encontrados")
    except Exception as e:
        logger.warning(f"   → Host discovery falló: {e}")
        hosts = []
        all_results['host_discovery'] = []

    # ── Step 2: Port Scan on alive hosts ──
    logger.info("\n[2/3] Port Scanning en hosts activos...")
    all_ports = []
    all_open = 0
    for host in hosts[:10]:  # Limitar a 10 hosts
        ip = host['ip']
        try:
            scanner = PortScanner(ip)
            port_results = scanner.scan(
                ports=[22, 80, 443, 8080, 8443, 3306, 3389, 5432, 6379, 27017],
                mode='connect',
                max_workers=20
            )
            open_ports = [p for p in port_results.get('ports', []) if p.get('state') == 'open']
            for p in open_ports:
                p['host_ip'] = ip
                all_ports.append(p)
            all_open += len(open_ports)
            if open_ports:
                logger.info(f"   → {ip}: {len(open_ports)} puertos abiertos")
        except Exception as e:
            logger.debug(f"   → Port scan en {ip} falló: {e}")

    all_results['port_scan'] = {"ports": all_ports, "ip": target}
    logger.info(f"   → Total puertos abiertos: {all_open}")

    # ── Step 3: Web Fingerprinting on HTTP(S) hosts ──
    logger.info("\n[3/3] Web Fingerprinting en servicios web...")
    web_results = []
    for port_info in all_ports:
        if port_info.get('service') in ('http', 'https') or port_info.get('port') in (80, 443, 8080, 8443):
            ip = port_info.get('host_ip')
            port = port_info.get('port')
            protocol = 'https' if port in (443, 8443) else 'http'
            url = f"{protocol}://{ip}:{port}" if port not in (80, 443) else f"{protocol}://{ip}"

            try:
                fp = WebFingerprinter(url)
                fp_results = fp.fingerprint(probe_paths=False)
                web_results.append(fp_results)
                logger.info(f"   → {url}: {', '.join(fp_results.get('frameworks', [])) or 'No frameworks'}")
            except Exception as e:
                logger.debug(f"   → Web fingerprint {url} falló: {e}")

    all_results['web_fingerprint'] = web_results

    total_duration = time.time() - start_time

    # ── Generate HTML Report ──
    logger.info(f"\n📊 Generando reporte HTML...")
    report_path = generate_report(all_results, output_path, target, total_duration)

    # ── Save to database ──
    save_scan_record('fullscan', target, {
        'hosts_found': len(hosts),
        'open_ports': all_open,
        'web_services': len(web_results)
    }, all_results, total_duration)

    # ── Print Summary ──
    print(f"""
╔══ ✅ FULL SCAN COMPLETED ═══════════════════════════╗
║  Target:     {target:<37} ║
║  Duration:   {total_duration:<8.2f}s{"":>28} ║
║  Hosts:      {len(hosts):<5}{"":>32} ║
║  Open Ports: {all_open:<5}{"":>32} ║
║  Web Svcs:   {len(web_results):<5}{"":>32} ║
║  Report:     {report_path:<37} ║
╚══════════════════════════════════════════════════════╝""")

    return 0


def cmd_history(args):
    """Show scan history from database."""
    init_db()
    history = get_scan_history(limit=args.limit)

    if not history:
        print("\n📁 No hay escaneos en el historial.")
        return 0

    print(f"\n📁 Últimos {len(history)} escaneos:")
    print(f"   {'ID':<4} {'Tipo':<20} {'Target':<30} {'Duración':<10} {'Timestamp'}")
    print(f"   {'-'*4} {'-'*20} {'-'*30} {'-'*10} {'-'*20}")
    for scan in history:
        print(f"   {scan['id']:<4} {scan['scan_type']:<20} {scan['target'][:28]:<30} "
              f"{str(scan.get('duration_seconds', '?'))+'s':<10} {scan['timestamp'][:19]}")

    return 0


def cmd_init(args):
    """Initialize the database."""
    init_db()
    print("\n✅ Base de datos inicializada correctamente.")
    return 0


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description='CyberSec Toolkit - Reconnaissance Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python -m reconnaissance.init discover --range 192.168.1.0/24 --methods icmp,syn --output hosts.json
  python -m reconnaissance.init portscan --target 192.168.1.1 --ports 22,80,443 --mode syn
  python -m reconnaissance.init subenum --domain example.com --crtsh --output subs.json
  python -m reconnaissance.init webfinger --url https://example.com
  python -m reconnaissance.init fullscan --target 192.168.1.0/24 --output report.html
  python -m reconnaissance.init history
  python -m reconnaissance.init init
        """
    )

    subparsers = parser.add_subparsers(dest='command', title='Comandos')

    # discover
    p_discover = subparsers.add_parser('discover', help='Host Discovery (Módulo 1.1)')
    p_discover.add_argument('--range', '-r', required=True, help='CIDR range (ej: 192.168.1.0/24)')
    p_discover.add_argument('--methods', '-m', default='icmp,syn', help='Métodos: arp,icmp,syn (default: icmp,syn)')
    p_discover.add_argument('--workers', '-w', type=int, default=100, help='Workers concurrentes')
    p_discover.add_argument('--output', '-o', help='Archivo de salida JSON')
    p_discover.add_argument('--verbose', '-v', action='store_true', help='Modo verbose')

    # portscan
    p_portscan = subparsers.add_parser('portscan', help='Port Scanner (Módulo 1.2)')
    p_portscan.add_argument('--target', '-t', required=True, help='IP o hostname objetivo')
    p_portscan.add_argument('--ports', '-p', default='1-1024', help='Puertos (ej: 22,80,443,8000-9000)')
    p_portscan.add_argument('--mode', '-m', choices=['connect', 'syn'], default='connect', help='Modo de escaneo')
    p_portscan.add_argument('--workers', '-w', type=int, default=100, help='Workers concurrentes')
    p_portscan.add_argument('--show-closed', action='store_true', help='Mostrar puertos cerrados')
    p_portscan.add_argument('--output', '-o', help='Archivo de salida JSON')
    p_portscan.add_argument('--verbose', '-v', action='store_true', help='Modo verbose')

    # subenum
    p_subenum = subparsers.add_parser('subenum', help='Subdomain Enumeration (Módulo 1.3)')
    p_subenum.add_argument('--domain', '-d', required=True, help='Dominio objetivo')
    p_subenum.add_argument('--wordlist', '-w', help='Archivo de wordlist')
    p_subenum.add_argument('--workers', type=int, default=50, help='Workers concurrentes')
    p_subenum.add_argument('--no-crtsh', action='store_true', help='Saltar Certificate Transparency')
    p_subenum.add_argument('--no-axfr', action='store_true', help='Saltar Zone Transfer')
    p_subenum.add_argument('--no-http', action='store_true', help='Saltar verificación HTTP')
    p_subenum.add_argument('--output', '-o', help='Archivo de salida JSON')
    p_subenum.add_argument('--verbose', '-v', action='store_true', help='Modo verbose')

    # webfinger
    p_webfinger = subparsers.add_parser('webfinger', help='Web Fingerprinting (Módulo 1.4)')
    p_webfinger.add_argument('--url', '-u', required=True, help='URL objetivo')
    p_webfinger.add_argument('--no-probe', action='store_true', help='Saltar active probing')
    p_webfinger.add_argument('--output', '-o', help='Archivo de salida JSON')
    p_webfinger.add_argument('--verbose', '-v', action='store_true', help='Modo verbose')

    # fullscan
    p_fullscan = subparsers.add_parser('fullscan', help='Full Scan Completo (Módulo 1.5)')
    p_fullscan.add_argument('--target', '-t', required=True, help='CIDR range objetivo')
    p_fullscan.add_argument('--output', '-o', default=None, help='Ruta del reporte HTML')
    p_fullscan.add_argument('--workers', '-w', type=int, default=100, help='Workers concurrentes')
    p_fullscan.add_argument('--verbose', '-v', action='store_true', help='Modo verbose')

    # history
    p_history = subparsers.add_parser('history', help='Ver historial de escaneos')
    p_history.add_argument('--limit', '-l', type=int, default=20, help='Número de registros')

    # init
    subparsers.add_parser('init', help='Inicializar base de datos')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    # Set verbose logging if requested
    if hasattr(args, 'verbose') and args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        for handler in logging.getLogger().handlers:
            handler.setLevel(logging.DEBUG)

    # Route to command handler
    commands = {
        'discover': cmd_discover,
        'portscan': cmd_portscan,
        'subenum': cmd_subenum,
        'webfinger': cmd_webfinger,
        'fullscan': cmd_fullscan,
        'history': cmd_history,
        'init': cmd_init,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.warning("\n\n⚠️  Interrumpido por el usuario")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Error fatal: {e}", exc_info=True)
        sys.exit(1)