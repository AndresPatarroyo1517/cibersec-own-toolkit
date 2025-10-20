import time
from datetime import datetime
import os
import argparse
import sys
import asyncio
import logging
from ipaddress import ip_network
from scapy.all import IP, ICMP, TCP, sr1, arping
sys.path.append(os.path.abspath("../utilities"))
from save_json import save_json

logger = logging.getLogger(__name__)
COMMON_TCP_PORTS_FOR_DISCOVERY = [22, 80, 443]
BANNER_TIMEOUT = 0.8
DEFAULT_PORT_SCAN_TIMEOUT = 1.0
MAX_PORT_SCAN_WORKERS = 100

class HostDiscoverer:
    """Escanea hosts activos en un rango CIDR usando ARP/ICMP/SYN."""
    def __init__(self, targets):
        self.targets = targets
        self.alive_hosts = []
    #Ping ICMP (rápido pero ruidoso)
    async def ping_icmp(self, target_ip):
        try:
            start_time = time.time()
            pkt = IP(dst=str(target_ip)) / ICMP()
            reply = await asyncio.to_thread(sr1, pkt, timeout=1, verbose=0)
            latency = (time.time() - start_time) * 1000
            if reply:
                return {"ip": str(target_ip), "alive": True, "method": "icmp", "latency_ms": round(latency, 2)}
        except Exception:
            logger.debug("ICMP error %s -> %s", target_ip, e)
        return None
    #SYN scan a puertos comunes (más silencioso)
    async def ping_syn(self, target_ip):
        for port in COMMON_TCP_PORTS_FOR_DISCOVERY:
            try:
                start_time = time.time()
                pkt = IP(dst=str(target_ip)) / TCP(dport=port, flags="S")
                reply = await asyncio.to_thread(sr1, pkt, timeout=1, verbose=0)
                latency = (time.time() - start_time) * 1000
                if reply and reply.haslayer(TCP):
                    # flags 0x12 significa SYN/ACK
                    tcp_layer = reply.getlayer(TCP)
                    if int(tcp_layer.flags) & 0x12 == 0x12:
                        # enviar RST para cerrar
                        await asyncio.to_thread(sr1, IP(dst=str(target_ip)) / TCP(dport=port, flags="R"), timeout=1, verbose=0)
                        return {"ip": str(target_ip), "alive": True, "method": "syn", "latency_ms": round(latency, 2), "port": port}
            except Exception:
                logger.debug("SYN error %s:%s -> %s", target_ip, port, e)
                continue
        return None
    #ARP scan — solo redes locales
    async def scan_arp(self, ip_range):
        try:
            results = await asyncio.to_thread(arping, ip_range, verbose=0)
            # arping devuelve (answered, unanswered) 
            answered = results[0] if isinstance(results, tuple) else results
            arp_hosts = []
            for sent, received in answered:
                # received.psrc es la IP del host respondiente
                arp_hosts.append({"ip": received.psrc, "alive": True, "method": "arp", "latency_ms": 0})
            return arp_hosts
        except Exception as e:
            logger.warning("Escaneo ARP falló (¿estás en la red local?): %s", e)
            return []

    #Ejecuta el reconocimiento con los métodos solicitados (lista de strings)
    async def discover(self, methods):
        start_time = time.time()
        tasks = []

        # ARP primero si fue solicitado
        if 'arp' in methods:
            arp_hosts = await self.scan_arp(self.targets)
            self.alive_hosts.extend(arp_hosts)

        discovered_ips = {host['ip'] for host in self.alive_hosts}

        # Validar rango CIDR
        try:
            network = ip_network(self.targets, strict=False)
            target_ips = list(network.hosts())
        except ValueError:
            print(f"Rango de red incorrecto, por favor usa el estándar CIDR: {self.targets}", file=sys.stderr)
            return []

        for ip in target_ips:
            if str(ip) in discovered_ips:
                continue

            if 'icmp' in methods:
                tasks.append(self.ping_icmp(ip))
            if 'syn' in methods:
                tasks.append(self.ping_syn(ip))

        # Ejecutar tasks en paralelo
        results = []
        if tasks:
            gathered = await asyncio.gather(*tasks, return_exceptions=True)
            for r in gathered:
                # Ignorar excepciones y None
                if isinstance(r, Exception) or r is None:
                    continue
                results.append(r)

        for result in results:
            if result and result['ip'] not in discovered_ips:
                self.alive_hosts.append(result)
                discovered_ips.add(result['ip'])

        duration = time.time() - start_time
        logger.info("Hosts descubiertos en %.2f segundos.", duration)
        logger.info("Se encontraron %d hosts vivos.", len(self.alive_hosts))
        return self.alive_hosts

#Logger con outpus en json
def setup_logging(verbose: bool, log_dir: str = "."):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s: %(message)s")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    logfile = os.path.join(log_dir, f"recon_{ts}.log")
    fh = logging.FileHandler(logfile, encoding="utf-8")
    fh.setLevel(level)
    formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
    fh.setFormatter(formatter)
    logging.getLogger().addHandler(fh)
    logging.getLogger().info("Logging iniciado. Archivo: %s", logfile)
    return logfile


def parse_methods(s: str):
    allowed = {'arp', 'icmp', 'syn'}
    methods = [m.strip().lower() for m in s.split(',') if m.strip()]
    invalid = [m for m in methods if m not in allowed]
    if invalid:
        raise ValueError(f"Métodos inválidos: {invalid}. Permitidos: {allowed}")
    return methods


async def run_discovery(targets, methods, output, out_path, verbose):
    setup_logging(verbose)
    discoverer = HostDiscoverer(targets)
    results = await discoverer.discover(methods)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = out_path if out_path else f"results_{ts}"
    if output in ("json"):
        json_path = f"{base}.json"
        save_json(results, json_path)

    print("\nResumen:")
    print(f"Targets: {targets}")
    print(f"Métodos: {methods}")
    print(f"Hosts vivos: {len(results)}")
    return results


def main():
    parser = argparse.ArgumentParser(description="Network host discovery (ARP/ICMP/SYN)")
    parser.add_argument("--targets", "-t", required=True, help="Rango CIDR objetivo (ej: 192.168.1.0/24)")
    parser.add_argument("--methods", "-m", default="arp,icmp,syn", help="Métodos separados por coma: arp, icmp, syn")
    parser.add_argument("--output", "-o", choices=["json", "csv", "both"], default="both", help="Formato de salida")
    parser.add_argument("--out-path", help="Ruta base para los archivos de salida (sin extensión). Por defecto: results_TIMESTAMP")
    parser.add_argument("--verbose", "-v", action="store_true", help="Habilitar logging DEBUG")
    args = parser.parse_args()

    try:
        methods = parse_methods(args.methods)
    except ValueError as e:
        print(f"Error en métodos: {e}")
        return

    asyncio.run(run_discovery(args.targets, methods, args.output, args.out_path, args.verbose))


if __name__ == "__main__":
    main()