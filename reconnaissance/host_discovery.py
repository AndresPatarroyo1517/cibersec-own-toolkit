from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime
import argparse
import logging
from ipaddress import ip_network, IPv4Address
from typing import List, Dict, Optional, Set
from scapy.all import IP, ICMP, TCP, sr1, arping, conf
import os, sys
sys.path.append(os.path.abspath("../utilities"))
from save_results import save_results

conf.verb = 0
ICMP_TIMEOUT = 0.3  
SYN_TIMEOUT = 0.5
ARP_TIMEOUT = 2.0
COMMON_TCP_PORTS = [22, 80, 443, 3389, 8080]
MAX_WORKERS = 100  

class HostDiscoverer:
    """Escanea hosts activos en un rango CIDR usando ARP/ICMP/SYN."""
    def __init__(self, cidr_range: str):
        try:
            self.network = ip_network(cidr_range, strict=False)
        except ValueError as e:
            raise ValueError(f"CIDR inválido '{cidr_range}': {e}")
        
        self.cidr_range = cidr_range
        self.alive_hosts: List[Dict] = []
        self.logger = logging.getLogger(__name__)

        self.stats = {
            'total_targets': self.network.num_addresses - 2, 
            'discovered': 0,
            'methods_used': [],
            'start_time': None,
            'end_time': None
        }

    #Ping ICMP (rápido pero ruidoso) con ICMP ECHO REQUEST
    def ping_icmp(self, target_ip: IPv4Address):
        try:
            start_time = time.time()
            pkt = IP(dst=str(target_ip)) / ICMP()
            reply = sr1(pkt, timeout=ICMP_TIMEOUT, verbose=0)
            latency = (time.time() - start_time) * 1000
            if reply and reply.haslayer(ICMP):
                return {"ip": str(target_ip), 
                        "alive": True, 
                        "método": "icmp", 
                        "latencia_ms": round(latency, 2)}
        except Exception as e:
            self.logger.debug(f"ICMP error para {target_ip}: {e}")
        return None


    #SYN scan a puertos comunes (más silencioso)
    def ping_syn(self, target_ip: IPv4Address):
        for port in COMMON_TCP_PORTS_FOR_DISCOVERY:
            try:
                start_time = time.time()
                pkt = IP(dst=str(target_ip)) / TCP(dport=port, flags="S")
                reply = sr1(pkt, timeout=SYN_TIMEOUT, verbose=0)
                latency = (time.time() - start_time) * 1000
                if reply and reply.haslayer(TCP):
                    #SYN-ACK usa como flag el 0x12 o SA
                    tcp_flags = reply[TCP].flags
                    if (tcp_flags & 0x12) == 0x12 or tcp_flags == 'SA':
                        # Enviar RST para cerrar
                        rst_pkt = IP(dst=str(target_ip)) / TCP(dport=port, flags="R")
                        sr1(rst_pkt, timeout=0.1, verbose=0)
                        return {
                            "ip": str(target_ip),
                            "alive": True,
                            "método": "syn",
                            "latencia_ms": round(latency, 2),
                            "puerto": port
                        }
            except Exception as e:
                self.logger.debug(f"SYN error para {target_ip}:{port}: {e}")
                continue
        return None


    #ARP scan — solo redes locales
    def scan_arp(self):
        try:
            # Arping devuelve (answered, unanswered) 
            answered, _ = arping(self.cidr_range, timeout=ARP_TIMEOUT, verbose=0)
            arp_hosts = []
            for sent, received in answered:
                arp_hosts.append({
                    "ip": received.psrc,
                    "alive": True,
                    "método": "arp",
                    "latencia_ms": 0,  
                    "mac": received.hwsrc  
                })
            self.logger.info(f"ARP descubrió {len(arp_hosts)} hosts")
            return arp_hosts
        except PermissionError:
            self.logger.error("ARP requiere privilegios root/admin")
            return []
        except Exception as e:
            self.logger.warning(f"ARP scan falló (¿no estás en red local?): {e}")
            return []


    #Ejecuta el reconocimiento con los métodos solicitados (lista de strings)
    def discover(self, methods: List[str], max_workers: int = MAX_WORKERS):
        self.stats['start_time'] = datetime.now()
        self.stats['methods_used'] = methods
        discovered_ips: Set[str] = set()
        all_results: List[Dict] = []
        #ARP es más rápido por lo que va primero
        if 'arp' in methods:
            arp_results = self.scan_arp()
            for host in arp_results:
                if host['ip'] not in discovered_ips:
                    discovered_ips.add(host['ip'])
                    all_results.append(host)
        
        # Generar lista de IPs a escanear (excluyendo ya descubiertas)
        target_ips = [
            ip for ip in self.network.hosts()
            if str(ip) not in discovered_ips
        ]

        if not target_ips:
            self.logger.info("Todos los hosts ya descubiertos por ARP")
            self.alive_hosts = all_results
            self.stats['discovered'] = len(all_results)
            self.stats['end_time'] = datetime.now()
            return all_results
        
        self.logger.info(f"Escaneando {len(target_ips)} IPs con {methods} (workers={max_workers})")
        
        #Threading para escanear con ECHO y SYN
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            
            # Crear tareas
            for ip in target_ips:
                if 'icmp' in methods:
                    futures.append(executor.submit(self.ping_icmp, ip))
                if 'syn' in methods:
                    futures.append(executor.submit(self.ping_syn, ip))
            
            # Procesar resultados conforme terminan
            completed = 0
            total = len(futures)
            
            for future in as_completed(futures):
                completed += 1
                if completed % 50 == 0 or completed == total:
                    self.logger.debug(f"Progreso: {completed}/{total} tareas completadas")
                
                try:
                    result = future.result()
                    if result and result['ip'] not in discovered_ips:
                        discovered_ips.add(result['ip'])
                        all_results.append(result)
                except Exception as e:
                    self.logger.error(f"Error en tarea: {e}")
        
        # Ordenar por IP para output legible
        all_results.sort(key=lambda x: IPv4Address(x['ip']))
        
        self.alive_hosts = all_results
        self.stats['discovered'] = len(all_results)
        self.stats['end_time'] = datetime.now()
        
        duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        self.logger.info(f"Descubrimiento completado en {duration:.2f}s")
        self.logger.info(f"Hosts vivos: {len(all_results)}/{self.stats['total_targets']}")
        
        return all_results

    def get_statistics(self) -> Dict:
        """Retorna estadísticas del escaneo."""
        if self.stats['start_time'] and self.stats['end_time']:
            duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        else:
            duration = 0
        
        return {
            'cidr_range': self.cidr_range,
            'total_targets': self.stats['total_targets'],
            'discovered': self.stats['discovered'],
            'methods_used': self.stats['methods_used'],
            'duration_seconds': round(duration, 2),
            'hosts_per_second': round(self.stats['total_targets'] / duration, 2) if duration > 0 else 0
        }

#Logger con outpus en json
def setup_logging(verbose: bool, log_file: Optional[str] = None) -> logging.Logger:
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    if logger.handlers:
        logger.handlers.clear()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        logger.info(f"Logs guardándose en: {log_file}")
    
    return logger

#Válida si existen problemas con los métodos en consola
def validate_methods(methods_str: str) -> List[str]:
    allowed = {'arp', 'icmp', 'syn'}
    methods = [m.strip().lower() for m in methods_str.split(',') if m.strip()]
    
    if not methods:
        raise ValueError("Debes especificar al menos un método")
    
    invalid = set(methods) - allowed
    if invalid:
        raise ValueError(
            f"Métodos inválidos: {invalid}. "
            f"Permitidos: {allowed}"
        )
    
    return methods

def main():
    parser = argparse.ArgumentParser(
        description='Network Host Discovery Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
        Ejemplos de uso:
        # Escaneo rápido de red local con ARP
        python host_discovery.py -t 192.168.1.0/24 -m arp

        # Escaneo completo con todos los métodos
        python host_discovery.py -t 10.0.0.0/24 -m arp,icmp,syn -o both -v

        # Solo ICMP (útil para testing)
        python host_discovery.py -t 192.168.1.1/32 -m icmp --verbose

        Notas:
        - ARP requiere privilegios root/admin en la mayoría de sistemas
        - SYN scan también puede requerir privilegios para raw sockets
        - Usa --verbose para debugging detallado
                '''
            )
    
    parser.add_argument(
        '-t', '--targets',
        required=True,
        metavar='CIDR',
        help='Rango CIDR objetivo (ej: 192.168.1.0/24)'
    )
    
    parser.add_argument(
        '-m', '--methods',
        default='icmp,syn',
        metavar='METHODS',
        help='Métodos separados por coma: arp, icmp, syn (default: icmp,syn)'
    )
    
    parser.add_argument(
        '-o', '--output',
        choices=['json', 'csv', 'both'],
        default='json',
        help='Formato de salida (default: json)'
    )
    
    parser.add_argument(
        '--out-path',
        metavar='PATH',
        help='Ruta base para archivos de salida sin extensión (default: results_TIMESTAMP)'
    )
    
    parser.add_argument(
        '-w', '--workers',
        type=int,
        default=MAX_WORKERS,
        metavar='N',
        help=f'Número de workers concurrentes (default: {MAX_WORKERS})'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Habilitar logging DEBUG'
    )
    
    parser.add_argument(
        '--log-file',
        metavar='PATH',
        help='Guardar logs en archivo (default: no file logging)'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.verbose, args.log_file)
    
    # Banner
    logger.info("=" * 60)
    logger.info("HOST DISCOVERY - Módulo de Reconocimiento")
    logger.info("=" * 60)
    
    # Validar métodos
    try:
        methods = validate_methods(args.methods)
    except ValueError as e:
        logger.error(f"Error en métodos: {e}")
        return 1
    
    # Validar workers
    if args.workers < 1 or args.workers > 500:
        logger.error("Workers debe estar entre 1 y 500")
        return 1
    
    # Iniciar descubrimiento
    try:
        discoverer = HostDiscoverer(args.targets)
        results = discoverer.discover(methods, max_workers=args.workers)
        stats = discoverer.get_statistics()
        
    except ValueError as e:
        logger.error(f"Error de validación: {e}")
        return 1
    except PermissionError:
        logger.error("Privilegios insuficientes. Ejecuta con sudo/admin para ARP/SYN")
        return 1
    except KeyboardInterrupt:
        logger.warning("\nEscaneo interrumpido por usuario")
        return 130
    except Exception as e:
        logger.error(f"Error inesperado: {e}", exc_info=args.verbose)
        return 1
    
    # Guardar resultados
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_path = args.out_path or f"host_discovery_{timestamp}"
    
    save_results(results, args.output, base_path, stats, logger)
    
    # Resumen final
    logger.info("=" * 60)
    logger.info("RESUMEN")
    logger.info("-" * 60)
    logger.info(f"Rango objetivo: {stats['cidr_range']}")
    logger.info(f"Hosts totales: {stats['total_targets']}")
    logger.info(f"Hosts descubiertos: {stats['discovered']}")
    logger.info(f"Tasa de descubrimiento: {stats['discovered']/stats['total_targets']*100:.1f}%")
    logger.info(f"Duración: {stats['duration_seconds']}s")
    logger.info(f"Velocidad: {stats['hosts_per_second']} hosts/s")
    logger.info("=" * 60)
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
