import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import logging
from scapy.all import IP, TCP, sr1, conf
import time
from typing import List, Dict, Optional
from datetime import datetime
import os, sys
sys.path.append(os.path.abspath("../utilities"))
from save_results import save_results

conf.verb = 0

BANNER_TIMEOUT = 0.5
SYN_TIMEOUT = 1.0
MAX_WORKERS = 100

SERVICE_SIGNATURES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    8080: "http-proxy",
}


class PortScanner:
    """Escáner de puertos TCP con detección de servicios."""
    
    def __init__(self, target: str):
        """
        Args:
            target: IP o hostname
        
        Raises:
            ValueError: Si el target es inválido
        """
        self.logger = logging.getLogger(__name__)
        
        # Validar y resolver target
        try:
            socket.inet_aton(target)
            self.target = target
        except socket.error:
            try:
                self.target = socket.gethostbyname(target)
                self.logger.info(f"Hostname {target} resuelto a {self.target}")
            except socket.gaierror:
                raise ValueError(f"Target inválido: {target}")
        
        self.results = {
            "ip": self.target,
            "hostname": target if target != self.target else None,
            "scan_time": datetime.now().isoformat(),
            "ports": []
        }
        
        self.stats = {
            'total_ports': 0,
            'open_ports': 0,
            'closed_ports': 0,
            'filtered_ports': 0,
            'start_time': None,
            'end_time': None
        }
    
    def grab_banner(self, port: int) -> tuple[str, str, str]:
        """
        Intenta obtener banner del servicio.
        
        Returns:
            (banner, service, version)
        """
        banner = ""
        service = SERVICE_SIGNATURES.get(port, "unknown")
        version = ""
        
        # Intento 1: Conectar y leer banner pasivo
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(BANNER_TIMEOUT)
                result = s.connect_ex((self.target, port))
                
                if result != 0:
                    return "", service, ""
                
                # Leer banner (algunos servicios lo envían inmediatamente)
                try:
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                except socket.timeout:
                    pass  # No hay banner pasivo
                
                # Si hay banner, parsear
                if banner:
                    service, version = self.parse_banner(banner, port)
                    return banner, service, version
        
        except Exception as e:
            self.logger.debug(f"Error en banner grab pasivo para puerto {port}: {e}")
        
        # Intento 2: Banner grabbing activo (HTTP)
        if port in [80, 8080, 8000, 8888]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(BANNER_TIMEOUT)
                    s.connect((self.target, port))
                    s.sendall(b'GET / HTTP/1.0\r\nHost: ' + self.target.encode() + b'\r\n\r\n')
                    http_response = s.recv(2048).decode('utf-8', errors='ignore')
                    
                    if "HTTP" in http_response:
                        service, version = self.parse_http(http_response)
                        return http_response[:200], service, version
            except Exception as e:
                self.logger.debug(f"Error en HTTP probe para puerto {port}: {e}")
        
        # Intento 3: SSL/TLS probe
        if port in [443, 8443, 993, 995]:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target, port), timeout=BANNER_TIMEOUT) as sock:
                    with context.wrap_socket(sock) as ssock:
                        cert = ssock.getpeercert()
                        # Extraer info del certificado
                        if cert:
                            subject = dict(x[0] for x in cert.get('subject', []))
                            issuer = dict(x[0] for x in cert.get('issuer', []))
                            version = f"SSL/TLS - CN: {subject.get('commonName', 'unknown')}"
                            return f"SSL cert: {subject.get('commonName', 'N/A')}", "https", version
            except Exception as e:
                self.logger.debug(f"Error en SSL probe para puerto {port}: {e}")
        
        return banner, service, version
    
    def parse_banner(self, banner: str, port: int) -> tuple[str, str]:
        """
        Parsea banner para identificar servicio y versión.
        
        Returns:
            (service, version)
        """
        banner_lower = banner.lower()
        
        # SSH
        if banner.startswith("SSH-"):
            parts = banner.split()
            version_str = parts[0].replace("SSH-", "") if parts else ""
            software = " ".join(parts[1:]) if len(parts) > 1 else ""
            return "ssh", f"{version_str} {software}".strip()
        
        # FTP
        if "ftp" in banner_lower:
            # Ejemplo: "220 ProFTPD 1.3.5 Server"
            parts = banner.split()
            for i, part in enumerate(parts):
                if any(char.isdigit() for char in part):
                    version = " ".join(parts[i:i+3])
                    return "ftp", version
            return "ftp", ""
        
        # SMTP
        if "smtp" in banner_lower or banner.startswith("220"):
            return "smtp", banner.split("\n")[0]
        
        # HTTP (en banner pasivo)
        if "http" in banner_lower:
            return self.parse_http(banner)
        
        return "unknown", ""
    
    def parse_http(self, http_response: str) -> tuple[str, str]:
        """Parsea respuesta HTTP para extraer servidor y versión."""
        lines = http_response.split('\n')
        server = ""
        powered_by = ""
        
        for line in lines:
            line_lower = line.lower()
            if line_lower.startswith('server:'):
                server = line.split(':', 1)[1].strip()
            elif line_lower.startswith('x-powered-by:'):
                powered_by = line.split(':', 1)[1].strip()
        
        if server:
            return "http", server
        elif powered_by:
            return "http", f"Powered by {powered_by}"
        else:
            return "http", ""
    
    def scan_port_connect(self, port: int) -> Optional[Dict]:
        """TCP Connect scan (completa el handshake)."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(SYN_TIMEOUT)
                result = s.connect_ex((self.target, port))
                
                if result == 0:
                    # Puerto abierto
                    banner, service, version = self.grab_banner(port)
                    
                    return {
                        "port": port,
                        "state": "open",
                        "service": service,
                        "version": version,
                        "banner": banner[:100] if banner else ""  # Limitar tamaño
                    }
                else:
                    # Puerto cerrado/filtrado
                    return None
        
        except socket.timeout:
            # Probablemente filtrado
            return {
                "port": port,
                "state": "filtered",
                "service": SERVICE_SIGNATURES.get(port, "unknown"),
                "version": "",
                "banner": ""
            }
        except Exception as e:
            self.logger.debug(f"Error en connect scan puerto {port}: {e}")
            return None
    
    def scan_port_syn(self, port: int) -> Optional[Dict]:
        """
        SYN scan (half-open scan).
        
        Ventajas:
        - Más stealth (no completa handshake)
        - Más rápido
        
        Desventajas:
        - Requiere privilegios root
        - Puede ser detectado por IDS
        """
        try:
            # Enviar SYN
            syn_pkt = IP(dst=self.target) / TCP(dport=port, flags="S")
            reply = sr1(syn_pkt, timeout=SYN_TIMEOUT, verbose=0)
            
            if reply is None:
                # Timeout = filtrado o puerto cerrado
                return None
            
            if reply.haslayer(TCP):
                tcp_flags = reply[TCP].flags
                
                # SYN-ACK (0x12 o 'SA')
                if tcp_flags == 'SA' or (tcp_flags & 0x12) == 0x12:
                    # Puerto abierto - enviar RST para cerrar
                    rst_pkt = IP(dst=self.target) / TCP(dport=port, flags="R")
                    sr1(rst_pkt, timeout=0.1, verbose=0)
                    
                    # Intentar banner grabbing con connect normal
                    banner, service, version = self.grab_banner(port)
                    
                    return {
                        "port": port,
                        "state": "open",
                        "service": service,
                        "version": version,
                        "banner": banner[:100] if banner else ""
                    }
                
                # RST (0x04 o 'R') = puerto cerrado
                elif tcp_flags == 'R' or tcp_flags == 'RA':
                    return None
            
            # ICMP unreachable = filtrado
            return None
        
        except PermissionError:
            raise PermissionError(
                "SYN scan requiere privilegios root. "
                "Ejecuta con sudo o usa modo 'connect'"
            )
        except Exception as e:
            self.logger.debug(f"Error en SYN scan puerto {port}: {e}")
            return None
    
    def scan(self, ports: List[int], mode: str = 'connect', 
             max_workers: int = MAX_WORKERS, show_closed: bool = False) -> Dict:
        """
        Ejecuta escaneo de puertos.
        
        Args:
            ports: Lista de puertos a escanear
            mode: 'connect' o 'syn'
            max_workers: Número de threads concurrentes
            show_closed: Si True, incluye puertos cerrados en resultados
        
        Returns:
            Diccionario con resultados
        """
        self.stats['start_time'] = datetime.now()
        self.stats['total_ports'] = len(ports)
        
        self.logger.info(f"Iniciando escaneo {mode.upper()} en {self.target}")
        self.logger.info(f"Puertos a escanear: {len(ports)}")
        self.logger.info(f"Workers concurrentes: {max_workers}")
        
        # Seleccionar función de escaneo
        if mode == 'syn':
            scan_func = self.scan_port_syn
        else:
            scan_func = self.scan_port_connect
        
        # Escaneo concurrente
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {
                executor.submit(scan_func, port): port 
                for port in ports
            }
            
            completed = 0
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                completed += 1
                
                # Progress cada 100 puertos
                if completed % 100 == 0 or completed == len(ports):
                    self.logger.debug(f"Progreso: {completed}/{len(ports)} puertos")
                
                try:
                    result = future.result()
                    
                    if result:
                        if result['state'] == 'open':
                            self.stats['open_ports'] += 1
                            self.results['ports'].append(result)
                            self.logger.info(
                                f"[+] {port}/tcp OPEN - {result['service']} "
                                f"{result['version']}"
                            )
                        elif result['state'] == 'filtered':
                            self.stats['filtered_ports'] += 1
                            if show_closed:
                                self.results['ports'].append(result)
                        else:
                            self.stats['closed_ports'] += 1
                            if show_closed:
                                self.results['ports'].append(result)
                    else:
                        self.stats['closed_ports'] += 1
                
                except Exception as e:
                    self.logger.error(f"Error procesando puerto {port}: {e}")
        
        # Ordenar por puerto
        self.results['ports'].sort(key=lambda x: x['port'])
        
        self.stats['end_time'] = datetime.now()
        duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        
        self.logger.info("=" * 60)
        self.logger.info(f"Escaneo completado en {duration:.2f} segundos")
        self.logger.info(f"Puertos abiertos: {self.stats['open_ports']}")
        self.logger.info(f"Puertos cerrados: {self.stats['closed_ports']}")
        self.logger.info(f"Puertos filtrados: {self.stats['filtered_ports']}")
        self.logger.info("=" * 60)
        
        return self.results
    
    def get_statistics(self) -> Dict:
        """Retorna estadísticas del escaneo."""
        if self.stats['start_time'] and self.stats['end_time']:
            duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        else:
            duration = 0
        
        return {
            **self.stats,
            'duration_seconds': round(duration, 2),
            'ports_per_second': round(self.stats['total_ports'] / duration, 2) if duration > 0 else 0
        }


def parse_port_range(port_str: str) -> List[int]:
    """
    Parsea string de puertos a lista de enteros.
    
    Soporta:
    - Individual: '80'
    - Lista: '80,443,8080'
    - Rango: '1-1024'
    - Mixto: '22,80,443,8000-9000'
    
    Args:
        port_str: String con puertos
    
    Returns:
        Lista ordenada de puertos únicos
    
    Raises:
        ValueError: Si el formato es inválido
    """
    ports = set()
    
    try:
        for part in port_str.split(','):
            part = part.strip()
            
            if '-' in part:
                # Rango
                start, end = part.split('-')
                start, end = int(start), int(end)
                
                if start < 1 or end > 65535 or start > end:
                    raise ValueError(f"Rango inválido: {part}")
                
                ports.update(range(start, end + 1))
            else:
                # Puerto individual
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(f"Puerto inválido: {port}")
                ports.add(port)
    
    except ValueError as e:
        raise ValueError(f"Formato de puertos inválido '{port_str}': {e}")
    
    return sorted(ports)


def setup_logging(verbose: bool, log_file: Optional[str] = None) -> logging.Logger:
    """Configura logging."""
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    if logger.handlers:
        logger.handlers.clear()
    
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
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
    
    return logger
                

def main():
    """Punto de entrada principal."""
    parser = argparse.ArgumentParser(
        description='Port Scanner - Escaneo de puertos TCP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Ejemplos:
  # Escaneo básico de puertos comunes
  python port_scanner.py -t 192.168.1.1 -p 1-1000

  # SYN scan (requiere root)
  sudo python port_scanner.py -t 192.168.1.1 -p 22,80,443 -m syn

  # Escaneo completo con detección de servicios
  python port_scanner.py -t scanme.nmap.org -p 1-10000 -o both -v
        '''
    )
    
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='IP o hostname objetivo'
    )
    
    parser.add_argument(
        '-p', '--ports',
        default='1-1024',
        help='Puertos a escanear (ej: 80, 22-443, 80,443,8000-9000)'
    )
    
    parser.add_argument(
        '-m', '--mode',
        choices=['connect', 'syn'],
        default='connect',
        help='Modo de escaneo (default: connect)'
    )
    
    parser.add_argument(
        '-o', '--output',
        choices=['json', 'csv', 'both'],
        default='json',
        help='Formato de salida (default: json)'
    )
    
    parser.add_argument(
        '--out-path',
        help='Ruta base para archivos de salida'
    )
    
    parser.add_argument(
        '-w', '--workers',
        type=int,
        default=MAX_WORKERS,
        help=f'Número de workers concurrentes (default: {MAX_WORKERS})'
    )
    
    parser.add_argument(
        '--show-closed',
        action='store_true',
        help='Mostrar también puertos cerrados/filtrados'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Habilitar logging DEBUG'
    )
    
    parser.add_argument(
        '--log-file',
        help='Guardar logs en archivo'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.verbose, args.log_file)
    
    # Banner
    logger.info("=" * 60)
    logger.info("PORT SCANNER - Módulo de Reconocimiento 1.2")
    logger.info("=" * 60)
    
    # Validar workers
    if args.workers < 1 or args.workers > 500:
        logger.error("Workers debe estar entre 1 y 500")
        return 1
    
    # Parsear puertos
    try:
        ports = parse_port_range(args.ports)
        logger.info(f"Puertos a escanear: {len(ports)}")
    except ValueError as e:
        logger.error(f"Error parseando puertos: {e}")
        return 1
    
    # Validar target y ejecutar scan
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
        logger.error(f"Error de validación: {e}")
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
    
    # Guardar resultados
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_path = args.out_path or f"portscan_{args.target}_{timestamp}"
    
    save_results(results, args.output, base_path, stats, logger)
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())