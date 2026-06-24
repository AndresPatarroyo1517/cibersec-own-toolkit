"""
Módulo 1.3: Subdomain Enumeration
Requisitos:
- Brute force DNS con wordlist
- Certificate Transparency Logs (crt.sh)
- DNS Zone Transfer (AXFR)
- Validación HTTP con detección de wildcards
- Extracción de títulos de página
- Concurrencia con asyncio + ThreadPoolExecutor
"""
import asyncio
import aiohttp
import json
import logging
import socket
import ssl
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urlparse

# Allow imports from project root
_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

logger = logging.getLogger(__name__)

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
    "blog", "shop", "app", "cdn", "static", "img", "cdn", "assets",
    "vpn", "remote", "webmail", "smtp", "pop", "ns1", "ns2", "mx",
    "owa", "autodiscover", "cpanel", "whm", "webdisk", "phpmyadmin",
    "backup", "git", "jenkins", "jira", "confluence", "wiki", "docs",
    "monitor", "status", "help", "support", "dashboard", "api-dev",
    "beta", "alpha", "demo", "panel", "portal", "secure", "ssl"
]

DNS_RESOLVERS = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]


class SubdomainEnumerator:
    """Enumeración de subdominios usando múltiples técnicas."""
    
    def __init__(self, domain: str, wordlist: Optional[List[str]] = None,
                 resolvers: Optional[List[str]] = None):
        self.domain = domain.lower().strip()
        self.wordlist = wordlist or COMMON_SUBDOMAINS
        self.resolvers = resolvers or DNS_RESOLVERS
        self.results: List[Dict] = []
        self.wildcard_ip: Optional[str] = None
        self.logger = logging.getLogger(__name__)
        
        self.stats = {
            'total_queries': 0,
            'found': 0,
            'wildcard_detected': False,
            'start_time': None,
            'end_time': None
        }
    
    def _resolve_dns(self, subdomain: str) -> Optional[Tuple[str, List[str]]]:
        """Resuelve un subdominio a IP usando socket.getaddrinfo."""
        fqdn = f"{subdomain}.{self.domain}"
        try:
            self.stats['total_queries'] += 1
            addrs = socket.getaddrinfo(fqdn, 80, socket.AF_INET, socket.SOCK_STREAM)
            ips = list(set(addr[4][0] for addr in addrs))
            if ips:
                return fqdn, ips
        except (socket.gaierror, socket.timeout):
            pass
        return None
    
    def _check_wildcard(self) -> Optional[str]:
        """Verifica si el dominio tiene wildcard DNS."""
        # Generar un subdominio aleatorio que no debería existir
        import random
        import string
        random_sub = ''.join(random.choices(string.ascii_lowercase, k=12))
        fqdn = f"{random_sub}.{self.domain}"
        try:
            addrs = socket.getaddrinfo(fqdn, 80, socket.AF_INET, socket.SOCK_STREAM)
            ips = list(set(addr[4][0] for addr in addrs))
            if ips:
                self.logger.warning(f"Wildcard DNS detectado! {random_sub}.{self.domain} -> {ips[0]}")
                self.stats['wildcard_detected'] = True
                return ips[0]
        except (socket.gaierror, socket.timeout):
            pass
        return None
    
    def _query_crtsh(self) -> List[str]:
        """Consulta Certificate Transparency logs via crt.sh."""
        subdomains: Set[str] = set()
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        try:
            import requests
            resp = requests.get(url, timeout=15, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; CyberSecToolkit/1.0)'
            })
            if resp.status_code == 200:
                entries = resp.json()
                for entry in entries:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{self.domain}") and sub != f"*.{self.domain}":
                            subdomains.add(sub.replace(f".{self.domain}", ""))
                self.logger.info(f"crt.sh encontró {len(subdomains)} subdominios potenciales")
        except ImportError:
            self.logger.warning("requests no instalado, saltando crt.sh")
        except Exception as e:
            self.logger.debug(f"Error consultando crt.sh: {e}")
        return list(subdomains)
    
    def _try_zone_transfer(self) -> List[str]:
        """Intenta DNS Zone Transfer (AXFR)."""
        subdomains: Set[str] = set()
        try:
            import dns.resolver
            import dns.query
            import dns.zone
            from dns.exception import DNSException
            
            # Obtener nameservers del dominio
            try:
                ns_records = dns.resolver.resolve(self.domain, 'NS', lifetime=5)
                nameservers = [str(rr) for rr in ns_records]
            except Exception:
                nameservers = []
            
            if not nameservers:
                return []
            
            self.logger.info(f"Intentando AXFR en {len(nameservers)} nameservers")
            for ns in nameservers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, self.domain, lifetime=10))
                    for name in zone.nodes.keys():
                        sub = str(name).rstrip('.')
                        if sub.endswith(f".{self.domain}"):
                            sub = sub.replace(f".{self.domain}", "")
                        if sub and sub != '@':
                            subdomains.add(sub)
                    self.logger.info(f"AXFR exitoso desde {ns}!")
                except DNSException as e:
                    self.logger.debug(f"AXFR falló en {ns}: {e}")
                except Exception as e:
                    self.logger.debug(f"Error AXFR en {ns}: {e}")
        except ImportError:
            self.logger.debug("dnspython no instalado, saltando AXFR")
        except Exception as e:
            self.logger.debug(f"Error en zone transfer: {e}")
        return list(subdomains)
    
    def _fetch_http_title(self, subdomain: str, ips: List[str]) -> Dict:
        """Intenta obtener título HTTP/HTTPS del subdominio."""
        fqdn = f"{subdomain}.{self.domain}"
        result = {
            "http_status": None,
            "https_status": None,
            "http_title": None,
            "https_title": None,
            "http_server": None,
            "https_server": None
        }
        
        for protocol, port in [("http", 80), ("https", 443)]:
            url = f"{protocol}://{fqdn}"
            try:
                import requests
                verify = False if protocol == "https" else None
                resp = requests.get(
                    url, timeout=5, verify=False,
                    headers={'User-Agent': 'Mozilla/5.0 CyberSecToolkit/1.0'},
                    allow_redirects=True
                )
                result[f"{protocol}_status"] = resp.status_code
                result[f"{protocol}_server"] = resp.headers.get('Server', '')
                
                # Extraer title con BeautifulSoup
                try:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    title = soup.title.string.strip() if soup.title and soup.title.string else None
                    result[f"{protocol}_title"] = title
                except ImportError:
                    # Fallback: buscar <title> con regex
                    import re
                    match = re.search(r'<title[^>]*>(.*?)</title>', resp.text, re.IGNORECASE | re.DOTALL)
                    if match:
                        result[f"{protocol}_title"] = match.group(1).strip()
                except Exception:
                    pass
                    
            except requests.exceptions.SSLWarning:
                # Ignorar warnings SSL - conexión exitosa
                result[f"{protocol}_status"] = "ssl_error"
            except requests.exceptions.ConnectionError:
                pass
            except requests.exceptions.Timeout:
                pass
            except Exception as e:
                self.logger.debug(f"Error HTTP en {fqdn}:{port}: {e}")
        
        return result
    
    async def _fetch_http_title_async(self, subdomain: str, ips: List[str], session: aiohttp.ClientSession) -> Dict:
        """Versión async de fetch_http_title."""
        fqdn = f"{subdomain}.{self.domain}"
        result = {
            "http_status": None,
            "http_title": None,
            "http_server": None
        }
        
        for protocol in ["http", "https"]:
            url = f"{protocol}://{fqdn}"
            try:
                ssl_ctx = False if protocol == "https" else None
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5),
                                       ssl=ssl_ctx) as resp:
                    result[f"{protocol}_status"] = resp.status
                    result[f"{protocol}_server"] = resp.headers.get('Server', '')
                    text = await resp.text()
                    
                    import re
                    match = re.search(r'<title[^>]*>(.*?)</title>', text, re.IGNORECASE | re.DOTALL)
                    if match:
                        result[f"{protocol}_title"] = match.group(1).strip()
            except Exception:
                pass
        
        return result
    
    def enumerate(self, use_crtsh: bool = True, use_axfr: bool = True,
                  resolve: bool = True, http_check: bool = True,
                  max_workers: int = 50) -> List[Dict]:
        """Ejecuta enumeración completa de subdominios."""
        self.stats['start_time'] = datetime.now()
        self.logger.info(f"Iniciando enumeración de subdominios para {self.domain}")
        self.logger.info(f"Wordlist: {len(self.wordlist)} subdominios")
        
        # 1. Detectar wildcard
        self.wildcard_ip = self._check_wildcard()
        if self.wildcard_ip:
            self.logger.warning(f"Wildcard DNS detectado: {self.wildcard_ip}")
        
        # 2. Recopilar subdominios potenciales
        potential_subs = set(s.strip().lower() for s in self.wordlist if s.strip())
        
        # 3. Certificate Transparency
        if use_crtsh:
            crtsh_subs = self._query_crtsh()
            potential_subs.update(crtsh_subs)
            self.logger.info(f"crt.sh añadió {len(crtsh_subs)} subdominios")
        
        # 4. Zone Transfer
        axfr_subs = []
        if use_axfr:
            axfr_subs = self._try_zone_transfer()
            potential_subs.update(axfr_subs)
            self.logger.info(f"AXFR añadió {len(axfr_subs)} subdominios")
        
        self.logger.info(f"Total subdominios a probar: {len(potential_subs)}")
        
        # 5. Resolución DNS con ThreadPoolExecutor
        found_subs: Dict[str, List[str]] = {}
        dns_futures = {}
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for sub in potential_subs:
                fqdn = f"{sub}.{self.domain}"
                # Si hay wildcard, verificar que no sea la wildcard IP
                future = executor.submit(self._resolve_dns, sub)
                dns_futures[future] = sub
            
            for future in as_completed(dns_futures):
                sub = dns_futures[future]
                try:
                    result = future.result()
                    if result:
                        fqdn, ips = result
                        # Filtrar wildcard ips
                        if self.wildcard_ip and self.wildcard_ip in ips:
                            if len(ips) == 1:
                                continue  # Solo wildcard, probablemente falso positivo
                        found_subs[sub] = ips
                except Exception as e:
                    self.logger.debug(f"Error resolviendo {sub}: {e}")
        
        self.logger.info(f"DNS Resolución completada: {len(found_subs)} encontrados")
        
        # 6. HTTP validation
        if http_check and found_subs:
            self.logger.info("Verificando HTTP/HTTPS...")
            async def check_all():
                async with aiohttp.ClientSession(
                    headers={'User-Agent': 'Mozilla/5.0 CyberSecToolkit/1.0'},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as session:
                    tasks = []
                    for sub, ips in list(found_subs.items())[:200]:  # Limitar a 200
                        tasks.append(self._fetch_http_title_async(sub, ips, session))
                    return await asyncio.gather(*tasks, return_exceptions=True)
            
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                http_results = loop.run_until_complete(check_all())
                loop.close()
                
                for (sub, ips), http_info in zip(found_subs.items(), http_results):
                    if isinstance(http_info, dict):
                        entry = {
                            "subdomain": f"{sub}.{self.domain}",
                            "ip": ips[0] if ips else None,
                            "ips": ips,
                            "wildcard": self.wildcard_ip is not None,
                            **http_info
                        }
                        self.results.append(entry)
            except Exception as e:
                self.logger.error(f"Error en verificación HTTP: {e}")
                # Fallback: agregar sin HTTP info
                for sub, ips in found_subs.items():
                    self.results.append({
                        "subdomain": f"{sub}.{self.domain}",
                        "ip": ips[0] if ips else None,
                        "ips": ips,
                        "wildcard": self.wildcard_ip is not None
                    })
        else:
            for sub, ips in found_subs.items():
                self.results.append({
                    "subdomain": f"{sub}.{self.domain}",
                    "ip": ips[0] if ips else None,
                    "ips": ips,
                    "wildcard": self.wildcard_ip is not None
                })
        
        # Ordenar resultados
        self.results.sort(key=lambda x: x['subdomain'])
        
        self.stats['found'] = len(self.results)
        self.stats['end_time'] = datetime.now()
        
        duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        self.logger.info(f"Enumeración completada en {duration:.2f}s")
        self.logger.info(f"Subdominios encontrados: {len(self.results)}")
        
        return self.results
    
    def get_statistics(self) -> Dict:
        if self.stats['start_time'] and self.stats['end_time']:
            duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        else:
            duration = 0
        return {
            'domain': self.domain,
            'total_queries': self.stats['total_queries'],
            'found': self.stats['found'],
            'wildcard_detected': self.stats['wildcard_detected'],
            'duration_seconds': round(duration, 2)
        }


def main():
    """CLI entry point."""
    import argparse
    parser = argparse.ArgumentParser(description='Subdomain Enumeration Tool')
    parser.add_argument('-d', '--domain', required=True, help='Dominio objetivo')
    parser.add_argument('-w', '--wordlist', help='Archivo de wordlist (opcional)')
    parser.add_argument('--no-crtsh', action='store_true', help='Saltar crt.sh')
    parser.add_argument('--no-axfr', action='store_true', help='Saltar AXFR')
    parser.add_argument('--no-http', action='store_true', help='Saltar verificación HTTP')
    parser.add_argument('-o', '--output', default='json', choices=['json', 'csv', 'both'])
    parser.add_argument('--out-path', help='Ruta de salida')
    parser.add_argument('-v', '--verbose', action='store_true')
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Cargar wordlist si se proporciona
    wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                wordlist = [line.strip() for line in f if line.strip()]
            logging.info(f"Wordlist cargada: {len(wordlist)} subdominios")
        except FileNotFoundError:
            logging.error(f"Wordlist no encontrada: {args.wordlist}")
            return 1
    
    enumerator = SubdomainEnumerator(args.domain, wordlist=wordlist)
    results = enumerator.enumerate(
        use_crtsh=not args.no_crtsh,
        use_axfr=not args.no_axfr,
        http_check=not args.no_http
    )
    stats = enumerator.get_statistics()
    
    # Output
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_path = args.out_path or f"subenum_{args.domain}_{timestamp}"
    
    from utilities.save_results import save_results
    save_results(results, args.output, base_path, stats, logging.getLogger())
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())