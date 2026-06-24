"""
Módulo 1.4: Web Technology Fingerprinting
Requisitos:
- HTTP Headers analysis (Server, X-Powered-By, WAF detection)
- HTML/JS framework detection (Angular, React, WordPress, etc.)
- Passive detection via cookies, response patterns
- Active probing of common paths
"""
import re
import json
import socket
import ssl
import os
import sys
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# Allow imports from project root
_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

logger = logging.getLogger(__name__)

# === WAF Signatures ===
WAF_SIGNATURES = {
    "Cloudflare": [
        "cf-ray", "__cfduid", "cloudflare",
        "cf-cache-status", "cf-request-id"
    ],
    "Akamai": [
        "x-akamai-transformed", "x-akamai-request-id",
        "akamai-grn"
    ],
    "AWS WAF": [
        "x-amzn-requestid", "x-amz-cf-id",
        "x-aws-waf-running-aws"
    ],
    "CloudFront": [
        "x-amz-cf-id", "x-amz-cf-pop",
        "x-edge-request-id", "x-cache"
    ],
    "ModSecurity": [
        "mod_security", "NOYB", "x-powered-by: mod_security"
    ],
    "F5 BIG-IP": [
        "big-ip", "x-request-uri", "x-wa-info",
        "x-request-id: f5-"
    ],
    "Sucuri": [
        "x-sucuri-id", "x-sucuri-cache",
        "x-sucuri-request-id"
    ],
    "Wordfence": [
        "wordfence", "x-wordfence-*"
    ],
    "Barracuda": [
        "barracuda", "x-bws-*"
    ]
}

# === Framework Signatures ===
FRAMEWORK_SIGNATURES = {
    "React": [
        r'__NEXT_DATA__', r'data-reactroot', r'data-reactid',
        r'react\.js', r'react\.min\.js', r'create-react-app'
    ],
    "Angular": [
        r'ng-app', r'ng-version', r'angular\.js', r'angular\.min\.js',
        r'_ngContent', r'ng_template'
    ],
    "Vue.js": [
        r'vue\.js', r'vue\.min\.js', r'v-bind', r'v-model',
        r'v-if', r'v-for', r'__VUE__'
    ],
    "Next.js": [
        r'__NEXT_DATA__', r'/_next/static', r'next\.js',
        r'navigation\.js'
    ],
    "Nuxt.js": [
        r'__NUXT__', r'/_nuxt/'
    ],
    "jQuery": [
        r'jquery-\d+\.\d+\.\d+\.min\.js', r'jquery\.js',
        r'\$\(document\)\.ready'
    ],
    "Bootstrap": [
        r'bootstrap\.min\.css', r'bootstrap\.css',
        r'bootstrap\.bundle\.min\.js'
    ],
    "WordPress": [
        r'wp-content', r'wp-includes', r'wp-json',
        r'wp-admin', r'wordpress'
    ],
    "Drupal": [
        r'drupal\.js', r'drupal-', r'sites/default',
        r'misc/drupal'
    ],
    "Joomla": [
        r'joomla', r'com_content', r'com_user',
        r'components/com_'
    ],
    "Laravel": [
        r'laravel', r'csrf-token', r'XSRF-TOKEN',
        r'livewire'
    ],
    "Django": [
        r'django', r'csrfmiddlewaretoken', r'sessionid',
        r'__admin__'
    ],
    "Flask": [
        r'flask', r'flask-login', r'__flask__'
    ],
    "Express": [
        r'express', r'x-powered-by: express',
        r'connect.sid'
    ]
}

# === Cookie to Technology Mapping ===
COOKIE_SIGNATURES = {
    r'PHPSESSID': 'PHP',
    r'JSESSIONID': 'Java/J2EE',
    r'ASP\.NET_SessionId': 'ASP.NET',
    r'laravel_session': 'Laravel',
    r'connect\.sid': 'Express',
    r'sessionid': 'Django',
    r'flask': 'Flask',
    r'wordpress_': 'WordPress',
    r'wp-settings-': 'WordPress',
    r'drupal': 'Drupal',
    r'SESS': 'Drupal/Generic PHP',
    r'CAKEPHP': 'CakePHP',
    r'symfony': 'Symfony',
    r'rails': 'Ruby on Rails',
    r'_session': 'Java',
    r'XSRF-TOKEN': 'Laravel',
    r'csrf_token': 'Django/Flask'
}

# === Interesting Paths for Active Probing ===
INTERESTING_PATHS = [
    "/admin", "/administrator", "/admin.php", "/admin/",
    "/wp-admin", "/wp-admin/admin-ajax.php",
    "/.git/config", "/.env", "/.gitignore",
    "/api/v1", "/api/v2", "/api/", "/api/v1/users",
    "/swagger.json", "/api-docs", "/docs", "/openapi.json",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/phpinfo.php", "/info.php", "/test.php",
    "/backup", "/backups", "/.backup",
    "/config", "/configuration.php", "/config.php",
    "/db", "/database", "/database.sql",
    "/login", "/signin", "/auth",
    "/manage", "/management", "/panel",
    "/server-status", "/server-info",
    "/.well-known/", "/.well-known/security.txt",
    "/console", "/debug", "/dev",
    "/static", "/assets", "/uploads",
    "/vendor", "/composer.json", "/package.json"
]

COMMON_TECH_PATHS = {
    "/wp-content/": "WordPress",
    "/administrator/": "Joomla",
    "/sites/default/": "Drupal",
    "/laravel.js": "Laravel",
    "/_next/static/": "Next.js",
    "/_nuxt/": "Nuxt.js",
    "/static/js/bundle.js": "React (CRA)",
    "/angular.js": "Angular",
    "/vue.js": "Vue.js"
}


class WebFingerprinter:
    """Web Technology Fingerprinting & Analysis."""
    
    def __init__(self, url: str):
        self.url = url.rstrip('/')
        self.parsed = urlparse(self.url)
        self.target = self.parsed.netloc or self.parsed.path
        self.results = {
            "url": self.url,
            "target": self.target,
            "scan_time": datetime.now().isoformat(),
            "server": None,
            "technologies": [],
            "frameworks": [],
            "waf": None,
            "cms": None,
            "cookies": [],
            "interesting_paths": [],
            "headers": {},
            "http_status": None,
            "latency_ms": None
        }
        self.logger = logging.getLogger(__name__)
        self.stats = {
            'start_time': None,
            'end_time': None,
            'paths_checked': 0,
            'technologies_found': 0
        }
    
    def _fingerprint_headers(self, headers: Dict) -> None:
        """Analiza HTTP headers para identificar tecnologías."""
        self.results['headers'] = dict(headers)
        
        # Server header
        server = headers.get('Server', headers.get('server', ''))
        if server:
            self.results['server'] = server
            self._add_tech("Server", server)
        
        # X-Powered-By
        xpb = headers.get('X-Powered-By', headers.get('x-powered-by', ''))
        if xpb:
            self._add_tech("X-Powered-By", xpb)
            if 'PHP' in xpb:
                self._add_framework("PHP")
        
        # X-AspNet-Version
        xav = headers.get('X-AspNet-Version', headers.get('x-aspnet-version', ''))
        if xav:
            self._add_tech("ASP.NET", f"v{xav}")
            self._add_framework("ASP.NET")
        
        # Content-Type / charset
        ct = headers.get('Content-Type', '')
        if 'charset=' in ct:
            charset = ct.split('charset=')[-1].split(';')[0].strip()
            self._add_tech("Charset", charset)
        
        # Via / X-Cache headers (CDN indicators)
        via = headers.get('Via', '')
        x_cache = headers.get('X-Cache', '')
        cf_ray = headers.get('cf-ray', '')
        if via or x_cache or cf_ray:
            self._detect_cdn(headers)
        
        # Security headers
        security_headers = {
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', ''),
            'Content-Security-Policy': headers.get('Content-Security-Policy', ''),
            'X-Frame-Options': headers.get('X-Frame-Options', ''),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', ''),
            'X-XSS-Protection': headers.get('X-XSS-Protection', ''),
            'Referrer-Policy': headers.get('Referrer-Policy', ''),
        }
        present = {k: v for k, v in security_headers.items() if v}
        if present:
            self.results['security_headers'] = present
            self._add_tech("Security Headers", ", ".join(present.keys()))
    
    def _detect_cdn(self, headers: Dict) -> None:
        """Detecta CDN por headers."""
        h = {k.lower(): v for k, v in headers.items()}
        
        if 'cf-ray' in h or 'cf-cache-status' in h:
            self._add_tech("CDN", "Cloudflare")
            self._add_framework("Cloudflare")
        if 'x-amz-cf-id' in h or 'x-edge-request-id' in h:
            self._add_tech("CDN", "AWS CloudFront")
        if 'x-akamai-transformed' in h:
            self._add_tech("CDN", "Akamai")
    
    def _detect_waf(self, headers: Dict, body: str) -> None:
        """Detecta WAF por headers y body."""
        h = {k.lower(): v for k, v in headers.items()}
        body_lower = body.lower()
        
        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                sig_lower = sig.lower()
                if sig_lower in h or sig_lower in body_lower:
                    self.results['waf'] = waf_name
                    self._add_tech("WAF", waf_name)
                    return
        
        # Cloudflare también detectable por ray
        if 'cf-ray' in h:
            self.results['waf'] = 'Cloudflare'
            self._add_tech("WAF", "Cloudflare")
    
    def _fingerprint_body(self, body: str) -> None:
        """Analiza el HTML/JS body para detectar frameworks."""
        body_lower = body.lower()
        
        for framework, patterns in FRAMEWORK_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    self._add_framework(framework)
                    # Detectar CMS específico
                    if framework in ['WordPress', 'Drupal', 'Joomla']:
                        self.results['cms'] = framework
                    break
        
        # Detectar generadores
        generator_match = re.search(
            r'<meta\s+name="generator"[^>]+content="([^"]+)"',
            body, re.IGNORECASE
        )
        if generator_match:
            generator = generator_match.group(1).strip()
            self._add_tech("Generator", generator)
            if 'wordpress' in generator.lower():
                self.results['cms'] = 'WordPress'
            elif 'drupal' in generator.lower():
                self.results['cms'] = 'Drupal'
            elif 'joomla' in generator.lower():
                self.results['cms'] = 'Joomla'
        
        # Detectar librerías JS en scripts
        script_matches = re.findall(
            r'<script[^>]+src=["\']([^"\']+)["\']',
            body, re.IGNORECASE
        )
        for script in script_matches:
            # Extraer nombre de librería
            name_match = re.search(r'/([\w.-]+)\.(?:min\.)?js', script)
            if name_match:
                lib_name = name_match.group(1)
                # Ignorar nombres genéricos
                if lib_name not in ['app', 'main', 'bundle', 'script', 'index']:
                    self._add_tech(f"JS Library", lib_name)
    
    def _fingerprint_cookies(self, cookies: List[Dict]) -> None:
        """Analiza cookies para identificar tecnologías."""
        for cookie in cookies:
            name = cookie.get('name', '') if isinstance(cookie, dict) else cookie
            self.results['cookies'].append(cookie)
            
            for pattern, tech in COOKIE_SIGNATURES.items():
                if re.search(pattern, str(name), re.IGNORECASE):
                    self._add_framework(tech)
                    if tech in ['WordPress', 'Drupal', 'Joomla']:
                        self.results['cms'] = tech
                    break
    
    def _active_probe(self, path: str, session: requests.Session, timeout: int = 5) -> Optional[Dict]:
        """Prueba un path interesante."""
        url = urljoin(self.url, path)
        try:
            resp = session.get(
                url, timeout=timeout, verify=False,
                headers={'User-Agent': 'Mozilla/5.0 CyberSecToolkit/1.0'},
                allow_redirects=True
            )
            self.stats['paths_checked'] += 1
            
            if resp.status_code != 404:
                return {
                    "path": path,
                    "status": resp.status_code,
                    "size": len(resp.content),
                    "title": self._extract_title(resp.text)
                }
        except requests.exceptions.SSLWarning:
            pass
        except Exception as e:
            self.logger.debug(f"Error probing {path}: {e}")
        return None
    
    def _extract_title(self, html: str) -> Optional[str]:
        """Extrae el título de una página HTML."""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            if soup.title and soup.title.string:
                return soup.title.string.strip()[:100]
        except Exception:
            pass
        # Fallback regex
        match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()[:100]
        return None
    
    def _add_tech(self, category: str, value: str) -> None:
        """Add a technology finding."""
        entry = {"category": category, "value": value}
        if entry not in self.results['technologies']:
            self.results['technologies'].append(entry)
    
    def _add_framework(self, name: str) -> None:
        """Add a framework finding."""
        if name not in self.results['frameworks']:
            self.results['frameworks'].append(name)
    
    def fingerprint(self, probe_paths: bool = True,
                    max_path_workers: int = 10) -> Dict:
        """Ejecuta fingerprinting completo."""
        self.stats['start_time'] = datetime.now()
        self.logger.info(f"Iniciando fingerprinting de {self.url}")
        
        session = requests.Session()
        session.verify = False
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 CyberSecToolkit/1.0'
        })
        
        try:
            # 1. HTTP Request inicial
            start = datetime.now()
            resp = session.get(self.url, timeout=15, allow_redirects=True)
            latency = (datetime.now() - start).total_seconds() * 1000
            self.results['http_status'] = resp.status_code
            self.results['latency_ms'] = round(latency, 2)
            
            # 2. Header Analysis
            self._fingerprint_headers(dict(resp.headers))
            
            # 3. WAF Detection
            self._detect_waf(dict(resp.headers), resp.text)
            
            # 4. Body Analysis (HTML/JS)
            self._fingerprint_body(resp.text)
            
            # 5. Cookie Analysis
            cookies = [dict(c) for c in session.cookies]
            self._fingerprint_cookies(cookies)
            
            # 6. Active Probing
            if probe_paths:
                self.logger.info(f"Probando {len(INTERESTING_PATHS)} paths...")
                found_paths = []
                
                with ThreadPoolExecutor(max_workers=max_path_workers) as executor:
                    futures = {
                        executor.submit(self._active_probe, path, session): path
                        for path in INTERESTING_PATHS
                    }
                    for future in as_completed(futures):
                        path = futures[future]
                        try:
                            result = future.result()
                            if result:
                                found_paths.append(result)
                                self.logger.debug(f"[+] {path} -> {result['status']}")
                        except Exception as e:
                            self.logger.debug(f"Error en {path}: {e}")
                
                # Ordenar por path
                found_paths.sort(key=lambda x: x['path'])
                self.results['interesting_paths'] = found_paths
        
        except requests.exceptions.SSLError as e:
            self.logger.warning(f"SSL Error: {e}")
            # Intentar sin SSL
            try:
                http_url = self.url.replace('https://', 'http://')
                resp = session.get(http_url, timeout=15)
                self.results['http_status'] = resp.status_code
                self._fingerprint_headers(dict(resp.headers))
            except Exception as e2:
                self.logger.error(f"Error HTTP fallback: {e2}")
        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"Connection Error: {e}")
        except requests.exceptions.Timeout:
            self.logger.error("Timeout en conexión inicial")
        except Exception as e:
            self.logger.error(f"Error inesperado: {e}")
        
        # Estadísticas
        self.stats['technologies_found'] = len(self.results['technologies'])
        self.stats['end_time'] = datetime.now()
        
        # Limpiar session
        session.close()
        
        duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        self.logger.info(f"Fingerprinting completado en {duration:.2f}s")
        self.logger.info(f"Tecnologías encontradas: {len(self.results['technologies'])}")
        self.logger.info(f"Frameworks: {', '.join(self.results['frameworks']) or 'Ninguno'}")
        
        return self.results
    
    def get_statistics(self) -> Dict:
        if self.stats['start_time'] and self.stats['end_time']:
            duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        else:
            duration = 0
        return {
            'url': self.url,
            'technologies_found': self.stats['technologies_found'],
            'paths_checked': self.stats['paths_checked'],
            'duration_seconds': round(duration, 2)
        }


def main():
    """CLI entry point."""
    import argparse
    parser = argparse.ArgumentParser(description='Web Technology Fingerprinting Tool')
    parser.add_argument('-u', '--url', required=True, help='URL objetivo')
    parser.add_argument('--no-probe', action='store_true', help='Saltar active probing')
    parser.add_argument('-o', '--output', default='json', choices=['json', 'csv', 'both'])
    parser.add_argument('--out-path', help='Ruta de salida')
    parser.add_argument('-v', '--verbose', action='store_true')
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    fingerprinter = WebFingerprinter(args.url)
    results = fingerprinter.fingerprint(probe_paths=not args.no_probe)
    stats = fingerprinter.get_statistics()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_path = args.out_path or f"webfinger_{results['target']}_{timestamp}"
    
    from utilities.save_results import save_results
    save_results(results, args.output, base_path, stats, logging.getLogger())
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())