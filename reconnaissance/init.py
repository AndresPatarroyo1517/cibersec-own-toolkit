from host_discovery import HostDiscoverer
from port_scanner import PortScanner
import asyncio

def print_banner():
    banner = """
    ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
    ██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██████╔╝█████╗  ██║     ███████║██╔██╗ ██║
    ██╔══██╗██╔══╝  ██║     ██╔══██║██║╚██╗██║
    ██║  ██║███████╗╚██████╗██║  ██║██║ ╚████║
    ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    -- Network Reconnaissance Suite --
    """
    print(banner)

async def main():
    print_banner()
    targets = "127.0.0.1"
    #discoverer = HostDiscoverer(targets)
    banner = PortScanner(targets)
    host = banner.get_banner(targets, port = '22')
    #hosts = discoverer.discover(['arp', 'icmp', 'syn'])
    #print(hosts)
    print(host)

if __name__ == "__main__":
    asyncio.run(main())