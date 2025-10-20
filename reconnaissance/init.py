from host_discovery import HostDiscoverer
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
    targets = "10.0.0.0/16"
    discoverer = HostDiscoverer(targets)
    hosts = await discoverer.discover(['arp', 'icmp', 'syn'])
    print(hosts)

if __name__ == "__main__":
    asyncio.run(main())