import netifaces
from typing import List, Dict, Any

def run_eth_survey_netifaces() -> List[Dict[str, Any]]:
    """
    Enumerates all network interfaces using netifaces and gathers:
      - interface name
      - MAC address
      - list of IPv4 addresses
      - list of IPv6 addresses

    Returns a list of dictionaries, one per interface.
    """
    results = []
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        mac = ""
        ipv4 = []
        ipv6 = []

        # Get MAC address
        if netifaces.AF_LINK in addrs:
            for addr_info in addrs[netifaces.AF_LINK]:
                if 'addr' in addr_info:
                    mac = addr_info['addr']
                    break

        # Get IPv4 addresses
        if netifaces.AF_INET in addrs:
            for addr_info in addrs[netifaces.AF_INET]:
                ip = addr_info.get('addr')
                if ip:
                    ipv4.append(ip)

        # Get IPv6 addresses
        if netifaces.AF_INET6 in addrs:
            for addr_info in addrs[netifaces.AF_INET6]:
                ip = addr_info.get('addr')
                if ip:
                    ipv6.append(ip)

        results.append({
            "name": iface,
            "mac": mac if mac else "N/A",
            "ipv4": ipv4 if ipv4 else ["None"],
            "ipv6": ipv6 if ipv6 else ["None"]
        })
    return results

# -----------------------------------------------------------------------------
# Example usage with Rich, to display in a multi-column table
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        from rich import print as rprint
        from rich.table import Table
        from rich.console import Console
        from rich.panel import Panel
        from rich import box
    except ImportError:
        print("Rich library is required for this script. Install with 'pip install rich'.")
        exit(1)

    console = Console()
    console.print(Panel.fit("[bold magenta]Ethernet Survey (netifaces)[/bold magenta]", border_style="cyan"))

    results = run_eth_survey_netifaces()

    if results:
        table = Table(
            title="[bold #00FF00]Ethernet Interface Details[/bold #00FF00]",
            show_header=True,
            header_style="bold yellow",
            highlight=True,
            show_lines=True,
            box=box.MINIMAL_DOUBLE_HEAD,
        )

        # Define columns with fixed widths and overflow handling
        table.add_column("Interface", style="bold cyan", no_wrap=True, width=15)
        table.add_column("MAC", style="bold white", no_wrap=True, width=18)
        table.add_column("IPv4", style="bold white", width=25, overflow="fold")
        table.add_column("IPv6", style="bold white", width=35, overflow="fold")

        for iface in results:
            name = iface["name"]
            mac = iface["mac"]
            ipv4 = ", ".join(iface["ipv4"])
            ipv6 = ", ".join(iface["ipv6"])
            table.add_row(name, mac, ipv4, ipv6)

        console.print(table)
        console.print(f"[bold cyan]Found {len(results)} interfaces.[/bold cyan]")
    else:
        console.print("[bold red]No interfaces found or error retrieving them.[/bold red]")
