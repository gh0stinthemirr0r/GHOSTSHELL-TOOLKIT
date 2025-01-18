# single_hostscan.py

import subprocess
import re
from typing import Tuple, List, Optional

try:
    from rich import print
    from rich.console import Console
    from rich.panel import Panel
except ImportError:
    # If Rich isn't installed, fallback to basic prints (no color).
    import sys
    def print(*args, **kwargs):
        __builtins__["print"](*args, **kwargs)
    Console = None
    Panel = None

def single_hostscan(
    host: str,
    port_range: str = "1-1024",
    udp: bool = False
) -> Tuple[bool, List[int]]:
    """
    Scans a single host using nmap for TCP or UDP ports within a given range.
    
    :param host:       IP or hostname to scan (e.g., "192.168.1.10").
    :param port_range: Port range string (e.g. "1-1024", "1-65535").
    :param udp:        If True, runs a UDP scan (-sU). Otherwise, a TCP scan (-sS by default).
    
    :return: (is_up, open_ports)
      - is_up: bool indicating if the host is responding.
      - open_ports: list of open ports found in the specified range.
    
    Requirements:
      - Nmap must be installed and in the system PATH.
    """
    scan_type = "-sU" if udp else "-sS"
    cmd = ["nmap", scan_type, "-p", port_range, host]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout
    except FileNotFoundError:
        raise RuntimeError("[bold red][ERROR][/bold red] Nmap is not installed or not found in PATH.")
    except subprocess.CalledProcessError as e:
        # Non-zero exit code from nmap. Possibly unreachable host, permission issues, etc.
        if Console:
            print(f"[bold yellow][WARNING][/bold yellow] Nmap scan failed with return code {e.returncode}.")
            print(f"[bold yellow]Stdout:[/bold yellow]\n{e.stdout}")
        return (False, [])

    # Nmap typically includes "Host is up" or "Host seems down" in the output
    is_up = bool(re.search(r"Host is up", output, re.IGNORECASE))

    # Parse open ports from lines like "22/tcp   open  ssh"
    protocol_pattern = "udp" if udp else "tcp"
    port_regex = re.compile(rf"(\d+)\/{protocol_pattern}\s+open", re.IGNORECASE)

    open_ports = []
    for line in output.splitlines():
        match = port_regex.search(line)
        if match:
            port_num = int(match.group(1))
            open_ports.append(port_num)

    return (is_up, open_ports)


# -------------------------------------------------------------------------
# CLI usage with color output
# -------------------------------------------------------------------------
if __name__ == "__main__":
    console = Console() if Console else None
    import sys
    
    # If user doesn't provide enough args, show usage in color-coded panel
    if len(sys.argv) < 2:
        usage_text = (
            "[bold cyan]Usage:[/bold cyan]\n"
            "  python single_hostscan.py [bold white]<host>[/bold white] "
            "[bold yellow][port_range=1-1024][/bold yellow] "
            "[bold magenta][--udp][/bold magenta]\n\n"
            "[bold cyan]Example:[/bold cyan]\n"
            "  python single_hostscan.py [bold white]192.168.1.10[/bold white] "
            "[bold yellow]1-1024[/bold yellow]"
        )
        if console and Panel:
            console.print(Panel.fit(usage_text, border_style="cyan"))
        else:
            print("Usage: python single_hostscan.py <host> [port_range] [--udp]")
            print("Example: python single_hostscan.py 192.168.1.10 1-1024")
        sys.exit(1)

    target_host = sys.argv[1]
    port_range = "1-1024"
    do_udp = False

    # If the second argument isn't "--udp", assume it's a port range
    if len(sys.argv) >= 3:
        if "--udp" not in sys.argv[2]:
            port_range = sys.argv[2]

    # If any arg is "--udp", set do_udp
    if "--udp" in sys.argv:
        do_udp = True

    if console:
        console.print(
            f"[bold cyan][INFO][/bold cyan] Scanning "
            f"[bold green]{target_host}[/bold green] for ports "
            f"[bold yellow]{port_range}[/bold yellow] (UDP={do_udp})..."
        )
    else:
        print(f"[INFO] Scanning {target_host} for ports {port_range} (UDP={do_udp})...")

    try:
        up, ports = single_hostscan(target_host, port_range, udp=do_udp)
    except RuntimeError as ex:
        if console:
            console.print(str(ex))
        else:
            print(str(ex))
        sys.exit(2)

    if up:
        if console:
            console.print(f"[bold green][INFO][/bold green] Host [bold white]{target_host}[/bold white] is up.")
            if ports:
                console.print(f"[bold cyan]Open ports in {port_range}:[/bold cyan] [bold #00FF00]{ports}[/bold #00FF00]")
            else:
                console.print(f"[bold yellow]No open ports found in {port_range}.[/bold yellow]")
        else:
            print(f"[INFO] Host {target_host} is up.")
            if ports:
                print(f"Open ports in {port_range}: {ports}")
            else:
                print(f"No open ports found in {port_range}.")
    else:
        if console:
            console.print(f"[bold red][WARNING][/bold red] Host [bold white]{target_host}[/bold white] is down or unreachable.")
        else:
            print(f"[WARNING] Host {target_host} is down or unreachable.")
