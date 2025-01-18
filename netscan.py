import subprocess
import re
from typing import List, Dict, Any, Optional

from rich import print
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.style import Style


def run_nmap_scan_basic(target: str) -> str:
    """
    Runs a simple Nmap 'ping' or 'host discovery' scan on a single IP
    or a CIDR range, using `nmap -sP` (also known as -sn in newer versions).
    """
    cmd = ["nmap", "-sP", target]  # '-sn' is the newer version of '-sP'
    return _run_nmap_command(cmd)


def run_nmap_scan_detailed(
    target: str,
    top_ports: Optional[int] = None,
    os_detect: bool = True,
    version_detect: bool = True
) -> str:
    """
    Runs a more detailed Nmap scan on the target, optionally limiting
    to top N ports, and using OS/version detection.
    """
    cmd = ["nmap", "-n", "-Pn", "-T4", "-sS"]

    if top_ports:
        cmd += ["--top-ports", str(top_ports)]
    else:
        cmd += ["-p-"]

    if os_detect:
        cmd += ["-O"]
    if version_detect:
        cmd += ["-sV"]

    cmd.append(target)
    return _run_nmap_command(cmd)


def _run_nmap_command(cmd: List[str]) -> str:
    """
    Internal helper to run an Nmap command and return the output.
    Handles FileNotFoundError (if nmap isn't installed) and CalledProcessError.
    """
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except FileNotFoundError:
        return "[ERROR] Nmap is not installed or not found in PATH."
    except subprocess.CalledProcessError as e:
        return f"[ERROR] Nmap command failed. Return code: {e.returncode}\n{e.stdout or ''}"


def parse_nmap_hosts(nmap_output: str) -> List[str]:
    """
    Minimal parser to extract discovered hosts from a 'ping' Nmap scan.
    E.g., lines containing "Nmap scan report for 192.168.1.10"
    """
    hosts = []
    pattern = re.compile(r"Nmap scan report for (.+)")
    for line in nmap_output.splitlines():
        match = pattern.search(line)
        if match:
            hosts.append(match.group(1).strip())
    return hosts


def parse_nmap_ports(nmap_output: str) -> List[Dict[str, Any]]:
    """
    Parse open ports from a detailed Nmap scan (run_nmap_scan_detailed),
    extracting OS guess, open ports, service, version, etc.
    """
    host_data = []
    current_host = None
    current_ports = []
    current_os_guess = None

    host_pattern = re.compile(r"^Nmap scan report for (.+)")
    port_pattern = re.compile(r"^(\d+)\/(\w+)\s+(\w+)\s+([\w\-]+)(.*)?")
    os_pattern = re.compile(r"OS details:\s*(.+)")

    for line in nmap_output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Check for new host
        host_match = host_pattern.search(line)
        if host_match:
            if current_host is not None:
                host_data.append({
                    "host": current_host,
                    "os": current_os_guess,
                    "ports": current_ports
                })
            current_host = host_match.group(1).strip()
            current_ports = []
            current_os_guess = None
            continue

        # Check for OS details
        os_match = os_pattern.search(line)
        if os_match:
            current_os_guess = os_match.group(1).strip()
            continue

        # Check for port line
        port_match = port_pattern.search(line)
        if port_match:
            port_num = port_match.group(1)
            protocol = port_match.group(2)
            state = port_match.group(3)
            service = port_match.group(4)
            extra = port_match.group(5).strip() if port_match.group(5) else ""

            port_info = {
                "port": int(port_num),
                "protocol": protocol,
                "state": state,
                "service": service,
                "version": extra if extra else None
            }
            current_ports.append(port_info)

    # If the last host block never got appended
    if current_host is not None:
        host_data.append({
            "host": current_host,
            "os": current_os_guess,
            "ports": current_ports
        })

    return host_data


# ------------------------------------------------------------------------------
# Example usage with colorized output (when run as a script)
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    console = Console()

    target = "192.168.1.0/24"

    # Decorative panel for "Basic Ping/Discovery Scan"
    console.print(Panel.fit("[bold cyan]=== Basic Ping/Discovery Scan ===[/bold cyan]", border_style="cyan"))

    basic_output = run_nmap_scan_basic(target)

    # Colorize the raw Nmap output
    # We'll highlight lines that contain "[ERROR]" in red, or use default color otherwise.
    if "[ERROR]" in basic_output:
        console.print(f"[bold red]{basic_output}[/bold red]")
    else:
        console.print(f"[bold white]{basic_output}[/bold white]")

    discovered = parse_nmap_hosts(basic_output)

    # Show discovered hosts in a color-coded way
    if discovered:
        console.print("[bold green]Discovered Hosts:[/bold green] " + ", ".join(discovered))
    else:
        console.print("[bold yellow]No hosts discovered in the ping scan.[/bold yellow]")
    console.print()  # blank line

    # Now let's run a detailed scan on the first discovered host, if any
    console.print(Panel.fit("[bold magenta]=== Detailed Scan ===[/bold magenta]", border_style="magenta"))
    if discovered:
        first_host = discovered[0]
        console.print(f"[bold yellow]Running detailed scan on [bold white]{first_host}[/bold white]...[/bold yellow]")
        detail_output = run_nmap_scan_detailed(first_host, top_ports=100, os_detect=True, version_detect=True)

        # Print the raw output colorfully
        if "[ERROR]" in detail_output:
            console.print(f"[bold red]{detail_output}[/bold red]")
        else:
            console.print(f"[bold white]{detail_output}[/bold white]")

        parsed_info = parse_nmap_ports(detail_output)

        # If we have parsed host/port data, let's display it in a Rich table
        if parsed_info:
            table = Table(title="[bold #00FF00]Parsed Host/Port Info[/bold #00FF00]", show_lines=True)
            table.add_column("Host", style="bold cyan")
            table.add_column("OS Guess", style="magenta")
            table.add_column("Open Ports", style="green")

            for host_entry in parsed_info:
                host_str = host_entry["host"]
                os_str = host_entry["os"] if host_entry["os"] else "None"
                
                # Build a bullet list of open ports
                # e.g. "22/tcp (open) [OpenSSH 7.2]" ...
                ports_info = []
                for p in host_entry["ports"]:
                    version_str = f" ({p['version']})" if p["version"] else ""
                    port_line = f"{p['port']}/{p['protocol']} [{p['state']}] {p['service']}{version_str}"
                    ports_info.append(port_line)

                ports_text = "\n".join(ports_info) if ports_info else "No open ports"
                table.add_row(host_str, os_str, ports_text)

            console.print(table)
        else:
            console.print("[bold yellow]No open ports or no data parsed.[/bold yellow]")
    else:
        console.print("[bold yellow]No hosts discovered in the ping scan; cannot perform a detailed scan.[/bold yellow]")
