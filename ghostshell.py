import argparse
from modules.connection_quality import measure_connection_quality
from modules.eth_survey import run_eth_survey
from modules.netscan import run_nmap_scan, parse_nmap_hosts
from modules.single_hostscan import single_hostscan
from modules.throughput import throughput_monitor
from modules.wifi_survey import run_wifi_survey
from modules.pcap_capture import capture_packets

# Rich imports for color
from rich import print as rprint
from rich.console import Console

console = Console()

def main():
    parser = argparse.ArgumentParser(
        description="[bold cyan]GhostShell Command-Line Tool: Network Diagnostics and Surveys[/bold cyan]"
    )
    subparsers = parser.add_subparsers(dest="command")

    # Connection Quality
    cq_parser = subparsers.add_parser("connection-quality", help="Measure connection quality")
    cq_parser.add_argument("-t", "--target", required=True, help="Target host to ping")
    cq_parser.add_argument("-d", "--duration", type=int, default=30, help="Duration in seconds")

    # Ethernet Survey
    subparsers.add_parser("eth-survey", help="Survey all Ethernet interfaces")

    # Network Scan
    netscan_parser = subparsers.add_parser("net-scan", help="Run network scan")
    netscan_parser.add_argument("-t", "--target", required=True, help="Target IP or CIDR range")

    # Single Host Scan
    hostscan_parser = subparsers.add_parser("single-hostscan", help="Scan single host for open ports")
    hostscan_parser.add_argument("-h", "--host", required=True, help="Host to scan")

    # Throughput Monitor
    throughput_parser = subparsers.add_parser("throughput-monitor", help="Monitor network throughput")
    throughput_parser.add_argument("-i", "--interface", help="Specific interface (optional)")
    throughput_parser.add_argument("--interval", type=float, default=1.0, help="Update interval in seconds")
    throughput_parser.add_argument("--max", type=float, default=100.0, help="Max throughput scale in MB/s")

    # WiFi Survey
    subparsers.add_parser("wifi-survey", help="Survey Wi-Fi networks")

    # Packet Capture
    pcap_parser = subparsers.add_parser("pcap-capture", help="Capture packets")
    pcap_parser.add_argument("-i", "--interface", required=True, help="Interface to capture on")
    pcap_parser.add_argument("-d", "--duration", type=int, default=10, help="Capture duration in seconds")
    pcap_parser.add_argument("-o", "--output", default="capture.pcap", help="Output PCAP file")

    args = parser.parse_args()

    if args.command == "connection-quality":
        result = measure_connection_quality(args.target, args.duration)
        rprint(
            f"[bold cyan]Avg Latency:[/bold cyan] [green]{result['avg_latency']:.2f} ms[/green], "
            f"[bold cyan]Packet Loss:[/bold cyan] [green]{result['packet_loss']:.2f}%[/green]"
        )

    elif args.command == "eth-survey":
        results = run_eth_survey()
        if not results:
            rprint("[bold yellow]No Ethernet interfaces found or error retrieving them.[/bold yellow]")
        else:
            rprint("[bold cyan]Ethernet Survey Results:[/bold cyan]")
            for iface in results:
                # You can color keys or values as you like
                rprint(f"[bold magenta]{iface['name']}[/bold magenta]: {iface}")

    elif args.command == "net-scan":
        output = run_nmap_scan(args.target)
        hosts = parse_nmap_hosts(output)
        rprint(f"[bold cyan]Discovered hosts:[/bold cyan]")
        if hosts:
            for host in hosts:
                rprint(f"  [green]{host}[/green]")
        else:
            rprint("[bold yellow]No hosts discovered.[/bold yellow]")

    elif args.command == "single-hostscan":
        is_up, ports = single_hostscan(args.host)
        status_color = "green" if is_up else "red"
        rprint(f"[bold cyan]Host[/bold cyan] [bold yellow]{args.host}[/bold yellow] is [bold {status_color}]{'up' if is_up else 'down'}[/bold {status_color}]")
        if is_up:
            if ports:
                rprint(f"[bold cyan]Open Ports:[/bold cyan] [green]{ports}[/green]")
            else:
                rprint("[bold yellow]No open ports found.[/bold yellow]")

    elif args.command == "throughput-monitor":
        rprint("[bold cyan]Starting throughput monitor...[/bold cyan]")
        throughput_monitor(args.interface, args.interval, args.max)
        # The throughput_monitor itself may do its own printing

    elif args.command == "wifi-survey":
        results = run_wifi_survey()
        if not results:
            rprint("[bold yellow]No Wi-Fi networks found or error retrieving them.[/bold yellow]")
        else:
            rprint(f"[bold cyan]Found [bold green]{len(results)}[/bold green] Wi-Fi networks:[/bold cyan]")
            for ap in results:
                ssid = ap.get("ssid", "Hidden")
                rprint(f"[bold magenta]{ssid}[/bold magenta] -> [green]{ap}[/green]")

    elif args.command == "pcap-capture":
        rprint(
            f"[bold cyan]Capturing packets on interface[/bold cyan] "
            f"[bold green]{args.interface}[/bold green] "
            f"[bold cyan]for[/bold cyan] [bold yellow]{args.duration}[/bold yellow]s => "
            f"[bold white]{args.output}[/bold white]"
        )
        capture_packets(args.interface, args.duration, args.output)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
