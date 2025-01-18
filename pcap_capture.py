# pcap_capture.py

import sys
from typing import Optional

try:
    from scapy.all import sniff, wrpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Rich imports for colorful logging
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import print

console = Console()

def capture_packets(
    interface: str,
    duration: int = 10,
    out_file: str = "capture.pcap",
    packet_filter: Optional[str] = None,
    store: bool = True
) -> None:
    """
    Captures packets on a given interface for a specified duration (in seconds),
    optionally applying a BPF filter, then saves them to a .pcap file.

    :param interface:    Network interface to capture on (e.g., "eth0", "wlan0", "en0").
    :param duration:     Time in seconds to capture before stopping (default=10).
    :param out_file:     Filename or path to .pcap file to write (default="capture.pcap").
    :param packet_filter: A BPF (Berkeley Packet Filter) string (e.g. "tcp and port 80") 
                         to filter traffic. If None, capture all traffic.
    :param store:        If True, packets are stored in memory and then written to the pcap.
                         If False, packets won't be in memory, which means wrpcap will have 
                         no data to write. Typically you want store=True.

    :raises RuntimeError: If Scapy is not installed or if insufficient privileges prevent capture.
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("[red]Scapy is not installed. Please install scapy to use packet capture.[/red]")

    console.print(f"[bold cyan][INFO][/bold cyan] Starting packet capture on '[bold #00FF00]{interface}[/bold #00FF00]' for [bold #00FF00]{duration}[/bold #00FF00] seconds...")
    console.print(f"[bold cyan][INFO][/bold cyan]  Filter: [bold yellow]{packet_filter if packet_filter else 'None'}[/bold yellow]")

    try:
        packets = sniff(
            iface=interface,
            timeout=duration,
            filter=packet_filter,
            store=store
        )
    except PermissionError:
        raise RuntimeError(f"[bold red]Insufficient privileges to capture on interface[/bold red] '[bold]{interface}[/bold]'. "
                           "Try running as root or with sudo.")
    except OSError as e:
        raise RuntimeError(f"[bold red]OS error occurred while capturing on[/bold red] '[bold]{interface}[/bold]': {e}")

    console.print(f"[bold cyan][INFO][/bold cyan] Capture complete. [bold #00FF00]{len(packets)}[/bold #00FF00] packets collected.")
    if packets:
        console.print(f"[bold cyan][INFO][/bold cyan] Writing packets to [bold #00FF00]{out_file}[/bold #00FF00]...")
        wrpcap(out_file, packets)
        console.print(f"[bold green][SUCCESS][/bold green] Packets saved to [bold #00FF00]{out_file}[/bold #00FF00].")
    else:
        console.print("[bold yellow][INFO][/bold yellow] No packets captured, skipping file write.")

def main():
    """
    A simple CLI entry point.
    Usage: python pcap_capture.py <interface> [duration=10] [out_file=capture.pcap]
    Example: python pcap_capture.py eth0 30 mycapture.pcap
    """
    # We'll show usage instructions in a color-coded panel
    if len(sys.argv) < 2:
        usage_text = (
            "[bold #FF69B4]Usage:[/bold #FF69B4]\n"
            "  python pcap_capture.py [bold cyan]<interface>[/bold cyan] "
            "[bold yellow][duration=10][/bold yellow] "
            "[bold green][out_file=capture.pcap][/bold green]\n\n"
            "[bold #FF69B4]Example:[/bold #FF69B4]\n"
            "  python pcap_capture.py [bold cyan]eth0[/bold cyan] "
            "[bold yellow]30[/bold yellow] "
            "[bold green]mycapture.pcap[/bold green]"
        )
        console.print(Panel.fit(usage_text, border_style="cyan"))
        sys.exit(1)

    interface = sys.argv[1]
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    out_file = sys.argv[3] if len(sys.argv) > 3 else "capture.pcap"

    try:
        capture_packets(interface, duration, out_file)
    except RuntimeError as e:
        # e can contain Rich markup, so just print it directly
        console.print(f"[bold red][ERROR][/bold red] {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()
