#!/usr/bin/env python3

"""
throughput.py

A real-time throughput visualization tool that uses psutil to measure
network traffic (sent and received) over a specified interval, and
displays the results along with color-enhanced ASCII bar graphs.
"""

import psutil
import time
import sys
import shutil
import argparse

from rich import print as rprint
from rich.console import Console

console = Console()


def format_bytes_per_second(bps: float) -> str:
    """
    Given a throughput in bytes per second, return a human-readable string
    (e.g., '5.23 MB/s', '200 KB/s', etc.).
    """
    units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"]
    val = float(bps)
    idx = 0
    while val >= 1024 and idx < len(units) - 1:
        val /= 1024.0
        idx += 1
    return f"{val:0.2f} {units[idx]}"


def draw_bar(value: float, max_value: float, bar_length: int = 20) -> str:
    """
    Create a color-coded ASCII bar with Rich markup.
    The filled portion is displayed in green if ratio < 0.75,
    yellow if ratio < 1.0, else red. The unfilled portion is gray.
    
    Example: draw_bar(25, 100, 20) -> "[#####---------------]"
    """
    if max_value <= 0:
        max_value = 1  # Avoid division by zero
    ratio = min(value / max_value, 1.0)
    filled_len = int(round(bar_length * ratio))
    
    # Choose color based on ratio
    if ratio < 0.75:
        fill_color = "green"
    elif ratio < 1.0:
        fill_color = "yellow"
    else:
        fill_color = "red"
    
    # Create filled and empty parts with markup
    filled_part = "[bold {color}]{chars}[/bold {color}]".format(color=fill_color, chars="#" * filled_len)
    empty_part = "[dim]" + "-" * (bar_length - filled_len) + "[/dim]"
    
    return f"[{filled_part}{empty_part}]"


def throughput_monitor(interface: str = None, interval: float = 1.0, max_scale_mb_s: float = 100.0) -> None:
    """
    Continuously monitor and display network throughput for the specified
    interface. If 'interface' is None, it monitors all interfaces combined.
    """
    try:
        _, _ = shutil.get_terminal_size(fallback=(80, 24))
    except:
        pass

    rprint(f"[bold cyan]Monitoring throughput on interface:[/bold cyan] [bold magenta]{interface if interface else 'ALL'}[/bold magenta]")
    rprint("[bold yellow]Press Ctrl+C to exit.[/bold yellow]\n")

    def get_net_io_counters():
        counters = psutil.net_io_counters(pernic=True) if interface else psutil.net_io_counters(pernic=False)
        if interface:
            return counters.get(interface)
        return counters

    old = get_net_io_counters()
    if not old:
        rprint(f"[bold red]Could not find interface '{interface}' or no counters are available.[/bold red]")
        sys.exit(1)

    old_bytes_sent = getattr(old, 'bytes_sent', None)
    old_bytes_recv = getattr(old, 'bytes_recv', None)

    if old_bytes_sent is None or old_bytes_recv is None:
        rprint(f"[bold red][ERROR][/bold red] No valid counters for interface '{interface}'. Exiting.")
        sys.exit(1)

    try:
        while True:
            time.sleep(interval)
            new = get_net_io_counters()
            if not new:
                rprint(f"[bold red]Interface '{interface}' is no longer available.[/bold red]")
                break

            new_bytes_sent = getattr(new, 'bytes_sent', 0)
            new_bytes_recv = getattr(new, 'bytes_recv', 0)

            sent_bps = (new_bytes_sent - old_bytes_sent) / interval
            recv_bps = (new_bytes_recv - old_bytes_recv) / interval

            old_bytes_sent = new_bytes_sent
            old_bytes_recv = new_bytes_recv

            sent_mb_s = sent_bps / (1024 * 1024)
            recv_mb_s = recv_bps / (1024 * 1024)

            sent_str = format_bytes_per_second(sent_bps)
            recv_str = format_bytes_per_second(recv_bps)

            upload_bar = draw_bar(sent_mb_s, max_scale_mb_s, bar_length=30)
            download_bar = draw_bar(recv_mb_s, max_scale_mb_s, bar_length=30)

            # Removed screen clear to allow continuous output
            # print("\033c", end="") 

            rprint(f"[bold cyan]Monitoring throughput on interface:[/bold cyan] [bold magenta]{interface if interface else 'ALL'}[/bold magenta]")
            rprint("[bold yellow]Press Ctrl+C to exit.[/bold yellow]\n")

            rprint(f"[bold green] Upload  :[/bold green] [white]{sent_str}[/white] {upload_bar}")
            rprint(f"[bold blue] Download:[/bold blue] [white]{recv_str}[/white] {download_bar}")
            rprint("[dim]" + "-" * 50 + "[/dim]")
            sys.stdout.flush()

    except KeyboardInterrupt:
        rprint("\n[bold cyan]Exiting throughput monitor.[/bold cyan]")
    except Exception as ex:
        rprint(f"[bold red][ERROR][/bold red] {ex}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A real-time throughput visualization tool using psutil."
    )
    parser.add_argument(
        "interface",
        nargs="?",
        default=None,
        help="Name of the network interface (e.g. 'eth0'). If omitted, all interfaces are monitored."
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Refresh interval in seconds (default: 1.0)."
    )
    parser.add_argument(
        "--max",
        type=float,
        default=100.0,
        help="Max throughput in MB/s for the visual bar scale (default: 100)."
    )
    args = parser.parse_args()

    throughput_monitor(interface=args.interface, interval=args.interval, max_scale_mb_s=args.max)
