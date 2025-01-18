# wifi_survey.py

import sys
import subprocess
import re
from typing import List, Dict, Any, Optional

# Try to import Rich
try:
    from rich import print as rprint
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
except ImportError:
    # Fallback if Rich is not available: define stubs
    def rprint(*args, **kwargs):
        print(*args, **kwargs)
    Console = None
    Table = None
    Panel = None
    box = None

def run_wifi_survey(force_rescan: bool = True) -> List[Dict[str, Any]]:
    """
    Runs a platform-appropriate Wi-Fi survey command:
      - Windows: netsh wlan show networks mode=bssid
      - Linux: nmcli dev wifi list (optionally forces a rescan).

    Returns a list of AP dictionaries, each with keys:
       {
         "ssid": str,
         "bssid": str,
         "signal": int,       # signal percentage or approximate
         "channel": int,
         "security": str,
       }
    If no networks are found or if the system has no Wi-Fi adapters,
    an empty list is returned.
    """
    if sys.platform.startswith("win"):
        return _survey_windows()
    else:
        return _survey_linux(force_rescan=force_rescan)

def _survey_windows() -> List[Dict[str, Any]]:
    """
    Parse output from: netsh wlan show networks mode=bssid
    """
    cmd = ["netsh", "wlan", "show", "networks", "mode=bssid"]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = completed.stdout
    except FileNotFoundError:
        rprint("[bold red][wifi_survey] ERROR:[/bold red] 'netsh' command not found. Are you on Windows?")
        return []
    except subprocess.CalledProcessError as e:
        output = e.stdout or ""
        rprint("[bold yellow][wifi_survey] WARNING:[/bold yellow] netsh command returned an error.")
        rprint(f"stdout:\n{output}")

    lines = output.splitlines()
    if not lines:
        rprint("[bold yellow][wifi_survey] No output from 'netsh wlan show networks'. "
               "No Wi-Fi networks or adapter may be present.[/bold yellow]")
        return []

    ap_list = []
    current_ssid = None
    current_security = "Unknown"

    ssid_pattern = re.compile(r"^SSID\s+\d+\s*:\s*(.*)$", re.IGNORECASE)
    bssid_pattern = re.compile(r"^\s*BSSID\s+\d+\s*:\s*([0-9A-Fa-f:]+)$")
    signal_pattern = re.compile(r"^\s*Signal\s*:\s*(\d+)%")
    channel_pattern = re.compile(r"^\s*Channel\s*:\s*(\d+)")
    auth_pattern = re.compile(r"^\s*Authentication\s*:\s*(.*)$")

    ap_entry: Dict[str, Any] = {}

    for line in lines:
        line = line.strip()
        if not line:
            continue

        ssid_match = ssid_pattern.match(line)
        if ssid_match:
            current_ssid = ssid_match.group(1).strip()
            current_security = "Unknown"
            continue

        auth_match = auth_pattern.match(line)
        if auth_match and current_ssid is not None:
            current_security = auth_match.group(1).strip()

        bssid_match = bssid_pattern.match(line)
        if bssid_match and current_ssid is not None:
            if ap_entry:
                ap_list.append(ap_entry)

            ap_entry = {
                "ssid": current_ssid,
                "bssid": bssid_match.group(1).lower(),
                "signal": 0,
                "channel": 0,
                "security": current_security
            }

        signal_match = signal_pattern.match(line)
        if signal_match and ap_entry:
            ap_entry["signal"] = int(signal_match.group(1))

        channel_match = channel_pattern.match(line)
        if channel_match and ap_entry:
            ap_entry["channel"] = int(channel_match.group(1))

    if ap_entry:
        ap_list.append(ap_entry)

    return ap_list

def _survey_linux(force_rescan: bool = True) -> List[Dict[str, Any]]:
    """
    Parse output from nmcli. We optionally force a rescan of Wi-Fi networks
    for fresher results.
    """
    if force_rescan:
        try:
            subprocess.run(["nmcli", "device", "wifi", "rescan"], 
                           capture_output=True, text=True, check=True)
        except FileNotFoundError:
            rprint("[bold red][wifi_survey] ERROR:[/bold red] 'nmcli' not found. Are you on Linux?")
            return []
        except subprocess.CalledProcessError as e:
            rprint("[bold yellow][wifi_survey] WARNING:[/bold yellow] nmcli wifi rescan returned an error.")
            rprint("stdout:\n", e.stdout or "")

    cmd = ["nmcli", "-f", "BSSID,SSID,CHAN,SIGNAL,SECURITY", "device", "wifi", "list"]

    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = completed.stdout
    except FileNotFoundError:
        rprint("[bold red][wifi_survey] ERROR:[/bold red] 'nmcli' command not found. Are you sure it's installed?")
        return []
    except subprocess.CalledProcessError as e:
        output = e.stdout or ""
        rprint("[bold yellow][wifi_survey] WARNING:[/bold yellow] nmcli command returned an error.")
        rprint("stdout:\n", output)

    lines = output.splitlines()
    if not lines:
        rprint("[bold yellow][wifi_survey] No output from nmcli dev wifi list. "
               "No Wi-Fi networks or adapter may be present.[/bold yellow]")
        return []

    header_detected = False
    if "BSSID" in lines[0] or "SSID" in lines[0].upper():
        header_detected = True
    if header_detected:
        lines = lines[1:]

    ap_list = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        columns = re.split(r"\s{2,}", line)
        if len(columns) < 2:
            continue

        bssid = columns[0].strip()
        if bssid == "*" or not re.match(r"[0-9A-Fa-f:]{11,}", bssid):
            bssid = ""

        ssid = "Hidden"
        channel = 0
        signal = 0
        security = "Unknown"

        if len(columns) >= 2:
            ssid = columns[1].strip() or "Hidden"
        if len(columns) >= 3:
            try:
                channel = int(columns[2].strip())
            except ValueError:
                channel = 0
        if len(columns) >= 4:
            try:
                signal = int(columns[3].strip())
            except ValueError:
                signal = 0
        if len(columns) >= 5:
            security = columns[4].strip()

        ap_entry = {
            "ssid": ssid,
            "bssid": bssid.lower() if bssid else "",
            "signal": signal,
            "channel": channel,
            "security": security,
        }
        ap_list.append(ap_entry)

    return ap_list

# -----------------------------------------------------------------------------
# Example usage with color-coded table output
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    results = run_wifi_survey(force_rescan=True)

    if Console and Table and box:
        console = Console()
        
        if results:
            # We can define a custom box style or use builtins (box.SIMPLE, box.MINIMAL, etc.)
            table = Table(
                title="[bold green]Nearby Wi-Fi Networks[/bold green]",
                show_header=True,
                header_style="bold cyan",
                show_lines=True,
                box=box.HEAVY_EDGE,   # or box.SIMPLE, box.MINIMAL_DOUBLE_HEAD, etc.
            )
            # We add columns with specific widths & alignment to keep from "mushing"
            table.add_column("SSID", style="bold yellow", width=25, no_wrap=False, overflow="fold")
            table.add_column("BSSID", style="dim white", width=19, no_wrap=True)
            table.add_column("Signal %", justify="right", style="bold white", width=8)
            table.add_column("Channel", justify="center", style="bold white", width=7)
            table.add_column("Security", style="bold magenta", width=12, no_wrap=False, overflow="fold")

            for ap in results:
                ssid = ap["ssid"]
                bssid = ap["bssid"] if ap["bssid"] else "N/A"
                signal = str(ap["signal"])
                chan = str(ap["channel"])
                sec = ap["security"] if ap["security"] else "Unknown"

                table.add_row(ssid, bssid, signal, chan, sec)

            console.print(table)
            console.print(f"[bold cyan]Found {len(results)} networks in total.[/bold cyan]")
        else:
            console.print("[bold yellow]No networks found.[/bold yellow]")
    else:
        # Fallback to basic output if Rich or box isn't installed
        print(f"Found {len(results)} Wi-Fi networks:")
        for ap in results:
            print(ap)
