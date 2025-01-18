import sys
import re
import subprocess
import time
import netifaces
from typing import List, Dict, Any

from PySide6.QtCore import (
    Qt, QProcess, QIODevice, QByteArray, Slot, QThread, Signal, QObject, QPoint
)
from PySide6.QtGui import QIcon, QMouseEvent
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QPushButton,
    QTextEdit, QLineEdit, QInputDialog, QMessageBox
)

# --------------------------------------------------------------------------
# TRY IMPORTS FOR OPTIONAL FEATURES
# --------------------------------------------------------------------------
try:
    from scapy.all import sniff, wrpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from pythonping import ping
    PYTHONPING_AVAILABLE = True
except ImportError:
    PYTHONPING_AVAILABLE = False

# Simplified function implementations for demonstration
def measure_connection_quality(target: str, duration: int):
    if not PYTHONPING_AVAILABLE:
        return {"avg_latency": -1, "packet_loss": 100.0}
    start_time = time.time()
    latencies = []
    sent = 0
    while (time.time() - start_time) < duration:
        sent += 1
        resp = ping(target, count=1, timeout=1, verbose=False)
        if resp.packet_loss == 0:
            latencies.append(resp.rtt_avg_ms)
        else:
            latencies.append(None)
        time.sleep(0.5)
    lost = sum(1 for x in latencies if x is None)
    received = sent - lost
    avg_latency = sum(x for x in latencies if x is not None) / max(received, 1)
    packet_loss = (lost / sent) * 100.0
    return {"avg_latency": avg_latency, "packet_loss": packet_loss}

def run_eth_survey():
    results = []
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        mac_addr = ""
        ipv4_list = []
        ipv6_list = []
        netmask_list = []
        bc_list = []

        if netifaces.AF_LINK in addrs:
            for link_info in addrs[netifaces.AF_LINK]:
                if 'addr' in link_info:
                    mac_addr = link_info['addr']

        if netifaces.AF_INET in addrs:
            for inet_info in addrs[netifaces.AF_INET]:
                ip = inet_info.get('addr')
                nm = inet_info.get('netmask')
                bc = inet_info.get('broadcast')
                if ip:
                    ipv4_list.append(ip)
                if nm:
                    netmask_list.append(nm)
                if bc:
                    bc_list.append(bc)

        if netifaces.AF_INET6 in addrs:
            for inet6_info in addrs[netifaces.AF_INET6]:
                ip6 = inet6_info.get('addr')
                if ip6:
                    ipv6_list.append(ip6)

        entry = {
            "name": iface,
            "mac": mac_addr,
            "ipv4": ipv4_list,
            "ipv6": ipv6_list,
            "netmask": netmask_list,
            "broadcast": bc_list,
        }
        results.append(entry)
    return results

def run_nmap_scan(target: str) -> str:
    cmd = ["nmap", "-sn", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"[ERROR] Nmap net scan failed: {e}\n{e.stdout or ''}"

def parse_nmap_hosts(nmap_output: str) -> List[str]:
    lines = nmap_output.splitlines()
    found_hosts = []
    for line in lines:
        if "Nmap scan report for " in line:
            host_line = line.split("for")
            if len(host_line) == 2:
                found_hosts.append(host_line[1].strip())
    return found_hosts

def single_hostscan(host: str):
    cmd = ["nmap", "-p", "1-1024", host]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout
        is_up = "Host is up" in output
        open_ports = []
        for line in output.splitlines():
            if "/tcp" in line and "open" in line:
                portnum = line.split("/")[0]
                open_ports.append(portnum)
        return (is_up, open_ports)
    except subprocess.CalledProcessError as e:
        return (False, [])

def throughput_monitor(interface=None, interval=1.0, max_val=100.0):
    print(f"[THROUGHPUT] Monitoring on interface={interface} with interval={interval}s (max scale={max_val}MB/s).")
    print("Press Ctrl+C to stop or kill the process from the GUI...")
    prev_rx = prev_tx = 0
    net_path = "/sys/class/net"
    if not interface:
        interface = "eth0"
    try:
        while True:
            with open(f"{net_path}/{interface}/statistics/rx_bytes", "r") as f:
                rx_bytes = int(f.read().strip())
            with open(f"{net_path}/{interface}/statistics/tx_bytes", "r") as f:
                tx_bytes = int(f.read().strip())
            rx_rate = (rx_bytes - prev_rx) / (interval * 1024 * 1024)
            tx_rate = (tx_bytes - prev_tx) / (interval * 1024 * 1024)
            print(f"RX: {rx_rate:.2f} MB/s   TX: {tx_rate:.2f} MB/s")
            prev_rx, prev_tx = rx_bytes, tx_bytes
            time.sleep(interval)
    except KeyboardInterrupt:
        print("[THROUGHPUT] Monitoring stopped by user.")

def run_wifi_survey() -> List[Dict[str, Any]]:
    if sys.platform.startswith("win"):
        return _survey_windows()
    else:
        return _survey_linux()

def _survey_windows() -> List[Dict[str, Any]]:
    cmd = ["netsh", "wlan", "show", "networks", "mode=bssid"]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = completed.stdout
    except subprocess.CalledProcessError as e:
        output = e.stdout or ""
    lines = output.splitlines()
    ap_list = []
    current_ssid = None
    current_security = "Unknown"
    ssid_pattern = re.compile(r"^SSID\s+\d+\s*:\s*(.*)$")
    bssid_pattern = re.compile(r"^\s*BSSID\s+\d+\s*:\s*([0-9A-Fa-f:]+)$")
    signal_pattern = re.compile(r"^\s*Signal\s*:\s*(\d+)%")
    channel_pattern = re.compile(r"^\s*Channel\s*:\s*(\d+)")
    auth_pattern = re.compile(r"^\s*Authentication\s*:\s*(.*)$")
    ap_entry = {}
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

def _survey_linux() -> List[Dict[str, Any]]:
    import re
    cmd = ["nmcli", "dev", "wifi", "list"]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = completed.stdout
    except subprocess.CalledProcessError as e:
        output = e.stdout or ""
    lines = output.splitlines()
    ap_list = []
    if lines and "SSID" in lines[0] and "SIGNAL" in lines[0]:
        lines = lines[1:]
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = re.split(r"\s{2,}", line)
        if len(parts) < 7:
            continue
        ssid = ""
        signal = 0
        chan = 0
        security = "Unknown"
        try:
            if parts[0] in ["*", ""]:
                ssid = parts[1]
                chan = int(parts[3])
                signal = int(parts[5])
                security = parts[7] if len(parts) >= 8 else "Unknown"
            else:
                ssid = parts[0]
                chan = int(parts[2])
                signal = int(parts[4])
                security = parts[6] if len(parts) >= 7 else "Unknown"
        except:
            pass
        ap_entry = {
            "ssid": ssid or "Hidden",
            "bssid": "",
            "signal": signal,
            "channel": chan,
            "security": security
        }
        ap_list.append(ap_entry)
    return ap_list

def capture_packets(interface: str, duration: int, output_file: str):
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy is not available.")
    from scapy.all import sniff, wrpcap
    packets = sniff(iface=interface, timeout=duration)
    wrpcap(output_file, packets)

class PcapWorker(QObject):
    captureFinished = Signal(str, int)
    captureError = Signal(str)

    def __init__(self, interface: str, out_file: str, duration: int):
        super().__init__()
        self.interface = interface
        self.out_file = out_file
        self.duration = duration

    @Slot()
    def runCapture(self):
        if not SCAPY_AVAILABLE:
            self.captureError.emit("Scapy not installed. Cannot capture packets.")
            return
        try:
            from scapy.all import sniff, wrpcap
            packets = sniff(iface=self.interface, timeout=self.duration)
            wrpcap(self.out_file, packets)
            self.captureFinished.emit(self.out_file, len(packets))
        except Exception as e:
            self.captureError.emit(str(e))

def run_ghostshell_command(command_line: str) -> str:
    import shlex
    parser = _build_subcommand_parser()
    args = shlex.split(command_line)
    if not args:
        return parser.format_help()
    try:
        parsed = parser.parse_args(args)
    except SystemExit:
        return parser.format_help()
    cmd = parsed.command
    if cmd == "connection-quality":
        result = measure_connection_quality(parsed.target, parsed.duration)
        return f"Avg Latency: {result['avg_latency']:.2f} ms, Packet Loss: {result['packet_loss']:.2f}%"
    elif cmd == "eth-survey":
        results = run_eth_survey()
        output = []
        for iface in results:
            msg = (f"Interface: {iface['name']}\n"
                   f"  MAC: {iface['mac']}\n"
                   f"  IPv4: {', '.join(iface['ipv4']) if iface['ipv4'] else 'None'}\n"
                   f"  IPv6: {', '.join(iface['ipv6']) if iface['ipv6'] else 'None'}\n"
                   f"  Netmask: {', '.join(iface['netmask']) if iface['netmask'] else 'None'}\n"
                   f"  Broadcast: {', '.join(iface['broadcast']) if iface['broadcast'] else 'None'}\n")
            output.append(msg)
        return "\n".join(output)
    elif cmd == "net-scan":
        raw_out = run_nmap_scan(parsed.target)
        hosts = parse_nmap_hosts(raw_out)
        return f"{raw_out}\nDiscovered hosts:\n" + "\n".join(hosts)
    elif cmd == "single-hostscan":
        is_up, ports = single_hostscan(parsed.host)
        return f"Host {'is up' if is_up else 'is down'}\nOpen Ports: {ports}"
    elif cmd == "throughput-monitor":
        interface = parsed.interface
        interval = parsed.interval
        maxval = parsed.max
        return (f"Starting throughput monitor on interface={interface} "
                f"interval={interval}, max={maxval}.\n"
                " (In real usage, run in separate QProcess.)")
    elif cmd == "wifi-survey":
        results = run_wifi_survey()
        output = []
        for ap in results:
            output.append(
                f"SSID: {ap.get('ssid')}  "
                f"BSSID: {ap.get('bssid','')}  "
                f"Signal: {ap.get('signal')}%  "
                f"Chan: {ap.get('channel')}  "
                f"Sec: {ap.get('security')}"
            )
        return "\n".join(output) if output else "[WIFI] No networks found."
    elif cmd == "pcap-capture":
        return ("Use the GUI button to start pcap capture, or adapt code here.\n"
                "pcap-capture from the command line is possible, but we integrated "
                "it as a threaded job in the GUI. For a CLI approach, you'd do something like:\n"
                f"capture_packets({parsed.interface}, {parsed.duration}, {parsed.output})")
    else:
        return parser.format_help()

def _build_subcommand_parser():
    import argparse
    parser = argparse.ArgumentParser(
        prog="GhostShell",
        description="GhostShell Subcommands Inside the Qt Pseudo-Terminal"
    )
    subparsers = parser.add_subparsers(dest="command")

    cq_parser = subparsers.add_parser("connection-quality", help="Measure connection quality")
    cq_parser.add_argument("-t", "--target", required=True, help="Target host to ping")
    cq_parser.add_argument("-d", "--duration", type=int, default=30, help="Duration in seconds")

    subparsers.add_parser("eth-survey", help="Survey all Ethernet interfaces")

    ns_parser = subparsers.add_parser("net-scan", help="Run network scan")
    ns_parser.add_argument("-t", "--target", required=True, help="Target IP or CIDR range")

    sh_parser = subparsers.add_parser("single-hostscan", help="Scan single host for open ports")
    sh_parser.add_argument("-h", "--host", required=True, help="Host to scan")

    tm_parser = subparsers.add_parser("throughput-monitor", help="Monitor network throughput")
    tm_parser.add_argument("-i", "--interface", default=None, help="Specific interface (optional)")
    tm_parser.add_argument("--interval", type=float, default=1.0, help="Update interval in seconds")
    tm_parser.add_argument("--max", type=float, default=100.0, help="Max throughput scale in MB/s")

    subparsers.add_parser("wifi-survey", help="Survey Wi-Fi networks")

    pc_parser = subparsers.add_parser("pcap-capture", help="Capture packets")
    pc_parser.add_argument("-i", "--interface", required=True, help="Interface to capture on")
    pc_parser.add_argument("-d", "--duration", type=int, default=10, help="Capture duration in seconds")
    pc_parser.add_argument("-o", "--output", default="capture.pcap", help="Output PCAP file")

    return parser

CMD_PATH = "C:/Windows/System32/cmd.exe"

DEFAULT_BORDER_COLOR = "#00FFC0"
DEFAULT_TEXT_COLOR = "#00ffe4"
DEFAULT_BACKGROUND_COLOR = "rgba(0, 30, 70, 0.98)"
DEFAULT_SELECTION_COLOR = "#FF00FF"

ASCII_BANNER = r"""
     +-------------------------------------------+
     |   W E L C O M E   T O   G H O S T S H E L L
     |            T O O L K I T
     +-------------------------------------------+
"""

RESIZE_MARGIN = 8

class GhostShellToolkit(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowSystemMenuHint)
        self.setWindowIcon(QIcon("ghost.svg"))
        self.resize(1000, 600)
        self.setMouseTracking(True)

        self._dragPos = None
        self._resizeRegion = None
        self._isMaximized = False

        self.buildUI()

        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self.onReadyReadStdOut)
        self.process.readyReadStandardError.connect(self.onReadyReadStdErr)
        self.process.start(CMD_PATH)
        self.process.waitForStarted(1000)

        self.commandOutput.clear()
        self.commandOutput.setHtml(f"<pre>{ASCII_BANNER}</pre>")

        self.throughputProcess = None

    def colorize_line(self, line: str) -> str:
        html_line = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        if "[ERROR]" in line:
            return f'<span style="color: red;">{html_line}</span>'
        elif line.startswith(">"):
            return f'<span style="color: #00ff00;">{html_line}</span>'
        else:
            return f'<span style="color: {DEFAULT_TEXT_COLOR};">{html_line}</span>'

    def appendColoredLine(self, line: str):
        colored_html = self.colorize_line(line)
        self.commandOutput.append(colored_html)

    def buildUI(self):
        central_widget = QWidget()
        central_layout = QVBoxLayout(central_widget)
        central_layout.setContentsMargins(0, 0, 0, 0)
        central_layout.setSpacing(0)
        self.setCentralWidget(central_widget)

        self.titleBar = QWidget()
        self.titleBar.setFixedHeight(40)
        self.titleBar.setStyleSheet(
            "background-color: rgba(90, 90, 90, 0.98); "
            f"border-bottom: 2px solid {DEFAULT_BORDER_COLOR};"
        )
        tb_layout = QHBoxLayout(self.titleBar)
        tb_layout.setContentsMargins(5, 5, 5, 5)
        tb_layout.setSpacing(5)
        tb_layout.addStretch()

        self.minBtn = QPushButton("_")
        self.minBtn.setFixedSize(24, 24)
        self.minBtn.setStyleSheet(f"color: {DEFAULT_TEXT_COLOR}; border: 1px solid {DEFAULT_BORDER_COLOR};")
        self.minBtn.clicked.connect(self.showMinimized)
        tb_layout.addWidget(self.minBtn)

        self.closeBtn = QPushButton("X")
        self.closeBtn.setFixedSize(24, 24)
        self.closeBtn.setStyleSheet(f"color: {DEFAULT_TEXT_COLOR}; border: 1px solid {DEFAULT_BORDER_COLOR};")
        self.closeBtn.clicked.connect(self.close)
        tb_layout.addWidget(self.closeBtn)

        central_layout.addWidget(self.titleBar)

        main_widget = QWidget()
        main_layout = QHBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self.initToolBar(main_layout)
        self.initMainContent(main_layout)

        central_layout.addWidget(main_widget)

    def initToolBar(self, parent_layout):
        toolbar_widget = QWidget()
        toolbar_layout = QVBoxLayout(toolbar_widget)
        toolbar_layout.setContentsMargins(5, 5, 5, 5)
        toolbar_layout.setSpacing(10)

        toolbar_widget.setStyleSheet(
            f"background-color: rgba(90, 90, 90, 0.98); "
            f"border-right: 2px solid {DEFAULT_BORDER_COLOR};"
        )

        buttons_info = [
            ("NET SCAN", self.onNetScan),
            ("HOSTSCAN", self.onHostScan),
            ("ADV CONN QUALITY", self.onConnQualityTimebased),
            ("THROUGHPUT MONITOR", self.onThroughputMonitor),
            ("WIFI SURVEY", self.onWifiSurvey),
            ("ETH SURVEY", self.onEthSurvey),
            ("PCAP CAPTURE", self.onPcapCapture),
        ]
        for (btn_name, slot_method) in buttons_info:
            btn = QPushButton(btn_name)
            btn.setStyleSheet(f"""
                QPushButton {{
                    color: {DEFAULT_TEXT_COLOR};
                    background-color: transparent;
                    border: 1px solid {DEFAULT_BORDER_COLOR};
                    padding: 6px;
                    margin: 2px 0;
                }}
                QPushButton:hover {{
                    background-color: rgba(255, 255, 255, 0.1);
                }}
            """)
            btn.clicked.connect(slot_method)
            toolbar_layout.addWidget(btn)

        toolbar_layout.addStretch()
        parent_layout.addWidget(toolbar_widget, 0)

    def initMainContent(self, parent_layout):
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(10, 10, 10, 10)
        right_layout.setSpacing(10)

        self.commandOutput = QTextEdit()
        self.commandOutput.setReadOnly(True)
        self.commandOutput.setStyleSheet(f"""
            QTextEdit {{
                background-color: {DEFAULT_BACKGROUND_COLOR};
                color: {DEFAULT_TEXT_COLOR};
                selection-background-color: {DEFAULT_SELECTION_COLOR};
                border: 2px solid {DEFAULT_BORDER_COLOR};
                padding: 5px;
                font-size: 14px;
                font-family: 'Courier New', monospace;
            }}
        """)
        right_layout.addWidget(self.commandOutput, 1)

        self.inputLine = QLineEdit()
        self.inputLine.setStyleSheet(f"""
            QLineEdit {{
                background-color: rgba(90, 90, 90, 0.98);
                color: {DEFAULT_TEXT_COLOR};
                selection-background-color: {DEFAULT_SELECTION_COLOR};
                border: 2px solid {DEFAULT_BORDER_COLOR};
                padding: 5px;
                font-size: 14px;
                font-family: 'Courier New', monospace;
            }}
        """)
        self.inputLine.setPlaceholderText("Enter command here...")
        self.inputLine.returnPressed.connect(self.onCommandEntered)
        right_layout.addWidget(self.inputLine, 0)

        parent_layout.addWidget(right_widget, 1)

    @Slot()
    def onReadyReadStdOut(self):
        data = self.process.readAllStandardOutput()
        text = data.data().decode("cp437", errors="replace")
        if text:
            for line in text.splitlines():
                self.appendColoredLine(line)

    @Slot()
    def onReadyReadStdErr(self):
        data = self.process.readAllStandardError()
        text = data.data().decode("cp437", errors="replace")
        if text:
            for line in text.splitlines():
                self.appendColoredLine("[ERROR] " + line.rstrip())

    @Slot()
    def onCommandEntered(self):
        cmd_line = self.inputLine.text().strip()
        if not cmd_line:
            return
        self.appendColoredLine(f"> {cmd_line}")
        self.inputLine.clear()

        subcommands = [
            "connection-quality", "eth-survey", "net-scan", "single-hostscan",
            "throughput-monitor", "wifi-survey", "pcap-capture"
        ]
        first_token = cmd_line.split()[0].lower() if cmd_line.split() else ""
        if first_token in subcommands:
            try:
                results_str = run_ghostshell_command(cmd_line)
            except Exception as e:
                results_str = f"[GhostShell ERROR] {str(e)}"
            if results_str:
                for line in results_str.splitlines():
                    self.appendColoredLine(line)
            return

        self.process.write(QByteArray((cmd_line + "\n").encode("utf-8")))
        self.process.flush()

    @Slot()
    def onNetScan(self):
        target, ok = QInputDialog.getText(self, "NET SCAN", "Enter IP or CIDR:")
        if not ok or not target.strip():
            return
        self.appendColoredLine(f"[NET SCAN] Scanning {target} ...")
        output = run_nmap_scan(target.strip())
        for line in output.splitlines():
            self.appendColoredLine(line)

    @Slot()
    def onHostScan(self):
        host, ok = QInputDialog.getText(self, "HOSTSCAN", "Enter single host IP:")
        if not ok or not host.strip():
            return
        self.appendColoredLine(f"[HOSTSCAN] Scanning host {host} ...")
        output = subprocess.run(["nmap", "-p", "1-1024", host.strip()],
                                capture_output=True, text=True).stdout
        for line in output.splitlines():
            self.appendColoredLine(line)

    @Slot()
    def onConnQualityTimebased(self):
        duration, ok = QInputDialog.getInt(self, "Connection Quality", "Enter duration in seconds:", 30, 1, 3600)
        if not ok:
            return
        target, ok = QInputDialog.getText(self, "Connection Quality", "Enter target IP or domain:")
        if not ok or not target.strip():
            return
        self.appendColoredLine(f"[ConnQuality] Measuring connection quality for {duration}s to {target.strip()}...")

        def worker():
            result = measure_connection_quality(target.strip(), duration)
            headers = f"{'Metric':<15} {'Value':<15}"
            separator = "-"*30
            rows = [
                f"{'Avg Latency:':<15} {result['avg_latency']:.2f} ms",
                f"{'Packet Loss:':<15} {result['packet_loss']:.2f}%",
            ]
            formatted = "\n".join([headers, separator] + rows)
            self.appendColoredLine(formatted)

        import threading
        t = threading.Thread(target=worker, daemon=True)
        t.start()

    @Slot()
    def onThroughputMonitor(self):
        iface, ok = QInputDialog.getText(
            self, "THROUGHPUT MONITOR",
            "Enter interface (optional). Leave blank for all interfaces."
        )
        if not ok:
            return
        
        self.appendColoredLine("[THROUGHPUT] Starting throughput monitor...")

        self.throughputProcess = QProcess(self)
        self.throughputProcess.setProcessChannelMode(QProcess.MergedChannels)
        self.throughputProcess.readyReadStandardOutput.connect(self.onThroughputOutput)
        self.throughputProcess.readyReadStandardError.connect(self.onThroughputError)

        python_executable = sys.executable
        args = ["-u", "throughput.py"]
        if iface.strip():
            args.extend(["--interface", iface.strip()])

        self.throughputProcess.start(python_executable, args)

    @Slot()
    def onThroughputOutput(self):
        data = self.throughputProcess.readAllStandardOutput()
        text = data.data().decode("utf-8", errors="ignore")
        for line in text.splitlines():
            self.appendColoredLine(line)

    @Slot()
    def onThroughputError(self):
        data = self.throughputProcess.readAllStandardError()
        text = data.data().decode("utf-8", errors="ignore")
        for line in text.splitlines():
            self.appendColoredLine("[ERROR] " + line)

    @Slot()
    def onWifiSurvey(self):
        self.appendColoredLine("[WIFI SURVEY] Scanning nearby Wi-Fi networks...")
        try:
            results = run_wifi_survey()
        except Exception as e:
            QMessageBox.warning(self, "WiFi Survey Error", str(e))
            return
        if not results:
            self.appendColoredLine("[WIFI SURVEY] No networks found.")
            return
        self.appendColoredLine(f"Found {len(results)} networks:")
        for ap in results:
            msg = (f"SSID: {ap.get('ssid')}  "
                   f"BSSID: {ap.get('bssid','')}  "
                   f"Signal: {ap.get('signal')}%  "
                   f"Chan: {ap.get('channel')}  "
                   f"Sec: {ap.get('security')}")
            self.appendColoredLine(msg)

    @Slot()
    def onEthSurvey(self):
        self.appendColoredLine("[ETH SURVEY] Gathering interface info via netifaces...")
        try:
            results = run_eth_survey()
        except Exception as e:
            QMessageBox.warning(self, "ETH Survey Error", str(e))
            return
        if not results:
            self.appendColoredLine("No interfaces found.")
            return
        self.appendColoredLine(f"Found {len(results)} interfaces:")
        for iface in results:
            iface_msg = (
                f"Interface: {iface['name']}\n"
                f"  MAC: {iface['mac']}\n"
                f"  IPv4: {', '.join(iface['ipv4']) if iface['ipv4'] else 'None'}\n"
                f"  IPv6: {', '.join(iface['ipv6']) if iface['ipv6'] else 'None'}\n"
                f"  Netmasks: {', '.join(iface['netmask']) if iface['netmask'] else 'None'}\n"
                f"  Broadcast: {', '.join(iface['broadcast']) if iface['broadcast'] else 'None'}\n"
            )
            for line in iface_msg.splitlines():
                self.appendColoredLine(line)

    @Slot()
    def onPcapCapture(self):
        if not SCAPY_AVAILABLE:
            QMessageBox.critical(self, "PCAP Capture Error", "Scapy is not installed.")
            return
        interface, ok = QInputDialog.getText(self, "PCAP Capture", "Enter interface (e.g. eth0 or Wi-Fi):")
        if not ok or not interface.strip():
            return
        duration, ok = QInputDialog.getInt(self, "Capture Duration", "Seconds to capture:", 10, 1, 3600)
        if not ok:
            return
        out_file, ok = QInputDialog.getText(self, "Output PCAP", "File name:", text="capture.pcap")
        if not ok or not out_file.strip():
            return
        self.appendColoredLine(f"[PCAP] Capturing on '{interface}' for {duration}s -> {out_file}")
        self.pcapWorker = PcapWorker(interface.strip(), out_file.strip(), duration)
        self.pcapThread = QThread(self)
        self.pcapWorker.moveToThread(self.pcapThread)
        self.pcapThread.started.connect(self.pcapWorker.runCapture)
        self.pcapWorker.captureFinished.connect(self.onCaptureFinished)
        self.pcapWorker.captureError.connect(self.onCaptureError)
        self.pcapThread.start()

    @Slot(str, int)
    def onCaptureFinished(self, out_file, num_packets):
        self.appendColoredLine(f"[PCAP] Capture finished. {num_packets} packets saved to {out_file}.")
        self.pcapThread.quit()
        self.pcapThread.wait()

    @Slot(str)
    def onCaptureError(self, error_msg):
        QMessageBox.critical(self, "Capture Error", error_msg)
        self.appendColoredLine(f"[PCAP] ERROR: {error_msg}")
        self.pcapThread.quit()
        self.pcapThread.wait()

    # Mouse/resize event handlers remain unchanged...

def main():
    app = QApplication(sys.argv)
    window = GhostShellToolkit()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
