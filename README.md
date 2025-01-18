GhostShell Toolkit
Welcome to GhostShell Toolkit – a cross-platform network diagnostics and survey GUI application built using Python and PySide6. It provides a suite of network diagnostic tools, including connection quality measurement, throughput monitoring, network scanning, Wi-Fi surveying, and packet capture, all within an elegant custom user interface.

Table of Contents
Features
Prerequisites
Installation
Usage
Launching the Application
Available Tools
Development
License
Features
Connection Quality Measurement: Ping a target host and display average latency and packet loss over a specified duration.
Ethernet Survey: Enumerate and display detailed information about all Ethernet interfaces on the system.
Network Scanning: Perform network scans (ping scan, host discovery, port scanning) using Nmap.
Wi-Fi Survey: Discover nearby Wi-Fi networks and display their SSID, signal strength, channel, and security details.
Throughput Monitoring: Visualize real-time network throughput with colorful ASCII bar graphs.
Packet Capture: Capture network packets on a specified interface for a given duration using Scapy.
Graphical User Interface: A custom frameless, draggable, and resizable window designed with PySide6.
Command-line Integration: Run subcommands inside a pseudo-terminal within the GUI for direct command execution.
Prerequisites
Python 3.7+
PySide6: For the GUI.
psutil: For throughput monitoring and network interface information.
pythonping: For ping-based connection quality measurement.
scapy: For packet capture functionality.
Nmap: Ensure nmap is installed and available in your system's PATH for network scanning.
Netifaces: For fetching network interface details.
Optional dependencies for enhanced output formatting:

Rich: For colored console output.
Installation
Clone the Repository:

bash
Copy
git clone https://github.com/yourusername/GhostShell-Toolkit.git
cd GhostShell-Toolkit
Create a Virtual Environment (Optional but Recommended):

bash
Copy
python -m venv .venv
source .venv/bin/activate      # On Windows: .venv\Scripts\activate
Install Dependencies:

bash
Copy
pip install -r requirements.txt
Note: If certain tools (like scapy, pythonping, psutil, and netifaces) are not listed in requirements.txt, install them manually:

bash
Copy
pip install PySide6 scapy pythonping psutil netifaces rich
Ensure Nmap is Installed:

On Ubuntu/Debian:
bash
Copy
sudo apt-get install nmap
On Windows: Download and install from Nmap's official site and ensure it's added to your PATH.
Usage
Launching the Application
Run the main application using:

bash
Copy
python main.py
This will open the GhostShell Toolkit window with a custom GUI.

Available Tools
NET SCAN: Scans a network using Nmap.
HOSTSCAN: Scans a single host for open ports.
ADV CONN QUALITY: Measures connection quality over a user-defined period.
THROUGHPUT MONITOR: Monitors network throughput in real-time.
WIFI SURVEY: Lists nearby Wi-Fi networks with details.
ETH SURVEY: Lists network interfaces and their configuration.
PCAP CAPTURE: Captures packets on a network interface for analysis.
Each button in the toolbar corresponds to one of these tools. You can click the buttons to perform the respective actions. Additionally, you can type subcommands directly into the input line at the bottom of the window to execute commands within the integrated pseudo-terminal.

Development
Feel free to fork this repository, submit issues, or contribute pull requests. When contributing:

Create a new branch: git checkout -b feature/your-feature-name
Commit your changes: git commit -am 'Add new feature'
Push to the branch: git push origin feature/your-feature-name
Create a new Pull Request.
License
This project is licensed under the MIT License. See the LICENSE file for details.

Note: Some features, like throughput monitoring, run external scripts or processes. Ensure those scripts (e.g., throughput.py) are in the correct location and unbuffered output is enabled if integrating with a GUI. Also, handling of Ctrl+C within a GUI application differs from terminal behavior; custom key events or stop buttons may be necessary for proper termination of long-running processes.