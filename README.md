# GhostShell Toolkit

Welcome to **GhostShell Toolkit** – a cross-platform network diagnostics and survey GUI application built using Python and PySide6. It provides a suite of network diagnostic tools, including connection quality measurement, throughput monitoring, network scanning, Wi-Fi surveying, and packet capture, all within an elegant custom user interface.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [Launching the Application](#launching-the-application)
  - [Available Tools](#available-tools)
- [Development](#development)
- [License](#license)

## Features

- **Connection Quality Measurement**: Ping a target host and display average latency and packet loss over a specified duration.
- **Ethernet Survey**: Enumerate and display detailed information about all Ethernet interfaces on the system.
- **Network Scanning**: Perform network scans (ping scan, host discovery, port scanning) using Nmap.
- **Wi-Fi Survey**: Discover nearby Wi-Fi networks and display their SSID, signal strength, channel, and security details.
- **Throughput Monitoring**: Visualize real-time network throughput with colorful ASCII bar graphs.
- **Packet Capture**: Capture network packets on a specified interface for a given duration using Scapy.
- **Graphical User Interface**: A custom frameless, draggable, and resizable window designed with PySide6.
- **Command-line Integration**: Run subcommands inside a pseudo-terminal within the GUI for direct command execution.

## Prerequisites

- Python 3.7+
- **PySide6**: For the GUI.
- **psutil**: For throughput monitoring and network interface information.
- **pythonping**: For ping-based connection quality measurement.
- **scapy**: For packet capture functionality.
- **Nmap**: Ensure `nmap` is installed and available in your system's PATH for network scanning.
- **Netifaces**: For fetching network interface details.

Optional dependencies for enhanced output formatting:
- **Rich**: For colored console output.

## Installation

### Create a Virtual Environment (Optional but Recommended):

```bash
python -m venv .venv
source .venv/bin/activate      # On Windows: .venv\Scripts\activate
