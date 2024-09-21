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
import json
from PySide6.QtWidgets import QApplication, QMainWindow, QTextEdit, QPushButton, QVBoxLayout, QWidget, QTabWidget, QLineEdit
from PySide6.QtCore import Signal, QObject, QThread

# ===================== Logging Setup ===================== #
if not os.path.exists('logs'):
    os.makedirs('logs')

log_file = os.path.join('logs', 'multi_tool.log')
log_handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=5)
logging.basicConfig(handlers=[log_handler], level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for Network Scanning and AI
LHOST = "localhost"
RHOST = "target_ip"
NMAP_ARGS = "-Pn -sT -O"

# API Credentials from config file
try:
    with open('config/api_credentials.json', 'r') as cred_file:
        api_credentials = json.load(cred_file)
    openai.api_key = api_credentials["openai_api_key"]
except (FileNotFoundError, json.JSONDecodeError) as e:
    logging.error(f"Error loading API credentials: {str(e)}")
    sys.exit("Error loading API credentials. Exiting...")

# ===================== AI Error Handling ===================== #
class WorkerSignals(QObject):
    result = Signal(str)  # Signal to send result messages to the GUI

def detect_and_fix_errors(error_message, output_area):
    """Use OpenAI to suggest fixes for detected errors."""
    class OpenAIThread(QThread):
        def __init__(self, error_message, signals):
            super().__init__()
            self.error_message = error_message
            self.signals = signals

        def run(self):
            try:
                response = openai.Completion.create(
                    model="text-davinci-003",
                    prompt=f"Error detected: {self.error_message}. Suggest a fix.",
                    max_tokens=150
                )
                suggestion = response.choices[0].text.strip()
                self.signals.result.emit(f"AI Suggestion: {suggestion}")
            except openai.error.OpenAIError as e:
                self.signals.result.emit(f"OpenAI Error: {str(e)}")
                logging.error(f"OpenAI error: {str(e)}")
            except Exception as e:
                self.signals.result.emit(f"Unhandled error in AI detection: {str(e)}")
                logging.error(f"AI detection error: {str(e)}")

    signals = WorkerSignals()
    signals.result.connect(output_area.append)

    openai_thread = OpenAIThread(error_message, signals)
    openai_thread.start()

# ===================== Victim Monitoring ===================== #
victims = []

def add_victim(ip_address, output_area):
    """Monitor victim and notify via AI suggestion on vulnerability."""
    class VictimThread(QThread):
        def __init__(self, ip_address, signals):
            super().__init__()
            self.ip_address = ip_address
            self.signals = signals

        def run(self):
            if not validate_ip(self.ip_address):
                self.signals.result.emit(f"Invalid IP address: {self.ip_address}\n")
                return

            victims.append(self.ip_address)
            self.signals.result.emit(f"Monitoring victim: {self.ip_address}\nVulnerability detected at {self.ip_address}.")

    signals = WorkerSignals()
    signals.result.connect(output_area.append)

    victim_thread = VictimThread(ip_address, signals)
    victim_thread.start()

def validate_ip(ip):
    """Validate if the given string is a valid IP address."""
    import re
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return re.match(ip_pattern, ip) is not None

# ===================== Scanning ===================== #
def scan_target(rhost, output_area):
    """Scan target using Nmap."""
    class ScanThread(QThread):
        def __init__(self, rhost, signals):
            super().__init__()
            self.rhost = rhost
            self.signals = signals

        def run(self):
            try:
                nm = nmap.PortScanner()
                nm.scan(self.rhost, arguments=NMAP_ARGS)
                result = f"Target OS: {nm[self.rhost]['osclass'][0]['osfamily']}\n{nm.csv()}"
                self.signals.result.emit(result)
            except Exception as e:
                self.signals.result.emit(f"Error: {str(e)}")
                logging.error(f"Nmap error: {str(e)}")

    signals = WorkerSignals()
    signals.result.connect(output_area.append)

    scan_thread = ScanThread(rhost, signals)
    scan_thread.start()

# ===================== GUI Application ===================== #
class MultiToolV4(QMainWindow):
    """Main GUI for MultiToolV4."""
    
    def __init__(self):
        super().__init__()
        self.init_ui()

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

# Main function to start the GUI application
def main():
    app = QApplication(sys.argv)
    gui = MultiToolV4()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()