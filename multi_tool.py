import socket
import subprocess
import nmap
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox
import logging

# Configure logging
logging.basicConfig(filename='multi_tool.log', level=logging.INFO, 
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
    MultiToolV4 - Enhanced Multi-Tool for Pentesting - By Kd*ir*tchi 🛠️
    """
    print(banner)

def scan_target(rhost):
    """Perform a passive scan using Nmap."""
    try:
        logging.info(f"Starting scan for target: {rhost}")
        nm = nmap.PortScanner()
        nm.scan(rhost, arguments=nmap_args)
        return nm
    except Exception as e:
        logging.error(f"Failed to scan target: {rhost} - {str(e)}")
        messagebox.showerror("Error", f"Failed to scan target: {str(e)}")
        return None

def get_os_info(nm, rhost):
    """Extract OS information from Nmap results."""
    try:
        os_info = nm[rhost].get('osmatch', [{}])[0].get('name', 'Unknown')
        return os_info
    except KeyError:
        logging.warning(f"OS information not available for: {rhost}")
        return "Unknown OS"

def create_backdoor(lhost, port=8080):
    """Create a simple backdoor using sockets."""
    try:
        logging.info(f"Creating backdoor on {lhost}:{port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((lhost, port))
        sock.listen(1)
        print(f"Listening on {lhost}:{port}...")
        conn, addr = sock.accept()
        print(f"Connection established with {addr}")
        while True:
            cmd = input("Enter command: ")
            if cmd.lower() in ['exit', 'quit']:
                logging.info("Backdoor session terminated by user.")
                break
            conn.sendall(cmd.encode())
            response = conn.recv(4096).decode()
            print(response)
        conn.close()
    except Exception as e:
        logging.error(f"Error in backdoor: {str(e)}")
        print(f"Error in backdoor: {str(e)}")
    finally:
        sock.close()

def create_listener(lhost, port=8081):
    """Create a listener to receive incoming connections."""
    try:
        logging.info(f"Creating listener on {lhost}:{port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((lhost, port))
        sock.listen(1)
        print(f"Listening on {lhost}:{port}...")
        conn, addr = sock.accept()
        print(f"Connected to {addr}")
        while True:
            data = conn.recv(4096).decode()
            if not data:
                break
            print(f"Received: {data}")
        conn.close()
    except Exception as e:
        logging.error(f"Error in listener: {str(e)}")
        print(f"Error in listener: {str(e)}")
    finally:
        sock.close()

def run_msfconsole():
    """Run the Metasploit console."""
    try:
        logging.info("Launching msfconsole...")
        subprocess.Popen(['msfconsole'])
    except Exception as e:
        logging.error(f"Failed to start msfconsole: {str(e)}")
        messagebox.showerror("Error", f"Failed to start msfconsole: {str(e)}")

def start_scan():
    """Start the scan by asking for a target IP."""
    rhost = simpledialog.askstring("Input", "Enter target IP:")
    if rhost:
        nm = scan_target(rhost)
        if nm:
            os_info = get_os_info(nm, rhost)
            messagebox.showinfo("Scan Result", f"Target OS: {os_info}")

def start_backdoor():
    """Start backdoor in a separate thread."""
    threading.Thread(target=create_backdoor, args=(LHOST,), daemon=True).start()

def start_listener():
    """Start listener in a separate thread."""
    threading.Thread(target=create_listener, args=(LHOST,), daemon=True).start()

def connect_bot():
    """Placeholder function to connect to a bot."""
    messagebox.showinfo("Bot Connection", "Connecting to bot... (Telegram, Discord, etc.)")

def create_gui():
    """Create the graphical user interface."""
    root = tk.Tk()
    root.title("Multi Tool V5")

    print_banner()

    # GUI Layout
    scan_button = tk.Button(root, text="Scan Target", command=start_scan)
    scan_button.pack(pady=10)

    backdoor_button = tk.Button(root, text="Start Backdoor", command=start_backdoor)
    backdoor_button.pack(pady=10)

    listener_button = tk.Button(root, text="Start Listener", command=start_listener)
    listener_button.pack(pady=10)

    msf_button = tk.Button(root, text="Run msfconsole", command=run_msfconsole)
    msf_button.pack(pady=10)

    bot_button = tk.Button(root, text="Connect to Bot", command=connect_bot)
    bot_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
