import os
import threading
import time
import random
import datetime
import ctypes
import socket
import hashlib
from flask import Flask, Response, render_template_string, request, jsonify
import tkinter as tk
from tkinter import ttk, messagebox, Frame, Label, Button, Text, Scrollbar, Canvas, BOTH, RIGHT, Y, END, Entry
import tkinter.font as tkFont
from backend import DetectionEngine, RecoveryManager
from frontend import VulnerabilityScannerGUI

# =============================================================================
# Global Variables and Locks
# =============================================================================
detected_vulnerabilities = []  # Global list for real-time vulnerability events
vuln_lock = threading.Lock()   # Lock for thread-safe updates
SIMULATION_SPEED = 1.0  # Control simulation speed (1.0 = normal)

# =============================================================================
# ALERT SYSTEM MODULE
# =============================================================================
class AlertSystem:
    def __init__(self):
        self.alert_count = 0
        self.severity_colors = {
            "high": "#ff4444",
            "medium": "#ffbb33",
            "low": "#00C851"
        }

    def log_alert(self, vuln_type, details, additional_info=None, severity="medium"):
        self.alert_count += 1
        alert = {
            "id": self.alert_count,
            "type": vuln_type,
            "details": details,
            "additional_info": additional_info,
            "timestamp": datetime.datetime.now().isoformat(),
            "severity": severity
        }
        with vuln_lock:
            detected_vulnerabilities.append(alert)
        print(f"ALERT #{self.alert_count}: {alert}")
        return alert

# =============================================================================
# RECOVERY / PREVENTION MANAGER MODULE
# =============================================================================
class RecoveryManager:
    def suggest_recovery(self, vuln_type):
        recs = {
            "Buffer Overflow": (
                "Recovery Steps:\n\n"
                "1. Input Validation:\n"
                "   • Check input length before processing\n"
                "   • Use safe string handling functions\n"
                "   • Implement bounds checking\n\n"
                "2. Memory Protection:\n"
                "   • Enable ASLR (Address Space Layout Randomization)\n"
                "   • Use stack canaries\n"
                "   • Implement DEP (Data Execution Prevention)\n\n"
                "3. Best Practices:\n"
                "   • Use modern programming languages with built-in safety\n"
                "   • Regular security audits\n"
                "   • Keep systems updated"
            ),
            "Trapdoor Injection": (
                "Recovery Steps:\n\n"
                "1. System Monitoring:\n"
                "   • Continuously monitor for unknown processes and open ports\n"
                "   • Use intrusion detection systems (IDS)\n"
                "   • Regular security scans\n\n"
                "2. Access Control:\n"
                "   • Implement strict whitelisting of permitted software\n"
                "   • Apply the principle of least privilege\n"
                "   • Perform regular access reviews\n\n"
                "3. Prevention:\n"
                "   • Code signing\n"
                "   • Secure boot\n"
                "   • Regular security training"
            ),
            "Cache Poisoning": (
                "Recovery Steps:\n\n"
                "1. Cache Security:\n"
                "   • Validate all cache inputs\n"
                "   • Use cryptographic signatures to verify cache integrity\n"
                "   • Implement cache validation routines\n\n"
                "2. Network Security:\n"
                "   • Use DNSSEC for DNS cache security\n"
                "   • Enable ARP inspection on switches\n"
                "   • Monitor network traffic for anomalies\n\n"
                "3. Best Practices:\n"
                "   • Regular cache clearing and maintenance\n"
                "   • Use secure protocols\n"
                "   • Implement proper TTLs for cached data"
            )
        }
        return recs.get(vuln_type, "No recommendations available.")

# =============================================================================
# VULNERABILITY SIMULATION FUNCTIONS 
# =============================================================================
def check_buffer_overflow(buffer_size, data_string, update_func=None):
    if update_func:
        update_func("Step 1: Allocating a fixed buffer of {} bytes.".format(buffer_size))
    buffer = ctypes.create_string_buffer(buffer_size)  # fixed-size buffer
    data_bytes = data_string.encode()  # convert string to bytes
    data_len = len(data_bytes)
    if update_func:
        update_func("Step 2: Received data of length {} bytes.".format(data_len))
    try:
        if update_func:
            update_func("Step 3: Attempting to copy data into the fixed buffer...")
        ctypes.memmove(buffer, data_bytes, data_len)
        if update_func:
            update_func("Step 4: Data copied successfully!")
        result = ("Success: {} bytes were copied safely into a {}-byte buffer."
                  .format(data_len, buffer_size))
        if data_len > buffer_size:
            result += "\n" + simulate_exploit(update_func)
        return result
    except Exception as e:
        if update_func:
            update_func("Step 4: Unexpected error: {}".format(e))
        return "Error: " + str(e)

def simulate_exploit(update_func=None):
    if update_func:
        update_func("\nEXPLOIT: Attempting to overwrite the return address...")
    fake_pointer = ctypes.c_void_p(0xdeadbeef)  
    exploit_msg = f"EXPLOIT: Overwriting return address with: {hex(fake_pointer.value)}"
    if update_func:
        update_func(exploit_msg)
        update_func("EXPLOIT: Buffer Overflow Exploit Successful!")
    return exploit_msg + "\nEXPLOIT: Buffer Overflow Exploit Successful!"

def simulate_cache_poisoning(update_func=None):
    if update_func:
        update_func("Step 1: Establishing secure ARP cache with safe mapping...")
    arp_cache = {"192.168.1.1": "00:11:22:33:44:55"}
    time.sleep(SIMULATION_SPEED)
    if update_func:
        update_func("Step 2: Current ARP cache: " + str(arp_cache))
        update_func("Step 3: Injecting malicious ARP entry (simulated attack)...")
    time.sleep(SIMULATION_SPEED)
    arp_cache["192.168.1.1"] = "AA:BB:CC:DD:EE:FF"  # Simulated poisoning
    if update_func:
        update_func("Step 4: ARP cache modified: " + str(arp_cache))
        update_func("Step 5: Verifying ARP cache integrity...")
    time.sleep(SIMULATION_SPEED)
    if arp_cache["192.168.1.1"] != "00:11:22:33:44:55":
        result = "Cache poisoning detected! ARP cache integrity compromised."
    else:
        result = "Cache remains secure."
    if update_func:
        update_func("Step 6: " + result)
    return result

def enhanced_trapdoor_simulation(port, update_func):
    def trapdoor_server():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.listen(1)
            if update_func:
                update_func("Step 1: Hidden trapdoor server started on port {}.".format(port))
            conn, addr = s.accept()
            if update_func:
                update_func("Step 2: Connection received from {}.".format(addr))
            while True:
                command = conn.recv(1024).decode().strip()
                if not command:
                    break
                if command.lower() == "secret_command":
                    if update_func:
                        update_func("Step 3: Secret command received! Activating trapdoor...")
                    conn.send("Hidden command executed.".encode())
                elif command.lower() == "exit":
                    if update_func:
                        update_func("Step 4: Exit command received. Closing trapdoor.")
                    break
                else:
                    conn.send("Unknown command.".encode())
            conn.close()
            s.close()
            if update_func:
                update_func("Trapdoor server closed.")
        except OSError as oe:
            if update_func:
                update_func("Socket error: " + str(oe))
    thread = threading.Thread(target=trapdoor_server, daemon=True)
    thread.start()
    return "Trapdoor simulation initiated on port {}. Awaiting secret command.".format(port)

# =============================================================================
# DETECTION ENGINE MODULE
# =============================================================================
class DetectionEngine:
    def __init__(self, alert_system):
        self.alert_system = alert_system

    def simulate_buffer_overflow(self, update_func=None, data_string=""):
        buffer_size = 10  # fixed buffer size
        if not data_string:
            length = random.randint(5, 20)
            data_string = "A" * length
            if update_func:
                update_func("No input provided. Using random data: " + data_string)
        result = check_buffer_overflow(buffer_size, data_string, update_func)
        additional_info = {"buffer_size": buffer_size, "data_length": len(data_string)}
        severity = "high" if len(data_string.encode()) > buffer_size else "low"
        self.alert_system.log_alert("Buffer Overflow", result, additional_info, severity)

    def simulate_cache_poisoning(self, update_func=None):
        result = simulate_cache_poisoning(update_func)
        additional_info = {"spoofed_ip": "192.168.1.1", "target_mac": "00:11:22:33:44:55"}
        severity = "high" if "compromised" in result else "low"
        self.alert_system.log_alert("Cache Poisoning", result, additional_info, severity)

    def simulate_trapdoor(self, update_func=None):
        port = 12345  # fixed port
        result = enhanced_trapdoor_simulation(port, update_func)
        additional_info = {"port": port}
        self.alert_system.log_alert("Trapdoor Injection", result, additional_info, "high")

    def run_simulations(self):
        while True:
            time.sleep(random.randint(15, 25))
            attack = random.choice([
                lambda: self.simulate_buffer_overflow(None, "A" * random.randint(5, 25)),
                lambda: self.simulate_trapdoor(None),
                lambda: self.simulate_cache_poisoning(None)
            ])
            attack()

alert_system = AlertSystem()
detection_engine = DetectionEngine(alert_system)

def start_detection_engine():
    thread = threading.Thread(target=detection_engine.run_simulations, daemon=True)
    thread.start()

start_detection_engine()

def start_cache_server():
    cache_app.run(host="0.0.0.0", port=5001, debug=False, use_reloader=False)

cache_app = Flask(__name__)
@cache_app.route("/")
def cache_resource():
    response = Response("Sensitive Resource Data")
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    etag = hashlib.md5(response.data).hexdigest()
    response.headers["ETag"] = etag
    return response

cache_thread = threading.Thread(target=start_cache_server, daemon=True)
cache_thread.start()

def main():
    # Create the main window
    root = tk.Tk()
    root.title("Security Vulnerability Detection Framework")
    root.geometry("800x600")
    root.minsize(800, 600)
    
    # Create main scrollable frame
    main_canvas = tk.Canvas(root)
    scrollbar = tk.Scrollbar(root, orient="vertical", command=main_canvas.yview)
    scrollable_frame = tk.Frame(main_canvas)
    
    scrollable_frame.bind(
        "<Configure>",
        lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
    )
    
    main_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    main_canvas.configure(yscrollcommand=scrollbar.set)
    
    # Pack the scrollbar and canvas
    scrollbar.pack(side="right", fill="y")
    main_canvas.pack(side="left", fill="both", expand=True)
    
    # Bind mouse wheel scrolling
    def _on_mousewheel(event):
        main_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
    main_canvas.bind_all("<MouseWheel>", _on_mousewheel)
    
    # Initialize backend components
    alert_system = AlertSystem()
    detection_engine = DetectionEngine(alert_system)
    recovery_manager = RecoveryManager()
    
    # Create and initialize the GUI
    app = VulnerabilityScannerGUI(scrollable_frame, detection_engine, recovery_manager)
    
    # Start the application
    root.mainloop()

if __name__ == "__main__":
    main()
