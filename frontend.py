import tkinter as tk
from tkinter import ttk, messagebox, Frame, Label, Button, Text, Scrollbar, Canvas, BOTH, RIGHT, Y, END, Entry
import tkinter.font as tkFont
import random
from backend import detected_vulnerabilities, vuln_lock, detection_engine, RecoveryManager, check_buffer_overflow

class VulnerabilityScannerGUI:
    def __init__(self, master, detection_engine, recovery_manager):
        self.master = master
        self.detection_engine = detection_engine
        self.recovery_manager = recovery_manager
        
        # Configure overall style
        self.master.configure(bg="#f0f0f0")
        
        # --------------------
        # Simulation Details Panel
        # --------------------
        self.details_frame = Frame(self.master, bg="#f0f0f0")
        self.details_frame.pack(fill=BOTH, padx=10, pady=5)
        self.details_label = Label(self.details_frame, text="Simulation Details:", 
                                 font=("Arial", 12, "bold"), bg="#f0f0f0")
        self.details_label.pack(anchor="w")
        self.details_text = Text(self.details_frame, height=8, wrap="word", 
                               bg="lightyellow", font=("Consolas", 10))
        self.details_text.pack(fill=BOTH, expand=True)
        
        # --------------------
        # Interactive Input Panel: For Buffer Overflow 
        # --------------------
        self.input_frame = Frame(self.master, bg="#f0f0f0")
        self.input_frame.pack(fill=BOTH, padx=10, pady=5)
        self.input_label = Label(self.input_frame, text="Enter data for Buffer Overflow simulation:", 
                               font=("Arial", 10), bg="#f0f0f0")
        self.input_label.pack(anchor="w")
        self.input_entry = Entry(self.input_frame, width=50, font=("Consolas", 10))
        self.input_entry.pack(anchor="w")
        
        # --------------------
        # Alerts Log Panel
        # --------------------
        self.alert_frame = Frame(self.master, bg="#f0f0f0")
        self.alert_frame.pack(fill=BOTH, padx=10, pady=5)
        self.alert_text = Text(self.alert_frame, height=10, wrap="word", 
                             bg="white", font=("Consolas", 10))
        self.alert_text.pack(side="left", fill=BOTH, expand=True)
        self.scrollbar = Scrollbar(self.alert_frame, command=self.alert_text.yview)
        self.scrollbar.pack(side=RIGHT, fill=Y)
        self.alert_text.config(yscrollcommand=self.scrollbar.set)
        
        # --------------------
        # Buttons Panel for Simulations
        # --------------------
        self.buttons_frame = Frame(self.master, bg="#f0f0f0")
        self.buttons_frame.pack(fill=BOTH, padx=10, pady=5)
        btn_style = {"font": ("Arial", 10, "bold"), "bg": "#2196F3", "fg": "white", 
                    "activebackground": "#1976D2"}
        self.bo_button = Button(self.buttons_frame, text="Simulate Buffer Overflow", 
                              command=self.test_buffer_overflow, **btn_style)
        self.bo_button.pack(pady=5)
        self.td_button = Button(self.buttons_frame, text="Simulate Trapdoor", 
                              command=self.simulate_trapdoor, **btn_style)
        self.td_button.pack(pady=5)
        self.cp_button = Button(self.buttons_frame, text="Simulate Cache Poisoning", 
                              command=self.simulate_cache_poisoning, **btn_style)
        self.cp_button.pack(pady=5)
        # Add button for automatic simulation
        self.auto_sim_button = Button(self.buttons_frame, text="Start Automatic Simulation", 
                                     command=self.start_automatic_simulation, **btn_style)
        self.auto_sim_button.pack(pady=5)
        
        # --------------------
        # Recovery / Prevention Panel
        # --------------------
        self.recovery_frame = Frame(self.master, bg="#f0f0f0")
        self.recovery_frame.pack(fill=BOTH, padx=10, pady=5)
        self.recovery_label = Label(self.recovery_frame, text="Recovery/Prevention Suggestions:", 
                                  font=("Arial", 12, "bold"), bg="#f0f0f0")
        self.recovery_label.pack(anchor="w")
        
        # Create a frame for the text area and scrollbar
        recovery_text_frame = Frame(self.recovery_frame, bg="#f0f0f0")
        recovery_text_frame.pack(fill=BOTH, expand=True)
        
        # Create text area with scrollbar
        self.recovery_text = Text(recovery_text_frame, height=12, wrap="word", 
                                bg="white", font=("Consolas", 10))
        self.recovery_text.pack(side="left", fill=BOTH, expand=True)
        
        # Add scrollbar for the recovery text
        recovery_scrollbar = Scrollbar(recovery_text_frame, command=self.recovery_text.yview)
        recovery_scrollbar.pack(side=RIGHT, fill=Y)
        self.recovery_text.config(yscrollcommand=recovery_scrollbar.set)
        
        # Add a separator line
        ttk.Separator(self.recovery_frame, orient='horizontal').pack(fill='x', pady=5)
        
        # --------------------
        # Canvas for Animations
        # --------------------
        self.canvas = None
        self.sim_status_label = Label(self.master, text="Simulation status will appear here.", 
                                    font=("Arial", 10), bg="#f0f0f0")
        self.sim_status_label.pack(pady=5)
        
        # Animation control state
        self.animation_step = 0
        self.current_animation = None
        self.animation_running = False
        self.speed_var = tk.StringVar(value="1.0")
        
        self.update_alerts()

    def update_alerts(self):
        self.alert_text.delete(1.0, END)
        with vuln_lock:
            for alert in detected_vulnerabilities[-20:]:
                line = f"[{alert['timestamp']}] {alert['type']}: {alert['details']}\n"
                if alert.get("additional_info"):
                    line += f"      (Details: {alert['additional_info']})\n"
                self.alert_text.insert(END, line)
        self.master.after(1000, self.update_alerts)

    def update_details(self, message):
        self.details_text.insert(END, message + "\n")
        self.details_text.see(END)
        self.master.update_idletasks()

    def simulation_log(self, message):
        self.sim_status_label.config(text=message)
        self.update_details("[SIMULATION] " + message)

    def test_buffer_overflow(self):
        self.details_text.delete(1.0, END)
        self.update_details("Initiating Buffer Overflow Simulation...")
        data_string = self.input_entry.get().strip()
        if not data_string:
            data_string = "A" * random.randint(5, 25)
            self.update_details("No input provided. Using random data: " + data_string)
        else:
            self.update_details("User provided data: " + data_string)
        buffer_size = 10
        result = check_buffer_overflow(buffer_size, data_string, self.update_details)
        self.update_details("Result: " + result)
        self.animate_buffer_overflow(buffer_size, data_string)
        if len(data_string.encode()) > buffer_size:
            recovery = self.recovery_manager.suggest_recovery("Buffer Overflow")
            self.recovery_text.delete(1.0, END)
            self.recovery_text.insert(END, recovery)
            messagebox.showwarning("Buffer Overflow Detected!",
                                 "A buffer overflow vulnerability has been detected!\n"
                                 "Check the recovery suggestions for mitigation steps.")

    def animate_buffer_overflow(self, buffer_size, data_string):
        if self.canvas is not None:
            self.canvas.destroy()
        self.canvas = Canvas(self.master, width=400, height=150, bg="white", 
                           highlightthickness=1, highlightbackground="#2196F3")
        self.canvas.pack(pady=5)
        start_x = 50
        start_y = 40
        cell_width = 20
        # Draw fixed buffer area
        for i in range(buffer_size):
            x1 = start_x + i * cell_width
            y1 = start_y
            x2 = x1 + cell_width
            y2 = start_y + 30
            self.canvas.create_rectangle(x1, y1, x2, y2, fill="#E3F2FD", 
                                      outline="#2196F3", width=2)
        self.canvas.create_text(start_x + (buffer_size * cell_width) / 2, 
                              start_y - 10, text="Buffer (Fixed: 10 bytes)", 
                              fill="#1976D2", font=("Arial", 10, "bold"))
        data_bytes = data_string.encode()
        data_length = len(data_bytes)
        for i in range(data_length):
            color = "#4CAF50" if i < buffer_size else "#F44336"
            x1 = start_x + (i % buffer_size) * cell_width
            y1 = start_y if i < buffer_size else start_y + 40
            x2 = x1 + cell_width
            y2 = y1 + 30
            self.canvas.create_rectangle(x1, y1, x2, y2, fill=color, 
                                      outline="black", width=1)
            self.canvas.create_text(x1 + cell_width//2, y1 + 15, 
                                  text=data_string[i], fill="white", 
                                  font=("Arial", 10, "bold"))
        if data_length > buffer_size:
            self.canvas.create_text(200, start_y + 75,
                                  text="Overflow! Red cells indicate excess data.", 
                                  fill="#F44336", font=("Arial", 10, "bold"))
        self.canvas.create_text(200, 130,
                              text=f"Data: {data_length} bytes | Buffer: {buffer_size} bytes", 
                              fill="#1976D2", font=("Arial", 10))

    def animate_trapdoor(self):
        if self.canvas is not None:
            self.canvas.destroy()
        self.canvas = Canvas(self.master, width=400, height=200, bg="white", 
                           highlightthickness=1, highlightbackground="#ff4444")
        self.canvas.pack(pady=5)
        # Draw a network diagram: Server (hidden trapdoor) and Client (attacker)
        self.canvas.create_rectangle(50, 50, 150, 100, fill="#E3F2FD", 
                                  outline="#2196F3", width=2)
        self.canvas.create_text(100, 75, text="Server", font=("Arial", 10, "bold"), 
                              fill="#1976D2")
        self.canvas.create_rectangle(250, 50, 350, 100, fill="#E8F5E9", 
                                  outline="#4CAF50", width=2)
        self.canvas.create_text(300, 75, text="Client", font=("Arial", 10, "bold"), 
                              fill="#388E3C")
        # Draw arrow from client to server representing secret command
        self.canvas.create_line(350, 75, 150, 75, arrow=tk.LAST, fill="#F44336", 
                              width=2)
        self.canvas.create_text(200, 30, text="Trapdoor\n(secret_command)", 
                              fill="#F44336", font=("Arial", 10, "bold"))
        self.master.after(2000, lambda: self.canvas.create_text(200, 150, 
                                                              text="Trapdoor Activated!", 
                                                              fill="#F44336", 
                                                              font=("Arial", 12, "bold")))

    def animate_cache_poisoning(self):
        if self.canvas is not None:
            self.canvas.destroy()
        self.canvas = Canvas(self.master, width=400, height=200, bg="white", 
                           highlightthickness=1, highlightbackground="#ffbb33")
        self.canvas.pack(pady=5)
        # Draw an ARP cache table
        self.canvas.create_rectangle(50, 50, 350, 100, outline="black", width=2)
        self.canvas.create_text(200, 30, text="ARP Cache", font=("Arial", 12, "bold"))
        self.canvas.create_text(120, 70, text="IP", font=("Arial", 10, "bold"))
        self.canvas.create_text(280, 70, text="MAC", font=("Arial", 10, "bold"))
        # Draw safe mapping initially
        self.canvas.create_text(120, 90, text="192.168.1.1", font=("Arial", 10))
        self.canvas.create_text(280, 90, text="00:11:22:33:44:55", font=("Arial", 10))
        # After delay, animate change to malicious mapping
        self.master.after(2000, lambda: (
            self.canvas.delete("mac"),
            self.canvas.create_text(280, 90, text="AA:BB:CC:DD:EE:FF", 
                                  font=("Arial", 10, "bold"), fill="#F44336", 
                                  tag="mac"),
            self.canvas.create_text(200, 150, text="Cache Poisoning Detected!", 
                                  font=("Arial", 12, "bold"), fill="#F44336")
        ))

    def simulate_trapdoor(self):
        self.details_text.delete(1.0, END)
        self.update_details("Initiating Trapdoor Simulation...")
        self.detection_engine.simulate_trapdoor(self.simulation_log)
        recovery = self.recovery_manager.suggest_recovery("Trapdoor")
        self.recovery_text.delete(1.0, END)
        self.recovery_text.insert(END, recovery)
        self.animate_trapdoor()
        messagebox.showwarning("Trapdoor Detected!",
                             "A hidden trapdoor has been activated!\n"
                             "Check the recovery suggestions for mitigation steps.")

    def simulate_cache_poisoning(self):
        self.details_text.delete(1.0, END)
        self.update_details("Initiating ARP Cache Poisoning Simulation...")
        self.detection_engine.simulate_cache_poisoning(self.simulation_log)
        recovery = self.recovery_manager.suggest_recovery("Cache Poisoning")
        self.recovery_text.delete(1.0, END)
        self.recovery_text.insert(END, recovery)
        self.animate_cache_poisoning()
        messagebox.showwarning("Cache Poisoning Detected!",
                             "Cache poisoning attack detected!\n"
                             "Check the recovery suggestions for mitigation steps.") 

    def start_automatic_simulation(self):
        if hasattr(self, 'auto_sim_thread') and self.auto_sim_thread.is_alive():
            messagebox.showinfo("Info", "Automatic simulation is already running.")
            return
        import threading
        def run_auto():
            self.update_details("Automatic simulation started. Attacks will be simulated at random intervals.")
            while True:
                import random, time
                attack = random.choice([
                    self.test_buffer_overflow,
                    self.simulate_trapdoor,
                    self.simulate_cache_poisoning
                ])
                attack()
                time.sleep(random.randint(10, 20))
        self.auto_sim_thread = threading.Thread(target=run_auto, daemon=True)
        self.auto_sim_thread.start()
