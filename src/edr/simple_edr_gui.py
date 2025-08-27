"""
Simple EDR Agent GUI
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import json
from datetime import datetime
import logging
from src.edr.agent.edr_agent import EDRAgent, EDREvent

class SimpleEDRGUI:
    def __init__(self, root, agent):
        self.root = root
        self.agent = agent
        self.setup_gui()
        
        # Register callback for new events
        self.agent.register_callback('event_received', self.on_event_received)
        
    def setup_gui(self):
        """Set up the GUI components."""
        self.root.title("EDR Agent Dashboard")
        self.root.geometry("1000x700")
        
        # Configure grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Status: Running")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=2, column=0, columnspan=2, sticky="ew")
        
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.columnconfigure(1, weight=1)
        
        # Event log
        ttk.Label(main_frame, text="Event Log").grid(row=0, column=0, sticky="w")
        self.event_log = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=100, height=20)
        self.event_log.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(0, 10))
        
        # Buttons frame
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        ttk.Button(btn_frame, text="Submit Test Event", command=self.submit_test_event).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Agent Status", command=self.show_status).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Exit", command=self.on_exit).pack(side=tk.RIGHT, padx=5)
        
        # Event details
        ttk.Label(main_frame, text="Event Details").grid(row=3, column=0, sticky="w", pady=(10, 0))
        self.event_details = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=100, height=10)
        self.event_details.grid(row=4, column=0, columnspan=2, sticky="nsew")
        
        # Configure row/column weights
        main_frame.rowconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
    def log_message(self, message):
        """Add a message to the event log."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.event_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.event_log.see(tk.END)
        
    def clear_log(self):
        """Clear the event log."""
        self.event_log.delete(1.0, tk.END)
        
    def show_status(self):
        """Show agent status."""
        status = {
            "Running": self.agent.running,
            "Queue Size": len(self.agent.event_queue),
            "Callbacks Registered": sum(len(callbacks) for callbacks in self.agent.callbacks.values())
        }
        messagebox.showinfo("Agent Status", "\n".join(f"{k}: {v}" for k, v in status.items()))
        
    def submit_test_event(self):
        """Submit a test event to the agent."""
        test_event = EDREvent(
            event_type="test",
            data={"message": "This is a test event"}
        )
        self.agent.submit_event(test_event)
        self.log_message("Submitted test event")
        
    def on_event_received(self, event):
        """Handle new events received by the agent."""
        self.root.after(0, self._update_event_display, event)
        
    def _update_event_display(self, event):
        """Update the GUI with the new event."""
        self.log_message(f"Event received: {event.event_type}")
        
        # Update event details
        self.event_details.delete(1.0, tk.END)
        self.event_details.insert(tk.END, json.dumps(event.to_dict(), indent=2))
        
    def on_exit(self):
        """Handle application exit."""
        if messagebox.askokcancel("Exit", "Are you sure you want to exit?"):
            self.agent.stop()
            self.root.destroy()

def main():
    # Create and configure the root window
    root = tk.Tk()
    root.title("EDR Agent")
    
    # Create the agent
    agent = EDRAgent(config={
        'agent_id': 'edr-agent-001',
        'data_dir': 'data',
        'rules_dir': 'rules'
    })
    
    # Start the agent
    agent.start()
    
    # Create and start the GUI
    app = SimpleEDRGUI(root, agent)
    
    # Set up window close handler
    root.protocol("WM_DELETE_WINDOW", app.on_exit)
    
    # Start the main loop
    root.mainloop()
    
    # Stop the agent when the GUI is closed
    agent.stop()

if __name__ == "__main__":
    main()
