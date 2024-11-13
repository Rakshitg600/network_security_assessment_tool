import tkinter as tk
from tkinter import ttk, scrolledtext
import socket
import threading
import json
from datetime import datetime
import nmap
import csv

class NetworkSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Security Assessment Tool")
        self.root.geometry("800x600")
        
        # NIST CSF Categories we'll assess
        self.nist_categories = {
            "Identify": ["Asset Management", "Network Mapping"],
            "Detect": ["Port Scanning", "Service Detection"],
            "Respond": ["Vulnerability Assessment"]
        }
        
        self.setup_gui()
        
    def setup_gui(self):
        # Create notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(pady=10, expand=True, fill="both")
        
        # Dashboard Tab
        dashboard_frame = ttk.Frame(notebook)
        notebook.add(dashboard_frame, text="Dashboard")
        
        # Add scan controls
        control_frame = ttk.LabelFrame(dashboard_frame, text="Scan Controls")
        control_frame.pack(padx=10, pady=5, fill="x")
        
        ttk.Label(control_frame, text="Target IP:").pack(side=tk.LEFT, padx=5)
        self.ip_entry = ttk.Entry(control_frame)
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        self.ip_entry.insert(0, "127.0.0.1")
        
        ttk.Button(control_frame, text="Start Scan", 
                  command=self.start_scan).pack(side=tk.LEFT, padx=5)
        
        # Add results area
        results_frame = ttk.LabelFrame(dashboard_frame, text="Scan Results")
        results_frame.pack(padx=10, pady=5, fill="both", expand=True)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=20)
        self.results_text.pack(padx=5, pady=5, fill="both", expand=True)
        
        # Reports Tab
        reports_frame = ttk.Frame(notebook)
        notebook.add(reports_frame, text="Reports")
        
        ttk.Button(reports_frame, text="Generate Report", 
                  command=self.generate_report).pack(pady=10)
        
        self.report_text = scrolledtext.ScrolledText(reports_frame, height=20)
        self.report_text.pack(padx=5, pady=5, fill="both", expand=True)
    
    def start_scan(self):
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Starting security assessment...\n")
        target_ip = self.ip_entry.get()
        
        # Start scan in separate thread to keep GUI responsive
        thread = threading.Thread(target=self.perform_scan, args=(target_ip,))
        thread.daemon = True
        thread.start()
    
    def perform_scan(self, target_ip):
        try:
            # Initialize nmap scanner
            nm = nmap.PortScanner()
            
            self.log_message("Performing port scan...")
            # Perform basic port scan
            nm.scan(target_ip, '22-443', arguments='-sV')
            
            # Analyze results
            for host in nm.all_hosts():
                self.log_message(f"\nHost: {host}")
                self.log_message(f"State: {nm[host].state()}")
                
                for proto in nm[host].all_protocols():
                    self.log_message(f"\nProtocol: {proto}")
                    ports = nm[host][proto].keys()
                    
                    for port in ports:
                        service = nm[host][proto][port]
                        self.log_message(
                            f"Port {port}: {service['state']} "
                            f"({service.get('name', 'unknown')})"
                        )
            
            # Save results for reporting
            self.scan_results = nm
            self.log_message("\nScan completed successfully!")
            
        except Exception as e:
            self.log_message(f"Error during scan: {str(e)}")
    
    def log_message(self, message):
        self.results_text.insert(tk.END, message + "\n")
        self.results_text.see(tk.END)
    
    def generate_report(self):
        if not hasattr(self, 'scan_results'):
            self.report_text.delete(1.0, tk.END)
            self.report_text.insert(tk.END, "No scan results available. Please run a scan first.")
            return
        
        report = []
        report.append("Network Security Assessment Report")
        report.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Add NIST CSF framework categories
        for category, subcategories in self.nist_categories.items():
            report.append(f"\n{category} Framework Category:")
            for subcategory in subcategories:
                report.append(f"- {subcategory}")
        
        # Add scan results
        report.append("\nScan Results:")
        for host in self.scan_results.all_hosts():
            report.append(f"\nHost: {host}")
            report.append(f"State: {self.scan_results[host].state()}")
            
            for proto in self.scan_results[host].all_protocols():
                report.append(f"\nProtocol: {proto}")
                ports = self.scan_results[host][proto].keys()
                
                for port in ports:
                    service = self.scan_results[host][proto][port]
                    report.append(
                        f"Port {port}: {service['state']} "
                        f"({service.get('name', 'unknown')})"
                    )
        
        # Display report
        self.report_text.delete(1.0, tk.END)
        self.report_text.insert(tk.END, "\n".join(report))
        
        # Save report to CSV
        self.save_report_csv()
    
    def save_report_csv(self):
        filename = f"security_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Category', 'Finding', 'Status'])
            
            for host in self.scan_results.all_hosts():
                for proto in self.scan_results[host].all_protocols():
                    ports = self.scan_results[host][proto].keys()
                    for port in ports:
                        service = self.scan_results[host][proto][port]
                        writer.writerow([
                            'Port Scan',
                            f'Port {port} ({service.get("name", "unknown")})',
                            service['state']
                        ])

def main():
    root = tk.Tk()
    app = NetworkSecurityTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()
