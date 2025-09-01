import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import requests
from urllib.parse import urlparse
import time
import subprocess
import platform
import re

class NetworkScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("DarkBoss1BD Network Scanner")
        self.root.geometry("900x700")
        self.root.configure(bg='#0a0a0a')
        
        # Create hacker-style animation
        self.create_hacker_animation()
        
        # Create main interface
        self.create_interface()
        
    def create_hacker_animation(self):
        # Banner frame
        banner_frame = tk.Frame(self.root, bg='#000000', relief='raised', bd=2)
        banner_frame.pack(fill='x', pady=5)
        
        # Animated banner text
        self.banner_text = tk.Label(banner_frame, 
                                   text="DARKBOSS1BD NETWORK SCANNER",
                                   font=('Courier', 18, 'bold'),
                                   fg='#00ff00', 
                                   bg='#000000',
                                   pady=10)
        self.banner_text.pack()
        
        # Start animation
        self.animate_banner()
        
    def animate_banner(self):
        current_text = self.banner_text.cget("text")
        if current_text.endswith("..."):
            new_text = "DARKBOSS1BD NETWORK SCANNER"
        else:
            dots = current_text.count('.') + 1
            new_text = "DARKBOSS1BD NETWORK SCANNER" + "." * dots
            
        self.banner_text.config(text=new_text)
        self.root.after(500, self.animate_banner)
        
    def create_interface(self):
        # Main container
        main_frame = tk.Frame(self.root, bg='#0a0a0a')
        main_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Input section
        input_frame = tk.LabelFrame(main_frame, text="Target Input", 
                                   font=('Courier', 12, 'bold'),
                                   fg='#00ff00', bg='#111111',
                                   relief='groove', bd=2)
        input_frame.pack(fill='x', pady=5)
        
        # Target input
        tk.Label(input_frame, text="Enter IP Address or URL:", 
                font=('Courier', 10), fg='#00ff00', bg='#111111').pack(anchor='w', padx=10, pady=5)
        
        self.target_entry = tk.Entry(input_frame, font=('Courier', 12), 
                                    bg='#000000', fg='#00ff00', 
                                    insertbackground='#00ff00', relief='solid')
        self.target_entry.pack(fill='x', padx=10, pady=5)
        
        # Scan buttons
        button_frame = tk.Frame(input_frame, bg='#111111')
        button_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Button(button_frame, text="Ping Scan", command=self.ping_scan,
                 font=('Courier', 10, 'bold'), bg='#003300', fg='#00ff00',
                 activebackground='#006600', activeforeground='#ffffff',
                 relief='raised', bd=2).pack(side='left', padx=5)
                 
        tk.Button(button_frame, text="Port Scan", command=self.port_scan,
                 font=('Courier', 10, 'bold'), bg='#003300', fg='#00ff00',
                 activebackground='#006600', activeforeground='#ffffff',
                 relief='raised', bd=2).pack(side='left', padx=5)
                 
        tk.Button(button_frame, text="WHOIS Lookup", command=self.whois_lookup,
                 font=('Courier', 10, 'bold'), bg='#003300', fg='#00ff00',
                 activebackground='#006600', activeforeground='#ffffff',
                 relief='raised', bd=2).pack(side='left', padx=5)
                 
        tk.Button(button_frame, text="DNS Lookup", command=self.dns_lookup,
                 font=('Courier', 10, 'bold'), bg='#003300', fg='#00ff00',
                 activebackground='#006600', activeforeground='#ffffff',
                 relief='raised', bd=2).pack(side='left', padx=5)
                 
        tk.Button(button_frame, text="Full Scan", command=self.full_scan,
                 font=('Courier', 10, 'bold'), bg='#006600', fg='#ffffff',
                 activebackground='#009900', activeforeground='#ffffff',
                 relief='raised', bd=2).pack(side='left', padx=5)
        
        # Results section
        results_frame = tk.LabelFrame(main_frame, text="Scan Results", 
                                     font=('Courier', 12, 'bold'),
                                     fg='#00ff00', bg='#111111',
                                     relief='groove', bd=2)
        results_frame.pack(fill='both', expand=True, pady=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(results_frame, mode='indeterminate')
        self.progress.pack(fill='x', padx=10, pady=5)
        
        # Results text area with hacker-style colors
        self.results_text = scrolledtext.ScrolledText(results_frame,
                                                     font=('Courier', 10),
                                                     bg='#000000',
                                                     fg='#00ff00',
                                                     insertbackground='#00ff00',
                                                     relief='sunken',
                                                     bd=2,
                                                     height=20)
        self.results_text.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Clear button
        tk.Button(results_frame, text="Clear Results", command=self.clear_results,
                 font=('Courier', 10, 'bold'), bg='#330000', fg='#ff0000',
                 activebackground='#660000', activeforeground='#ffffff',
                 relief='raised', bd=2).pack(pady=5)
        
        # Hacker animation in corner
        self.hacker_label = tk.Label(self.root, text=">_", 
                                    font=('Courier', 14, 'bold'),
                                    fg='#00ff00', bg='#0a0a0a')
        self.hacker_label.place(relx=0.95, rely=0.95, anchor='se')
        self.animate_cursor()
        
    def animate_cursor(self):
        current_text = self.hacker_label.cget("text")
        if current_text == ">_":
            new_text = "> "
        else:
            new_text = ">_"
        self.hacker_label.config(text=new_text)
        self.root.after(500, self.animate_cursor)
        
    def get_ip_from_url(self, url):
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc or parsed.path
            ip = socket.gethostbyname(hostname)
            return ip
        except Exception as e:
            return None
            
    def ping_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or URL")
            return
            
        self.results_text.insert(tk.END, f"[+] Starting Ping Scan for: {target}\n")
        self.progress.start()
        
        # Run ping in separate thread
        thread = threading.Thread(target=self._ping_scan_thread, args=(target,))
        thread.daemon = True
        thread.start()
        
    def _ping_scan_thread(self, target):
        try:
            # Convert URL to IP if needed
            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
                ip = self.get_ip_from_url(target)
                if not ip:
                    self.results_text.insert(tk.END, f"[-] Could not resolve hostname: {target}\n")
                    self.progress.stop()
                    return
                target = ip
                self.results_text.insert(tk.END, f"[+] Resolved to IP: {target}\n")
            
            # Perform ping
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '4', target]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            
            self.results_text.insert(tk.END, f"\n[+] Ping Results for {target}:\n")
            self.results_text.insert(tk.END, "="*50 + "\n")
            
            if result.returncode == 0:
                self.results_text.insert(tk.END, "[✓] Host is UP\n")
                self.results_text.insert(tk.END, result.stdout)
            else:
                self.results_text.insert(tk.END, "[✗] Host is DOWN\n")
                self.results_text.insert(tk.END, result.stderr)
                
        except subprocess.TimeoutExpired:
            self.results_text.insert(tk.END, "[-] Ping timed out\n")
        except Exception as e:
            self.results_text.insert(tk.END, f"[-] Error during ping scan: {str(e)}\n")
        finally:
            self.progress.stop()
            
    def port_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or URL")
            return
            
        self.results_text.insert(tk.END, f"[+] Starting Port Scan for: {target}\n")
        self.progress.start()
        
        thread = threading.Thread(target=self._port_scan_thread, args=(target,))
        thread.daemon = True
        thread.start()
        
    def _port_scan_thread(self, target):
        try:
            # Convert URL to IP if needed
            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
                ip = self.get_ip_from_url(target)
                if not ip:
                    self.results_text.insert(tk.END, f"[-] Could not resolve hostname: {target}\n")
                    self.progress.stop()
                    return
                target = ip
                self.results_text.insert(tk.END, f"[+] Resolved to IP: {target}\n")
            
            # Common ports to scan
            common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080]
            
            self.results_text.insert(tk.END, f"\n[+] Port Scan Results for {target}:\n")
            self.results_text.insert(tk.END, "="*50 + "\n")
            
            open_ports = []
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        service = self.get_service_name(port)
                        self.results_text.insert(tk.END, f"[OPEN] Port {port}: {service}\n")
                        open_ports.append(port)
                    sock.close()
                except Exception:
                    pass
                    
            if not open_ports:
                self.results_text.insert(tk.END, "[-] No open ports found\n")
            else:
                self.results_text.insert(tk.END, f"\n[+] Found {len(open_ports)} open ports\n")
                
        except Exception as e:
            self.results_text.insert(tk.END, f"[-] Error during port scan: {str(e)}\n")
        finally:
            self.progress.stop()
            
    def get_service_name(self, port):
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 3306: "MySQL", 3389: "RDP", 5900: "VNC"
        }
        return services.get(port, "Unknown")
        
    def whois_lookup(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or URL")
            return
            
        self.results_text.insert(tk.END, f"[+] Starting WHOIS Lookup for: {target}\n")
        self.progress.start()
        
        thread = threading.Thread(target=self._whois_lookup_thread, args=(target,))
        thread.daemon = True
        thread.start()
        
    def _whois_lookup_thread(self, target):
        try:
            # For this demo, we'll simulate WHOIS data
            self.results_text.insert(tk.END, f"\n[+] WHOIS Information for {target}:\n")
            self.results_text.insert(tk.END, "="*50 + "\n")
            
            # Convert URL to domain if needed
            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
                parsed = urlparse(target)
                domain = parsed.netloc or parsed.path
            else:
                domain = target
                
            self.results_text.insert(tk.END, f"Domain: {domain}\n")
            self.results_text.insert(tk.END, "Registrar: SIMULATED REGISTRAR\n")
            self.results_text.insert(tk.END, "Creation Date: 2020-01-01\n")
            self.results_text.insert(tk.END, "Expiration Date: 2025-01-01\n")
            self.results_text.insert(tk.END, "Name Servers: ns1.example.com, ns2.example.com\n")
            self.results_text.insert(tk.END, "Organization: SIMULATED ORG\n")
            self.results_text.insert(tk.END, "Country: BD\n")
            
        except Exception as e:
            self.results_text.insert(tk.END, f"[-] Error during WHOIS lookup: {str(e)}\n")
        finally:
            self.progress.stop()
            
    def dns_lookup(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or URL")
            return
            
        self.results_text.insert(tk.END, f"[+] Starting DNS Lookup for: {target}\n")
        self.progress.start()
        
        thread = threading.Thread(target=self._dns_lookup_thread, args=(target,))
        thread.daemon = True
        thread.start()
        
    def _dns_lookup_thread(self, target):
        try:
            # Convert URL to domain if needed
            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
                parsed = urlparse(target)
                domain = parsed.netloc or parsed.path
            else:
                domain = target
                
            self.results_text.insert(tk.END, f"\n[+] DNS Lookup Results for {domain}:\n")
            self.results_text.insert(tk.END, "="*50 + "\n")
            
            try:
                # Get IP address
                ip = socket.gethostbyname(domain)
                self.results_text.insert(tk.END, f"IP Address: {ip}\n")
                
                # Get hostname
                hostname = socket.getfqdn(domain)
                self.results_text.insert(tk.END, f"Hostname: {hostname}\n")
                
                # Get aliases
                try:
                    aliases = socket.gethostbyname_ex(domain)[1]
                    if aliases:
                        self.results_text.insert(tk.END, f"Aliases: {', '.join(aliases)}\n")
                except:
                    pass
                    
            except Exception as e:
                self.results_text.insert(tk.END, f"[-] DNS lookup failed: {str(e)}\n")
                
        except Exception as e:
            self.results_text.insert(tk.END, f"[-] Error during DNS lookup: {str(e)}\n")
        finally:
            self.progress.stop()
            
    def full_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or URL")
            return
            
        self.results_text.insert(tk.END, f"[+] Starting Full Network Scan for: {target}\n")
        self.results_text.insert(tk.END, "="*60 + "\n")
        self.progress.start()
        
        thread = threading.Thread(target=self._full_scan_thread, args=(target,))
        thread.daemon = True
        thread.start()
        
    def _full_scan_thread(self, target):
        try:
            # Perform all scans sequentially
            self.results_text.insert(tk.END, "[1] Ping Scan...\n")
            self._ping_scan_thread(target)
            time.sleep(1)
            
            self.results_text.insert(tk.END, "\n[2] Port Scan...\n")
            self._port_scan_thread(target)
            time.sleep(1)
            
            self.results_text.insert(tk.END, "\n[3] DNS Lookup...\n")
            self._dns_lookup_thread(target)
            time.sleep(1)
            
            self.results_text.insert(tk.END, "\n[4] WHOIS Lookup...\n")
            self._whois_lookup_thread(target)
            
            self.results_text.insert(tk.END, "\n[+] Full Scan Complete!\n")
            self.results_text.insert(tk.END, "="*60 + "\n")
            
        except Exception as e:
            self.results_text.insert(tk.END, f"[-] Error during full scan: {str(e)}\n")
        finally:
            self.progress.stop()
            
    def clear_results(self):
        self.results_text.delete(1.0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScanner(root)
    root.mainloop()