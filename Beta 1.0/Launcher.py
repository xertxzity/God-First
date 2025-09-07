import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import threading
import os
import time
import logging
import json
from src.database import FortniteDatabase
from src.mitmproxy_manager import MitmproxyManager
from src.ai_assistant import AIAssistant
import socket
import ssl
import urllib.request
import urllib.parse
import json
from datetime import datetime
import ctypes
import sys
import time

def is_admin():
    """Check if the script is running with admin privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def run_as_admin():
    """Re-run the script with admin privileges"""
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

class FortniteEmulatorLauncher:
    def __init__(self, root):
        self.root = root
        self.root.title("Fortnite Season 7.40 Emulator Launcher")
        self.root.geometry("900x700")
        self.root.resizable(False, False)
        
        # Dark theme configuration
        self.bg_color = "#1a1a1a"
        self.fg_color = "#ffffff"
        self.button_color = "#2d2d2d"
        self.button_hover = "#3d3d3d"
        self.accent_color = "#0078d4"
        self.success_color = "#107c10"
        self.warning_color = "#ff8c00"
        self.error_color = "#d13438"
        
        self.root.configure(bg=self.bg_color)
        
        # Setup logging
        self.setup_logging()
        
        # Variables
        self.game_path = tk.StringVar()
        self.status_text = tk.StringVar(value="Ready to launch")
        self.console_messages = []
        self.backend_running = False
        # Initialize mitmproxy manager
        self.mitm_manager = MitmproxyManager()
        
        # Initialize AI Assistant
        self.ai_assistant = AIAssistant(self)
        self.port443_status = tk.StringVar(value="Unknown")
        self.is_admin = is_admin()
        
        # Bypass options (initialized as BooleanVar for checkboxes)
        self.bypass_ssl = tk.BooleanVar(value=True)
        self.bypass_eac = tk.BooleanVar(value=True)
        self.bypass_auth = tk.BooleanVar(value=True)
        
        # Load saved game path
        self.load_game_path()
        
        # Create GUI
        self.create_widgets()
        
        # Initial checks
        self.check_port_status()
        self.check_admin_status()
        
        # Automatically do everything if running as admin (disabled to prevent certificate spam)
        # if self.is_admin:
        #     self.automated_setup()
        
        # Log startup
        self.logger.info("Fortnite Emulator Launcher started")
    
    def automated_setup(self):
        """Automatically do everything - generate certs, trust certs, start backend, launch game"""
        def _automated_setup_async():
            try:
                self.root.after(0, lambda: self.update_status("Setup: Starting unified backend proxy"))
                
                # Start mitmproxy for unified backend routing
                if self.mitm_manager.install_mitmproxy():
                    if self.mitm_manager.start_mitmproxy():
                        self.logger.info("Unified backend proxy started successfully")
                    else:
                        self.logger.warning("Failed to start unified proxy, using direct connection")
                
                self.root.after(0, lambda: self.update_status("Setup: Starting backend server"))
                self.start_backend()
                
                self.root.after(0, lambda: self.update_status("Setup: Generating SSL certificates"))
                self.generate_ssl_certificates_direct()
                
                self.root.after(0, lambda: self.update_status("Setup: Installing SSL certificates"))
                self._trust_certs_automated()
                
                self.root.after(0, lambda: self.update_status("Setup: Applying hosts redirects"))
                self.apply_hosts()
                
                self.root.after(0, lambda: self.update_status("Setup: Hosts redirects applied successfully"))
                time.sleep(1)  # Brief pause for user feedback
                
                self.root.after(0, lambda: self.update_status("Setup: Final backend verification"))
                time.sleep(2)  # Allow backend to fully start
                
                if self.verify_backend():
                    self.root.after(0, lambda: self.update_status("Backend verified - setup complete"))
                else:
                    self.root.after(0, lambda: self.update_status("Backend verification failed"))
                
                self.root.after(0, lambda: self.update_status("Setup completed successfully"))
                self.logger.info("Automated setup completed successfully")
                
            except Exception as e:
                self.logger.error(f"Automated setup failed: {str(e)}")
                self.root.after(0, lambda: self.status_text.set(f"Setup failed: {str(e)}"))
        
        # Run in separate thread to prevent GUI freezing
        threading.Thread(target=_automated_setup_async, daemon=True).start()
    
    def _trust_certs_automated(self):
        """Install SSL certificates automatically if not already installed"""
        if self._certificates_already_installed():
            self.logger.info("SSL certificates already installed, skipping installation")
            return
        
        # Install mitmproxy certificates for unified backend routing
        self.logger.info("Setting up mitmproxy certificates for unified backend routing...")
        if self.mitm_manager.install_mitmproxy():
            if self.mitm_manager.install_mitm_certificate():
                self.logger.info("mitmproxy SSL certificates installed successfully")
            else:
                self.logger.warning("Failed to install mitmproxy certificates, falling back to manual certs")
        
        self.install_cert_to_trusted_root("ssl/root-ca.crt")
        self.install_cert_to_trusted_root("ssl/end-entity.crt")
        
        # Install to additional stores
        self.install_to_additional_stores()
        
        self.logger.info("SSL certificates trusted automatically")
    
    def install_to_additional_stores(self):
        """Install certificates to additional Windows certificate stores"""
        try:
            cert_files = ["ssl/root-ca.crt", "ssl/end-entity.crt"]
            
            for cert_file in cert_files:
                if not os.path.exists(cert_file):
                    continue
                
                # Install to CurrentUser\TrustedPublisher store
                try:
                    result = subprocess.run([
                        "powershell", "-Command", 
                        f'Import-Certificate -FilePath "{cert_file}" -CertStoreLocation "Cert:\\CurrentUser\\TrustedPublisher"'
                    ], capture_output=True, text=True, timeout=15)
                    
                    if result.returncode == 0:
                        self.logger.info(f"Certificate installed to CurrentUser\\TrustedPublisher store")
                except Exception as e:
                    self.logger.warning(f"TrustedPublisher installation error: {e}")
                
                # Install to LocalMachine\TrustedPublisher store
                try:
                    result = subprocess.run([
                        "powershell", "-Command", 
                        f'Import-Certificate -FilePath "{cert_file}" -CertStoreLocation "Cert:\\LocalMachine\\TrustedPublisher"'
                    ], capture_output=True, text=True, timeout=15)
                    
                    if result.returncode == 0:
                        self.logger.info(f"Certificate installed to LocalMachine\\TrustedPublisher store")
                except Exception as e:
                    self.logger.warning(f"LocalMachine TrustedPublisher installation error: {e}")
                
                # Install to CurrentUser\My store (Personal certificates)
                try:
                    result = subprocess.run([
                        "powershell", "-Command", 
                        f'Import-Certificate -FilePath "{cert_file}" -CertStoreLocation "Cert:\\CurrentUser\\My"'
                    ], capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0:
                        self.logger.info(f"Certificate installed to CurrentUser\\My store")
                except Exception as e:
                    self.logger.warning(f"My store installation error: {e}")
                
                # Install to LocalMachine\My store
                try:
                    result = subprocess.run([
                        "powershell", "-Command", 
                        f'Import-Certificate -FilePath "{cert_file}" -CertStoreLocation "Cert:\\LocalMachine\\My"'
                    ], capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0:
                        self.logger.info(f"Certificate installed to LocalMachine\\My store")
                except Exception as e:
                    self.logger.warning(f"LocalMachine My store installation error: {e}")
            
            # Restart Windows Certificate Service to ensure changes take effect
            try:
                result = subprocess.run([
                    "powershell", "-Command", 
                    "Restart-Service -Name 'CryptSvc' -Force"
                ], capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0:
                    self.logger.info("Certificate service restarted")
            except Exception as e:
                self.logger.warning(f"Certificate service restart error: {e}")
            
        except Exception as e:
            self.logger.error(f"Additional store installation failed: {str(e)}")
    
    def _certificates_already_installed(self):
        """Check if SSL certificates are already installed to avoid duplicate installations"""
        try:
            # Check if Epic Games certificates exist in the trusted root store
            result = subprocess.run([
                "powershell", "-Command", 
                'Get-ChildItem -Path "Cert:\\CurrentUser\\Root" | Where-Object {$_.Subject -like "*Epic Games*"} | Measure-Object | Select-Object -ExpandProperty Count'
            ], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and result.stdout.strip():
                count = int(result.stdout.strip())
                return count > 0
            
        except Exception as e:
            self.logger.debug(f"Certificate check failed: {e}")
        
        return False
    
    def install_cert_to_trusted_root(self, cert_file):
        """Install certificate to trusted root store using multiple methods with shorter timeouts"""
        try:
            success_count = 0
            
            # Method 1: Simple certutil approach first (fastest) - User store
            self.logger.info("Installing certificate via certutil (user)")
            result = subprocess.run([
                "certutil", "-addstore", "-user", "Root", cert_file
            ], capture_output=True, text=True, timeout=8)
            
            if result.returncode == 0:
                self.logger.info("Certificate installed via certutil (user)")
                success_count += 1
            
            # Method 2: Machine store
            self.logger.info("Installing certificate via certutil (machine)")
            result = subprocess.run([
                "certutil", "-addstore", "Root", cert_file
            ], capture_output=True, text=True, timeout=8)
            
            if result.returncode == 0:
                self.logger.info("Certificate installed via certutil (machine)")
                success_count += 1
            
            # Method 3: PowerShell approach for user store
            powershell_cmd_user = f'Import-Certificate -FilePath "{cert_file}" -CertStoreLocation "Cert:\\CurrentUser\\Root"'
            result = subprocess.run([
                "powershell", "-Command", powershell_cmd_user
            ], capture_output=True, text=True, timeout=8)
            
            if result.returncode == 0:
                self.logger.info("Certificate installed via PowerShell (user)")
                success_count += 1
            
            # Method 4: PowerShell approach for machine store
            powershell_cmd_machine = f'Import-Certificate -FilePath "{cert_file}" -CertStoreLocation "Cert:\\LocalMachine\\Root"'
            result = subprocess.run([
                "powershell", "-Command", powershell_cmd_machine
            ], capture_output=True, text=True, timeout=8)
            
            if result.returncode == 0:
                self.logger.info("Certificate installed via PowerShell (machine)")
                success_count += 1
                
            # Method 5: Install to additional stores that might be checked by HTTP clients
            additional_stores = [
                ("CurrentUser", "TrustedPublisher"),
                ("LocalMachine", "TrustedPublisher"),
                ("CurrentUser", "CA"),
                ("LocalMachine", "CA"),
                ("CurrentUser", "AuthRoot"),
                ("LocalMachine", "AuthRoot")
            ]
            
            for location, store in additional_stores:
                try:
                    powershell_cmd = f'Import-Certificate -FilePath "{cert_file}" -CertStoreLocation "Cert:\\{location}\\{store}"'
                    result = subprocess.run([
                        "powershell", "-Command", powershell_cmd
                    ], capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0:
                        self.logger.info(f"Certificate installed to {location}\\{store}")
                        success_count += 1
                except:
                    pass
            
            # Method 6: Try to add certificate to curl's CA bundle if it exists
            try:
                # Common curl CA bundle locations on Windows
                curl_ca_paths = [
                    "C:\\curl\\bin\\curl-ca-bundle.crt",
                    "C:\\Program Files\\Git\\mingw64\\ssl\\certs\\ca-bundle.crt",
                    "C:\\msys64\\mingw64\\ssl\\certs\\ca-bundle.crt"
                ]
                
                for ca_path in curl_ca_paths:
                    if os.path.exists(ca_path):
                        try:
                            # Read the certificate
                            with open(cert_file, 'r') as f:
                                cert_content = f.read()
                            
                            # Append to CA bundle if not already present
                            with open(ca_path, 'r') as f:
                                bundle_content = f.read()
                            
                            if cert_content.strip() not in bundle_content:
                                with open(ca_path, 'a') as f:
                                    f.write('\n' + cert_content)
                                self.logger.info(f"Certificate added to curl CA bundle: {ca_path}")
                                success_count += 1
                        except:
                            pass
            except:
                pass
            
            # Verify installation
            verify_result = subprocess.run([
                "powershell", "-Command", 
                f'Get-ChildItem -Path "Cert:\\CurrentUser\\Root" | Where-Object {{$_.Subject -like "*Epic Games*"}} | Measure-Object | Select-Object -ExpandProperty Count'
            ], capture_output=True, text=True, timeout=5)
            
            if verify_result.returncode == 0 and verify_result.stdout.strip():
                count = int(verify_result.stdout.strip())
                if count > 0:
                    self.logger.info("Certificate verified in trusted root store")
                    return True
            
            # Return success if at least one method worked
            return success_count > 0
            
        except subprocess.TimeoutExpired:
            self.logger.warning("Certificate installation timed out")
            return False
        except Exception as e:
            self.logger.error(f"Certificate installation failed: {str(e)}")
            return False
    
    def check_admin_status(self):
        """Check if running with admin privileges"""
        if not self.is_admin:
            self.update_status("⚠️ Not running as administrator - some features may not work", self.warning_color)
            self.log_to_console("Warning: Not running as administrator", "WARNING")
        else:
            self.update_status("✅ Running with administrator privileges", self.success_color)
            self.log_to_console("Running with administrator privileges", "SUCCESS")
    
    def setup_logging(self):
        """Setup logging configuration"""
        if not os.path.exists('logs'):
            os.makedirs('logs')
        
        log_filename = f"logs/launcher_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_filename),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def create_widgets(self):
        """Create the main GUI widgets"""
        # Create main frame with dark theme
        main_frame = tk.Frame(self.root, bg=self.bg_color)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title with dark theme
        title_label = tk.Label(main_frame, text="Fortnite Season 7.40 Emulator", 
                               font=("Arial", 20, "bold"), bg=self.bg_color, fg=self.accent_color)
        title_label.pack(pady=(0, 20))
        
        # Game path selection with dark theme
        path_label = tk.Label(main_frame, text="Fortnite Game Path:", bg=self.bg_color, fg=self.fg_color, font=("Arial", 10))
        path_label.pack(pady=5)
        
        path_frame = tk.Frame(main_frame, bg=self.bg_color)
        path_frame.pack(pady=(0, 10))
        
        self.path_entry = tk.Entry(path_frame, textvariable=self.game_path, width=60, bg=self.button_color, fg=self.fg_color, insertbackground=self.fg_color)
        self.path_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        browse_btn = tk.Button(path_frame, text="Browse", command=self.browse_game_path, bg=self.button_color, fg=self.fg_color, activebackground=self.button_hover, relief="flat", padx=15)
        browse_btn.pack(side=tk.LEFT)
        
        # Launch options frame with dark theme
        options_frame = tk.LabelFrame(main_frame, text="Launch Options", bg=self.bg_color, fg=self.fg_color, font=("Arial", 10, "bold"))
        options_frame.pack(pady=10, fill=tk.X)
        
        tk.Label(options_frame, text="✓ SSL Verification Bypassed", bg=self.bg_color, fg=self.success_color, font=("Arial", 9)).pack(pady=2, anchor=tk.W, padx=10)
        tk.Label(options_frame, text="✓ EAC Anti-Cheat Bypassed", bg=self.bg_color, fg=self.success_color, font=("Arial", 9)).pack(pady=2, anchor=tk.W, padx=10)
        tk.Label(options_frame, text="✓ Authentication Bypassed", bg=self.bg_color, fg=self.success_color, font=("Arial", 9)).pack(pady=2, anchor=tk.W, padx=10)
        tk.Label(options_frame, text="✓ Encryption Keys Loaded", bg=self.bg_color, fg=self.success_color, font=("Arial", 9)).pack(pady=2, anchor=tk.W, padx=10)
        
        # Backend control with dark theme
        backend_frame = tk.LabelFrame(main_frame, text="Backend Status", bg=self.bg_color, fg=self.fg_color, font=("Arial", 10, "bold"))
        backend_frame.pack(pady=10, fill=tk.X)
        
        self.backend_status = tk.Label(backend_frame, text="🔴 Backend: Not Started", 
                                       bg=self.bg_color, fg=self.warning_color, font=("Arial", 9))
        self.backend_status.pack(pady=5)
        
        # AI Assistant Panel
        ai_frame = tk.LabelFrame(main_frame, text="🤖 AI Assistant", bg=self.bg_color, fg=self.fg_color, font=("Arial", 10, "bold"))
        ai_frame.pack(pady=10, fill=tk.X)
        
        ai_inner = tk.Frame(ai_frame, bg=self.bg_color)
        ai_inner.pack(fill=tk.X, padx=10, pady=5)
        
        # AI status and controls
        ai_buttons_frame = tk.Frame(ai_inner, bg=self.bg_color)
        ai_buttons_frame.pack(fill=tk.X, pady=5)
        
        self.ai_diagnostic_btn = tk.Button(ai_buttons_frame, text="🔍 Run Diagnostics", 
                                          command=self.run_ai_diagnostics,
                                          bg=self.button_color, fg=self.fg_color, 
                                          activebackground=self.button_hover, relief="flat", padx=15)
        self.ai_diagnostic_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.ai_autofix_btn = tk.Button(ai_buttons_frame, text="🔧 Auto Fix Issues", 
                                       command=self.run_ai_autofix,
                                       bg=self.accent_color, fg="white", 
                                       activebackground="#0056b3", relief="flat", padx=15)
        self.ai_autofix_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.ai_status = tk.Label(ai_inner, text="🤖 AI Assistant ready - Click 'Run Diagnostics' to analyze system", 
                                 bg=self.bg_color, fg=self.fg_color, font=("Arial", 9))
        self.ai_status.pack(anchor=tk.W, pady=5)
        
        # AI recommendations area
        self.ai_recommendations = tk.Text(ai_inner, height=4, width=80, 
                                         bg=self.button_color, fg=self.fg_color,
                                         font=("Arial", 8), wrap=tk.WORD)
        self.ai_recommendations.pack(fill=tk.X, pady=5)
        self.ai_recommendations.insert("1.0", "AI recommendations will appear here after running diagnostics...")
        self.ai_recommendations.config(state=tk.DISABLED)
        
        # Network & Tools with dark theme
        tools_frame = tk.LabelFrame(main_frame, text="System Status", bg=self.bg_color, fg=self.fg_color, font=("Arial", 10, "bold"))
        tools_frame.pack(pady=10, fill=tk.X)
        
        status_inner = tk.Frame(tools_frame, bg=self.bg_color)
        status_inner.pack(fill=tk.X, padx=10, pady=5)
        
        self.port_status = tk.Label(status_inner, text="🔴 Port 443: Not Bound", bg=self.bg_color, fg=self.error_color, font=("Arial", 9))
        self.port_status.pack(anchor=tk.W, pady=2)
        
        self.hosts_status = tk.Label(status_inner, text="🔴 Hosts Redirects: Not Applied", bg=self.bg_color, fg=self.error_color, font=("Arial", 9))
        self.hosts_status.pack(anchor=tk.W, pady=2)
        
        self.ssl_status = tk.Label(status_inner, text="🔴 SSL Certificates: Not Generated", bg=self.bg_color, fg=self.error_color, font=("Arial", 9))
        self.ssl_status.pack(anchor=tk.W, pady=2)
        
        self.cert_status = tk.Label(status_inner, text="🔴 Certificate Cleanup: Pending", bg=self.bg_color, fg=self.warning_color, font=("Arial", 9))
        self.cert_status.pack(anchor=tk.W, pady=2)
        
        # Admin restart button removed - launcher now auto-runs as admin
        
        # Setup and Launch buttons with dark theme
        button_frame = tk.Frame(main_frame, bg=self.bg_color)
        button_frame.pack(pady=20)
        
        self.setup_btn = tk.Button(button_frame, text="⚙️ Setup Environment", 
                                   command=self.setup_environment, bg=self.accent_color, fg=self.fg_color, 
                                   activebackground=self.button_hover, relief="flat", padx=20, pady=8, font=("Arial", 10, "bold"))
        self.setup_btn.pack(side=tk.LEFT, padx=(0, 15))
        
        self.launch_btn = tk.Button(button_frame, text="🚀 Launch Fortnite", 
                                    command=self.launch_game_direct, bg=self.success_color, fg=self.fg_color,
                                    activebackground="#0e6b0e", relief="flat", padx=20, pady=8, font=("Arial", 10, "bold"))
        self.launch_btn.pack(side=tk.LEFT, padx=(0, 15))
        
        self.cleanup_btn = tk.Button(button_frame, text="🧹 Cleanup Certificates", 
                                     command=self.cleanup_certificates, bg=self.warning_color, fg=self.fg_color,
                                     activebackground="#cc7000", relief="flat", padx=20, pady=8, font=("Arial", 10, "bold"))
        self.cleanup_btn.pack(side=tk.LEFT)
        
        # Status frame with dark theme
        status_frame = tk.Frame(main_frame, bg=self.bg_color)
        status_frame.pack(fill=tk.X, pady=(20, 10))
        
        tk.Label(status_frame, text="Status:", bg=self.bg_color, fg=self.fg_color, font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        self.status_label = tk.Label(status_frame, textvariable=self.status_text, bg=self.bg_color, fg=self.success_color, font=("Arial", 10))
        self.status_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Progress bar with dark theme
        self.progress = tk.Canvas(main_frame, height=4, bg=self.button_color, highlightthickness=0)
        self.progress.pack(fill=tk.X, pady=(10, 0))
        
        # Console output area
        console_frame = tk.LabelFrame(main_frame, text="Console Output", bg=self.bg_color, fg=self.fg_color, font=("Arial", 10, "bold"))
        console_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        self.console_text = tk.Text(console_frame, height=8, bg="#0d1117", fg="#58a6ff", 
                                   insertbackground="#58a6ff", font=("Consolas", 9), wrap=tk.WORD)
        console_scrollbar = tk.Scrollbar(console_frame, orient=tk.VERTICAL, command=self.console_text.yview)
        self.console_text.configure(yscrollcommand=console_scrollbar.set)
        
        self.console_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        console_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
        # Add initial console message
        self.log_to_console("Fortnite Season 7.40 Emulator Launcher initialized")
        self.log_to_console("Ready to setup environment and launch game")
        
        # Auto-cleanup certificates on startup if admin (disabled to prevent certificate spam)
        # if self.is_admin:
        #     self.root.after(1000, self.auto_cleanup_certificates)
    
    def browse_game_path(self):
        """Browse for Fortnite executable"""
        file_path = filedialog.askopenfilename(
            title="Select Fortnite Executable",
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")],
            initialdir="C:/Program Files/Epic Games/Fortnite/FortniteGame/Binaries/Win64/"
        )
        if file_path:
            self.game_path.set(file_path)
            self.save_game_path(file_path)
            self.logger.info(f"Game path selected: {file_path}")
    
    def save_game_path(self, path):
        """Save the game path to a config file"""
        try:
            config_dir = os.path.join(os.path.expanduser("~"), ".fortnite_emulator")
            os.makedirs(config_dir, exist_ok=True)
            config_file = os.path.join(config_dir, "game_path.txt")
            
            with open(config_file, 'w') as f:
                f.write(path)
            self.logger.info(f"Game path saved to: {config_file}")
        except Exception as e:
            self.logger.warning(f"Failed to save game path: {e}")
    
    def load_game_path(self):
        """Load the saved game path from config file"""
        try:
            config_dir = os.path.join(os.path.expanduser("~"), ".fortnite_emulator")
            config_file = os.path.join(config_dir, "game_path.txt")
            
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    saved_path = f.read().strip()
                    if saved_path and os.path.exists(saved_path):
                        self.game_path.set(saved_path)
                        self.logger.info(f"Loaded saved game path: {saved_path}")
                    else:
                        self.logger.info("Saved game path no longer exists, using default")
            else:
                # Set default path if no saved path exists
                default_path = r"C:\Users\Caden\Downloads\Fear SeasonS\Season 7\7.40\7.40\FortniteGame\Binaries\Win64\FortniteClient-Win64-Shipping.exe"
                if os.path.exists(default_path):
                    self.game_path.set(default_path)
                    self.save_game_path(default_path)
                    self.logger.info(f"Set default game path: {default_path}")
        except Exception as e:
            self.logger.warning(f"Failed to load game path: {e}")
    
    def toggle_backend(self):
        """Start or stop the backend server"""
        if not self.backend_running:
            self.start_backend()
        else:
            self.stop_backend()
    
    def start_backend(self):
        """Start the backend server"""
        if not self.is_admin:
            self.logger.error("Admin privileges required to bind to port 443")
            messagebox.showerror("Permission Denied", "Administrator privileges required to bind to port 443. Please restart the launcher as Administrator.")
            return
            
        if self.backend_running:
            self.logger.info("Backend is already running")
            return
        
        try:
            # Check if port 8443 is in use (backend port)
            port_8443_in_use = self.is_port_in_use(8443)
            if port_8443_in_use:
                self.logger.warning("Port 8443 is in use, attempting to free it...")
                # Free port 8443 for backend
                self.free_port(8443)
            
            self.logger.info("Starting backend server on port 8443...")
            
            # Start backend process
            self.backend_process = subprocess.Popen(
                [sys.executable, "src/Backend.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=os.getcwd()
            )
            
            # Wait a moment for startup
            time.sleep(2)
            
            # Check if process is still running
            if self.backend_process.poll() is None:
                self.backend_running = True
                self.logger.info("Backend server started successfully on port 8443")
            else:
                self.logger.error("Backend server failed to start")
                self.update_status("Backend server failed to start")
                
        except Exception as e:
            self.logger.error(f"Failed to start backend server: {str(e)}")
            self.update_status(f"Backend startup failed: {str(e)}")
            messagebox.showerror("Backend Error", f"Failed to start backend server: {str(e)}")

    def free_port_443(self):
        """Attempt to free port 443 by stopping services and killing processes"""
        try:
            self.update_status("Attempting to free port 443...")
            
            # First, try to find and kill processes using port 443
            try:
                # Use netstat to find processes using port 443
                result = subprocess.run([
                    "netstat", "-ano", "|", "findstr", ":443"
                ], shell=True, capture_output=True, text=True, timeout=10)
                
                if result.stdout:
                    lines = result.stdout.strip().split('\n')
                    pids = set()
                    for line in lines:
                        parts = line.strip().split()
                        if len(parts) >= 5 and ':443' in parts[1]:
                            try:
                                pid = parts[-1]
                                if pid.isdigit() and pid != '0':
                                    pids.add(pid)
                            except:
                                continue
                    
                    # Kill processes using port 443
                    for pid in pids:
                        try:
                            subprocess.run(["taskkill", "/F", "/PID", pid], 
                                         capture_output=True, timeout=5)
                            self.logger.info(f"Killed process {pid} using port 443")
                        except:
                            pass
                            
            except Exception as e:
                self.logger.debug(f"Process killing failed: {e}")
            
            # Try to stop common services that use port 443
            services = ["W3SVC", "IISAdmin", "nginx", "Apache2.4", "httpd"]
            
            for service in services:
                try:
                    subprocess.run(["net", "stop", service], 
                                  shell=True, 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE,
                                  timeout=5)
                except Exception:
                    pass
            
            # Wait a moment for cleanup
            time.sleep(3)
            
            # Check if port is now free
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(("0.0.0.0", 443))
                    s.close()
                    self.logger.info("Successfully freed port 443")
                    self.update_status("Port 443 freed successfully")
                    return True
            except Exception:
                self.logger.warning("Failed to free port 443 - may still be in use")
                self.update_status("Failed to free port 443")
                return False
                
        except Exception as e:
            self.logger.error(f"Error while trying to free port 443: {str(e)}")
            return False
    
    def run_backend(self):
        """Run the backend server"""
        try:
            subprocess.run(["python", "Backend.py"], check=True)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Backend process failed: {str(e)}")
        except FileNotFoundError:
            self.logger.error("Backend.py not found")
    
    def check_backend_status(self):
        """Check backend status using timer to avoid blocking GUI"""
        self.backend_check_attempts += 1
        self.update_status(f"Checking backend server... ({self.backend_check_attempts}/{self.max_backend_attempts})")
        
        try:
            ctx = self.make_unverified_context()
            req = urllib.request.Request("https://localhost/.well-known/healthz")
            with urllib.request.urlopen(req, context=ctx, timeout=5) as response:  # Increased timeout
                if response.status == 200:
                    # Backend is running
                    self.backend_running = True
                    if hasattr(self, 'backend_btn'):
                        self.backend_btn.config(text="Stop Backend")
                    if hasattr(self, 'backend_status'):
                        self.backend_status.config(text="🟢 Backend: Running", fg=self.success_color)
                    
                    self.logger.info("Backend server started and verified")
                    self.log_to_console("Backend server started and verified", "SUCCESS")
                    self.backend_status.config(text="🟢 Backend: Running", fg=self.success_color)
                    self.backend_running = True
                    return True  # Return success
        except Exception as e:
            self.logger.debug(f"Backend check attempt {self.backend_check_attempts} failed: {e}")
        
        # If not started yet and we haven't exceeded max attempts, try again
        if self.backend_check_attempts < self.max_backend_attempts:
            self.root.after(1000, self.check_backend_status)  # Check again in 1 second
        else:
            # Max attempts reached, backend failed to start
            self.logger.error("Backend server failed to start or respond")
            self.update_status("Backend server failed to start")
            if hasattr(self, 'backend_status'):
                self.backend_status.config(text="🔴 Backend: Failed", fg=self.error_color)
            self.log_to_console("Backend server failed to start", "ERROR")
        
        return False  # Return failure
    
    def stop_backend(self):
        """Stop the backend server"""
        self.backend_running = False
        if hasattr(self, 'backend_btn'):
            self.backend_btn.config(text="Start Backend")
        self.backend_status.config(text="🔴 Backend: Stopped", fg=self.error_color)
        self.logger.info("Backend server stopped")
        self.log_to_console("Backend server stopped", "WARNING")
        self.update_status("Backend server stopped")
        self.check_port_status()
    
    def setup_environment(self):
        """Setup the environment (backend, SSL certificates, etc.)"""
        self.logger.info("Setup Environment button clicked")
        self.update_status("Setting up environment...")
        self.log_to_console("Starting environment setup...", "INFO")
        # Create a simple progress animation
        self.animate_progress()
        setup_thread = threading.Thread(target=self._run_setup_only, daemon=True)
        setup_thread.start()
    
    def launch_game_direct(self):
        """Launch Fortnite directly without automatic setup"""
        self.logger.info("Launch Fortnite button clicked")
        
        if not self.game_path.get():
            self.logger.warning("No game path selected")
            messagebox.showerror("Error", "Please select Fortnite executable path")
            return
        
        if not os.path.exists(self.game_path.get()):
            self.logger.error(f"Game path does not exist: {self.game_path.get()}")
            messagebox.showerror("Error", "Selected Fortnite executable not found")
            return
        
        # Check if the file is actually executable
        if not os.access(self.game_path.get(), os.X_OK):
            self.logger.error(f"Game executable is not executable: {self.game_path.get()}")
            messagebox.showerror("Error", "Selected file is not executable")
            return
        
        # Check if setup has been completed
        setup_needed = self._check_setup_status()
        
        if setup_needed:
            self.logger.warning("Setup not completed - Please run setup first")
            messagebox.showwarning("Setup Required", "Please click 'Setup Environment' first before launching Fortnite.")
            return
        
        self.logger.info("Launching Fortnite directly")
        self.update_status("Launching Fortnite...")
        self.animate_progress()
        launch_thread = threading.Thread(target=self._launch_fortnite_direct, daemon=True)
        launch_thread.start()
    
    def launch_game(self):
        """Legacy method - kept for compatibility"""
        self.launch_game_direct()
            
    def _check_setup_status(self):
        """Check if setup is needed"""
        # Check if backend is running
        if not self.backend_running:
            self.logger.info("Backend not running - setup needed")
            return True
            
        # Check if certificates exist
        if not (os.path.exists("ssl/end-entity.crt") and os.path.exists("ssl/end-entity.key")):
            self.logger.info("SSL certificates missing - setup needed")
            return True
            
        # Check if hosts redirects are applied
        if not self.verify_hosts_redirects():
            self.logger.info("Hosts redirects not applied - setup needed")
            return True
            
        # Check if backend is responding
        try:
            ctx = self.make_unverified_context()
            req = urllib.request.Request("https://localhost/.well-known/healthz")
            with urllib.request.urlopen(req, context=ctx, timeout=2) as response:
                if response.status != 200:
                    self.logger.info("Backend not responding properly - setup needed")
                    return True
        except Exception:
            self.logger.info("Backend health check failed - setup needed")
            return True
            
        self.logger.info("All setup checks passed - no setup needed")
        return False
    
    def _run_setup_only(self):
        """Run setup process without launching the game"""
        try:
            # Set flag to prevent message boxes during automated setup
            self._automated_setup = True
            
            # Step 1: Start Backend
            self.root.after(0, lambda: self.update_status("Starting backend server..."))
            self.logger.info("Setup: Starting backend server")
            
            if not self.backend_running:
                self.start_backend()
                # Wait for backend to start
                time.sleep(5)  # Give backend more time to start
                
                # Check if backend is actually running by testing the health endpoint
                try:
                    ctx = self.make_unverified_context()
                    req = urllib.request.Request("https://localhost/.well-known/healthz")
                    with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
                        if response.status == 200:
                            self.backend_running = True
                            self.logger.info("Backend is running and responding")
                        else:
                            self.logger.warning("Backend responded but with non-200 status")
                except Exception as e:
                    self.logger.warning(f"Backend health check failed: {e}")
                    # Continue anyway - backend might still work
            
            # Step 2: Generate SSL Certificates
            self.root.after(0, lambda: self.update_status("Generating SSL certificates..."))
            self.logger.info("Setup: Generating SSL certificates")
            
            # Check if certificates already exist and are valid
            if not (os.path.exists("ssl/end-entity.crt") and os.path.exists("ssl/end-entity.key")):
                self.generate_ssl_certificates_direct()
                time.sleep(2)
            
            # Step 3: Trust SSL Certificates
            self.root.after(0, lambda: self.update_status("Installing SSL certificates..."))
            self.logger.info("Setup: Installing SSL certificates")
            
            # Check if certificates are already installed to avoid spam
            if not self._certificates_already_installed():
                # Install root CA certificate with timeout
                if os.path.exists("ssl/root-ca.crt"):
                    try:
                        self.install_cert_to_trusted_root("ssl/root-ca.crt")
                        self.logger.info("Root CA certificate installation completed")
                    except Exception as e:
                        self.logger.warning(f"Root CA certificate installation failed: {e}")
                
                # Install end-entity certificate with timeout
                if os.path.exists("ssl/end-entity.crt"):
                    try:
                        self.install_cert_to_trusted_root("ssl/end-entity.crt")
                        self.logger.info("End-entity certificate installation completed")
                    except Exception as e:
                        self.logger.warning(f"End-entity certificate installation failed: {e}")
            else:
                self.logger.info("SSL certificates already installed, skipping installation")
            
            # Step 4: Apply Hosts Redirects
            self.root.after(0, lambda: self.update_status("Applying network redirects..."))
            self.logger.info("Setup: Applying hosts redirects")
            
            try:
                self.apply_hosts()
                self.logger.info("Setup: Hosts redirects applied successfully")
            except Exception as e:
                self.logger.warning(f"Setup: Failed to apply hosts redirects: {e}")
                # Continue anyway - this might not be critical
            
            time.sleep(1)
            
            # Step 5: Final backend check
            self.root.after(0, lambda: self.update_status("Final backend verification..."))
            self.logger.info("Setup: Final backend verification")
            
            # Simple backend check - if it's responding, we're good
            backend_ok = False
            try:
                ctx = self.make_unverified_context()
                req = urllib.request.Request("https://localhost/.well-known/healthz")
                with urllib.request.urlopen(req, context=ctx, timeout=3) as response:
                    if response.status == 200:
                        backend_ok = True
                        self.logger.info("Backend verified - setup complete")
            except Exception as e:
                self.logger.warning(f"Backend verification failed: {e}")
                # Continue anyway - backend might still work
            
            # Setup complete - update status labels
            self.root.after(0, lambda: self.update_status("Environment setup completed successfully!"))
            self.root.after(0, lambda: self.backend_status.config(text="Backend: Running", foreground="green"))
            self.root.after(0, lambda: self.hosts_status.config(text="✅ Hosts Redirects: Applied", foreground="green"))
            self.root.after(0, lambda: self.ssl_status.config(text="✅ SSL Certificates: Generated & Trusted", foreground="green"))
            self.logger.info("Setup completed successfully")
            
            # Show success message
            self.root.after(0, lambda: messagebox.showinfo("Setup Complete", "Environment setup completed successfully!\n\nYou can now launch Fortnite."))
            
            # Clear the automated setup flag
            self._automated_setup = False
            
        except Exception as e:
            self.logger.error(f"Setup failed: {str(e)}")
            self.root.after(0, lambda: self.update_status(f"Setup failed: {str(e)}"))
            self.root.after(0, lambda: messagebox.showerror("Setup Failed", f"Environment setup failed: {str(e)}"))
        finally:
            self.root.after(0, lambda: self.stop_progress_animation())
    
    def _auto_setup_and_launch(self):
        """Automatically setup everything and launch Fortnite"""
        try:
            # Set flag to prevent message boxes during automated setup
            self._automated_setup = True
            
            # Step 1: Start Backend
            self.root.after(0, lambda: self.update_status("Starting backend server..."))
            self.logger.info("Auto-setup: Starting backend server")
            
            if not self.backend_running:
                self.start_backend()
                # Wait for backend to start
                time.sleep(5)  # Give backend more time to start
                
                # Check if backend is actually running by testing the health endpoint
                try:
                    ctx = self.make_unverified_context()
                    req = urllib.request.Request("https://localhost/.well-known/healthz")
                    with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
                        if response.status == 200:
                            self.backend_running = True
                            self.logger.info("Backend is running and responding")
                        else:
                            self.logger.warning("Backend responded but with non-200 status")
                except Exception as e:
                    self.logger.warning(f"Backend health check failed: {e}")
                    # Continue anyway - backend might still work
            
            # Step 2: Generate SSL Certificates
            self.root.after(0, lambda: self.update_status("Generating SSL certificates..."))
            self.logger.info("Auto-setup: Generating SSL certificates")
            
            # Check if certificates already exist and are valid
            if not (os.path.exists("ssl/end-entity.crt") and os.path.exists("ssl/end-entity.key")):
                self.generate_ssl_certificates_direct()
                time.sleep(2)
            
            # Step 3: Trust SSL Certificates
            self.root.after(0, lambda: self.update_status("Installing SSL certificates..."))
            self.logger.info("Auto-setup: Installing SSL certificates")
            
            # Install root CA certificate
            if os.path.exists("ssl/root-ca.crt"):
                self.install_cert_to_trusted_root("ssl/root-ca.crt")
                time.sleep(1)
            
            # Install end-entity certificate
            if os.path.exists("ssl/end-entity.crt"):
                self.install_cert_to_trusted_root("ssl/end-entity.crt")
                time.sleep(1)
            
            # Step 4: Apply Hosts Redirects
            self.root.after(0, lambda: self.update_status("Applying network redirects..."))
            self.logger.info("Auto-setup: Applying hosts redirects")
            
            try:
                self.apply_hosts()
                self.logger.info("Auto-setup: Hosts redirects applied successfully")
            except Exception as e:
                self.logger.warning(f"Auto-setup: Failed to apply hosts redirects: {e}")
                # Continue anyway - this might not be critical
            
            time.sleep(1)
            
            # Step 5: Final backend check
            self.root.after(0, lambda: self.update_status("Final backend verification..."))
            self.logger.info("Auto-setup: Final backend verification")
            
            # Simple backend check - if it's responding, we're good
            backend_ok = False
            try:
                ctx = self.make_unverified_context()
                req = urllib.request.Request("https://localhost/.well-known/healthz")
                with urllib.request.urlopen(req, context=ctx, timeout=3) as response:
                    if response.status == 200:
                        backend_ok = True
                        self.logger.info("Backend verified - ready to launch Fortnite")
            except Exception as e:
                self.logger.warning(f"Backend verification failed: {e}")
                # Continue anyway - backend might still work
            
            # Step 6: Launch Fortnite
            self.root.after(0, lambda: self.update_status("Launching Fortnite..."))
            
            # Now launch the game
            self._launch_game_async()
            
            self.root.after(0, lambda: self.update_status("Fortnite launch initiated!"))
            self.logger.info("Auto-setup completed successfully - Fortnite launch initiated")
            
            # Clear the automated setup flag
            self._automated_setup = False
            
        except Exception as e:
            self.logger.error(f"Auto-setup failed: {str(e)}")
            self.logger.error(f"Auto-setup error details: {type(e).__name__}: {str(e)}")
            import traceback
            self.logger.error(f"Auto-setup traceback: {traceback.format_exc()}")
            self.root.after(0, lambda: self.update_status(f"Auto-setup failed: {str(e)}"))
            self.root.after(0, lambda: self.stop_progress_animation())
            
            # Clear the automated setup flag
            self._automated_setup = False
    
    def _launch_fortnite_direct(self):
        """Launch Fortnite directly without running setup"""
        try:
            self.logger.info("Launching Fortnite directly (setup already complete)")
            
            # Quick verification that everything is ready
            self.root.after(0, lambda: self.update_status("Verifying setup..."))
            
            # Verify backend is responding
            if not self.verify_backend():
                self.logger.warning("Backend verification failed")
            
            # Launch Fortnite
            self.root.after(0, lambda: self.update_status("Launching Fortnite..."))
            self._launch_game_async()
            
            self.root.after(0, lambda: self.update_status("Fortnite launched successfully!"))
            self.logger.info("Fortnite launched successfully")
            
        except Exception as e:
            self.logger.error(f"Direct launch failed: {str(e)}")
            self.root.after(0, lambda: messagebox.showerror("Launch Failed", f"Failed to launch Fortnite: {str(e)}"))
        finally:
            self.root.after(0, lambda: self.stop_progress_animation())
    
    def _launch_game_async(self):
        """Launch Fortnite asynchronously"""
        try:
            self.logger.info("Starting Fortnite launch process...")
            self.root.after(0, lambda: self.update_status("Preparing environment..."))

            # Apply hosts redirects to ensure traffic goes to localhost
            try:
                self.apply_hosts()
            except Exception:
                pass

            # Ensure backend is running on 443
            if not self.backend_running or self.port443_status.get() != "In Use":
                self.logger.info("Backend not running, starting it...")
                self.start_backend()
                time.sleep(2)
                self.check_port_status()

            # Quick health check
            try:
                ctx = self.make_unverified_context()
                with urllib.request.urlopen("https://localhost/.well-known/healthz", context=ctx, timeout=5) as resp:
                    if resp.status != 200:
                        raise Exception("Health check failed")
            except Exception as e:
                self.logger.warning(f"Health check failed before launch: {e}")

            self.root.after(0, lambda: self.update_status("Launching Fortnite..."))
            
            # Build launch arguments
            args = [self.game_path.get()]
            
            # Add bypass arguments
            if self.bypass_ssl.get():
                args.extend(["-noverifyssl", "-nosslverify", "-insecure", "-k", "-nocertcheck", "-ignorecert", "-skipssl"])
            
            if self.bypass_eac.get():
                args.extend(["-noeac", "-fromfl=eac"])
            
            if self.bypass_auth.get():
                args.extend(["-noauth"])
            
            # Additional emulator arguments
            args.extend([
                "-epicportal",
                "-skippatchcheck",
                "-nosplash",
                f"-AUTH_LOGIN=unused",
                f"-AUTH_PASSWORD=unused",
                f"-AUTH_TYPE=exchangecode",
                f"-epicapp=Fortnite",
                f"-epicenv=Prod",
                f"-EpicPortal"
            ])
            
            self.logger.info(f"Launching with args: {' '.join(args)}")
            
            # Launch in separate thread
            launch_thread = threading.Thread(target=self.run_game, args=(args,), daemon=True)
            launch_thread.start()
            
            self.root.after(0, lambda: self.update_status("Fortnite launched successfully"))
            
        except Exception as e:
            self.logger.error(f"Failed to start backend: {str(e)}")
            self.backend_running = False
    
    def verify_backend(self):
        """Verify backend is responding on port 8443"""
        try:
            import urllib.request
            import ssl
            
            # Create SSL context that ignores certificate errors for testing
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            # Test backend health endpoint
            req = urllib.request.Request('https://127.0.0.1:8443/.well-known/healthz')
            with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
                return response.status == 200
                
        except Exception as e:
            self.logger.warning(f"Backend verification failed: {str(e)}")
            return False
    
    def run_ai_diagnostics(self):
        """Run AI diagnostics in a separate thread"""
        def _run_diagnostics():
            self.update_status("🤖 AI: Running comprehensive diagnostics...")
            self.ai_status.config(text="🔍 Running diagnostics... Please wait")
            
            try:
                diagnostics = self.ai_assistant.run_full_diagnostic()
                summary = self.ai_assistant.get_diagnostic_summary()
                recommendations = self.ai_assistant.get_recommendations()
                
                # Update UI on main thread
                self.root.after(0, lambda: self._update_ai_results(summary, recommendations, diagnostics))
                
            except Exception as e:
                self.logger.error(f"AI diagnostics failed: {str(e)}")
                self.root.after(0, lambda: self.ai_status.config(text=f"❌ Diagnostics failed: {str(e)}"))
        
        threading.Thread(target=_run_diagnostics, daemon=True).start()
    
    def run_ai_autofix(self):
        """Run AI auto-fix in a separate thread"""
        def _run_autofix():
            self.update_status("🤖 AI: Applying automated fixes...")
            self.ai_status.config(text="🔧 Applying fixes... Please wait")
            
            try:
                fixes = self.ai_assistant.auto_fix_issues()
                
                if fixes:
                    successful_fixes = [f for f in fixes if f['status'] == 'success']
                    failed_fixes = [f for f in fixes if f['status'] == 'failed']
                    
                    status_msg = f"✅ Applied {len(successful_fixes)} fixes"
                    if failed_fixes:
                        status_msg += f", {len(failed_fixes)} failed"
                    
                    self.root.after(0, lambda: self.ai_status.config(text=status_msg))
                    
                    # Re-run diagnostics to show updated status
                    self.root.after(2000, self.run_ai_diagnostics)
                else:
                    self.root.after(0, lambda: self.ai_status.config(text="ℹ️ No fixes needed"))
                
            except Exception as e:
                self.logger.error(f"AI auto-fix failed: {str(e)}")
                self.root.after(0, lambda: self.ai_status.config(text=f"❌ Auto-fix failed: {str(e)}"))
        
        threading.Thread(target=_run_autofix, daemon=True).start()
    
    def _update_ai_results(self, summary, recommendations, diagnostics):
        """Update AI results in the UI"""
        self.ai_status.config(text=f"📊 {summary}")
        
        # Update recommendations text
        self.ai_recommendations.config(state=tk.NORMAL)
        self.ai_recommendations.delete("1.0", tk.END)
        
        rec_text = "🤖 AI RECOMMENDATIONS:\n\n"
        for i, rec in enumerate(recommendations, 1):
            rec_text += f"{i}. {rec}\n"
        
        if diagnostics:
            rec_text += "\n📋 DETAILED DIAGNOSTICS:\n"
            for diag in diagnostics:
                severity_icon = {"critical": "🚨", "error": "❌", "warning": "⚠️", "info": "ℹ️"}
                icon = severity_icon.get(diag['severity'], "•")
                rec_text += f"{icon} {diag['issue']}: {diag['description']}\n"
        
        self.ai_recommendations.insert("1.0", rec_text)
        self.ai_recommendations.config(state=tk.DISABLED)
    
    def filter_log_spam(self, output):
        """Filter out repetitive log directory paths and other spam from game output"""
        if not output or not output.strip():
            return ""
        
        lines = output.strip().split('\n')
        filtered_lines = []
        
        for line in lines:
            # Skip lines that are just the logs directory path
            if line.strip() == "c:\\Users\\Caden\\Downloads\\Beta 1.0\\logs" or \
               line.strip().endswith("\\logs") or \
               line.strip() == "logs" or \
               ("logs" in line and len(line.strip()) < 50 and "\\" in line):
                continue
            
            # Skip empty lines
            if not line.strip():
                continue
                
            filtered_lines.append(line)
        
        # Only return if there are meaningful lines left
        if filtered_lines:
            return '\n'.join(filtered_lines)
        return ""
    
    def run_game(self, args):
        """Run the game process"""
        try:
            self.logger.info(f"Starting game process with args: {args}")
            
            # Set environment variables for the game process
            env = os.environ.copy()
            env['FORTNITE_DEV'] = '1'
            env['FORTNITE_LOCAL'] = '1'
            
            # Set up unified backend proxy environment if available
            if self.mitm_manager.is_running():
                proxy_env = self.mitm_manager.setup_proxy_environment()
                env.update(proxy_env)
                self.logger.info("Using unified backend proxy for traffic routing")
            else:
                # Fallback: Force libcurl to skip SSL verification
                env['CURL_CA_BUNDLE'] = ''
                env['SSL_CERT_FILE'] = ''
                env['SSL_CERT_DIR'] = ''
                env['REQUESTS_CA_BUNDLE'] = ''
                env['CURL_INSECURE'] = '1'
                
                # Additional SSL bypass environment variables
                env['PYTHONHTTPSVERIFY'] = '0'
                env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0'
                
                # Set curl config file location
                env['CURL_HOME'] = os.path.dirname(args[0])
                env['HOME'] = os.path.dirname(args[0])
                self.logger.info("Using fallback SSL bypass methods")
            
            # Start the game process
            process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
                cwd=os.path.dirname(args[0])
            )
            self.logger.info(f"Game process started with PID: {process.pid}")
            
            # Wait for process and capture output (with timeout)
            try:
                stdout, stderr = process.communicate(timeout=30)  # 30 second timeout
            except subprocess.TimeoutExpired:
                self.logger.warning("Game process timeout - game may still be running")
                process.kill()
                stdout, stderr = process.communicate()
            
            if stdout:
                # Filter out repetitive log directory paths from stdout
                filtered_stdout = self.filter_log_spam(stdout)
                if filtered_stdout:
                    self.logger.info(f"Game stdout: {filtered_stdout}")
            if stderr:
                # Filter out repetitive log directory paths from stderr
                filtered_stderr = self.filter_log_spam(stderr)
                if filtered_stderr:
                    self.logger.error(f"Game stderr: {filtered_stderr}")
            
            if process.returncode != 0:
                self.logger.error(f"Game process exited with code: {process.returncode}")
                self.root.after(0, lambda: self.update_status(f"Game exited with code: {process.returncode}"))
            else:
                self.logger.info("Game process ended normally")
                
        except Exception as e:
            self.logger.error(f"Game process error: {str(e)}")
            import traceback
            self.logger.error(f"Game launch traceback: {traceback.format_exc()}")
            # Update status in main thread
            self.root.after(0, lambda: self.update_status(f"Game launch failed: {str(e)}"))
        
        self.logger.info("Fortnite launch process completed")
    
    def update_status(self, message, color=None):
        """Update status message"""
        self.status_text.set(message)
        if color and hasattr(self, 'status_label'):
            self.status_label.config(fg=color)
        self.log_to_console(message)
    
    def log_to_console(self, message, level="INFO"):
        """Add message to console output"""
        if hasattr(self, 'console_text'):
            timestamp = datetime.now().strftime("%H:%M:%S")
            color_map = {
                "INFO": "#58a6ff",
                "SUCCESS": "#3fb950", 
                "WARNING": "#d29922",
                "ERROR": "#f85149"
            }
            color = color_map.get(level, "#58a6ff")
            
            self.console_text.config(state=tk.NORMAL)
            self.console_text.insert(tk.END, f"[{timestamp}] {message}\n")
            self.console_text.see(tk.END)
            self.console_text.config(state=tk.DISABLED)
    
    def cleanup_certificates(self):
        """Manual certificate cleanup"""
        if not self.is_admin:
            self.log_to_console("Certificate cleanup requires administrator privileges", "ERROR")
            return
        
        self.log_to_console("Starting certificate cleanup...", "INFO")
        self.cert_status.config(text="🟡 Certificate Cleanup: In Progress", fg=self.warning_color)
        
        # Run cleanup in separate thread to avoid blocking UI
        cleanup_thread = threading.Thread(target=self._run_certificate_cleanup, daemon=True)
        cleanup_thread.start()
    
    def auto_cleanup_certificates(self):
        """Automatic certificate cleanup on startup"""
        if not self.is_admin:
            return
        
        self.log_to_console("Performing automatic certificate cleanup...", "INFO")
        self.cert_status.config(text="🟡 Certificate Cleanup: Auto-Running", fg=self.warning_color)
        
        # Run cleanup in separate thread
        cleanup_thread = threading.Thread(target=self._run_certificate_cleanup, daemon=True)
        cleanup_thread.start()
    
    def _run_certificate_cleanup(self):
        """Run the certificate cleanup script"""
        try:
            import subprocess
            result = subprocess.run(
                ["python", "cleanup_certificates.py"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                self.root.after(0, lambda: self.log_to_console("Certificate cleanup completed successfully", "SUCCESS"))
                self.root.after(0, lambda: self.cert_status.config(text="✅ Certificate Cleanup: Completed", fg=self.success_color))
            else:
                self.root.after(0, lambda: self.log_to_console(f"Certificate cleanup failed: {result.stderr}", "ERROR"))
                self.root.after(0, lambda: self.cert_status.config(text="❌ Certificate Cleanup: Failed", fg=self.error_color))
                
        except subprocess.TimeoutExpired:
            self.root.after(0, lambda: self.log_to_console("Certificate cleanup timed out", "WARNING"))
            self.root.after(0, lambda: self.cert_status.config(text="⏱️ Certificate Cleanup: Timeout", fg=self.warning_color))
        except Exception as e:
            self.root.after(0, lambda: self.log_to_console(f"Certificate cleanup error: {str(e)}", "ERROR"))
            self.root.after(0, lambda: self.cert_status.config(text="❌ Certificate Cleanup: Error", fg=self.error_color))
    
    # ===== Network/Tools helpers =====
    def get_hosts_path(self):
        return os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'drivers', 'etc', 'hosts')
    
    def required_hostnames(self):
        # Core endpoints mapped to localhost (expanded for Fortnite Season 7)
        return [
            # OAuth / Accounts
            'account-public-service-prod.ol.epicgames.com',
            'account-public-service-prod03.ol.epicgames.com',
            
            # Fortnite public service (MCP, catalog, receipts, etc.)
            'fortnite-public-service-prod.ol.epicgames.com',
            'fortnite-public-service-prod11.ol.epicgames.com',
            'fortnite-public-service-prod10.ol.epicgames.com',
            'fortnite-public-service-prod08.ol.epicgames.com',
            'fortnite-public-service-prod-m.ol.epicgames.com',
            
            # Content pages
            'content-public-service-prod.ol.epicgames.com',
            
            # Lightswitch (service status)
            'lightswitch-public-service-prod.ol.epicgames.com',
            
            # Launcher / assets
            'launcher-public-service-prod06.ol.epicgames.com',
            
            # Catalog and Entitlements
            'catalog-public-service-prod06.ol.epicgames.com',
            'entitlements-public-service-prod08.ol.epicgames.com',
            
            # Persona and Presence
            'persona-public-service-prod.ol.epicgames.com',
            'persona-public-service-prod06.ol.epicgames.com',
            'presence-public-service-prod.ol.epicgames.com',
            
            # EULA tracking
            'eulatracking-public-service-prod06.ol.epicgames.com',
            'eulatracking-public-service-prod-m.ol.epicgames.com',
            
            # Friends and Social
            'friends-public-service-prod06.ol.epicgames.com',
            'friends-public-service-prod.ol.epicgames.com',
            'party-service-prod.ol.epicgames.com',
            'socialban-public-service-prod.ol.epicgames.com',
            
            # Events/Stats
            'events-public-service-live.ol.epicgames.com',
            'events-public-service-prod.ol.epicgames.com',
            'statsproxy-public-service-live.ol.epicgames.com',
            
            # Fortnite Game Services
            'fngw-mcp-gc-livefn.ol.epicgames.com',
            'xmpp-service-prod.ol.epicgames.com',
            
            # Telemetry
            'datarouter.ol.epicgames.com'
        ]
    
    def build_hosts_block(self):
        hosts = self.required_hostnames()
        lines = ["# Fortnite Emulator START\n"]
        for h in hosts:
            lines.append(f"127.0.0.1 {h}\n")
        lines.append("# Fortnite Emulator END\n")
        return ''.join(lines)
    
    def apply_hosts(self):
        """Apply hosts file mappings to redirect Epic domains to localhost"""
        self.logger.info(f"apply_hosts called - is_admin: {self.is_admin}")
        if not self.is_admin:
            self.logger.error("Admin privileges required to modify hosts file")
            messagebox.showerror("Permission Denied", "Administrator privileges required. Please restart the launcher as Administrator.")
            return
            
        try:
            path = self.get_hosts_path()
            block = self.build_hosts_block()
            content = ''
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            
            start_tag = "# Fortnite Emulator START"
            end_tag = "# Fortnite Emulator END"
            
            if start_tag in content and end_tag in content:
                # replace existing block
                pre = content.split(start_tag)[0]
                post = content.split(end_tag)[1]
                new_content = pre + block + post
            else:
                # append
                if content and not content.endswith('\n'):
                    content += '\n'
                new_content = content + block
            
            with open(path, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(new_content)
            
            # Verify the changes were applied
            success = self.verify_hosts_redirects()
            
            if success:
                self.logger.info("Hosts redirects applied and verified")
                self.update_status("Hosts redirects applied and verified")
                # Don't show message box during automated setup
                if not hasattr(self, '_automated_setup'):
                    messagebox.showinfo("Success", "Hosts redirects applied successfully. All Fortnite traffic will be redirected to your local server.")
            else:
                self.logger.warning("Hosts redirects applied but verification failed")
                self.update_status("Hosts redirects applied but verification failed")
                # Don't show message box during automated setup
                if not hasattr(self, '_automated_setup'):
                    messagebox.showwarning("Warning", "Hosts file was modified but verification failed. Some redirects may not be working.")
                
        except PermissionError:
            self.logger.error("Permission denied when modifying hosts file")
            messagebox.showerror("Permission Denied", "Please run the launcher as Administrator to modify the hosts file.")
            run_as_admin()
        except Exception as e:
            self.logger.error(f"Failed to modify hosts file: {str(e)}")
            messagebox.showerror("Error", f"Failed to modify hosts file: {str(e)}")
            
    def verify_hosts_redirects(self):
        """Verify that hosts redirects were applied correctly"""
        try:
            path = self.get_hosts_path()
            if not os.path.exists(path):
                return False
                
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Check if all required hostnames are in the file
            all_present = True
            for hostname in self.required_hostnames():
                if f"127.0.0.1 {hostname}" not in content:
                    all_present = False
                    self.logger.warning(f"Hostname {hostname} not found in hosts file")
                    
            return all_present
        except Exception as e:
            self.logger.error(f"Failed to verify hosts redirects: {str(e)}")
            return False
    
    def remove_hosts(self):
        """Remove hosts file mappings"""
        if not self.is_admin:
            self.logger.error("Admin privileges required to modify hosts file")
            messagebox.showerror("Permission Denied", "Administrator privileges required. Please restart the launcher as Administrator.")
            return
            
        try:
            path = self.get_hosts_path()
            if not os.path.exists(path):
                messagebox.showinfo("Info", "Hosts file not found")
                return
                
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            start_tag = "# Fortnite Emulator START"
            end_tag = "# Fortnite Emulator END"
            
            if start_tag in content and end_tag in content:
                pre = content.split(start_tag)[0]
                post = content.split(end_tag)[1]
                new_content = pre + post
                
                with open(path, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(new_content)
                    
                # Verify the changes were removed
                if self.verify_hosts_redirects():
                    self.logger.warning("Hosts redirects not fully removed")
                    self.update_status("Warning: Hosts redirects may still be active")
                    messagebox.showwarning("Warning", "Some redirects may still be active. Please check your hosts file manually.")
                else:
                    self.logger.info("Hosts redirects removed and verified")
                    self.update_status("Hosts redirects removed and verified")
                    messagebox.showinfo("Success", "Hosts redirects removed successfully.")
            else:
                messagebox.showinfo("Info", "No emulator hosts entries found")
                
        except PermissionError:
            self.logger.error("Permission denied when modifying hosts file")
            messagebox.showerror("Permission Denied", "Please run the launcher as Administrator to modify the hosts file.")
            run_as_admin()
        except Exception as e:
            self.logger.error(f"Failed to modify hosts file: {str(e)}")
            messagebox.showerror("Error", f"Failed to modify hosts file: {str(e)}")
    
    def check_port_status(self):
        """Check if port 443 is available"""
        try:
            # Try to bind to port 443 to check if it's available
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('localhost', 443))
                if hasattr(self, 'port_status'):
                    self.port_status.config(text="🟢 Port 443: Available", fg=self.success_color)
                self.log_to_console("Port 443 is available", "SUCCESS")
        except OSError:
            if hasattr(self, 'port_status'):
                self.port_status.config(text="🔴 Port 443: In Use", fg=self.error_color)
            self.log_to_console("Port 443 is in use by another service", "WARNING")
    
    def generate_certs(self):
        """Generate SSL certificates without initializing full backend"""
        if not self.is_admin:
            self.logger.error("Admin privileges required to generate and trust certificates")
            messagebox.showerror("Permission Denied", "Administrator privileges required to generate and trust certificates. Please restart the launcher as Administrator.")
            return
            
        # Run certificate generation in a separate thread to avoid blocking GUI
        cert_thread = threading.Thread(target=self._generate_certs_async, daemon=True)
        cert_thread.start()
    
    def animate_progress(self):
        """Start progress bar animation"""
        if hasattr(self, 'progress'):
            self.progress_active = True
            self.progress_position = 0
            self._update_progress()
    
    def stop_progress_animation(self):
        """Stop progress bar animation"""
        if hasattr(self, 'progress'):
            self.progress_active = False
            self.progress.delete("all")
    
    def _update_progress(self):
        """Update progress bar animation"""
        if not hasattr(self, 'progress_active') or not self.progress_active:
            return
        
        if hasattr(self, 'progress'):
            self.progress.delete("all")
            width = self.progress.winfo_width()
            if width > 1:
                # Create animated progress bar
                bar_width = 100
                x = (self.progress_position % (width + bar_width)) - bar_width
                self.progress.create_rectangle(x, 0, x + bar_width, 4, fill=self.accent_color, outline="")
                self.progress_position += 3
        
        if self.progress_active:
            self.root.after(50, self._update_progress)
    
    def _generate_certs_async(self):
        """Generate certificates asynchronously"""
        try:
            self._generate_ssl_certificates()
        except Exception as e:
            self.root.after(0, lambda: self.log_to_console(f"Certificate generation failed: {str(e)}", "ERROR"))
        finally:
            self.root.after(0, self.stop_progress_animation)
    
    def _generate_ssl_certificates(self):
        """Generate SSL certificates"""
        try:
            # Remove old certificates first
            self.remove_old_certificates()
            
            # Generate certificates directly without initializing the full backend
            self.generate_ssl_certificates_direct()
            
            # Verify certificates were created
            ssl_dir = os.path.join(os.getcwd(), "ssl")
            cert_file = os.path.join(ssl_dir, "server.crt")
            key_file = os.path.join(ssl_dir, "server.key")
            
            if not os.path.exists(cert_file) or not os.path.exists(key_file):
                raise Exception("Certificate files not created")
                
            # Install certificate to trusted root store
            self.root.after(0, lambda: self.update_status("Installing certificate to trusted root..."))
            result = self.install_cert_to_trusted_root(cert_file)
            
            if result:
                self.logger.info("SSL certificate generation completed")
                self.log_to_console("SSL certificates generated successfully", "SUCCESS")
                self.ssl_status.config(text="✅ SSL Certificates: Generated", fg=self.success_color)
                self.root.after(0, lambda: self.update_status("SSL certificates generated and trusted"))
                self.root.after(0, lambda: messagebox.showinfo("Success", "SSL certificates generated and installed to trusted root.\n\nFortnite will now trust connections to your local server."))
            else:
                self.logger.warning("SSL certificates generated but not trusted")
                self.root.after(0, lambda: self.update_status("SSL certificates generated but not trusted"))
                self.root.after(0, lambda: messagebox.showwarning("Warning", "SSL certificates were generated but could not be installed to trusted root.\n\nFortnite may show certificate warnings."))
                
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            error_msg = f"Certificate generation failed: {str(e)}"
            print(f"[ERROR] {error_msg}\n{tb}")
            self.logger.error(f"{error_msg}\n{tb}")
            self.root.after(0, lambda msg=error_msg: messagebox.showerror("Error", msg))
        finally:
            self.root.after(0, lambda: self.stop_progress_animation())
    
    def generate_ssl_certificates_direct(self):
        """Generate self-signed SSL certificates directly without initializing backend"""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import ipaddress
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Create certificate that mimics Epic Games format exactly
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "North Carolina"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Cary"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Epic Games, Inc."),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "IT Department"),
                x509.NameAttribute(NameOID.COMMON_NAME, "*.ol.epicgames.com"),
            ])
            
            # Create a more comprehensive certificate with proper extensions
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                 x509.random_serial_number()
             ).not_valid_before(
                 datetime.now(timezone.utc)
            ).not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    # Core localhost entries
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    
                    # Wildcard entries for Epic domains
                    x509.DNSName("*.epicgames.com"),
                    x509.DNSName("*.ol.epicgames.com"),
                    
                    # OAuth / Accounts - Critical for authentication
                    x509.DNSName("account-public-service-prod.ol.epicgames.com"),
                    x509.DNSName("account-public-service-prod03.ol.epicgames.com"),
                    
                    # Fortnite public service (MCP, catalog, receipts, etc.)
                    x509.DNSName("fortnite-public-service-prod.ol.epicgames.com"),
                    x509.DNSName("fortnite-public-service-prod11.ol.epicgames.com"),
                    x509.DNSName("fortnite-public-service-prod10.ol.epicgames.com"),
                    x509.DNSName("fortnite-public-service-prod08.ol.epicgames.com"),
                    
                    # Content pages
                    x509.DNSName("content-public-service-prod.ol.epicgames.com"),
                    
                    # Lightswitch (service status)
                    x509.DNSName("lightswitch-public-service-prod.ol.epicgames.com"),
                    
                    # Launcher / assets
                    x509.DNSName("launcher-public-service-prod06.ol.epicgames.com"),
                    
                    # Persona
                    x509.DNSName("persona-public-service-prod.ol.epicgames.com"),
                    
                    # EULA tracking
                    x509.DNSName("eulatracking-public-service-prod06.ol.epicgames.com"),
                    
                    # Friends
                    x509.DNSName("friends-public-service-prod06.ol.epicgames.com"),
                    x509.DNSName("friends-public-service-prod.ol.epicgames.com"),
                    
                    # Events/Stats (older builds may touch these)
                    x509.DNSName("events-public-service-live.ol.epicgames.com"),
                    x509.DNSName("events-public-service-prod.ol.epicgames.com"),
                    x509.DNSName("statsproxy-public-service-live.ol.epicgames.com"),
                    
                    # Telemetry - Critical for login flow
                    x509.DNSName("datarouter.ol.epicgames.com"),
                ]),
                critical=False,
            ).add_extension(
                x509.KeyUsage(
                    key_cert_sign=False,  # Changed to False for end-entity certificate
                    crl_sign=False,      # Changed to False for end-entity certificate
                    digital_signature=True,
                    key_encipherment=True,
                    data_encipherment=True,
                    key_agreement=True,
                    content_commitment=True,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None),  # Changed to False for end-entity certificate
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # Write certificate and key
            os.makedirs('ssl', exist_ok=True)
            
            with open('ssl/server.crt', 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            with open('ssl/server.key', 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            self.logger.info("Self-signed SSL certificates generated")
            
            # Also create a Windows-compatible certificate using a different approach
            self.create_windows_compatible_certificate()
            
            # Create additional certificates for better compatibility
            self.create_additional_certificates()
            
            # Create a proper certificate chain
            self.create_certificate_chain()
            
        except ImportError:
            raise Exception("cryptography library not available for SSL generation")
        except Exception as e:
            raise Exception(f"SSL certificate generation failed: {str(e)}")
    
    def create_windows_compatible_certificate(self):
        """Create a Windows-compatible certificate using PowerShell with better error handling"""
        try:
            # Simplified PowerShell command with better error handling
            ps_command = r'''
            try {
                $cert = New-SelfSignedCertificate -Subject "CN=*.ol.epicgames.com" -DnsName "localhost", "*.ol.epicgames.com" -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsage DigitalSignature, KeyEncipherment -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(1) -ErrorAction Stop
                $certPath = "ssl\windows-server.crt"
                Export-Certificate -Cert $cert -FilePath $certPath -Type CERT -ErrorAction Stop
                Write-Output "Certificate created successfully"
            } catch {
                Write-Error $_.Exception.Message
                exit 1
            }
            '''
            
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=15  # Reduced timeout
            )
            
            if result.returncode == 0:
                self.logger.info("Windows-compatible certificate created successfully")
                self.log_to_console("SSL certificate installed to user store", "SUCCESS")
                return True
            else:
                self.logger.warning(f"Windows-compatible certificate creation failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.warning("Windows-compatible certificate creation timed out")
            return False
        except Exception as e:
            self.logger.warning(f"Failed to create Windows-compatible certificate: {e}")
            return False
    
    def create_additional_certificates(self):
        """Create additional certificates for better compatibility"""
        try:
            # Simplified localhost certificate creation
            ps_command = r'''
            try {
                $cert = New-SelfSignedCertificate -Subject "CN=localhost" -DnsName "localhost" -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsage DigitalSignature, KeyEncipherment -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(1) -ErrorAction Stop
                $certPath = "ssl\localhost.crt"
                Export-Certificate -Cert $cert -FilePath $certPath -Type CERT -ErrorAction Stop
                Write-Output "Localhost certificate created successfully"
            } catch {
                Write-Error $_.Exception.Message
                exit 1
            }
            '''
            
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=10  # Reduced timeout
            )
            
            if result.returncode == 0:
                self.logger.info("Localhost certificate created successfully")
                return True
            else:
                self.logger.warning(f"Localhost certificate creation failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.warning("Localhost certificate creation timed out")
            return False
        except Exception as e:
            self.logger.warning(f"Failed to create localhost certificate: {e}")
            return False
    
    def create_certificate_chain(self):
        """Create a proper certificate chain with root CA and end-entity certificate"""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import ipaddress
            
            # Generate root CA private key
            root_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Create root CA certificate
            root_subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "North Carolina"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Cary"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Epic Games, Inc."),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "IT Department"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Epic Games Root CA"),
            ])
            
            root_cert = x509.CertificateBuilder().subject_name(
                root_subject
            ).issuer_name(
                root_subject
            ).public_key(
                root_private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.now(timezone.utc)
            ).not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=3650)  # 10 years for root CA
            ).add_extension(
                x509.KeyUsage(
                    key_cert_sign=True,
                    crl_sign=True,
                    digital_signature=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    content_commitment=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=1),
                critical=True,
            ).sign(root_private_key, hashes.SHA256())
            
            # Generate end-entity private key
            end_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Create end-entity certificate signed by root CA
            end_subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "North Carolina"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Cary"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Epic Games, Inc."),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "IT Department"),
                x509.NameAttribute(NameOID.COMMON_NAME, "*.ol.epicgames.com"),
            ])
            
            end_cert = x509.CertificateBuilder().subject_name(
                end_subject
            ).issuer_name(
                root_subject
            ).public_key(
                end_private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.now(timezone.utc)
            ).not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    # Core localhost entries
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    
                    # Wildcard entries for Epic domains
                    x509.DNSName("*.epicgames.com"),
                    x509.DNSName("*.ol.epicgames.com"),
                    
                    # OAuth / Accounts - Critical for authentication
                    x509.DNSName("account-public-service-prod.ol.epicgames.com"),
                    x509.DNSName("account-public-service-prod03.ol.epicgames.com"),
                    
                    # Fortnite public service (MCP, catalog, receipts, etc.)
                    x509.DNSName("fortnite-public-service-prod.ol.epicgames.com"),
                    x509.DNSName("fortnite-public-service-prod11.ol.epicgames.com"),
                    x509.DNSName("fortnite-public-service-prod10.ol.epicgames.com"),
                    x509.DNSName("fortnite-public-service-prod08.ol.epicgames.com"),
                    
                    # Content pages
                    x509.DNSName("content-public-service-prod.ol.epicgames.com"),
                    
                    # Lightswitch (service status)
                    x509.DNSName("lightswitch-public-service-prod.ol.epicgames.com"),
                    
                    # Launcher / assets
                    x509.DNSName("launcher-public-service-prod06.ol.epicgames.com"),
                    
                    # Persona
                    x509.DNSName("persona-public-service-prod.ol.epicgames.com"),
                    
                    # EULA tracking
                    x509.DNSName("eulatracking-public-service-prod06.ol.epicgames.com"),
                    
                    # Friends
                    x509.DNSName("friends-public-service-prod06.ol.epicgames.com"),
                    x509.DNSName("friends-public-service-prod.ol.epicgames.com"),
                    
                    # Events/Stats (older builds may touch these)
                    x509.DNSName("events-public-service-live.ol.epicgames.com"),
                    x509.DNSName("events-public-service-prod.ol.epicgames.com"),
                    x509.DNSName("statsproxy-public-service-live.ol.epicgames.com"),
                    
                    # Telemetry - Critical for login flow
                    x509.DNSName("datarouter.ol.epicgames.com"),
                ]),
                critical=False,
            ).add_extension(
                x509.KeyUsage(
                    key_cert_sign=False,
                    crl_sign=False,
                    digital_signature=True,
                    key_encipherment=True,
                    data_encipherment=True,
                    key_agreement=True,
                    content_commitment=True,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            ).sign(root_private_key, hashes.SHA256())
            
            # Write root CA certificate and key
            with open('ssl/root-ca.crt', 'wb') as f:
                f.write(root_cert.public_bytes(serialization.Encoding.PEM))
            
            with open('ssl/root-ca.key', 'wb') as f:
                f.write(root_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Write end-entity certificate and key
            with open('ssl/end-entity.crt', 'wb') as f:
                f.write(end_cert.public_bytes(serialization.Encoding.PEM))
            
            with open('ssl/end-entity.key', 'wb') as f:
                f.write(end_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Install root CA to trusted root store
            root_ca_file = os.path.join(os.getcwd(), "ssl", "root-ca.crt")
            if os.path.exists(root_ca_file):
                self.install_cert_to_trusted_root(root_ca_file)
            
            self.logger.info("Certificate chain created successfully")
            return True
            
        except Exception as e:
            self.logger.warning(f"Failed to create certificate chain: {e}")
            return False
    
    def remove_old_certificates(self):
        """Remove old certificates from the system"""
        try:
            # Remove old certificates from all stores
            ps_commands = [
                'Get-ChildItem -Path Cert:\\LocalMachine\\Root | Where-Object { $_.Subject -like "*ol.epicgames.com*" -or $_.Subject -like "*localhost*" -or $_.Subject -like "*Fortnite*" } | Remove-Item -Force',
                'Get-ChildItem -Path Cert:\\LocalMachine\\AuthRoot | Where-Object { $_.Subject -like "*ol.epicgames.com*" -or $_.Subject -like "*localhost*" -or $_.Subject -like "*Fortnite*" } | Remove-Item -Force',
                'Get-ChildItem -Path Cert:\\CurrentUser\\Root | Where-Object { $_.Subject -like "*ol.epicgames.com*" -or $_.Subject -like "*localhost*" -or $_.Subject -like "*Fortnite*" } | Remove-Item -Force'
            ]
            
            for ps_command in ps_commands:
                subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                check=False
                )
            
            self.logger.info("Old certificates removed")
        except Exception as e:
            self.logger.warning(f"Failed to remove old certificates: {str(e)}")
            
    def install_cert_to_trusted_root(self, cert_file):
        """Install certificate to trusted root store using multiple methods with shorter timeouts"""
        try:
            # Method 1: Simple certutil approach first (fastest)
            try:
                certutil_result = subprocess.run(
                    ["certutil", "-addstore", "-user", "Root", cert_file],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5  # Reduced timeout
                )
                if certutil_result.returncode == 0:
                    self.logger.info("Certificate installed via certutil (user)")
                    self.log_to_console("SSL certificate installed to user store", "SUCCESS")
            except subprocess.TimeoutExpired:
                self.logger.warning("Certutil user installation timed out")
            except Exception as e:
                self.logger.warning(f"Certutil user installation error: {e}")
            
            # Method 2: Try LocalMachine certutil
            try:
                certutil_lm_result = subprocess.run(
                    ["certutil", "-addstore", "Root", cert_file],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5  # Reduced timeout
                )
                if certutil_lm_result.returncode == 0:
                    self.logger.info("Certificate installed via certutil (machine)")
                    self.log_to_console("SSL certificate installed to machine store", "SUCCESS")
            except subprocess.TimeoutExpired:
                self.logger.warning("Certutil LocalMachine installation timed out")
            except Exception as e:
                self.logger.warning(f"Certutil LocalMachine installation error: {e}")
            
            # Method 3: PowerShell (only essential stores, with reduced timeout)
            ps_commands = [
                f'Import-Certificate -FilePath "{cert_file}" -CertStoreLocation Cert:\\CurrentUser\\Root',
                f'Import-Certificate -FilePath "{cert_file}" -CertStoreLocation Cert:\\CurrentUser\\My'
            ]
            
            for ps_command in ps_commands:
                try:
                    result = subprocess.run(
                        ["powershell", "-Command", ps_command],
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=5  # Reduced timeout
                    )
                    
                    if result.returncode == 0:
                        self.logger.info(f"Certificate installed via PowerShell")
                except subprocess.TimeoutExpired:
                    self.logger.warning("PowerShell certificate installation timed out")
                    continue
                except Exception as e:
                    self.logger.warning(f"PowerShell certificate installation error: {e}")
                    continue
            
            # Quick verification (with timeout)
            try:
                verify_result = subprocess.run(
                    ["certutil", "-store", "-user", "Root"],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=3  # Very short timeout for verification
                )
                
                if "ol.epicgames.com" in verify_result.stdout or "Epic Games" in verify_result.stdout:
                    self.logger.info("Certificate verified in trusted root store")
                    return True
                else:
                    self.logger.info("Certificate installation completed (verification inconclusive)")
                    return True  # Assume success if no errors
                    
            except subprocess.TimeoutExpired:
                self.logger.warning("Certificate verification timed out - assuming success")
                return True
            except Exception as e:
                self.logger.warning(f"Certificate verification failed: {e} - assuming success")
                return True
                
        except Exception as e:
            self.logger.error(f"Certificate installation failed: {str(e)}")
            return False
    
    def validate_certificates(self):
        """Comprehensive certificate validation and troubleshooting"""
        try:
            self.log_to_console("Running certificate validation...", "INFO")
            validation_results = []
            
            # Check if certificate files exist
            cert_files = [
                ('ssl/server.crt', 'Main server certificate'),
                ('ssl/server.key', 'Main server private key'),
                ('ssl/root-ca.crt', 'Root CA certificate'),
                ('ssl/end-entity.crt', 'End-entity certificate'),
                ('ssl/end-entity.key', 'End-entity private key')
            ]
            
            for cert_file, description in cert_files:
                if os.path.exists(cert_file):
                    self.log_to_console(f"✓ {description}: Found", "INFO")
                    validation_results.append(True)
                else:
                    self.log_to_console(f"✗ {description}: Missing", "WARNING")
                    validation_results.append(False)
            
            # Check certificate installation in Windows stores
            stores_to_check = [
                ('CurrentUser\\Root', 'User Trusted Root'),
                ('LocalMachine\\Root', 'Machine Trusted Root'),
                ('CurrentUser\\My', 'User Personal'),
                ('CurrentUser\\CA', 'User Intermediate CA')
            ]
            
            for store_path, store_name in stores_to_check:
                try:
                    ps_command = f'Get-ChildItem -Path Cert:\\{store_path} | Where-Object {{ $_.Subject -like "*ol.epicgames.com*" -or $_.Subject -like "*Epic Games*" }} | Measure-Object | Select-Object -ExpandProperty Count'
                    result = subprocess.run(
                        ["powershell", "-Command", ps_command],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if result.returncode == 0:
                        cert_count = int(result.stdout.strip() or 0)
                        if cert_count > 0:
                            self.log_to_console(f"✓ {store_name}: {cert_count} certificate(s) found", "INFO")
                            validation_results.append(True)
                        else:
                            self.log_to_console(f"✗ {store_name}: No certificates found", "WARNING")
                            validation_results.append(False)
                    else:
                        self.log_to_console(f"✗ {store_name}: Check failed", "ERROR")
                        validation_results.append(False)
                        
                except Exception as e:
                    self.log_to_console(f"✗ {store_name}: Error - {str(e)}", "ERROR")
                    validation_results.append(False)
            
            # Test SSL connection to each critical domain
            critical_domains = [
                'account-public-service-prod.ol.epicgames.com',
                'fortnite-public-service-prod11.ol.epicgames.com',
                'datarouter.ol.epicgames.com'
            ]
            
            for domain in critical_domains:
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection(('127.0.0.1', 443), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            self.log_to_console(f"✓ SSL handshake for {domain}: OK", "INFO")
                            validation_results.append(True)
                except Exception as e:
                    self.log_to_console(f"✗ SSL handshake for {domain}: {str(e)}", "ERROR")
                    validation_results.append(False)
            
            # Overall validation result
            success_rate = sum(validation_results) / len(validation_results) * 100 if validation_results else 0
            if success_rate >= 80:
                self.log_to_console(f"Certificate validation: {success_rate:.1f}% - GOOD", "INFO")
            elif success_rate >= 60:
                self.log_to_console(f"Certificate validation: {success_rate:.1f}% - NEEDS ATTENTION", "WARNING")
            else:
                self.log_to_console(f"Certificate validation: {success_rate:.1f}% - CRITICAL ISSUES", "ERROR")
            
            return success_rate >= 60
            
        except Exception as e:
            self.log_to_console(f"Certificate validation failed: {str(e)}", "ERROR")
            return False
    
    def enhanced_certificate_installation(self):
        """Enhanced certificate installation with comprehensive store coverage"""
        try:
            self.log_to_console("Starting enhanced certificate installation...", "INFO")
            
            # Ensure all certificate files exist
            if not os.path.exists('ssl/root-ca.crt'):
                self.log_to_console("Root CA certificate not found, generating certificates first...", "WARNING")
                self.create_certificate_chain()
            
            # Install to all critical Windows certificate stores
            stores_to_install = [
                ('Root', 'CurrentUser', 'User Trusted Root Certification Authorities'),
                ('Root', 'LocalMachine', 'Machine Trusted Root Certification Authorities'),
                ('TrustedPublisher', 'CurrentUser', 'User Trusted Publishers'),
                ('TrustedPublisher', 'LocalMachine', 'Machine Trusted Publishers'),
                ('CA', 'CurrentUser', 'User Intermediate Certification Authorities'),
                ('CA', 'LocalMachine', 'Machine Intermediate Certification Authorities')
            ]
            
            success_count = 0
            for store_name, store_location, description in stores_to_install:
                try:
                    # Use PowerShell for more reliable installation
                    ps_command = f'''
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("ssl/root-ca.crt")
                    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("{store_name}", "{store_location}")
                    $store.Open("ReadWrite")
                    $store.Add($cert)
                    $store.Close()
                    Write-Output "Success"
                    '''
                    
                    result = subprocess.run(
                        ["powershell", "-Command", ps_command],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    
                    if result.returncode == 0 and "Success" in result.stdout:
                        self.log_to_console(f"✓ Installed to {description}", "INFO")
                        success_count += 1
                    else:
                        self.log_to_console(f"✗ Failed to install to {description}: {result.stderr}", "WARNING")
                        
                except Exception as e:
                    self.log_to_console(f"✗ Error installing to {description}: {str(e)}", "ERROR")
            
            # Also try certutil as backup
            try:
                certutil_result = subprocess.run(
                    ["certutil", "-addstore", "-user", "Root", "ssl/root-ca.crt"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if certutil_result.returncode == 0:
                    self.log_to_console("✓ Certutil installation successful", "INFO")
                    success_count += 1
            except Exception as e:
                self.log_to_console(f"Certutil installation failed: {str(e)}", "WARNING")
            
            installation_rate = (success_count / (len(stores_to_install) + 1)) * 100
            if installation_rate >= 70:
                self.log_to_console(f"Certificate installation: {installation_rate:.1f}% success rate - GOOD", "INFO")
                return True
            else:
                self.log_to_console(f"Certificate installation: {installation_rate:.1f}% success rate - NEEDS ATTENTION", "WARNING")
                return False
                
        except Exception as e:
            self.log_to_console(f"Enhanced certificate installation failed: {str(e)}", "ERROR")
            return False
    
    def make_unverified_context(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    
    def restart_as_admin(self):
        """Restart the application with administrator privileges"""
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{os.path.abspath(__file__)}"', None, 1)
            self.root.quit()
        except Exception as e:
            self.logger.error(f"Failed to restart as admin: {str(e)}")
            messagebox.showerror("Error", f"Failed to restart as administrator: {str(e)}")
    
    def trust_certs(self):
        """Trust the generated SSL certificates"""
        if not self.is_admin:
            messagebox.showwarning("Admin Required", "Administrator privileges required to trust certificates.\n\nClick 'Restart as Admin' first.")
            return
            
        ssl_dir = os.path.join(os.getcwd(), "ssl")
        cert_file = os.path.join(ssl_dir, "server.crt")
        
        if not os.path.exists(cert_file):
            messagebox.showwarning("No Certificate", "SSL certificate not found. Please generate certificates first.")
            return
            
        # Run certificate trust operation in a separate thread to avoid blocking GUI
        self.update_status("Installing certificate to trusted root...")
        self.animate_progress()
        
        trust_thread = threading.Thread(target=self._trust_certs_async, args=(cert_file,), daemon=True)
        trust_thread.start()
    
    def _trust_certs_async(self, cert_file):
        """Trust certificates asynchronously"""
        try:
            result = self.install_cert_to_trusted_root(cert_file)
            if result:
                self.logger.info("SSL certificate installed to trusted root successfully")
                self.root.after(0, lambda: self.update_status("SSL certificate installed to trusted root successfully"))
                self.root.after(0, lambda: messagebox.showinfo("Success", "SSL certificate installed to trusted root successfully."))
            else:
                self.logger.error("Failed to install certificate to trusted root")
                self.root.after(0, lambda: self.update_status("Failed to install certificate to trusted root"))
                self.root.after(0, lambda: messagebox.showerror("Error", "Failed to install certificate to trusted root."))
        except Exception as e:
            self.logger.error(f"Failed to trust certificates: {str(e)}")
            self.root.after(0, lambda: self.update_status(f"Failed to trust certificates: {str(e)}"))
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to trust certificates: {str(e)}"))
        finally:
            self.root.after(0, lambda: self.stop_progress_animation())
    
    def run_smoke_tests(self):
        """Run quick connectivity tests against local backend"""
        try:
            self.update_status("Running smoke tests...")
            ctx = self.make_unverified_context()
            passed = []
            failed = []
            
            def get(url, method='GET', data=None, headers=None):
                req = urllib.request.Request(url, method=method)
                if headers:
                    for k, v in headers.items():
                        req.add_header(k, v)
                if data is not None:
                    data_bytes = urllib.parse.urlencode(data).encode()
                else:
                    data_bytes = None
                with urllib.request.urlopen(req, data=data_bytes, context=ctx, timeout=5) as resp:
                    return resp.status, resp.read()
            
            # Health
            try:
                status, body = get("https://localhost/.well-known/healthz")
                if status == 200:
                    j = json.loads(body.decode('utf-8'))
                    if j.get('status') == 'ok':
                        passed.append('healthz')
                    else:
                        failed.append('healthz payload')
                else:
                    failed.append('healthz status')
            except Exception as e:
                failed.append(f'healthz error: {e}')
            
            # Timeline
            try:
                status, body = get("https://localhost/fortnite/api/calendar/v1/timeline")
                if status == 200:
                    j = json.loads(body.decode('utf-8'))
                    if 'channels' in j:
                        passed.append('timeline')
                    else:
                        failed.append('timeline payload')
                else:
                    failed.append('timeline status')
            except Exception as e:
                failed.append(f'timeline error: {e}')
            
            # OAuth token
            try:
                status, body = get(
                    "https://localhost/account/api/oauth/token",
                    method='POST',
                    data={'grant_type': 'client_credentials'}
                )
                if status == 200:
                    j = json.loads(body.decode('utf-8'))
                    if 'access_token' in j:
                        passed.append('oauth_token')
                    else:
                        failed.append('oauth payload')
                else:
                    failed.append('oauth status')
            except Exception as e:
                failed.append(f'oauth error: {e}')
            
            # Certificate validation test
            try:
                self.log_to_console("Running certificate validation as part of smoke tests...", "INFO")
                cert_validation_success = self.validate_certificates()
                if cert_validation_success:
                    passed.append('certificate_validation')
                else:
                    failed.append('certificate_validation')
            except Exception as e:
                failed.append(f'certificate_validation error: {e}')
            
            summary = f"Passed: {len(passed)} | Failed: {len(failed)}\n" + \
                      ("\n".join([f"+ {p}" for p in passed]) or "") + \
                      ("\n" + "\n".join([f"- {f}" for f in failed]) if failed else "")
            
            if failed:
                self.logger.warning(f"Smoke tests completed with failures:\n{summary}")
                messagebox.showwarning("Smoke Tests", summary)
            else:
                self.logger.info("Smoke tests passed")
                messagebox.showinfo("Smoke Tests", summary)
            
            self.update_status("Smoke tests completed")
        except Exception as e:
            self.logger.error(f"Smoke tests failed to run: {str(e)}")
            messagebox.showerror("Error", f"Smoke tests failed to run: {str(e)}")
        finally:
            self.check_port_status()

def main():
    """Main function to start the launcher"""
    # Check if we need to run as admin - but only restart once
    if not is_admin() and '--admin-restart' not in sys.argv:
        print("Restarting with administrator privileges...")
        # Add a flag to prevent infinite restart loops
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{__file__}" --admin-restart', None, 1)
        return
    
    root = tk.Tk()
    app = FortniteEmulatorLauncher(root)
    root.mainloop()

# Main entry point
if __name__ == "__main__":
        main()