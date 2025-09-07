"""
mitmproxy Manager for Fortnite SSL Interception
Manages mitmproxy process and certificate installation
"""

import subprocess
import os
import time
import logging
import threading
import shutil
from pathlib import Path


class MitmproxyManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.mitm_process = None
        self.mitm_port = 443  # mitmproxy takes port 443 (HTTPS)
        self.backend_port = 8443  # Our backend runs on 8443
        
    def install_mitmproxy(self):
        """Install mitmproxy if not available"""
        try:
            # Check if mitmproxy is already installed
            result = subprocess.run(['mitmdump', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.logger.info("mitmproxy is already installed")
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
            
        try:
            self.logger.info("Installing mitmproxy...")
            # Install mitmproxy via pip
            result = subprocess.run(['pip', 'install', 'mitmproxy'], 
                                  capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                self.logger.info("mitmproxy installed successfully")
                return True
            else:
                self.logger.error(f"Failed to install mitmproxy: {result.stderr}")
                return False
        except Exception as e:
            self.logger.error(f"Error installing mitmproxy: {e}")
            return False
    
    def install_mitm_certificate(self):
        """Install mitmproxy certificate to Windows certificate store"""
        try:
            # Get mitmproxy certificate directory
            mitm_cert_dir = Path.home() / '.mitmproxy'
            cert_file = mitm_cert_dir / 'mitmproxy-ca-cert.pem'
            
            if not cert_file.exists():
                self.logger.warning("mitmproxy certificate not found, starting mitmdump to generate it...")
                # Start mitmdump briefly to generate certificates
                proc = subprocess.Popen(['mitmdump', '--listen-port', str(self.mitm_port)], 
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                time.sleep(3)  # Wait for cert generation
                proc.terminate()
                proc.wait()
                
            if cert_file.exists():
                # Install certificate to Windows certificate stores
                stores = ['Root', 'TrustedPublisher', 'CA', 'AuthRoot']
                locations = ['CurrentUser', 'LocalMachine']
                
                for location in locations:
                    for store in stores:
                        try:
                            cmd = [
                                'certutil', '-user' if location == 'CurrentUser' else '-enterprise',
                                '-addstore', store, str(cert_file)
                            ]
                            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                            if result.returncode == 0:
                                self.logger.info(f"Installed mitmproxy cert to {location}\\{store}")
                        except Exception as e:
                            self.logger.warning(f"Failed to install cert to {location}\\{store}: {e}")
                            
                # Also copy to ssl directory for backup
                ssl_dir = Path('ssl')
                ssl_dir.mkdir(exist_ok=True)
                shutil.copy2(cert_file, ssl_dir / 'mitmproxy-ca.crt')
                self.logger.info("mitmproxy certificate installed successfully")
                return True
            else:
                self.logger.error("Could not find or generate mitmproxy certificate")
                return False
                
        except Exception as e:
            self.logger.error(f"Error installing mitmproxy certificate: {e}")
            return False
    
    def start_mitmproxy(self):
        """Start mitmproxy with Fortnite addon"""
        try:
            if self.mitm_process and self.mitm_process.poll() is None:
                self.logger.info("mitmproxy is already running")
                return True
            
            # Create SSL bypass configuration
            self.create_ssl_bypass_config()
                
            # Start mitmproxy with our addon and enhanced SSL bypass
            addon_path = os.path.abspath('src/mitmproxy_addon.py')
            config_file = Path.home() / '.mitmproxy' / 'config.yaml'
            
            cmd = [
                'mitmdump',
                '--listen-port', str(self.mitm_port),
                '--set', 'confdir=~/.mitmproxy',
                '--set', 'ssl_insecure=true',
                '--set', 'ssl_verify_upstream_cert=false',
                '--set', 'ssl_version_client=all',
                '--set', 'ssl_version_server=all',
                '--set', 'ciphers_client=all',
                '--set', 'ciphers_server=all',
                '--mode', 'reverse:https://127.0.0.1:8443',
                '--scripts', addon_path,
                '--set', 'upstream_cert=false',
                '--set', 'upstream_bind_address=127.0.0.1',
                '--conf', str(config_file),
                '--quiet'
            ]
            
            self.logger.info(f"Starting mitmproxy on port {self.mitm_port}")
            self.mitm_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait a moment for startup
            time.sleep(2)
            
            if self.mitm_process.poll() is None:
                self.logger.info("mitmproxy started successfully")
                return True
            else:
                stdout, stderr = self.mitm_process.communicate()
                self.logger.error(f"mitmproxy failed to start: {stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error starting mitmproxy: {e}")
            return False
    
    def stop_mitmproxy(self):
        """Stop mitmproxy process"""
        try:
            if self.mitm_process and self.mitm_process.poll() is None:
                self.logger.info("Stopping mitmproxy...")
                self.mitm_process.terminate()
                self.mitm_process.wait(timeout=10)
                self.logger.info("mitmproxy stopped")
        except Exception as e:
            self.logger.error(f"Error stopping mitmproxy: {e}")
    
    def setup_proxy_environment(self):
        """Set up environment variables for proxy"""
        proxy_url = f"http://127.0.0.1:{self.mitm_port}"
        env_vars = {
            'HTTP_PROXY': proxy_url,
            'HTTPS_PROXY': proxy_url,
            'http_proxy': proxy_url,
            'https_proxy': proxy_url,
        }
        
        for key, value in env_vars.items():
            os.environ[key] = value
            
        self.logger.info(f"Proxy environment variables set to {proxy_url}")
        return env_vars
    
    def is_running(self):
        """Check if mitmproxy is running"""
        return self.mitm_process and self.mitm_process.poll() is None
    
    def create_ssl_bypass_config(self):
        """Create SSL bypass configuration file"""
        try:
            config_dir = Path.home() / '.mitmproxy'
            config_dir.mkdir(exist_ok=True)
            
            config_file = config_dir / 'config.yaml'
            
            # SSL bypass configuration
            config_content = """
# SSL Bypass Configuration for Fortnite Emulator
ssl_insecure: true
ssl_verify_upstream_cert: false
ssl_version_client: all
ssl_version_server: all
ciphers_client: all
ciphers_server: all
upstream_cert: false
upstream_bind_address: 127.0.0.1

# Additional bypass settings
confdir: ~/.mitmproxy
listen_port: 443
mode: reverse:https://127.0.0.1:8443

# Headers to bypass
set_headers:
  - "X-SSL-Bypass: true"
  - "X-Fortnite-Emulator: true"

# Ignore certificate errors
ignore_hosts:
  - "*.ol.epicgames.com"
  - "*.epicgames.com"
  - "epicgames.com"
"""
            
            with open(config_file, 'w') as f:
                f.write(config_content)
            
            self.logger.info(f"SSL bypass configuration created at {config_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create SSL bypass config: {e}")
            return False
