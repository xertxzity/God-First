"""
AI Assistant for Fortnite Emulator Launcher
Provides intelligent diagnostics, troubleshooting, and automated fixes
"""

import logging
import subprocess
import os
import socket
import ssl
import urllib.request
import json
import time
from datetime import datetime
try:
    import psutil
except ImportError:
    psutil = None


class AIAssistant:
    def __init__(self, launcher_instance):
        self.launcher = launcher_instance
        self.logger = logging.getLogger(__name__)
        self.diagnostics = []
        self.fixes_applied = []
        
    def run_full_diagnostic(self):
        """Run comprehensive system diagnostic"""
        self.logger.info("AI Assistant: Starting full system diagnostic...")
        self.diagnostics = []
        
        # Check system requirements
        self._check_admin_privileges()
        self._check_python_environment()
        self._check_network_connectivity()
        
        # Check ports
        self._check_port_availability()
        
        # Check file structure
        self._check_file_structure()
        
        # Check SSL certificates
        self._check_ssl_certificates()
        
        # Check backend health
        self._check_backend_health()
        
        # Check mitmproxy status
        self._check_mitmproxy_status()
        
        return self.diagnostics
    
    def auto_fix_issues(self):
        """Automatically fix detected issues"""
        self.logger.info("AI Assistant: Starting automated fixes...")
        self.fixes_applied = []
        
        for diagnostic in self.diagnostics:
            if diagnostic['severity'] == 'critical' or diagnostic['severity'] == 'error':
                self._apply_fix(diagnostic)
        
        return self.fixes_applied
    
    def _check_admin_privileges(self):
        """Check if running with admin privileges"""
        if not self.launcher.is_admin:
            self.diagnostics.append({
                'category': 'system',
                'severity': 'critical',
                'issue': 'Not running as Administrator',
                'description': 'Port 443 binding requires Administrator privileges',
                'fix': 'restart_as_admin'
            })
    
    def _check_python_environment(self):
        """Check Python environment and dependencies"""
        try:
            import aiohttp
            import mitmproxy
            self.diagnostics.append({
                'category': 'environment',
                'severity': 'info',
                'issue': 'Dependencies available',
                'description': 'All required Python packages are installed'
            })
        except ImportError as e:
            self.diagnostics.append({
                'category': 'environment',
                'severity': 'error',
                'issue': f'Missing dependency: {str(e)}',
                'description': 'Required Python packages are missing',
                'fix': 'install_dependencies'
            })
    
    def _check_network_connectivity(self):
        """Check network connectivity"""
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            self.diagnostics.append({
                'category': 'network',
                'severity': 'info',
                'issue': 'Network connectivity OK',
                'description': 'Internet connection is available'
            })
        except OSError:
            self.diagnostics.append({
                'category': 'network',
                'severity': 'warning',
                'issue': 'No internet connectivity',
                'description': 'Internet connection may be required for some features'
            })
    
    def _check_port_availability(self):
        """Check if required ports are available"""
        ports_to_check = [443, 8443, 80]
        
        for port in ports_to_check:
            if self._is_port_in_use(port):
                if port == 443:
                    # Check if it's our mitmproxy
                    if self._is_our_process_on_port(port):
                        self.diagnostics.append({
                            'category': 'ports',
                            'severity': 'info',
                            'issue': f'Port {port} in use by our mitmproxy',
                            'description': f'Port {port} is correctly occupied by our process'
                        })
                    else:
                        self.diagnostics.append({
                            'category': 'ports',
                            'severity': 'error',
                            'issue': f'Port {port} blocked by other process',
                            'description': f'Port {port} is needed for mitmproxy but occupied by another process',
                            'fix': f'free_port_{port}'
                        })
                elif port == 8443:
                    # Check if it's our backend
                    if self._is_our_process_on_port(port):
                        self.diagnostics.append({
                            'category': 'ports',
                            'severity': 'info',
                            'issue': f'Port {port} in use by our backend',
                            'description': f'Port {port} is correctly occupied by our backend'
                        })
                    else:
                        self.diagnostics.append({
                            'category': 'ports',
                            'severity': 'error',
                            'issue': f'Port {port} blocked by other process',
                            'description': f'Port {port} is needed for backend but occupied by another process',
                            'fix': f'free_port_{port}'
                        })
            else:
                self.diagnostics.append({
                    'category': 'ports',
                    'severity': 'info',
                    'issue': f'Port {port} available',
                    'description': f'Port {port} is free and ready for use'
                })
    
    def _check_file_structure(self):
        """Check if all required files and directories exist"""
        required_files = [
            'src/Backend.py',
            'src/database.py',
            'src/mitmproxy_addon.py',
            'src/mitmproxy_manager.py',
            'config/Season7.json'
        ]
        
        required_dirs = ['src', 'config', 'data', 'ssl', 'logs']
        
        # Check directories
        for dir_path in required_dirs:
            if not os.path.exists(dir_path):
                self.diagnostics.append({
                    'category': 'files',
                    'severity': 'error',
                    'issue': f'Missing directory: {dir_path}',
                    'description': f'Required directory {dir_path} does not exist',
                    'fix': f'create_directory_{dir_path}'
                })
        
        # Check files
        for file_path in required_files:
            if not os.path.exists(file_path):
                self.diagnostics.append({
                    'category': 'files',
                    'severity': 'error',
                    'issue': f'Missing file: {file_path}',
                    'description': f'Required file {file_path} does not exist',
                    'fix': f'restore_file_{file_path}'
                })
    
    def _check_ssl_certificates(self):
        """Check SSL certificate status"""
        ssl_files = ['ssl/server.crt', 'ssl/server.key']
        
        for ssl_file in ssl_files:
            if not os.path.exists(ssl_file):
                self.diagnostics.append({
                    'category': 'ssl',
                    'severity': 'warning',
                    'issue': f'Missing SSL file: {ssl_file}',
                    'description': 'SSL certificates will be auto-generated on backend startup',
                    'fix': 'generate_ssl_certificates'
                })
    
    def _check_backend_health(self):
        """Check if backend is responding"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            req = urllib.request.Request('https://127.0.0.1:8443/.well-known/healthz')
            with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
                if response.status == 200:
                    self.diagnostics.append({
                        'category': 'backend',
                        'severity': 'info',
                        'issue': 'Backend responding',
                        'description': 'Backend server is healthy and responding'
                    })
                else:
                    self.diagnostics.append({
                        'category': 'backend',
                        'severity': 'warning',
                        'issue': f'Backend returned status {response.status}',
                        'description': 'Backend is responding but with unexpected status',
                        'fix': 'restart_backend'
                    })
        except Exception as e:
            self.diagnostics.append({
                'category': 'backend',
                'severity': 'error',
                'issue': 'Backend not responding',
                'description': f'Backend health check failed: {str(e)}',
                'fix': 'start_backend'
            })
    
    def _check_mitmproxy_status(self):
        """Check mitmproxy status"""
        if hasattr(self.launcher, 'mitm_manager') and self.launcher.mitm_manager:
            if self.launcher.mitm_manager.mitm_process and self.launcher.mitm_manager.mitm_process.poll() is None:
                self.diagnostics.append({
                    'category': 'mitmproxy',
                    'severity': 'info',
                    'issue': 'mitmproxy running',
                    'description': 'mitmproxy process is active and running'
                })
            else:
                self.diagnostics.append({
                    'category': 'mitmproxy',
                    'severity': 'error',
                    'issue': 'mitmproxy not running',
                    'description': 'mitmproxy process is not active',
                    'fix': 'start_mitmproxy'
                })
    
    def _apply_fix(self, diagnostic):
        """Apply automated fix for a diagnostic issue"""
        fix_type = diagnostic.get('fix')
        if not fix_type:
            return
        
        self.logger.info(f"AI Assistant: Applying fix for {diagnostic['issue']}")
        
        try:
            if fix_type == 'restart_as_admin':
                self._fix_restart_as_admin()
            elif fix_type == 'install_dependencies':
                self._fix_install_dependencies()
            elif fix_type.startswith('free_port_'):
                port = int(fix_type.split('_')[-1])
                self._fix_free_port(port)
            elif fix_type.startswith('create_directory_'):
                dir_path = fix_type.replace('create_directory_', '')
                self._fix_create_directory(dir_path)
            elif fix_type == 'generate_ssl_certificates':
                self._fix_generate_ssl_certificates()
            elif fix_type == 'start_backend':
                self._fix_start_backend()
            elif fix_type == 'restart_backend':
                self._fix_restart_backend()
            elif fix_type == 'start_mitmproxy':
                self._fix_start_mitmproxy()
            
            self.fixes_applied.append({
                'fix': fix_type,
                'issue': diagnostic['issue'],
                'status': 'success',
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            self.logger.error(f"AI Assistant: Fix failed for {diagnostic['issue']}: {str(e)}")
            self.fixes_applied.append({
                'fix': fix_type,
                'issue': diagnostic['issue'],
                'status': 'failed',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })
    
    def _fix_restart_as_admin(self):
        """Restart launcher as administrator"""
        self.launcher.root.after(0, lambda: self.launcher.update_status("AI: Restarting as Administrator..."))
        import ctypes
        import sys
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    
    def _fix_install_dependencies(self):
        """Install missing Python dependencies"""
        self.launcher.root.after(0, lambda: self.launcher.update_status("AI: Installing dependencies..."))
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'aiohttp', 'aiohttp-cors', 'mitmproxy'], check=True)
    
    def _fix_free_port(self, port):
        """Free a blocked port"""
        self.launcher.root.after(0, lambda: self.launcher.update_status(f"AI: Freeing port {port}..."))
        if hasattr(self.launcher, 'free_port'):
            self.launcher.free_port(port)
    
    def _fix_create_directory(self, dir_path):
        """Create missing directory"""
        self.launcher.root.after(0, lambda: self.launcher.update_status(f"AI: Creating directory {dir_path}..."))
        os.makedirs(dir_path, exist_ok=True)
    
    def _fix_generate_ssl_certificates(self):
        """Generate SSL certificates"""
        self.launcher.root.after(0, lambda: self.launcher.update_status("AI: Generating SSL certificates..."))
        # SSL certificates will be auto-generated by backend on startup
        pass
    
    def _fix_start_backend(self):
        """Start the backend server"""
        self.launcher.root.after(0, lambda: self.launcher.update_status("AI: Starting backend..."))
        if hasattr(self.launcher, 'start_backend'):
            self.launcher.start_backend()
    
    def _fix_restart_backend(self):
        """Restart the backend server"""
        self.launcher.root.after(0, lambda: self.launcher.update_status("AI: Restarting backend..."))
        if hasattr(self.launcher, 'stop_backend'):
            self.launcher.stop_backend()
        time.sleep(2)
        if hasattr(self.launcher, 'start_backend'):
            self.launcher.start_backend()
    
    def _fix_start_mitmproxy(self):
        """Start mitmproxy"""
        self.launcher.root.after(0, lambda: self.launcher.update_status("AI: Starting mitmproxy..."))
        if hasattr(self.launcher, 'mitm_manager') and self.launcher.mitm_manager:
            self.launcher.mitm_manager.start_mitmproxy()
    
    def _is_port_in_use(self, port):
        """Check if a port is in use"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', port)) == 0
    
    def _is_our_process_on_port(self, port):
        """Check if the process on a port belongs to us"""
        if not psutil:
            return False
        try:
            for conn in psutil.net_connections():
                if conn.laddr.port == port:
                    try:
                        proc = psutil.Process(conn.pid)
                        # Check if it's our Python process or mitmproxy
                        if 'python' in proc.name().lower() or 'mitmdump' in proc.name().lower():
                            return True
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            return False
        except Exception:
            return False
    
    def get_diagnostic_summary(self):
        """Get a summary of diagnostic results"""
        if not self.diagnostics:
            return "No diagnostics run yet"
        
        critical = len([d for d in self.diagnostics if d['severity'] == 'critical'])
        errors = len([d for d in self.diagnostics if d['severity'] == 'error'])
        warnings = len([d for d in self.diagnostics if d['severity'] == 'warning'])
        info = len([d for d in self.diagnostics if d['severity'] == 'info'])
        
        return f"Critical: {critical}, Errors: {errors}, Warnings: {warnings}, Info: {info}"
    
    def get_recommendations(self):
        """Get AI recommendations based on diagnostics"""
        recommendations = []
        
        # Check for critical issues
        critical_issues = [d for d in self.diagnostics if d['severity'] == 'critical']
        if critical_issues:
            recommendations.append("🚨 Critical issues detected - immediate action required")
        
        # Check for port conflicts
        port_issues = [d for d in self.diagnostics if d['category'] == 'ports' and d['severity'] == 'error']
        if port_issues:
            recommendations.append("🔌 Port conflicts detected - run 'Auto Fix' to resolve")
        
        # Check backend status
        backend_issues = [d for d in self.diagnostics if d['category'] == 'backend' and d['severity'] == 'error']
        if backend_issues:
            recommendations.append("🖥️ Backend issues detected - restart may be needed")
        
        # Check SSL status
        ssl_issues = [d for d in self.diagnostics if d['category'] == 'ssl']
        if ssl_issues:
            recommendations.append("🔒 SSL certificates missing - will auto-generate on startup")
        
        if not recommendations:
            recommendations.append("✅ System appears healthy - ready to launch")
        
        return recommendations
