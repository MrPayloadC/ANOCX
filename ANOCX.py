#!/usr/bin/env python3
import os
import subprocess
import threading
import time
import requests
import signal
import sys
import random
import logging
import argparse
import psutil
import socket
import hashlib
import json
import platform
from datetime import datetime

class ANOCXFinal:
    LOG_FILES = [
        "/var/log/syslog", "/var/log/auth.log", "/var/log/kern.log", "/var/log/dpkg.log",
        "/var/log/faillog", "/var/log/lastlog", "/var/log/wtmp", "/var/log/btmp",
        "/var/log/messages", "/var/log/user.log"
    ]

    FIREFOX_PROFILE_DIR = os.path.expanduser("~/.mozilla/firefox")
    CHROME_HISTORY_PATH = os.path.expanduser("~/.config/google-chrome/Default/History")
    EDGE_HISTORY_PATH = os.path.expanduser("~/.config/microsoft-edge/Default/History")

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/118.0.5993.117 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/18.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/118.0.5993.117 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/117.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:117.0) Gecko/20100101 Firefox/117.0"
    ]

    SUSPICIOUS_PROCESSES = [
        'tcpdump', 'wireshark', 'ettercap', 'dsniff', 'strace', 'tcpflow',
        'netsniff-ng', 'nmap', 'john', 'hydra', 'hashcat', 'aircrack-ng'
    ]

    def __init__(self, interface: str, openvpn_config: str, tor_enabled: bool, openvpn_enabled: bool):
        self.interface = interface
        self.openvpn_config = openvpn_config
        self.tor_enabled = tor_enabled
        self.openvpn_enabled = openvpn_enabled
        self.stop_event = threading.Event()
        self.start_time = datetime.now()

        logging.basicConfig(
            level=logging.INFO,
            format="[%(asctime)s] %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("anocx_final.log"),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger("ANOCXFinal")

    def clear_file(self, filepath: str):
        try:
            if os.path.exists(filepath):
                with open(filepath, 'w') as f:
                    f.truncate(0)
                self.logger.info(f"Cleared {filepath}")
        except Exception as e:
            self.logger.warning(f"Failed to clear {filepath}: {e}")

    def clear_system_logs(self):
        for log_file in self.LOG_FILES:
            self.clear_file(log_file)

    def clear_browser_history(self):
        try:
            for profile in os.listdir(self.FIREFOX_PROFILE_DIR):
                places_db = os.path.join(self.FIREFOX_PROFILE_DIR, profile, "places.sqlite")
                if os.path.exists(places_db):
                    os.remove(places_db)
                    self.logger.info(f"Cleared Firefox history: {places_db}")
        except Exception as e:
            self.logger.warning(f"Failed to clear Firefox history: {e}")

        try:
            if os.path.exists(self.CHROME_HISTORY_PATH):
                os.remove(self.CHROME_HISTORY_PATH)
                self.logger.info(f"Cleared Chrome history: {self.CHROME_HISTORY_PATH}")
        except Exception as e:
            self.logger.warning(f"Failed to clear Chrome history: {e}")

        try:
            if os.path.exists(self.EDGE_HISTORY_PATH):
                os.remove(self.EDGE_HISTORY_PATH)
                self.logger.info(f"Cleared Edge history: {self.EDGE_HISTORY_PATH}")
        except Exception as e:
            self.logger.warning(f"Failed to clear Edge history: {e}")

    def flush_dns_cache(self):
        try:
            subprocess.run(["systemd-resolve", "--flush-caches"], check=True)
            self.logger.info("Flushed DNS cache with systemd-resolve")
        except Exception:
            try:
                subprocess.run(["service", "nscd", "restart"], check=True)
                self.logger.info("Restarted nscd to flush DNS cache")
            except Exception as e:
                self.logger.warning(f"Failed to flush DNS cache: {e}")

    def clear_temp_files(self):
        temp_dirs = ["/tmp", "/var/tmp"]
        for temp_dir in temp_dirs:
            try:
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        try:
                            os.remove(os.path.join(root, file))
                        except Exception:
                            pass
                self.logger.info(f"Cleared temp files in {temp_dir}")
            except Exception as e:
                self.logger.warning(f"Failed to clear temp files in {temp_dir}: {e}")

    def terminate_suspicious_processes(self):
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                for keyword in self.SUSPICIOUS_PROCESSES:
                    if keyword in (proc.info['name'] or '') or any(keyword in cmd for cmd in proc.info.get('cmdline', [])):
                        self.logger.info(f"Terminating suspicious process {proc.info['name']} (PID: {proc.info['pid']})")
                        proc.terminate()
            except Exception:
                pass

    def change_mac_address(self):
        try:
            self.logger.info(f"Changing MAC address of interface {self.interface}")
            subprocess.run(["sudo", "ip", "link", "set", self.interface, "down"], check=True)
            mac = "02:%02x:%02x:%02x:%02x:%02x" % (
                random.randint(0x00, 0x7f),
                random.randint(0x00, 0xff),
                random.randint(0x00, 0xff),
                random.randint(0x00, 0xff),
                random.randint(0x00, 0xff)
            )
            subprocess.run(["sudo", "ip", "link", "set", self.interface, "address", mac], check=True)
            subprocess.run(["sudo", "ip", "link", "set", self.interface, "up"], check=True)
            self.logger.info(f"MAC address changed to {mac} on {self.interface}")
            return mac
        except Exception as e:
            self.logger.error(f"Failed to change MAC address: {e}")
            return None

    def start_tor(self):
        if not self.tor_enabled:
            self.logger.info("Tor service not enabled, skipping start.")
            return
        try:
            subprocess.run(["systemctl", "start", "tor"], check=True)
            self.logger.info("Tor service started successfully.")
        except Exception as e:
            self.logger.error(f"Failed to start Tor: {e}")

    def start_openvpn(self):
        if not self.openvpn_enabled:
            self.logger.info("OpenVPN not enabled, skipping start.")
            return
        if not os.path.exists(self.openvpn_config):
            self.logger.error(f"OpenVPN config file not found: {self.openvpn_config}")
            return
        try:
            subprocess.Popen(["sudo", "openvpn", "--config", self.openvpn_config])
            self.logger.info(f"OpenVPN started with config: {self.openvpn_config}")
        except Exception as e:
            self.logger.error(f"Failed to start OpenVPN: {e}")

    def get_external_ip(self) -> str:
        try:
            ip = requests.get("https://api.ipify.org", timeout=5).text
            self.logger.info(f"External IP: {ip}")
            return ip
        except Exception:
            self.logger.warning("Failed to fetch external IP.")
            return "Unknown"

    def get_random_user_agent(self) -> str:
        return random.choice(self.USER_AGENTS)

    def quantum_noise_delay(self, min_ms=5, max_ms=250):
        base = random.gauss(mu=90, sigma=40)
        delay = max(min_ms, min(max_ms, base))
        self.logger.debug(f"Injecting quantum noise delay of {delay:.2f} ms")
        time.sleep(delay / 1000.0)

    def simulate_network_activity(self, user_agent: str):
        self.quantum_noise_delay()
        self.logger.info(f"Simulated network activity with User-Agent: {user_agent}")

    def dynamic_identity_morphing(self):
        mac = self.change_mac_address()
        user_agent = self.get_random_user_agent()
        ip = self.get_external_ip()
        fingerprint = self.generate_fingerprint(mac, ip, user_agent)
        self.logger.info(f"Dynamic Identity Morphing: IP={ip}, MAC={mac}, UA={user_agent}, Fingerprint={fingerprint}")
        self.simulate_network_activity(user_agent)

    def generate_fingerprint(self, mac, ip, ua):
        raw = f"{mac}-{ip}-{ua}-{platform.platform()}-{datetime.now().timestamp()}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def randomize_dns_servers(self):
        dns_options = [
            "nameserver 1.1.1.1",
            "nameserver 8.8.8.8",
            "nameserver 9.9.9.9",
            "nameserver 8.26.56.26",
            "nameserver 208.67.222.222"
        ]
        try:
            resolv_path = "/etc/resolv.conf"
            backup_path = "/etc/resolv.conf.bak"
            if os.path.exists(resolv_path):
                subprocess.run(["sudo", "cp", resolv_path, backup_path], check=True)
            new_dns = "\n".join(random.sample(dns_options, k=3)) + "\n"
            with open("/tmp/resolv.conf.temp", "w") as f:
                f.write(new_dns)
            subprocess.run(["sudo", "mv", "/tmp/resolv.conf.temp", resolv_path], check=True)
            self.logger.info("Randomized DNS servers in /etc/resolv.conf")
        except Exception as e:
            self.logger.warning(f"Failed to randomize DNS servers: {e}")

    def rotate_ip_via_dhcp(self):
        try:
            self.logger.info(f"Releasing and renewing DHCP lease on {self.interface}")
            subprocess.run(["sudo", "dhclient", "-r", self.interface], check=True)
            subprocess.run(["sudo", "dhclient", self.interface], check=True)
            self.logger.info("DHCP lease renewed successfully")
        except Exception as e:
            self.logger.warning(f"Failed to rotate IP via DHCP: {e}")

    def stealth_mode_check(self):
        # Example: Check if running inside VM or container and log it
        try:
            with open('/proc/1/cgroup', 'rt') as f:
                cgroup_info = f.read()
            if 'docker' in cgroup_info or 'lxc' in cgroup_info:
                self.logger.warning("Running inside a container environment detected.")
            else:
                self.logger.info("No container environment detected.")
        except Exception:
            self.logger.warning("Could not detect container environment.")

    def save_status_snapshot(self):
        # Save a JSON snapshot of current system state for audit or rollback
        try:
            snapshot = {
                "time": datetime.now().isoformat(),
                "external_ip": self.get_external_ip(),
                "interface": self.interface,
                "mac": self.get_current_mac(),
                "os": platform.platform(),
                "uptime_sec": (datetime.now() - self.start_time).seconds,
                "processes": [proc.info for proc in psutil.process_iter(['pid','name']) if proc.info]
            }
            with open("anocx_status_snapshot.json", "w") as f:
                json.dump(snapshot, f, indent=4)
            self.logger.info("Saved system status snapshot.")
        except Exception as e:
            self.logger.warning(f"Failed to save status snapshot: {e}")

    def get_current_mac(self):
        try:
            path = f"/sys/class/net/{self.interface}/address"
            with open(path) as f:
                return f.read().strip()
        except Exception:
            return "Unknown"

    def clean_cycle(self):
        self.logger.info("Starting cleaning cycle.")
        self.stealth_mode_check()
        self.clear_system_logs()
        self.clear_browser_history()
        self.flush_dns_cache()
        self.clear_temp_files()
        self.terminate_suspicious_processes()
        self.randomize_dns_servers()
        self.rotate_ip_via_dhcp()
        self.dynamic_identity_morphing()
        self.save_status_snapshot()
        self.logger.info("Cleaning cycle completed.")

    def run(self, interval_sec=10):
        self.logger.info("Starting ANOCXFinal main loop.")
        try:
            while not self.stop_event.is_set():
                self.clean_cycle()
                self.stop_event.wait(interval_sec)
        except KeyboardInterrupt:
            self.logger.info("Received KeyboardInterrupt, stopping...")
        finally:
            self.logger.info("ANOCXFinal stopped.")

    def stop(self):
        self.stop_event.set()

def parse_args():
    parser = argparse.ArgumentParser(description="ANOCXFinal: The Most Advanced Anonymity & Cleaning Tool")
    parser.add_argument("--interface", type=str, default="eth0", help="Network interface for MAC & DHCP operations")
    parser.add_argument("--openvpn-config", type=str, default=os.path.expanduser("~/vpn_config.ovpn"), help="Path to OpenVPN config file")
    parser.add_argument("--no-tor", action="store_true", help="Disable Tor service start")
    parser.add_argument("--no-openvpn", action="store_true", help="Disable OpenVPN start")
    parser.add_argument("--interval", type=int, default=10, help="Interval between cleaning cycles (seconds)")
    return parser.parse_args()

def main():
    args = parse_args()
    anocx = ANOCXFinal(
        interface=args.interface,
        openvpn_config=args.openvpn_config,
        tor_enabled=not args.no_tor,
        openvpn_enabled=not args.no_openvpn
    )

    def signal_handler(sig, frame):
        anocx.logger.info("Signal received, shutting down gracefully...")
        anocx.stop()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    anocx.logger.info("ANOCXFinal started.")
    anocx.logger.info(f"Using interface: {args.interface}")
    anocx.logger.info(f"OpenVPN config: {args.openvpn_config}")
    anocx.logger.info(f"Tor enabled: {anocx.tor_enabled}")
    anocx.logger.info(f"OpenVPN enabled: {anocx.openvpn_enabled}")

    anocx.start_tor()
    anocx.start_openvpn()

    anocx.run(interval_sec=args.interval)

if __name__ == "__main__":
    main()
