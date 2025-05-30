import os
import socket
import platform
import subprocess

class FirewallBlocker:
    def __init__(self):
        self.os_type = platform.system()

    def resolve_url_to_ip(self, url: str) -> str:
        """
        Resolve a domain (or full URL) to an IP address.
        """
        try:
            hostname = url.split("//")[-1].split("/")[0]
            return socket.gethostbyname(hostname)
        except Exception as e:
            return f"error: {e}"

    def block_ip(self, ip: str) -> str:
        """
        Block the given IP using system firewall.
        """
        try:
            if self.os_type == "Windows":
                cmd = f'netsh advfirewall firewall add rule name="Block {ip}" dir=out action=block remoteip={ip}'
            elif self.os_type == "Linux":
                cmd = f'sudo iptables -A OUTPUT -d {ip} -j DROP'
            else:
                return f"Unsupported OS: {self.os_type}"

            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                return f"✅ Blocked {ip} on {self.os_type} firewall."
            else:
                return f"⚠️ Error blocking IP: {result.stderr}"
        except Exception as e:
            return f"Exception: {str(e)}"

    def block_url(self, url: str) -> str:
        """
        Block a URL by resolving its IP and blocking that IP.
        """
        ip = self.resolve_url_to_ip(url)
        if ip.startswith("error"):
            return f"❌ Failed to resolve URL: {ip}"
        return self.block_ip(ip)
