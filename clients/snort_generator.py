import os
from datetime import datetime

class SnortRuleGenerator:
    """
    Generates and writes Snort detection rules based on suspicious IOCs.
    """

    def __init__(self, output_dir: str = "snort_rules"):
        """
        Initialize the generator with an optional output directory.
        """
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_ip_rule(self, ip: str, sid: int = 1000001, rev: int = 1) -> str:
        """
        Generate a Snort alert rule for a given malicious IP address.
        
        Returns the rule string.
        """
        return f'alert ip {ip} any -> any any (msg:"IOCScanner: Malicious IP detected {ip}"; sid:{sid}; rev:{rev};)'

    def write_rule_to_file(self, rule: str, ip: str) -> str:
        """
        Write the rule to a timestamped .rules file and return the path.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        filename = f"{self.output_dir}/malicious_{ip}_{timestamp}.rules"
        with open(filename, "w") as f:
            f.write(rule + "\n")
        return filename

    def generate_and_save_ip_rule(self, ip: str) -> str:
        """
        Full pipeline: generate IP rule and save it.
        Returns the filepath.
        """
        rule = self.generate_ip_rule(ip)
        path = self.write_rule_to_file(rule, ip)
        return path
