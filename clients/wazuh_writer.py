import os
from datetime import datetime

class WazuhRuleWriter:
    """
    Generates and writes Wazuh custom alert rules based on malicious file hashes.
    """

    def __init__(self, rule_id_start=100100, rules_path="wazuh_rules"):
        self.rule_id = rule_id_start
        self.rules_path = rules_path
        os.makedirs(self.rules_path, exist_ok=True)

    def generate_xml_rule(self, sha256: str, description: str = "Malicious file hash detected") -> str:
        """
        Generate Wazuh XML rule block for a SHA256 hash.
        """
        return f"""<group name="iocscanner">
  <rule id="{self.rule_id}" level="12">
    <decoded_as>json</decoded_as>
    <field name="hash">{sha256}</field>
    <description>IOCScanner: {description}</description>
  </rule>
</group>"""

    def write_rule_to_file(self, rule: str, sha256: str) -> str:
        """
        Write the generated rule to a file.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        filename = f"{self.rules_path}/malicious_hash_{sha256[:6]}_{timestamp}.xml"
        with open(filename, "w") as f:
            f.write(rule + "\n")
        return filename

    def create_rule(self, sha256: str, description: str = "Malicious file hash detected") -> str:
        """
        Full pipeline: generate + write to file
        """
        rule = self.generate_xml_rule(sha256, description)
        return self.write_rule_to_file(rule, sha256)
