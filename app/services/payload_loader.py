import os
from typing import List

class PayloadLoader:
    def __init__(self, payloads_dir: str = "payloads"):
        self.payloads_dir = payloads_dir

    def load_payloads(self, filename: str) -> List[str]:
        """Loads payloads from a file in the payloads directory."""
        path = os.path.join(self.payloads_dir, filename)
        if not os.path.exists(path):
            return []
        
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]

    def get_sqli_payloads(self) -> List[str]:
        return self.load_payloads("sqli.txt")

    def get_xss_payloads(self) -> List[str]:
        return self.load_payloads("xss.txt")

    def get_cmd_payloads(self) -> List[str]:
        return self.load_payloads("cmd.txt")

    def get_lfi_payloads(self) -> List[str]:
        return self.load_payloads("lfi.txt")

payload_loader = PayloadLoader()
