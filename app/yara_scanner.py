import yara
from app.logging_config import log_security_event

RULES = """
rule MaliciousFile
{
    strings:
        $malicious_string = "malware"
    condition:
        $malicious_string
}
"""

def scan_file(file_path):
    rules = yara.compile(source=RULES)
    matches = rules.match(file_path)

    # Registrar el evento en Elasticsearch
    log_security_event("FILE_SCAN", file_path, "THREAT FOUND" if matches else "CLEAN")

    return matches

