from pathlib import Path
import yara

RULES = Path(__file__).parent / "signature" / "rules.yar"

def scan(path):
    rules = yara.compile(filepath=str(RULES))
    findings = []
    for m in rules.match(str(path)):
        desc = m.meta.get("description", "")
        level = m.meta.get("severity", "medium")
        findings.append((level, f"YARA {m.rule}: {desc}"))
    return findings