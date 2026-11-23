from .common import analyze_common
from .pe import analyze_pe
from .elf import analyze_elf

def analyze(binary, fmt):
    findings = analyze_common(binary, fmt)
    if fmt == "PE":
        findings += analyze_pe(binary)
    elif fmt == "ELF":
        findings += analyze_elf(binary)
    return findings