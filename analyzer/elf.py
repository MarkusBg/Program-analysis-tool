def analyze_elf(binary):
    findings = []

    if len(binary.sections) == 0:
        findings.append(("high", "There is no section table (it has been removed or the file is compressed)"))

    if not binary.has_nx:
        findings.append(("medium", "NX is disabled (executable stack)"))

    if not binary.is_pie:
        findings.append(("low", "Not PIE (no address randomization)"))

    if len(list(binary.symbols)) == 0:
        findings.append(("low", "The file is stripped (no characters)"))

    # сегменты W+X (флаги ELF: X=1, W=2, R=4)
    for seg in binary.segments:
        f = int(seg.flags)
        if (f & 1) and (f & 2):
            findings.append(("high", "A segment that is written to and executed simultaneously (W+X)"))

    return findings