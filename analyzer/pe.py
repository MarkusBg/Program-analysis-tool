# Flags from the PE specification (standard numbers; not dependent on the LIEF version)
MEM_EXECUTE = 0x20000000
MEM_WRITE   = 0x80000000

STANDARD_SECTIONS = {".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata",
                     ".edata", ".pdata", ".xdata", ".bss", ".tls", ".CRT",
                     ".gfids", ".didat"}

def analyze_pe(binary):
    findings = []

    # секции: W+X и нестандартные имена
    for s in binary.sections:
        ch = s.characteristics
        if (ch & MEM_EXECUTE) and (ch & MEM_WRITE):
            findings.append(("high", f"Секция {s.name} одновременно записываемая и исполняемая (W+X)"))
        if s.name not in STANDARD_SECTIONS:
            findings.append(("low", f"Нестандартное имя секции: {s.name}"))

    # entry point вне секции кода
    ep = binary.optional_header.addressof_entrypoint
    owner = next((s for s in binary.sections
                  if s.virtual_address <= ep < s.virtual_address + s.virtual_size), None)
    if owner is None:
        findings.append(("high", "Entry point не попадает ни в одну секцию"))
    elif owner.name != ".text":
        findings.append(("medium", f"Entry point находится в секции {owner.name}, а не в .text"))

    # таймстемп
    ts = binary.header.time_date_stamps
    if ts == 0:
        findings.append(("low", "Нулевой timestamp компиляции"))

    return findings