"""gathering results and bulding up the report"""
import json
import os
from datetime import datetime
from loader import load
from analyzer import analyze
from analyzer.common import entropy
# YARA unnecessary: in case yara-python didn't downloaded, report will be writed
try:
    from yara_scan import scan
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

WEIGHTS = {"high": 3, "medium": 2, "low": 1}
LEVEL_ORDER = {"high": 0, "medium": 1, "low": 2}


def _safe(func, default="?"):
    """The LIEF fields vary between versions, give them no chance to break the report."""
    try:
        return func()
    except Exception:
        return default


def _architecture(binary):
    machine = _safe(lambda: binary.header.machine_type)
    # using architecture name to write it in the report
    return str(machine).split(".")[-1]


def _sections(binary):
    rows = []
    for s in binary.sections:
        rows.append({
            "name": s.name or "(without name)",
            "virtual_address": hex(s.virtual_address),
            "size": s.size,
            "entropy": round(entropy(bytes(s.content)), 2),
        })
    return rows


def _imports(binary, fmt):
    """return {library: [function]}."""
    groups = {}
    if fmt == "PE":
        for lib in binary.imports:
            groups[lib.name] = sorted(e.name or "(According to the order)" for e in lib.entries)
    else:
        # in ELF - one group
        names = sorted({f.name for f in binary.imported_functions if f.name})
        if names:
            groups["importing fuctions"] = names
    return groups


def _risk(findings):
    score = sum(WEIGHTS.get(f["level"], 0) for f in findings)
    if score >= 9:
        verdict = "High"
    elif score >= 4:
        verdict = "medium"
    else:
        verdict = "low"
    return score, verdict


def build_report(path):
    """main function: Analyzes a file and returns a dictionary report."""
    path = str(path)
    fmt, bits, binary, hashes = load(path)

    raw = analyze(binary, fmt)
    notes = []
    if YARA_AVAILABLE:
        try:
            raw += scan(path)
        except Exception as e:
            notes.append(f"YARA didn't worked: {e}")
    else:
        notes.append("yara-python is not downloaded: signatures missed")

    findings = [{"level": lvl, "message": msg} for lvl, msg in raw]
    findings.sort(key=lambda f: LEVEL_ORDER.get(f["level"], 9))
    score, verdict = _risk(findings)

    return {
        "file": path,
        "file_name": os.path.basename(path),
        "size": os.path.getsize(path),
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "format": fmt,
        "bits": bits,
        "arch": _architecture(binary),
        "entry_point": hex(binary.entrypoint),
        "hashes": hashes,
        "sections": _sections(binary),
        "libraries": _safe(lambda: [str(lib) for lib in binary.libraries], []),
        "imports": _imports(binary, fmt),
        "findings": findings,
        "risk_score": score,
        "verdict": verdict,
        "notes": notes,
    }


def format_text(r):
    """Text-based report (for console and tabs «Overview»)."""
    lines = [
        f"File:        {r['file_name']} ({r['size']} bite)",
        f"Path:        {r['file']}",
        f"Format:      {r['format']}, {r['bits']} bite, architecture {r['arch']}",
        f"Entry point: {r['entry_point']}",
        f"Risk:        {r['verdict']} ({r['risk_score']} points)",
        f"Analiz:      {r['analyzed_at']}",
        "",
        "--- hashes ---",
    ]
    lines += [f"{name:7} {value}" for name, value in r["hashes"].items()]

    lines += ["", "--- sections ---"]
    for s in r["sections"]:
        lines.append(f"{s['name']:22} {s['virtual_address']:>12} {s['size']:>10}  entropy {s['entropy']:.2f}")

    lines += ["", "--- libraries ---"]
    lines += r["libraries"] or ["(no)"]

    lines += ["", "--- Findings ---"]
    if r["findings"]:
        lines += [f"[{f['level'].upper()}] {f['message']}" for f in r["findings"]]
    else:
        lines.append("Nothin suspicious were found")

    if r["notes"]:
        lines += ["", "--- notes ---"] + r["notes"]
    return "\n".join(lines)


def save_json(report, out_path):
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
