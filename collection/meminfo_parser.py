"""Parse `adb shell dumpsys meminfo -a <package>` into CCCS-CIC-AndMal-2020 memory features.
"""
import re

# The 23 AndMal2020 memory features.
ANDMAL_MEMORY_COLUMNS = [
    "Memory_PssTotal", "Memory_PssClean", "Memory_SharedDirty", "Memory_PrivateDirty",
    "Memory_SharedClean", "Memory_PrivateClean", "Memory_SwapPssDirty",
    "Memory_HeapSize", "Memory_HeapAlloc", "Memory_HeapFree",
    "Memory_Views", "Memory_ViewRootImpl", "Memory_AppContexts", "Memory_Activities",
    "Memory_Assets", "Memory_AssetManagers", "Memory_LocalBinders", "Memory_ProxyBinders",
    "Memory_ParcelMemory", "Memory_ParcelCount", "Memory_DeathRecipients",
    "Memory_OpenSSLSockets", "Memory_WebViews",
]

_TOTAL_RE = re.compile(r"^[ \t]*TOTAL(?=[ \t])(?:[ \t]+(?:\d+|N/A|-))+[ \t]*$")
_PAIR_RE = re.compile(r"([A-Za-z][A-Za-z ]*?):\s+(\d+)")
_PROCESS_RE = re.compile(r"^[ \t]*\*\* MEMINFO in pid \d+ \[([^\]]+)\] \*\*[ \t]*\r?$", re.MULTILINE)


def parse_meminfo(text: str, *, process_name: str | None = None) -> dict[str, int | None]:
    """Read the available measurements for a single process."""
    # Read the table and object counts from the same process.
    processes = list(_PROCESS_RE.finditer(text))
    for i, process in enumerate(processes):
        if process_name is None or process[1] == process_name:
            end = processes[i + 1].start() if i + 1 < len(processes) else len(text)
            text = text[process.end():end]
            break
    else:
        if process_name is not None:
            return {}

    lines = text.splitlines()
    out = {}

    # Join the two column headers (for example, Pss + Total) and read the TOTAL row.
    for i, line in enumerate(lines):
        if line.strip().startswith("------") and i >= 2:
            top, bottom = lines[i - 2].split(), lines[i - 1].split()
            if len(top) != len(bottom) or not top or top[0] != "Pss":
                continue
            names = [a + b for a, b in zip(top, bottom)]
            for later in lines[i + 1:]:
                if not later.strip():
                    break
                if _TOTAL_RE.fullmatch(later):
                    values = list(re.finditer(r"\d+|N/A|-", later))
                    if len(values) == len(names):
                        pairs = zip(names, (v[0] for v in values))
                    else:
                        # Android right-aligns values, so blank cells preserve the other columns.
                        at_end = {v.end(): v[0] for v in values}
                        columns = list(re.finditer(r"-{6,}", line))
                        pairs = ((n, at_end.get(col.end(), "")) for n, col in zip(names, columns))
                    for n, v in pairs:
                        if v.isdigit():
                            out["Memory_" + n] = int(v)
                    break
            break

    # The "Objects" section uses pairs such as "Views:   12   ViewRootImpl:   1"
    in_objects = False
    for line in lines:
        s = line.strip()
        if s == "Objects":
            in_objects = True
            continue
        if in_objects:
            if s in ("SQL", "DATABASES", "Asset Allocations") or s.startswith("Dalvik"):
                break
            for name, value in _PAIR_RE.findall(line):
                # "Parcel memory" -> "ParcelMemory", "OpenSSL Sockets" -> "OpenSSLSockets"
                key = "".join(w[0].upper() + w[1:] for w in name.split())
                out["Memory_" + key] = int(value)
    return out


def to_andmal_row(parsed: dict) -> dict[str, int | None]:
    """Return all 23 expected features using None for missing measurements."""
    return {c: parsed.get(c) for c in ANDMAL_MEMORY_COLUMNS}
