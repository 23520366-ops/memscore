"""Map Volatility 3 output to CIC-MalMem-2022 columns."""

from collections import Counter


PLUGINS = {
    "pslist": "windows.pslist.PsList",
    "dlllist": "windows.dlllist.DllList",
    "handles": "windows.handles.Handles",
    "ldrmodules": "windows.malware.ldrmodules.LdrModules",
    "malfind": "windows.malware.malfind.Malfind",
    "psxview": "windows.malware.psxview.PsXView",
    "modules": "windows.modules.Modules",
    "svcscan": "windows.svcscan.SvcScan",
    "callbacks": "windows.callbacks.Callbacks",
}

HANDLE_TYPES = ("Port", "File", "Event", "Desktop", "Key", "Thread", "Directory",
                "Semaphore", "Timer", "Section", "Mutant")

PSX_SOURCES = {
    "pslist": "pslist", "eprocess_pool": "psscan", "ethread_pool": "thrdscan",
    "pspcid_list": None, "csrss_handles": "csrss", "session": None, "deskthrd": None,
}

SERVICE_TYPES = {
    "kernel_drivers": "SERVICE_KERNEL_DRIVER", "fs_drivers": "SERVICE_FILE_SYSTEM_DRIVER",
    "process_services": "SERVICE_WIN32_OWN_PROCESS", "shared_process_services": "SERVICE_WIN32_SHARE_PROCESS",
    "interactive_process_services": "SERVICE_INTERACTIVE_PROCESS",
}

# Volatility 3 reports protection names; VolMemLyzer summed Volatility 2 numeric codes. This mapping is an approximation.
PROTECTION_CODES = {
    "PAGE_NOACCESS": 0, "PAGE_READONLY": 1, "PAGE_EXECUTE": 2, "PAGE_EXECUTE_READ": 3,
    "PAGE_READWRITE": 4, "PAGE_WRITECOPY": 5, "PAGE_EXECUTE_READWRITE": 6, "PAGE_EXECUTE_WRITECOPY": 7,
}

FEATURE_NOTES = {
    "pslist.nprocs64bit": "Count Wow64=true following VolMemLyzer. The original column name refers to 64-bit processes.",
    "pslist.avg_handlers": "Fall back to the number of handle records for the PID when the EPROCESS count is missing.",
    "handles.nport": "Count Port records as in the original dataset. ALPC Port has a separate type.",
    "malfind.ninjections": "Count the regions reported by Malfind 3, which uses a different filter from Volatility 2.",
    "malfind.commitCharge": "Sum CommitCharge over the regions reported by Malfind 3, in pages.",
    "malfind.protection": "Sum the base VAD protection codes mapped from PAGE_* names.",
    "malfind.uniqueInjections": "Divide the number of regions by the number of distinct PIDs, following VolMemLyzer.",
    "svcscan.interactive_process_services": "Count records of type SERVICE_INTERACTIVE_PROCESS, following VolMemLyzer.",
    "callbacks.nanonymous": "Count callbacks whose module is unidentified in Volatility 3.",
}

for source, column in PSX_SOURCES.items():
    note = (f"Use {column} from the combined Volatility 3 process set."
            if column else "Volatility 3 PsXView lacks an equivalent source.")
    FEATURE_NOTES[f"psxview.not_in_{source}"] = note
    FEATURE_NOTES[f"psxview.not_in_{source}_false_avg"] = note


def mean(values):
    return sum(values) / len(values) if values else None


def mean_known(values):
    """Mean of the values that were actually measured; None when nothing was measured."""
    known = [v for v in values if type(v) in (int, float)]
    return sum(known) / len(known) if known else None


def average_per_pid(rows):
    return len(rows) / len({r["PID"] for r in rows}) if rows else 0


def extract_features(rows_by_plugin):
    """Convert plugin JSON rows. PsXView can be None if it was unavailable."""
    processes = rows_by_plugin["pslist"]
    dlls = rows_by_plugin["dlllist"]
    handles = rows_by_plugin["handles"]
    handle_by_pid = Counter(r["PID"] for r in handles)
    handle_types = Counter(r["Type"] for r in handles)
    loader = rows_by_plugin["ldrmodules"]
    injections = rows_by_plugin["malfind"]
    services = rows_by_plugin["svcscan"]
    callbacks = rows_by_plugin["callbacks"]

    protection = [PROTECTION_CODES.get(r["Protection"].split("|")[0])
                  if isinstance(r["Protection"], str) else None for r in injections]
    commits = [r["CommitCharge"] for r in injections]
    out = {
        "pslist.nproc": len(processes),
        "pslist.nppid": len({r["PPID"] for r in processes}),
        "pslist.avg_threads": mean_known(r.get("Threads") for r in processes),
        "pslist.nprocs64bit": sum(r["Wow64"] is True for r in processes),
        # Volatility 3 often leaves PsList Handles empty; fall back to the Handles plugin only for PIDs it saw.
        "pslist.avg_handlers": mean_known(
            r["Handles"] if type(r.get("Handles")) is int and r["Handles"] >= 0
            else handle_by_pid.get(r["PID"]) for r in processes
        ),
        "dlllist.ndlls": len(dlls),
        "dlllist.avg_dlls_per_proc": average_per_pid(dlls),
        "handles.nhandles": len(handles),
        "handles.avg_handles_per_proc": average_per_pid(handles),
        **{f"handles.n{name.lower()}": handle_types[name] for name in HANDLE_TYPES},
    }

    for key, column in (("load", "InLoad"), ("init", "InInit"), ("mem", "InMem")):
        count = sum(r[column] is False for r in loader)
        out[f"ldrmodules.not_in_{key}"] = count
        # The original extractor substitutes 1 for a zero ratio when plugin data is available.
        out[f"ldrmodules.not_in_{key}_avg"] = (count / len(loader) or 1) if loader else None

    out.update({
        "malfind.ninjections": len(injections),
        "malfind.commitCharge": sum(commits) if all(type(v) is int for v in commits) else None,
        "malfind.protection": sum(protection) if None not in protection else None,
        "malfind.uniqueInjections": average_per_pid(injections),
    })

    cross_view = rows_by_plugin.get("psxview")
    for key, column in PSX_SOURCES.items():
        flags = [r.get(column) for r in cross_view] if cross_view and column else []
        count = flags.count(False) if flags and all(type(flag) is bool for flag in flags) else None
        out[f"psxview.not_in_{key}"] = count
        out[f"psxview.not_in_{key}_false_avg"] = count / len(flags) if count is not None else None

    service_types = Counter(r["Type"] for r in services)
    out.update({
        "modules.nmodules": len(rows_by_plugin["modules"]),
        "svcscan.nservices": len(services),
        **{f"svcscan.{key}": service_types[value] for key, value in SERVICE_TYPES.items()},
        "svcscan.nactive": sum(r["State"] == "SERVICE_RUNNING" for r in services),
        "callbacks.ncallbacks": len(callbacks),
        "callbacks.nanonymous": sum(r["Module"] in (None, "UNKNOWN", "N/A", "") for r in callbacks),
        "callbacks.ngeneric": sum(r["Type"] == "GenericKernelCallback" for r in callbacks),
    })
    return out
