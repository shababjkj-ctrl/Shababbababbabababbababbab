# -*- coding: utf-8 -*-
"""
Device pool: ~35 different phone models with matching specs (GPU, screen, DPI, RAM, CPU).
Every account gets its OWN device: the least-used model is picked, and all IDs are unique.
Run `python regen_devices.py` to give every saved account a brand-new device.
"""
import json
import os
import random
import secrets
import uuid
from collections import Counter

# brand, model, gpu, width, height, dpi, ram_options_MB, cpu_mhz, cpu_cores, android_versions
CATALOG = [
    ("Samsung", "SM-A546E", "Mali-G68 MC4", 1080, 2340, 403, [6144, 8192], 2400, 8, [13, 14]),
    ("Samsung", "SM-A346E", "Mali-G68 MC4", 1080, 2340, 390, [6144, 8192], 2400, 8, [13, 14]),
    ("Samsung", "SM-A245F", "Mali-G52 MC2", 1080, 2340, 396, [4096, 6144, 8192], 2200, 8, [13, 14]),
    ("Samsung", "SM-A145F", "Mali-G52 MC2", 1080, 2408, 400, [4096, 6144], 2000, 8, [13, 14]),
    ("Samsung", "SM-A525F", "Adreno (TM) 618", 1080, 2400, 411, [6144, 8192], 2300, 8, [12, 13]),
    ("Samsung", "SM-A736B", "Adreno (TM) 642L", 1080, 2400, 393, [6144, 8192], 2400, 8, [12, 13, 14]),
    ("Samsung", "SM-M336B", "Mali-G68 MC4", 1080, 2408, 400, [6144, 8192], 2400, 8, [12, 13]),
    ("Samsung", "SM-G991B", "Mali-G78 MP14", 1080, 2400, 421, [8192], 2900, 8, [12, 13, 14]),
    ("Samsung", "SM-G998B", "Mali-G78 MP14", 1440, 3200, 515, [12288], 2900, 8, [12, 13]),
    ("Samsung", "SM-G973F", "Mali-G76 MP12", 1080, 2280, 424, [6144], 2700, 8, [11, 12]),
    ("Samsung", "SM-S911B", "Adreno (TM) 740", 1080, 2340, 425, [8192], 3360, 8, [13, 14]),
    ("Samsung", "SM-S918B", "Adreno (TM) 740", 1440, 3088, 500, [8192, 12288], 3360, 8, [13, 14]),
    ("Xiaomi", "2201122G", "Adreno (TM) 730", 1080, 2400, 419, [8192, 12288], 2995, 8, [12, 13]),
    ("Xiaomi", "2210132G", "Adreno (TM) 740", 1080, 2400, 414, [8192, 12288], 3200, 8, [13, 14]),
    ("Xiaomi", "2203121C", "Adreno (TM) 730", 1440, 3200, 522, [12288], 3000, 8, [12, 13]),
    ("Xiaomi", "21081111RG", "Mali-G77 MC9", 1080, 2400, 395, [8192], 2600, 8, [11, 12, 13]),
    ("Redmi", "2201116SG", "Mali-G76 MC4", 1080, 2400, 395, [6144, 8192], 2200, 8, [11, 12, 13]),
    ("Redmi", "22101316G", "Mali-G68 MC4", 1080, 2400, 395, [6144, 8192], 2600, 8, [12, 13]),
    ("Redmi", "M2101K6G", "Adreno (TM) 618", 1080, 2400, 395, [6144, 8192], 2300, 8, [11, 12, 13]),
    ("Redmi", "2201117TG", "Adreno (TM) 610", 1080, 2400, 409, [4096, 6144], 2000, 8, [11, 12, 13]),
    ("Redmi", "220333QAG", "Adreno (TM) 610", 720, 1650, 268, [3072, 4096], 2000, 8, [11, 12, 13]),
    ("Poco", "M2102J20SG", "Adreno (TM) 640", 1080, 2400, 395, [6144, 8192], 2300, 8, [11, 12, 13]),
    ("Poco", "2201116PG", "Adreno (TM) 619", 1080, 2400, 395, [6144, 8192], 2400, 8, [12, 13]),
    ("Poco", "22111317PG", "Adreno (TM) 619", 1080, 2400, 395, [6144, 8192], 2400, 8, [12, 13]),
    ("Poco", "M2007J20CG", "Adreno (TM) 618", 1080, 2400, 395, [6144], 2300, 8, [11, 12, 13]),
    ("Realme", "RMX3370", "Adreno (TM) 642L", 1080, 2400, 411, [8192, 12288], 2400, 8, [12, 13]),
    ("Realme", "RMX3085", "Mali-G76 MC4", 1080, 2400, 409, [4096, 6144, 8192], 2050, 8, [11, 12, 13]),
    ("Realme", "RMX3700", "Mali-G68 MC4", 1080, 2412, 394, [8192], 2600, 8, [13, 14]),
    ("OnePlus", "CPH2451", "Adreno (TM) 740", 1440, 3216, 525, [12288, 16384], 3200, 8, [13, 14]),
    ("OnePlus", "IN2013", "Adreno (TM) 650", 1080, 2400, 402, [8192, 12288], 2840, 8, [11, 12, 13]),
    ("OnePlus", "LE2111", "Adreno (TM) 660", 1080, 2400, 402, [8192, 12288], 2840, 8, [12, 13]),
    ("OPPO", "CPH2611", "Adreno (TM) 720", 1080, 2400, 394, [8192], 3200, 8, [14]),
    ("vivo", "V2027", "Adreno (TM) 610", 720, 1600, 268, [3072, 4096], 1800, 8, [11, 12]),
]

_API = {11: 30, 12: 31, 13: 33, 14: 34}
_BUILD = {
    11: ["RP1A.200720.012", "RKQ1.201004.002", "RKQ1.211019.001"],
    12: ["SP1A.210812.016", "SKQ1.211006.001", "SP2A.220305.013", "SKQ1.220303.001"],
    13: ["TP1A.220624.014", "TKQ1.221114.001", "TP1A.221005.002", "TQ2A.230405.003"],
    14: ["UP1A.231005.007", "UKQ1.230917.001", "UP1A.231105.001", "UQ1A.240105.004"],
}


def _used_ids(devices: dict, field: str) -> set:
    return {str(d.get(field)) for d in devices.values() if isinstance(d, dict)}


def _unique_hex(devices: dict, field: str, nbytes: int = 8) -> str:
    used = _used_ids(devices, field)
    while True:
        v = secrets.token_hex(nbytes)
        if v not in used:
            return v


def make_device(devices: dict) -> dict:
    """Build one new device. `devices` = already saved devices (used to spread models + keep IDs unique)."""
    usage = Counter(d.get("model") for d in devices.values() if isinstance(d, dict))
    least = min(usage.get(c[1], 0) for c in CATALOG)
    pool = [c for c in CATALOG if usage.get(c[1], 0) == least]
    brand, model, gpu, w, h, dpi, rams, mhz, cores, androids = random.choice(pool)
    ver = random.choice(androids)
    build = random.choice(_BUILD[ver])
    ram = random.choice(rams)
    return {
        "unique_device_id": f"Google|{uuid.uuid4()}",
        "brand": brand,
        "model": model,
        "gpu_renderer": gpu,
        "system_software": f"Android OS {ver} / API-{_API[ver]}",
        "screen_width": w,
        "screen_height": h,
        "screen_dpi": str(dpi),
        "memory": int(ram * random.uniform(0.88, 0.96)),
        "processor_details": f"ARM64 FP ASIMD AES VMH | {mhz + random.randint(-40, 0)} | {cores}",
        "client_ip": f"{random.randint(103, 223)}.{random.randint(10, 250)}.{random.randint(10, 250)}.{random.randint(10, 250)}",
        "android_id": _unique_hex(devices, "android_id"),
        "gsf_id": _unique_hex(devices, "gsf_id"),
        "build_fingerprint": f"{brand.lower()}/{model}/{model}:{ver}/{build}/{random.randint(1000000, 9999999)}:user/release-keys",
        "serial_number": _unique_hex(devices, "serial_number"),
        "hardware_id": _unique_hex(devices, "hardware_id"),
    }


def regenerate_all(path: str = "devices.json", backup: bool = True) -> int:
    """Give every saved account a new device (keeps the account keys)."""
    old = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            old = json.load(f)
        if backup:
            with open(path + ".bak", "w", encoding="utf-8") as f:
                json.dump(old, f, indent=4)
    new = {}
    for key in old:
        new[key] = make_device(new)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(new, f, indent=4)
    return len(new)
