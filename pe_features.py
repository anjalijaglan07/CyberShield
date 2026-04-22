import math
from dataclasses import dataclass
from typing import Dict, List, Tuple

import pefile


DEFAULT_FEATURES = [
    "AddressOfEntryPoint",
    "MajorLinkerVersion",
    "MajorImageVersion",
    "MajorOperatingSystemVersion",
    "DllCharacteristics",
    "SizeOfStackReserve",
    "NumberOfSections",
    "SizeOfImage",
    "SizeOfCode",
    "SizeOfInitializedData",
    "SizeOfUninitializedData",
    "Subsystem",
    "ImageBase",
    "SectionAlignment",
    "FileAlignment",
    "ImportsCount",
    "ImportsDLLCount",
    "ExportsCount",
    "HasTLS",
    "HasDebug",
    "HasReloc",
    "SectionsMeanEntropy",
    "SectionsMaxEntropy",
    "SectionsMinEntropy",
    "SectionsMeanRawSize",
    "SectionsMeanVirtualSize",
    "SectionsMaxVirtualSize",
]


SUSPICIOUS_IMPORTS = {
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "OpenProcess",
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
}


@dataclass
class PEAnalysis:
    features: Dict[str, float]
    signals: List[str]
    imphash: str | None


def _safe_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    data_len = len(data)
    for c in counts:
        if c:
            p = c / data_len
            entropy -= p * math.log2(p)
    return entropy


def _section_stats(pe: pefile.PE) -> Tuple[float, float, float, float, float, float]:
    entropies = []
    raw_sizes = []
    virtual_sizes = []
    for section in pe.sections:
        try:
            data = section.get_data() or b""
        except Exception:
            data = b""
        entropies.append(_safe_entropy(data))
        raw_sizes.append(section.SizeOfRawData or 0)
        virtual_sizes.append(section.Misc_VirtualSize or 0)
    if not entropies:
        return 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
    return (
        sum(entropies) / len(entropies),
        max(entropies),
        min(entropies),
        sum(raw_sizes) / len(raw_sizes),
        sum(virtual_sizes) / len(virtual_sizes),
        max(virtual_sizes),
    )


def _imports_stats(pe: pefile.PE) -> Tuple[int, int, List[str]]:
    imports_count = 0
    dll_count = 0
    suspicious = set()
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_count += 1
            for imp in entry.imports:
                imports_count += 1
                name = (imp.name.decode(errors="ignore") if imp.name else "").strip()
                if name in SUSPICIOUS_IMPORTS:
                    suspicious.add(name)
    return imports_count, dll_count, sorted(suspicious)


def extract_pe_features(file_bytes: bytes) -> PEAnalysis:
    pe = pefile.PE(data=file_bytes, fast_load=False)
    pe.parse_data_directories()

    imports_count, dll_count, suspicious_imports = _imports_stats(pe)
    mean_ent, max_ent, min_ent, mean_raw, mean_virt, max_virt = _section_stats(pe)

    features = {
        "AddressOfEntryPoint": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        "MajorLinkerVersion": pe.OPTIONAL_HEADER.MajorLinkerVersion,
        "MajorImageVersion": pe.OPTIONAL_HEADER.MajorImageVersion,
        "MajorOperatingSystemVersion": pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        "DllCharacteristics": pe.OPTIONAL_HEADER.DllCharacteristics,
        "SizeOfStackReserve": pe.OPTIONAL_HEADER.SizeOfStackReserve,
        "NumberOfSections": len(pe.sections),
        "SizeOfImage": pe.OPTIONAL_HEADER.SizeOfImage,
        "SizeOfCode": pe.OPTIONAL_HEADER.SizeOfCode,
        "SizeOfInitializedData": pe.OPTIONAL_HEADER.SizeOfInitializedData,
        "SizeOfUninitializedData": pe.OPTIONAL_HEADER.SizeOfUninitializedData,
        "Subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "ImageBase": pe.OPTIONAL_HEADER.ImageBase,
        "SectionAlignment": pe.OPTIONAL_HEADER.SectionAlignment,
        "FileAlignment": pe.OPTIONAL_HEADER.FileAlignment,
        "ImportsCount": imports_count,
        "ImportsDLLCount": dll_count,
        "ExportsCount": 1 if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else 0,
        "HasTLS": 1 if hasattr(pe, "DIRECTORY_ENTRY_TLS") else 0,
        "HasDebug": 1 if hasattr(pe, "DIRECTORY_ENTRY_DEBUG") else 0,
        "HasReloc": 1 if hasattr(pe, "DIRECTORY_ENTRY_BASERELOC") else 0,
        "SectionsMeanEntropy": mean_ent,
        "SectionsMaxEntropy": max_ent,
        "SectionsMinEntropy": min_ent,
        "SectionsMeanRawSize": mean_raw,
        "SectionsMeanVirtualSize": mean_virt,
        "SectionsMaxVirtualSize": max_virt,
    }

    signals = []
    if max_ent > 7.2 and len(pe.sections) >= 2:
        signals.append("High section entropy (possible packing/obfuscation)")
    if imports_count == 0:
        signals.append("No imports found (unusual for benign EXE)")
    if suspicious_imports:
        signals.append(f"Suspicious imports: {', '.join(suspicious_imports[:6])}")
    if not hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"):
        signals.append("No base relocations")

    imphash = None
    try:
        imphash = pe.get_imphash()
    except Exception:
        imphash = None

    return PEAnalysis(features=features, signals=signals, imphash=imphash)


def features_to_vector(features: Dict[str, float], feature_order: List[str]) -> List[float]:
    return [float(features.get(name, 0)) for name in feature_order]
