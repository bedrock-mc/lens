"""Standalone IDAPython worker used by :mod:`bedrock_lens.ida`.

This file intentionally imports only IDA modules. It is launched inside IDA with
``-S`` and communicates with the host process through a JSON request/result file.
"""

from __future__ import annotations

import json
import traceback
from pathlib import Path


def _parameter_count(address: int) -> int:
    try:
        import ida_nalt
        import ida_typeinf

        type_info = ida_typeinf.tinfo_t()
        if not ida_nalt.get_tinfo(type_info, address):
            return 0
        details = ida_typeinf.func_type_data_t()
        if not type_info.get_func_details(details):
            return 0
        return int(details.size())
    except Exception:
        return 0


def _collect_functions() -> list[dict[str, object]]:
    import ida_funcs
    import ida_nalt
    import idautils

    image_base = int(ida_nalt.get_imagebase())
    strings_by_function: dict[int, set[tuple[int, str]]] = {}
    for item in idautils.Strings():
        try:
            address = int(item.ea)
            value = str(item)
        except Exception:
            continue
        for reference in idautils.XrefsTo(address, 0):
            function = ida_funcs.get_func(reference.frm)
            if function is not None:
                strings_by_function.setdefault(int(function.start_ea), set()).add(
                    (address - image_base, value)
                )

    functions: list[dict[str, object]] = []
    for address in idautils.Functions():
        function = ida_funcs.get_func(address)
        if function is None:
            continue
        start = int(function.start_ea)
        name = ida_funcs.get_func_name(start) or f"sub_{start:x}"
        namespace, separator, _ = name.rpartition("::")
        functions.append(
            {
                "rva": start - image_base,
                "name": name,
                "namespace": namespace if separator else "",
                "size": max(0, int(function.end_ea) - start),
                "parameter_count": _parameter_count(start),
                "strings": [
                    {"address": address, "value": value}
                    for address, value in sorted(strings_by_function.get(start, set()))
                ],
            }
        )
    return functions


def _decompile(rva: int) -> dict[str, object]:
    import ida_funcs
    import ida_hexrays
    import ida_nalt

    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("IDA Hex-Rays decompiler is unavailable")
    image_base = int(ida_nalt.get_imagebase())
    address = image_base + rva
    function = ida_funcs.get_func(address)
    if function is None:
        raise KeyError(f"no function contains RVA 0x{rva:x}")
    decompiled = ida_hexrays.decompile(function)
    if decompiled is None:
        raise RuntimeError(f"Hex-Rays could not decompile RVA 0x{rva:x}")
    name = ida_funcs.get_func_name(int(function.start_ea)) or f"sub_{int(function.start_ea):x}"
    return {
        "rva": int(function.start_ea) - image_base,
        "name": name,
        "code": str(decompiled),
    }


def _exit(code: int) -> None:
    import idc

    idc.qexit(code)


def main() -> None:
    import ida_auto
    import idc

    arguments = list(getattr(idc, "ARGV", []))
    if len(arguments) < 2:
        raise RuntimeError("IDA worker requires a JSON request path")
    request_path = Path(arguments[1])
    request = json.loads(request_path.read_text(encoding="utf-8"))
    output_path = Path(request["output"])
    try:
        ida_auto.auto_wait()
        mode = request["mode"]
        if mode == "analyze":
            result: dict[str, object] = {"functions": _collect_functions()}
        elif mode == "decompile":
            result = _decompile(int(request["rva"]))
        else:
            raise ValueError(f"unknown IDA worker mode: {mode}")
        output_path.write_text(json.dumps(result), encoding="utf-8")
    except Exception:
        output_path.write_text(
            json.dumps({"error": traceback.format_exc()}),
            encoding="utf-8",
        )
        _exit(1)
    _exit(0)


if __name__ == "__main__":
    main()
