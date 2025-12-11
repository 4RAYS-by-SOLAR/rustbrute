import os
import sys

import idaapi
import idc

HASH_LEN = 16
HASH_PREFIX = "::h"


def _unescape(input_str, sequence, value):
    """Unescape a sequence in the input string if it starts with the given sequence."""
    if input_str.startswith(sequence):
        return value, input_str[len(sequence):]
    return None, input_str


def _strip_symbol_prefix_legacy(sym):
    """Strip legacy symbol prefixes from Rust mangled symbols."""
    if sym.startswith("__ZN"):
        return sym[len("__ZN"):]
    if sym.startswith("_ZN"):
        return sym[len("_ZN"):]
    if sym.startswith("ZN"):
        return sym[len("ZN"):]
    return None


def _rust_demangle_symbol_element_legacy(legacy_symbol_element):
    """Demangle a single element of a legacy Rust symbol."""
    i = 0
    output = ""
    input_str = legacy_symbol_element
    last_char = '\0'

    while input_str:
        c = input_str[0]
        if c == '$':
            replacements = [
                ("$C$", ','), ("$SP$", '@'), ("$BP$", '*'), ("$RF$", '&'),
                ("$LT$", '<'), ("$GT$", '>'), ("$LP$", '('), ("$RP$", ')'),
                ("$u20$", ' '), ("$u22$", '"'), ("$u27$", "'"), ("$u2b$", '+'),
                ("$u3b$", ';'), ("$u5b$", '['), ("$u5d$", ']'), ("$u7b$", '{'),
                ("$u7d$", '}'), ("$u7e$", '~')
            ]
            matched = False
            for seq, val in replacements:
                res, new_input = _unescape(input_str, seq, val)
                if res is not None:
                    output += res
                    input_str = new_input
                    matched = True
                    break
            if not matched:
                raise ValueError(f"invalid legacy symbol element {legacy_symbol_element}")
        elif c == '.':
            if len(input_str) > 1 and input_str[1] == '.':
                output += "::"
                input_str = input_str[2:]
            else:
                output += '-'
                input_str = input_str[1:]
        elif c == '_':
            if not ((i == 0 or last_char == ':') and len(input_str) > 1 and input_str[1] == '$'):
                output += c
            input_str = input_str[1:]
        elif c.isalpha() or c.isdigit():
            output += c
            input_str = input_str[1:]
        else:
            raise ValueError(f"Invalid character '{c}'")
        i += 1
        last_char = c

    return output


def _split_symbol_into_elements_legacy(legacy_symbol):
    """Split a legacy symbol into its constituent elements."""
    cursor = 0
    i = 0
    end = len(legacy_symbol) - (len(HASH_PREFIX) + HASH_LEN) - 1
    legacy_symbol_elements = []

    while i < end:
        c = legacy_symbol[i]
        if c.isdigit():
            cursor = cursor * 10 + int(c)
            i += 1
        else:
            if cursor == 0:
                raise ValueError(f"Invalid legacy symbol 'ZN{legacy_symbol}'")
            legacy_symbol_elements.append(legacy_symbol[i:i + cursor])
            i += cursor
            cursor = 0
    return legacy_symbol_elements


def demangle_rust_symbol(symbol):
    """Demangle a Rust symbol to its human-readable form."""
    if not (len(symbol) > 1 and symbol[-1] == 'E'):
        return symbol

    stripped = _strip_symbol_prefix_legacy(symbol)
    if stripped is None:
        return symbol

    elements = _split_symbol_into_elements_legacy(stripped)
    demangled_elements = [_rust_demangle_symbol_element_legacy(el) for el in elements]
    return "::".join(demangled_elements)


def find_real_funcs_name(func_names):
    """Find real function names by demangling and matching against provided names."""
    cur = idc.get_next_func(0)
    result = []
    while cur != idc.BADADDR:
        name = idc.get_func_name(cur)
        next_func = idc.get_next_func(cur + 1)
        if not name:
            cur = next_func
            continue
        try:
            real_name = demangle_rust_symbol(name)
        except Exception:
            real_name = ""
        if real_name in func_names:
            result.append([real_name, name, cur, idc.find_func_end(cur)])
        cur = next_func
    if len(result) != len(func_names):
        return None

    return result


def main():
    """Main entry point for the IDA script."""
    func_names = idc.ARGV[1:]

    sys.stdout = os.fdopen(1, "w", buffering=1)

    if not func_names:
        print("Nothing to do!", flush=True)
        idaapi.qexit(0)

    real_funcs = find_real_funcs_name(func_names)

    if not real_funcs:
        print("Cant resolve!", flush=True)
        idaapi.qexit(0)

    for f in real_funcs:
        print(f"func_: {f[0]} {f[1]} {f[2]} {f[3]}", flush=True)

    idaapi.qexit(0)


if __name__ == "__main__":
    main()
