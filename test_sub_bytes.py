#!/usr/bin/env python3
import ctypes
import os
import random
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
AES_PY_PATH = ROOT / "aes" / "aes.py"
RIJNDAEL_C_PATH = ROOT / "rijndael.c"
RIJNDAEL_SO_PATH = ROOT / "rijndael.so"

sys.path.insert(0, str(ROOT))

import aes.aes as aes_py

AES_BLOCK_128 = 0

FUNCTION_PATTERN_PY = re.compile(r"^def\s+(\w+)\s*\(", re.M)
FUNCTION_PATTERN_C = re.compile(r"^\s*(?:void|unsigned char\*|unsigned char|size_t)\s+(\w+)\s*\(", re.M)


def extract_functions(path: Path, pattern: re.Pattern[str]) -> list[str]:
    source = path.read_text()
    return pattern.findall(source)


def to_python_state(flat: list[int]) -> list[list[int]]:
    return [flat[i * 4 : (i + 1) * 4] for i in range(4)]


def flatten_python_state(state: list[list[int]]) -> list[int]:
    return [state[row][col] for row in range(4) for col in range(4)]


def load_c_sub_bytes() -> ctypes._CFuncPtr:
    if not RIJNDAEL_SO_PATH.exists():
        raise FileNotFoundError(f"Shared library not found: {RIJNDAEL_SO_PATH}")

    lib = ctypes.CDLL(str(RIJNDAEL_SO_PATH))
    sub_bytes = lib.sub_bytes
    sub_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
    sub_bytes.restype = None
    return sub_bytes


def compare_sub_bytes(num_tests: int = 3) -> None:
    sub_bytes = load_c_sub_bytes()

    for test_index in range(1, num_tests + 1):
        data = [random.randrange(256) for _ in range(16)]
        py_state = to_python_state(data.copy())
        aes_py.sub_bytes(py_state)
        py_output = bytes(flatten_python_state(py_state))

        c_buffer_type = ctypes.c_ubyte * 16
        c_buffer = c_buffer_type(*data)
        sub_bytes(c_buffer, AES_BLOCK_128)
        c_output = bytes(c_buffer)

        if c_output != py_output:
            print(f"Test {test_index} FAILED")
            print(f"input: {data}")
            print(f"python output: {list(py_output)}")
            print(f"c output:      {list(c_output)}")
            raise AssertionError("C and Python sub_bytes outputs differ")

        print(f"Test {test_index} OK")


def main() -> None:
    py_functions = extract_functions(AES_PY_PATH, FUNCTION_PATTERN_PY)
    c_functions = extract_functions(RIJNDAEL_C_PATH, FUNCTION_PATTERN_C)

    print("Python AES algorithm functions:")
    print(sorted(py_functions))
    print()
    print("C AES algorithm functions:")
    print(sorted(c_functions))
    print()
    print("Running sub_bytes comparison tests...")
    compare_sub_bytes(3)
    print("All sub_bytes tests passed.")


if __name__ == "__main__":
    main()
