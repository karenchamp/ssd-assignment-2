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

sys.path.insert(0, str(ROOT / "aes"))

import aes as aes_py

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


def load_c_functions(lib, function_names):
    functions = {}
    for name in function_names:
        func = getattr(lib, name)
        func.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
        func.restype = None
        functions[name] = func
    return functions


def compare_functions(function_names, num_tests=3):
    lib = ctypes.CDLL(str(RIJNDAEL_SO_PATH))
    c_functions = load_c_functions(lib, function_names)
    
    for func_name in function_names:
        py_func = getattr(aes_py, func_name)
        c_func = c_functions[func_name]
        
        print(f"Testing {func_name}...")
        for test_index in range(1, num_tests + 1):
            data = [random.randrange(256) for _ in range(16)]
            py_state = to_python_state(data.copy())
            py_func(py_state)
            py_output = bytes(flatten_python_state(py_state))

            c_buffer_type = ctypes.c_ubyte * 16
            c_buffer = c_buffer_type(*data)
            c_func(c_buffer, AES_BLOCK_128)
            c_output = bytes(c_buffer)

            if c_output != py_output:
                print(f"Test {test_index} for {func_name} FAILED")
                print(f"input: {data}")
                print(f"python output: {list(py_output)}")
                print(f"c output:      {list(c_output)}")
                raise AssertionError(f"C and Python {func_name} outputs differ")

            print(f"  Test {test_index} OK")
        print(f"All {func_name} tests passed.\n")


def main() -> None:
    py_functions = extract_functions(AES_PY_PATH, FUNCTION_PATTERN_PY)
    c_functions = extract_functions(RIJNDAEL_C_PATH, FUNCTION_PATTERN_C)

    print("Python AES algorithm functions:")
    print(sorted(py_functions))
    print()
    print("C AES algorithm functions:")
    print(sorted(c_functions))
    print()
    
    functions_to_test = ['sub_bytes']
    print("Running comparison tests...")
    compare_functions(functions_to_test, 3)
    print("All tests passed.")


if __name__ == "__main__":
    main()
