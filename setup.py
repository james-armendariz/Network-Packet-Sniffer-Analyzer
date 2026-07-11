"""
setup.py — Build script for the parser_c C extension.

Usage:
    python3 setup.py build_ext --inplace

This compiles parser_c.c into a shared library
(parser_c.cpython-312-x86_64-linux-gnu.so or similar) placed directly
in the packet_sniffer/ directory, where Python's import system will
find it automatically when you do `from packet_sniffer import parser_c`.

The --inplace flag is what puts the .so next to the source rather than
in a build/ subdirectory, which is what we want for a development build.
"""

from setuptools import setup, Extension

parser_c_ext = Extension(
    name="packet_sniffer.parser_c",
    sources=["packet_sniffer/parser_c.c"],
    extra_compile_args=[
        "-O2",
        "-Wall",
        "-Wextra",
    ],
)

setup(
    name="packet_sniffer",
    version="0.1.0",
    ext_modules=[parser_c_ext],
)
