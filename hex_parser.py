"""
Module for parsing hex files, and extracting the described memory contents from this
"""

from math import log2, ceil
from typing import Optional
from pathlib import Path

DEFAULT_UNSET_VAL: int = 0
"""The default value for any unset bytes"""

PAD_END: bool = False
"""Whether or not to pad the end of the hex file with ``DEFAULT_UNSET_VAL`` when changing from .hex file to bytes obj"""


class HexFormatError(Exception):
    """An exception raised, signalling an issue with the .hex file, preventing successful parsing"""

    def __init__(self, format_err: str):
        super().__init__(f".hex file is not formatted correctly.\n{format_err}")


type MemoryDict = dict[int, int]  # Means that memory array size can be calculated later
"""MemoryDict in the form (mem_addr, mem_data)"""


def parse_hex_data_line(mem_dict: MemoryDict, line: str, line_num: int, base_address: int, byte_count: int) -> None:
    """
    Parses a single line in a .hex file
    :param mem_dict: the ``MemoryDict`` representing the binary contents of the .hex file
    :param line: the line string
    :param line_num: the line number.  Used primarily for error messages
    :param base_address: the current base address specified in the .hex file
    :param byte_count: the number of bytes in the line (could be derived here, but done in a parent function for
    efficiency)
    :return: None - all changes are completed on the ``MemoryDict`` directly
    """
    address_offset: int = int(line[3:7], 16)

    all_bytes: list[int] = [byte_count, address_offset >> 8, address_offset & 0xFF, 0]

    curr_str_index: int = 9

    for byte_i in range(byte_count):
        byte_val: int = int(line[curr_str_index:curr_str_index + 2], 16)
        mem_dict[base_address + address_offset + byte_i] = byte_val
        all_bytes.append(byte_val)

        curr_str_index += 2

    expected_checksum: int = (~(sum(all_bytes) & 0xFF) + 1) & 0xFF

    actual_checksum: int = int(line[curr_str_index:curr_str_index + 2], 16)

    if actual_checksum != expected_checksum:
        raise HexFormatError(
            f"Checksum on line {line_num} invalid: expected '{expected_checksum:x}', got '{actual_checksum:x}'")


def mem_dict_to_bytes(mem_dict: MemoryDict, pad_start: bool) -> bytes:
    """
    Converts a ``MemoryDict`` into a ``bytes`` object, to allow for hashing
    :param mem_dict: the ``MemoryDict`` to convert
    :param pad_start: whether to pad the start of the ``bytes`` object down to address 0
    :return: the ``bytes`` conversion of ``MemoryDict``
    """
    min_addr: int = min(mem_dict.keys()) if not pad_start else 0
    max_addr: int = max(mem_dict.keys())
    if PAD_END:
        max_addr = 2 ** ceil(log2(max_addr)) - 1

    mem_buffer: list[int] = [mem_dict.get(i) or DEFAULT_UNSET_VAL for i in range(min_addr, max_addr + 1)]

    return bytes(mem_buffer)


def extract_extended_segment_address(line: str, line_num: int, byte_count: int) -> int:
    """
    Extracts the 'extended segment address' from a '02' action line
    :param line: the line string to parse
    :param line_num: the (1-based indexing) line number, primarily for error messages
    :param byte_count: the number of bytes, as indicated by ``line`` (this could be done here, but is done at a parent
    function for efficiency)
    :return: the extended segment address indicated by ``line``
    """
    if byte_count != 2:
        raise HexFormatError(
            f"Invalid byte count: byte count of 02 expected on all extended segment addresses (line {line_num}"
        )

    return 16 * int(line[9:13], 16)


def extract_extended_linear_address(line: str, line_num: int, byte_count: int) -> int:
    """
    Extracts the 'extended linear address' from a '04' action line.
    This address is the upper 16 bits of a 32-bit base address
    :param line: the line string, to parse
    :param line_num: the (1-based indexing) line number, primary for error messages
    :param byte_count: the number of bytes, as indicated by ``line`` (this could be done here, but is done in the parent
    function for efficiency)
    :return: the extended linear address indicated by ``line``
    """
    if byte_count != 2:
        raise HexFormatError(
            f"Invalid byte count: byte count of 02 expected on all extended linear addresses (line {line_num}"
        )

    return int(line[9:13]) << 16


def dump_hex_contents(hex_contents: bytes, hex_file_fp: Path) -> None:
    """
    Dumps a bytes object into a text file (this is primarily intended for the memory described by .hex files, but can be
    used for any ``bytes`` object)
    :param hex_contents: the ``bytes`` object to dump the contents of
    :param hex_file_fp: the file path to dump the contents at
    :return: None
    """
    file_str: str = ""
    is_lsb: bool = False

    for char in hex_contents.hex("\n", 16):
        if char == "\n":
            file_str += "\n"
            is_lsb = False
            continue

        file_str += char.upper()

        if is_lsb:
            file_str += " "

        is_lsb = not is_lsb

    with open(hex_file_fp, "w") as file:
        file.write(file_str)


def parse_hex_file(file_str: str, pad_start: bool, dump_file_fp: Optional[Path] = None) -> bytes:
    """
    Parses a hex file, returning the described memory contents as a ``bytes`` object
    :param file_str: the stringified contents of the file
    :param pad_start: whether to pad the .hex ``bytes`` down to address 0
    :param dump_file_fp: the file path to dump the contents in the .hex file at
    :return: the ``bytes`` contents of this file
    """
    mem_dict: MemoryDict = {}
    curr_linear_component: int = 0
    curr_segment_component: int = 0

    for i_line, line in enumerate(file_str.splitlines()):
        if not line.startswith(":"):
            raise HexFormatError(f"Line {i_line + 1} does not start with ':'.")

        line_type: int = int(line[7:9])

        byte_count: int = int(line[1:3], 16)

        match line_type:
            case 0:
                try:
                    parse_hex_data_line(mem_dict, line, i_line, curr_linear_component + curr_segment_component,
                                        byte_count)
                except Exception as e:
                    raise HexFormatError(str(e))

            case 1:
                file_bytes: bytes = mem_dict_to_bytes(mem_dict, pad_start)

                if dump_file_fp is not None:
                    dump_hex_contents(file_bytes, dump_file_fp)

                return file_bytes

            case 2:
                curr_segment_component = extract_extended_segment_address(line, i_line + 1, byte_count)

            case 3:
                continue

            case 4:
                curr_linear_component = extract_extended_linear_address(line, i_line + 1, byte_count)

            case 5:
                continue

            case _:
                raise HexFormatError(f"Unknown .hex file instruction '{line_type:0>2x}'")

    raise HexFormatError("Hex file must end on 01 instruction.")


if __name__ == '__main__':
    from sys import argv

    __fp: str = input("fp: ") if len(argv) < 2 else argv[1]

    with open(__fp, "r") as __file:
        parse_hex_file(__file.read())
