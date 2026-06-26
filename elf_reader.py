from typing import Dict, Optional
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


class ElfReader:
    def __init__(self, elf_path: str):
        self.elf_path = elf_path
        self.text_section = None
        self.text_addr = 0
        self.text_size = 0
        self.text_data = b''
        self.symbol_map: Dict[int, str] = {}
        self._parse_elf()

    def _parse_elf(self) -> None:
        """Parse ELF file, cache .text section and symbol table"""
        try:
            with open(self.elf_path, 'rb') as f:
                elffile = ELFFile(f)

                # Find .text section
                self.text_section = elffile.get_section_by_name('.text')
                if self.text_section:
                    self.text_addr = self.text_section['sh_addr']
                    self.text_size = self.text_section['sh_size']
                    self.text_data = self.text_section.data()

                # Build symbol table
                symtab = elffile.get_section_by_name('.symtab')
                if isinstance(symtab, SymbolTableSection):
                    for symbol in symtab.iter_symbols():
                        name = symbol.name
                        addr = symbol['st_value']
                        if name and addr != 0:
                            # We'll keep the symbol - when looking up we'll find the matching one
                            self.symbol_map[addr] = name

                # Also check dynsym if symtab not found
                if not self.symbol_map:
                    dynsym = elffile.get_section_by_name('.dynsym')
                    if isinstance(dynsym, SymbolTableSection):
                        for symbol in dynsym.iter_symbols():
                            name = symbol.name
                            addr = symbol['st_value']
                            if name and addr != 0:
                                self.symbol_map[addr] = name
        except Exception as e:
            # Let constructor succeed, methods will return None
            pass

    def get_raw_bytes(self, pc: int) -> Optional[int]:
        """
        Return instruction bytes as integer at given PC.
        - 4-byte instructions: return full 4-byte little-endian as int
        - 2-byte compressed instructions: return 2-byte zero-extended as int
        - Returns None if PC not in .text section
        """
        if not self.text_section:
            return None

        # Check if PC is within .text section
        if pc < self.text_addr or pc >= self.text_addr + self.text_size:
            return None

        offset = pc - self.text_addr

        # Check how many bytes we can read
        # Try 4 bytes first (most RISC-V instructions are 4-byte)
        # For RISC-V, instructions can be 16-bit (2-byte) or 32-bit (4-byte)
        # We need to determine the length - but since we don't decode, we check if at boundary
        # Actually: RISC-V instructions are aligned to 2-byte boundaries
        # We check if the 2-byte at offset is a compressed instruction
        # But for simplicity, let's check if we have 4 bytes left - if not, check 2
        if offset + 4 <= len(self.text_data):
            raw = self.text_data[offset:offset+4]
            # Check if it's a compressed instruction (bits 1-0 != 11 are 16-bit)
            first_byte = raw[0]
            if (first_byte & 0b11) != 0b11:
                # 16-bit compressed instruction
                return int.from_bytes(raw[:2], byteorder='little', signed=False)
            # 32-bit instruction
            return int.from_bytes(raw, byteorder='little', signed=False)
        elif offset + 2 <= len(self.text_data):
            # Only 2 bytes left - must be compressed
            raw = self.text_data[offset:offset+2]
            return int.from_bytes(raw, byteorder='little', signed=False)

        return None

    def get_symbol(self, pc: int) -> Optional[str]:
        """
        Return symbol name for given PC.
        Format: @symbol+offset or @symbol if offset=0
        Returns None if no symbol found
        """
        if not self.symbol_map:
            return None

        # Find the closest symbol whose address <= pc
        best_addr = None
        best_name = None
        for addr, name in sorted(self.symbol_map.items()):
            if addr <= pc:
                best_addr = addr
                best_name = name
            else:
                break

        if best_name is None:
            return None

        offset = pc - best_addr
        if offset == 0:
            return f"@{best_name}"
        return f"@{best_name}+{offset}"

    def get_symbol_table(self) -> Dict[int, str]:
        """Return full PC→symbol mapping"""
        return self.symbol_map.copy()
