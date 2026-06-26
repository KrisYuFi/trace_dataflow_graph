from typing import Iterator, List, Optional, Set

from .models import InstructionEvent, RawEvent, RawEventType, RegAccess


LOAD_MNEMONICS: Set[str] = {
    "flw",
    "fld",
    "lw",
    "ld",
    "lb",
    "lh",
    "lbu",
    "lhu",
    "lwu",
}

STORE_MNEMONICS: Set[str] = {
    "fsw",
    "fsd",
    "sw",
    "sd",
    "sb",
    "sh",
}


class EventMerger:
    def __init__(self, elf_reader):
        self._elf_reader = elf_reader
        self._buffer: List[RawEvent] = []

    def merge(self, events: Iterator[RawEvent]) -> Iterator[InstructionEvent]:
        for event in events:
            if event.event_type == RawEventType.INST_EXEC:
                yield self._flush_buffer(event)
                self._buffer.clear()
            else:
                self._buffer.append(event)

    def _flush_buffer(self, inst_event: RawEvent) -> InstructionEvent:
        src_regs: List[RegAccess] = []
        dst_regs: List[RegAccess] = []

        for raw in self._buffer:
            if raw.event_type == RawEventType.REG_READ:
                src_regs.append(
                    RegAccess(
                        reg_phys=raw.reg_phys,
                        reg_abi=raw.reg_abi,
                        reg_type=raw.reg_type,
                        value=raw.value,
                    )
                )
            elif raw.event_type == RawEventType.REG_WRITE:
                dst_regs.append(
                    RegAccess(
                        reg_phys=raw.reg_phys,
                        reg_abi=raw.reg_abi,
                        reg_type=raw.reg_type,
                        value=raw.value,
                    )
                )

        pc = inst_event.pc
        raw_int = self._elf_reader.get_raw_bytes(pc) if self._elf_reader else None
        raw_bytes = self._raw_int_to_bytes(raw_int)

        mnemonic = inst_event.mnemonic
        is_load = mnemonic in LOAD_MNEMONICS if mnemonic else False
        is_store = mnemonic in STORE_MNEMONICS if mnemonic else False

        return InstructionEvent(
            tick=inst_event.tick,
            pc=pc,
            raw_bytes=raw_bytes,
            symbol=inst_event.symbol,
            mnemonic=mnemonic,
            operands=inst_event.operands,
            src_regs=src_regs,
            dst_regs=dst_regs,
            is_load=is_load,
            is_store=is_store,
        )

    @staticmethod
    def _raw_int_to_bytes(raw_int: Optional[int]) -> Optional[bytes]:
        if raw_int is None:
            return None
        if raw_int <= 0xFFFF:
            return raw_int.to_bytes(2, byteorder="little")
        return raw_int.to_bytes(4, byteorder="little")
