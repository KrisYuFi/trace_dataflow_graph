import re
from typing import Iterator, Optional
from .models import RawEvent, RawEventType


# RISC-V ABI Register Mapping
# Integer registers (x0 - x31)
INTEGER_ABI_MAP = {
    0: "zero",
    1: "ra",
    2: "sp",
    3: "gp",
    4: "tp",
    5: "t0",
    6: "t1",
    7: "t2",
    8: "s0",
    9: "s1",
    10: "a0",
    11: "a1",
    12: "a2",
    13: "a3",
    14: "a4",
    15: "a5",
    16: "a6",
    17: "a7",
    18: "s2",
    19: "s3",
    20: "s4",
    21: "s5",
    22: "s6",
    23: "s7",
    24: "s8",
    25: "s9",
    26: "s10",
    27: "s11",
    28: "t3",
    29: "t4",
    30: "t5",
    31: "t6",
}

# Floating point registers (f0 - f31)
FLOATING_POINT_ABI_MAP = {
    0: "ft0",
    1: "ft1",
    2: "ft2",
    3: "ft3",
    4: "ft4",
    5: "ft5",
    6: "ft6",
    7: "ft7",
    8: "fs0",
    9: "fs1",
    10: "fa0",
    11: "fa1",
    12: "fa2",
    13: "fa3",
    14: "fa4",
    15: "fa5",
    16: "fa6",
    17: "fa7",
    18: "fs2",
    19: "fs3",
    20: "fs4",
    21: "fs5",
    22: "fs6",
    23: "fs7",
    24: "fs8",
    25: "fs9",
    26: "fs10",
    27: "fs11",
    28: "ft8",
    29: "ft9",
    30: "ft10",
    31: "ft11",
}


class TraceParser:
    """
    Streaming parser for gem5 execution trace logs with register access events.
    Streams line-by-line without loading the full file into memory.
    """

    def __init__(self, trace_path: str):
        self.trace_path = trace_path

        # Compile regex patterns once at initialization
        # Pattern for register reads: {tick}: ... Reading {reg_type} reg {name}[{idx}] ({idx}) as {value}.
        self.REG_READ = re.compile(
            r"^(?P<tick>\d+):.*Reading (?P<reg_type>integer|floating_point) reg \w+\[(?P<reg_idx>\d+)\].*as (?P<value>0x[0-9a-fA-F]+)\.$"
        )

        # Pattern for register writes: {tick}: ... Setting {reg_type} register {name}[{idx}] ({idx}) to {value}.
        self.REG_WRITE = re.compile(
            r"^(?P<tick>\d+):.*Setting (?P<reg_type>integer|floating_point) register \w+\[(?P<reg_idx>\d+)\].*to (?P<value>0x[0-9a-fA-F]+)\.$"
        )

        # Pattern for instruction execution with optional D=result (handles branches without result)
        self.INST_EXEC = re.compile(
            r"^(?P<tick>\d+):.*(?P<pc>0x[0-9a-fA-F]+) @(?P<symbol>\S+)\s*:\s+(?P<mnemonic>\S+)\s+(?P<operands>[^:]*?)\s*:\s*(D=(?P<result>0x[0-9a-fA-F]+))?$"
        )

    def _get_abi_name(self, reg_type: str, reg_idx: int) -> Optional[str]:
        """Convert gem5 internal register index to RISC-V ABI name."""
        if reg_type == "integer":
            return INTEGER_ABI_MAP.get(reg_idx)
        elif reg_type == "floating_point":
            return FLOATING_POINT_ABI_MAP.get(reg_idx)
        return None

    def parse(self) -> Iterator[RawEvent]:
        """
        Stream through the trace file line-by-line and yield RawEvent objects
        for matching events. Skips non-matching lines (warnings, info, empty).
        """
        with open(self.trace_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                # Skip gem5 warning/info lines
                if line.startswith("gem5") or line.startswith("WARN") or line.startswith("INFO"):
                    continue

                # Try matching register read
                match = self.REG_READ.match(line)
                if match:
                    tick = int(match.group("tick"), 10)
                    reg_type = match.group("reg_type")
                    reg_idx = int(match.group("reg_idx"), 10)
                    value = int(match.group("value"), 16)
                    reg_abi = self._get_abi_name(reg_type, reg_idx)

                    yield RawEvent(
                        tick=tick,
                        event_type=RawEventType.REG_READ,
                        reg_type=reg_type,
                        reg_phys=reg_idx,
                        reg_abi=reg_abi,
                        value=value,
                    )
                    continue

                # Try matching register write
                match = self.REG_WRITE.match(line)
                if match:
                    tick = int(match.group("tick"), 10)
                    reg_type = match.group("reg_type")
                    reg_idx = int(match.group("reg_idx"), 10)
                    value = int(match.group("value"), 16)
                    reg_abi = self._get_abi_name(reg_type, reg_idx)

                    yield RawEvent(
                        tick=tick,
                        event_type=RawEventType.REG_WRITE,
                        reg_type=reg_type,
                        reg_phys=reg_idx,
                        reg_abi=reg_abi,
                        value=value,
                    )
                    continue

                # Try matching instruction execution
                match = self.INST_EXEC.match(line)
                if match:
                    tick = int(match.group("tick"), 10)
                    pc = int(match.group("pc"), 16)
                    symbol = match.group("symbol")
                    mnemonic = match.group("mnemonic")
                    operands = match.group("operands").strip()
                    result_str = match.group("result")
                    result = int(result_str, 16) if result_str is not None else None

                    yield RawEvent(
                        tick=tick,
                        event_type=RawEventType.INST_EXEC,
                        pc=pc,
                        symbol=symbol,
                        mnemonic=mnemonic,
                        operands=operands,
                        result=result,
                    )
                    continue

                # No match - skip line
                continue
