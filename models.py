import json
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional


class RawEventType(Enum):
    REG_READ = "REG_READ"
    REG_WRITE = "REG_WRITE"
    INST_EXEC = "INST_EXEC"


class EdgeType(Enum):
    REG_RAW = "REG_RAW"  # Read after Write
    REG_WAW = "REG_WAW"  # Write after Write


@dataclass
class RawEvent:
    tick: int
    event_type: RawEventType
    reg_type: Optional[str] = None
    reg_phys: Optional[int] = None
    reg_abi: Optional[str] = None
    value: Optional[int] = None
    pc: Optional[int] = None
    symbol: Optional[str] = None
    mnemonic: Optional[str] = None
    operands: Optional[str] = None
    result: Optional[int] = None


@dataclass
class RegAccess:
    reg_phys: int
    reg_abi: str
    reg_type: str
    value: int
    before_value: Optional[int] = None

    def to_dict(self) -> dict:
        result = {
            "reg_phys": f"0x{self.reg_phys:x}",
            "reg_abi": self.reg_abi,
            "reg_type": self.reg_type,
            "value": f"0x{self.value:x}",
        }
        if self.before_value is not None:
            result["before_value"] = f"0x{self.before_value:x}"
        return result

    @classmethod
    def from_dict(cls, d: dict) -> 'RegAccess':
        before_value = None
        if "before_value" in d and d["before_value"] is not None:
            before_value = int(d["before_value"], 16)
        return cls(
            reg_phys=int(d["reg_phys"], 16),
            reg_abi=d["reg_abi"],
            reg_type=d["reg_type"],
            value=int(d["value"], 16),
            before_value=before_value
        )


@dataclass
class InstructionEvent:
    tick: int
    pc: int
    raw_bytes: Optional[bytes] = None
    symbol: Optional[str] = None
    mnemonic: Optional[str] = None
    operands: Optional[str] = None
    src_regs: List[RegAccess] = field(default_factory=list)
    dst_regs: List[RegAccess] = field(default_factory=list)
    is_load: bool = False
    is_store: bool = False


@dataclass
class Node:
    id: int
    tick: int
    pc: int
    raw_bytes: Optional[bytes] = None
    symbol: Optional[str] = None
    mnemonic: Optional[str] = None
    operands: Optional[str] = None
    src_regs: List[RegAccess] = field(default_factory=list)
    dst_regs: List[RegAccess] = field(default_factory=list)
    is_load: bool = False
    is_store: bool = False

    def to_dict(self) -> dict:
        result = {
            "id": self.id,
            "tick": self.tick,
            "pc": f"0x{self.pc:x}",
            "symbol": self.symbol,
            "mnemonic": self.mnemonic,
            "operands": self.operands,
            "src_regs": [r.to_dict() for r in self.src_regs],
            "dst_regs": [r.to_dict() for r in self.dst_regs],
            "is_load": self.is_load,
            "is_store": self.is_store,
        }
        if self.raw_bytes is not None:
            result["raw_bytes"] = self.raw_bytes.hex()
        return result

    @classmethod
    def from_dict(cls, d: dict) -> 'Node':
        raw_bytes = None
        if "raw_bytes" in d and d["raw_bytes"] is not None:
            raw_bytes = bytes.fromhex(d["raw_bytes"])
        return cls(
            id=d["id"],
            tick=d["tick"],
            pc=int(d["pc"], 16),
            raw_bytes=raw_bytes,
            symbol=d.get("symbol"),
            mnemonic=d.get("mnemonic"),
            operands=d.get("operands"),
            src_regs=[RegAccess.from_dict(r) for r in d["src_regs"]],
            dst_regs=[RegAccess.from_dict(r) for r in d["dst_regs"]],
            is_load=d.get("is_load", False),
            is_store=d.get("is_store", False)
        )


@dataclass
class Edge:
    src: int
    dst: int
    edge_type: EdgeType
    label: Optional[str] = None
    value: Optional[int] = None

    def to_dict(self) -> dict:
        result = {
            "src": self.src,
            "dst": self.dst,
            "edge_type": self.edge_type.value,
            "label": self.label,
        }
        if self.value is not None:
            result["value"] = f"0x{self.value:x}"
        return result

    @classmethod
    def from_dict(cls, d: dict) -> 'Edge':
        value = None
        if "value" in d and d["value"] is not None:
            value = int(d["value"], 16)
        return cls(
            src=d["src"],
            dst=d["dst"],
            edge_type=EdgeType(d["edge_type"]),
            label=d.get("label"),
            value=value
        )


class DataflowGraph:
    def __init__(self):
        self.nodes: Dict[int, Node] = {}
        self.edges: List[Edge] = []

    def add_node(self, node: Node) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)

    def to_dict(self) -> dict:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges]
        }

    def to_json(self, filepath: str) -> None:
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def from_dict(cls, d: dict) -> 'DataflowGraph':
        graph = cls()
        for node_dict in d["nodes"]:
            node = Node.from_dict(node_dict)
            graph.add_node(node)
        for edge_dict in d["edges"]:
            edge = Edge.from_dict(edge_dict)
            graph.add_edge(edge)
        return graph

    @classmethod
    def from_json(cls, filepath: str) -> 'DataflowGraph':
        with open(filepath, 'r') as f:
            data = json.load(f)
        return cls.from_dict(data)