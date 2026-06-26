from typing import Dict, Iterator

from .models import (
    DataflowGraph,
    Edge,
    EdgeType,
    InstructionEvent,
    Node,
)


class GraphBuilder:
    """Constructs a DataflowGraph from InstructionEvents, creating REG_RAW edges for register data dependencies."""

    def __init__(self) -> None:
        self.reg_tracker: Dict[int, int] = {}
        self.reg_value: Dict[int, int] = {}
        self._next_id: int = 0

    def build(self, events: Iterator[InstructionEvent]) -> DataflowGraph:
        graph = DataflowGraph()

        for inst in events:
            node_id = self._next_id
            self._next_id += 1

            node = Node(
                id=node_id,
                tick=inst.tick,
                pc=inst.pc,
                raw_bytes=inst.raw_bytes,
                symbol=inst.symbol,
                mnemonic=inst.mnemonic,
                operands=inst.operands,
                src_regs=inst.src_regs,
                dst_regs=inst.dst_regs,
                is_load=inst.is_load,
                is_store=inst.is_store,
            )
            graph.add_node(node)

            for src_reg in inst.src_regs:
                if src_reg.reg_phys in self.reg_tracker:
                    edge = Edge(
                        src=self.reg_tracker[src_reg.reg_phys],
                        dst=node_id,
                        edge_type=EdgeType.REG_RAW,
                        label=src_reg.reg_abi,
                        value=src_reg.value,
                    )
                    graph.add_edge(edge)

            for dst_reg in inst.dst_regs:
                if dst_reg.reg_phys in self.reg_tracker:
                    edge = Edge(
                        src=self.reg_tracker[dst_reg.reg_phys],
                        dst=node_id,
                        edge_type=EdgeType.REG_WAW,
                        label=dst_reg.reg_abi,
                        value=dst_reg.value,
                    )
                    graph.add_edge(edge)
                dst_reg.before_value = self.reg_value.get(dst_reg.reg_phys)
                self.reg_tracker[dst_reg.reg_phys] = node_id
                self.reg_value[dst_reg.reg_phys] = dst_reg.value

        return graph
