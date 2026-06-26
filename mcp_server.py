#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path
from typing import Callable, Iterable, Optional

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp.server import FastMCP

from trace_dataflow_graph.models import DataflowGraph, Edge, EdgeType, Node, RegAccess
from trace_dataflow_graph.query import backward_deps, critical_path, forward_deps

mcp = FastMCP("Trace Dataflow Graph MCP Server")
graph: Optional[DataflowGraph] = None


def _require_graph() -> Optional[DataflowGraph]:
    return graph


def _bounded_limit(limit: int, default: int, maximum: int = 500) -> int:
    try:
        value = int(limit)
    except (TypeError, ValueError):
        return default
    if value < 1:
        return default
    return min(value, maximum)


def _format_value(value: Optional[int]) -> str:
    if value is None:
        return "None"
    return f"0x{value:x}"


def _format_regs(regs: Iterable[RegAccess]) -> str:
    parts = [f"{reg.reg_abi}={_format_value(reg.value)}" for reg in regs]
    return ", ".join(parts) if parts else "none"


def _format_node_summary(node: Node) -> str:
    symbol = node.symbol or "<no symbol>"
    mnemonic = node.mnemonic or "<no mnemonic>"
    operands = node.operands or ""
    return (
        f"node_id={node.id} | tick={node.tick} | pc=0x{node.pc:x} | "
        f"symbol={symbol} | instruction={mnemonic} {operands}".rstrip()
        + f" | src_regs={_format_regs(node.src_regs)} | dst_regs={_format_regs(node.dst_regs)}"
    )


def _format_node_list(nodes: Iterable[Node], limit: int) -> str:
    selected = list(nodes)[:limit]
    if not selected:
        return "No results found."
    return "\n".join(_format_node_summary(node) for node in selected)


def _search_nodes(predicate: Callable[[Node], bool], limit: int) -> str:
    current_graph = _require_graph()
    if current_graph is None:
        return "Error: Graph not loaded. Run build_cache.py first."
    try:
        nodes = sorted(
            (node for node in current_graph.nodes.values() if predicate(node)),
            key=lambda node: node.tick,
        )
        return _format_node_list(nodes, _bounded_limit(limit, 20))
    except Exception as exc:
        return f"Error: {exc}"


def _raw_edges_from(node_id: int) -> list[Edge]:
    current_graph = _require_graph()
    if current_graph is None:
        return []
    return [
        edge for edge in current_graph.edges
        if edge.src == node_id and edge.edge_type == EdgeType.REG_RAW
    ]


@mcp.tool()
def get_graph_stats() -> str:
    """Return basic graph size and coverage statistics."""
    current_graph = _require_graph()
    if current_graph is None:
        return "Error: Graph not loaded. Run build_cache.py first."
    try:
        nodes = list(current_graph.nodes.values())
        if not nodes:
            return "Nodes: 0 | Edges: 0 | Tick: n/a | Unique PCs: 0 | Symbols: 0"
        min_tick = min(node.tick for node in nodes)
        max_tick = max(node.tick for node in nodes)
        unique_pcs = {node.pc for node in nodes}
        unique_symbols = {node.symbol for node in nodes if node.symbol}
        return (
            f"Nodes: {len(current_graph.nodes):,} | "
            f"Edges: {len(current_graph.edges):,} | "
            f"Tick: {min_tick} - {max_tick} | "
            f"Unique PCs: {len(unique_pcs):,} | "
            f"Symbols: {len(unique_symbols):,}"
        )
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def search_nodes_by_pc(pc: str, limit: int = 20) -> str:
    """Find dynamic instruction nodes at a hexadecimal or decimal PC."""
    if _require_graph() is None:
        return "Error: Graph not loaded. Run build_cache.py first."
    try:
        pc_value = int(pc, 0)
    except (TypeError, ValueError):
        return f"Error: Invalid PC {pc!r}. Use hex like 0x3009a or a decimal integer."
    return _search_nodes(lambda node: node.pc == pc_value, limit)


@mcp.tool()
def search_nodes_by_symbol(symbol: str, limit: int = 20) -> str:
    """Find dynamic instruction nodes whose symbol contains the given text."""
    return _search_nodes(
        lambda node: node.symbol is not None and symbol in node.symbol,
        limit,
    )


@mcp.tool()
def search_nodes_by_tick(start: int, end: int, limit: int = 50) -> str:
    """Find dynamic instruction nodes in the inclusive tick range."""
    try:
        start_tick = int(start)
        end_tick = int(end)
    except (TypeError, ValueError):
        return "Error: start and end must be integers."
    if start_tick > end_tick:
        start_tick, end_tick = end_tick, start_tick
    return _search_nodes(lambda node: start_tick <= node.tick <= end_tick, _bounded_limit(limit, 50))


@mcp.tool()
def search_nodes_by_mnemonic(mnemonic: str, limit: int = 20) -> str:
    """Find dynamic instruction nodes whose mnemonic contains the given text."""
    pattern = mnemonic.lower()
    return _search_nodes(
        lambda node: node.mnemonic is not None and pattern in node.mnemonic.lower(),
        limit,
    )


@mcp.tool()
def get_node_detail(node_id: int) -> str:
    """Return full instruction and register detail for one node."""
    current_graph = _require_graph()
    if current_graph is None:
        return "Error: Graph not loaded. Run build_cache.py first."
    try:
        node_key = int(node_id)
        node = current_graph.nodes.get(node_key)
        if node is None:
            return f"Error: Node {node_id} not found."
        raw_bytes = node.raw_bytes.hex() if node.raw_bytes is not None else "None"
        lines = [
            f"node_id: {node.id}",
            f"tick: {node.tick}",
            f"pc: 0x{node.pc:x}",
            f"symbol: {node.symbol or '<no symbol>'}",
            f"mnemonic: {node.mnemonic or '<no mnemonic>'}",
            f"operands: {node.operands or ''}",
            f"raw_bytes: {raw_bytes}",
            f"is_load: {node.is_load}",
            f"is_store: {node.is_store}",
            "src_regs:",
        ]
        if node.src_regs:
            lines.extend(
                f"  - {reg.reg_abi}: value={_format_value(reg.value)}, before_value={_format_value(reg.before_value)}"
                for reg in node.src_regs
            )
        else:
            lines.append("  none")
        lines.append("dst_regs:")
        if node.dst_regs:
            lines.extend(
                f"  - {reg.reg_abi}: before_value={_format_value(reg.before_value)}, value={_format_value(reg.value)}"
                for reg in node.dst_regs
            )
        else:
            lines.append("  none")
        return "\n".join(lines)
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def trace_dependency_chain(node_id: int, direction: str = "backward", max_depth: int = 5) -> str:
    """Trace RAW producers or consumers from one node."""
    current_graph = _require_graph()
    if current_graph is None:
        return "Error: Graph not loaded. Run build_cache.py first."
    try:
        node_key = int(node_id)
        if node_key not in current_graph.nodes:
            return f"Error: Node {node_id} not found."
        depth = _bounded_limit(max_depth, 5, maximum=100)
        normalized_direction = direction.lower()
        if normalized_direction == "backward":
            subgraph = backward_deps(current_graph, node_key, depth)
            nodes = sorted(subgraph.nodes.values(), key=lambda node: (node.tick, node.id))
        elif normalized_direction == "forward":
            subgraph = forward_deps(current_graph, node_key, depth)
            nodes = sorted(subgraph.nodes.values(), key=lambda node: (node.tick, node.id))
        else:
            return 'Error: direction must be "backward" or "forward".'
        return _format_node_list(nodes, len(nodes))
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def get_critical_path(limit: int = 100) -> str:
    """Return the longest RAW dependency chain."""
    current_graph = _require_graph()
    if current_graph is None:
        return "Error: Graph not loaded. Run build_cache.py first."
    try:
        nodes = critical_path(current_graph)
        return _format_node_list(nodes, _bounded_limit(limit, 100, maximum=1000))
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def trace_register_value(reg_name: str, limit: int = 50) -> str:
    """Trace writes to an ABI register name over time."""
    current_graph = _require_graph()
    if current_graph is None:
        return "Error: Graph not loaded. Run build_cache.py first."
    try:
        normalized_reg = reg_name.lower()
        rows = []
        for node in current_graph.nodes.values():
            for reg in node.dst_regs:
                if reg.reg_abi and reg.reg_abi.lower() == normalized_reg:
                    rows.append((node.tick, node.id, node.symbol, node.mnemonic, reg.before_value, reg.value))
        rows.sort(key=lambda row: row[0])
        selected = rows[:_bounded_limit(limit, 50)]
        if not selected:
            return "No results found."
        return "\n".join(
            f"tick={tick} | node_id={node_id} | symbol={symbol or '<no symbol>'} | "
            f"mnemonic={mnemonic or '<no mnemonic>'} | before_value={_format_value(before)} | after_value={_format_value(after)}"
            for tick, node_id, symbol, mnemonic, before, after in selected
        )
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def find_instruction_consumers(node_id: int, limit: int = 20) -> str:
    """Find instructions that consume values produced by the given node."""
    current_graph = _require_graph()
    if current_graph is None:
        return "Error: Graph not loaded. Run build_cache.py first."
    try:
        node_key = int(node_id)
        if node_key not in current_graph.nodes:
            return f"Error: Node {node_id} not found."
        edges = sorted(
            _raw_edges_from(node_key),
            key=lambda edge: current_graph.nodes[edge.dst].tick if edge.dst in current_graph.nodes else -1,
        )
        selected = edges[:_bounded_limit(limit, 20)]
        if not selected:
            return "No results found."
        lines = []
        for edge in selected:
            consumer = current_graph.nodes.get(edge.dst)
            if consumer is None:
                continue
            lines.append(
                f"consumer node_id={consumer.id} | tick={consumer.tick} | "
                f"symbol={consumer.symbol or '<no symbol>'} | "
                f"instruction={(consumer.mnemonic or '<no mnemonic>') + ' ' + (consumer.operands or '')} | "
                f"consumed_register={edge.label or '<unknown>'}"
            )
        return "\n".join(lines) if lines else "No results found."
    except Exception as exc:
        return f"Error: {exc}"


def load_graph(graph_path: str) -> Optional[str]:
    global graph
    try:
        graph = DataflowGraph.from_json(graph_path)
    except FileNotFoundError:
        graph = None
        return f"Error: Graph cache not found: {graph_path}. Run build_cache.py first."
    except Exception as exc:
        graph = None
        return f"Error: Failed to load graph cache {graph_path}: {exc}"
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Trace Dataflow Graph MCP stdio server")
    parser.add_argument(
        "--graph",
        default="graph_cache.json",
        help="Path to graph JSON cache from build_cache.py (default: graph_cache.json)",
    )
    args = parser.parse_args()
    error = load_graph(args.graph)
    if error:
        print(error, file=sys.stderr)
    mcp.run()


if __name__ == "__main__":
    main()
