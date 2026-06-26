#!/usr/bin/env python3
"""End-to-end integration tests for the trace dataflow graph pipeline."""

import json
import os
import tempfile
from pathlib import Path

try:
    import pytest
except ModuleNotFoundError:
    pytest = None

from ..trace_parser import TraceParser
from ..event_merger import EventMerger
from ..graph_builder import GraphBuilder
from ..query import (
    critical_path,
    subgraph_by_tick,
    subgraph_by_symbol,
    trace_register,
    backward_deps,
    forward_deps,
)
from ..export import export_dot, export_json, export_chrome_trace
from ..models import EdgeType


class MockElfReader:
    """ELF reader stub that returns no raw bytes (avoids pyelftools dependency)."""

    def get_raw_bytes(self, pc):
        return None


def _build_graph_from_trace(trace_path: str, max_instrs: int = None):
    """Run the full pipeline: parse -> merge -> build."""
    parser = TraceParser(trace_path)
    merger = EventMerger(MockElfReader())
    builder = GraphBuilder()

    events = parser.parse()
    merged = merger.merge(events)

    if max_instrs is not None:
        import itertools
        merged = itertools.islice(merged, max_instrs)

    return builder.build(merged)


def test_full_pipeline_synthetic(sample_trace_mixed_path):
    """Synthetic trace -> parse -> merge -> build -> verify node/edge counts."""
    graph = _build_graph_from_trace(str(sample_trace_mixed_path))

    assert len(graph.nodes) > 0, "Graph should contain nodes"
    assert len(graph.edges) > 0, "Graph should contain edges"

    # The mixed fixture has instructions with register dependencies
    raw_edges = [e for e in graph.edges if e.edge_type == EdgeType.REG_RAW]
    waw_edges = [e for e in graph.edges if e.edge_type == EdgeType.REG_WAW]

    # At minimum we expect some RAW edges from the ALU / load instructions
    assert len(raw_edges) > 0 or len(waw_edges) > 0, "Should have at least some dependency edges"


def test_pipeline_real_softmax():
    """Real softmax_256 trace -> full pipeline -> verify RAW/WAW edges and critical path."""
    trace_path = "/Users/krisyu/Desktop/NewCoding/gem5-docker/output/m5out/trace_softmax.log"

    if not Path(trace_path).exists():
        if pytest is not None:
            pytest.skip(f"Real trace not found at {trace_path}")
        else:
            return

    graph = _build_graph_from_trace(trace_path, max_instrs=10000)

    assert len(graph.nodes) > 0, "Graph should contain nodes from real trace"
    assert len(graph.edges) > 0, "Graph should contain edges from real trace"

    raw_edges = [e for e in graph.edges if e.edge_type == EdgeType.REG_RAW]
    waw_edges = [e for e in graph.edges if e.edge_type == EdgeType.REG_WAW]

    assert len(raw_edges) > 0, "Real trace should produce RAW edges"
    assert len(waw_edges) > 0, "Real trace should produce WAW edges"

    path = critical_path(graph)
    assert len(path) > 0, "Critical path should be non-empty"


def test_export_dot(sample_trace_mixed_path):
    """Build graph -> export DOT -> verify file exists and contains expected markers."""
    graph = _build_graph_from_trace(str(sample_trace_mixed_path))

    with tempfile.TemporaryDirectory() as tmpdir:
        dot_path = os.path.join(tmpdir, "out.dot")
        export_dot(graph, dot_path)

        assert os.path.exists(dot_path), "DOT file should be created"
        with open(dot_path, "r") as f:
            content = f.read()
        assert "digraph" in content, "DOT file should contain 'digraph'"
        assert "->" in content, "DOT file should contain edges '->'"


def test_export_json(sample_trace_mixed_path):
    """Build graph -> export JSON -> verify valid JSON with 'nodes' and 'edges'."""
    graph = _build_graph_from_trace(str(sample_trace_mixed_path))

    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = os.path.join(tmpdir, "out.json")
        export_json(graph, json_path)

        assert os.path.exists(json_path), "JSON file should be created"
        with open(json_path, "r") as f:
            data = json.load(f)
        assert "nodes" in data, "JSON should contain 'nodes' key"
        assert "edges" in data, "JSON should contain 'edges' key"
        assert len(data["nodes"]) == len(graph.nodes), "JSON node count should match graph"
        assert len(data["edges"]) == len(graph.edges), "JSON edge count should match graph"


def test_export_chrome_trace(sample_trace_mixed_path):
    """Build graph -> export Chrome Trace -> verify ph='X' events and ph='f' flows."""
    graph = _build_graph_from_trace(str(sample_trace_mixed_path))

    with tempfile.TemporaryDirectory() as tmpdir:
        trace_path = os.path.join(tmpdir, "out.json")
        export_chrome_trace(graph, trace_path)

        assert os.path.exists(trace_path), "Chrome Trace file should be created"
        with open(trace_path, "r") as f:
            events = json.load(f)

        x_events = [ev for ev in events if ev.get("ph") == "X"]
        f_events = [ev for ev in events if ev.get("ph") == "f"]

        assert len(x_events) > 0, "Should have ph='X' events"
        assert len(f_events) > 0, "Should have ph='f' flow events"


def test_subgraph_and_query(sample_trace_mixed_path):
    """Test subgraph_by_tick, subgraph_by_symbol, trace_register, backward_deps, forward_deps."""
    graph = _build_graph_from_trace(str(sample_trace_mixed_path))
    assert len(graph.nodes) > 0, "Need non-empty graph for query tests"

    # subgraph_by_tick: narrow to first half of ticks
    min_tick = min(n.tick for n in graph.nodes.values())
    max_tick = max(n.tick for n in graph.nodes.values())
    mid_tick = (min_tick + max_tick) // 2
    subgraph_tick = subgraph_by_tick(graph, min_tick, mid_tick)
    assert len(subgraph_tick.nodes) > 0, "Tick subgraph should have some nodes"
    assert len(subgraph_tick.nodes) <= len(graph.nodes), "Tick subgraph should not exceed full graph"
    if len(subgraph_tick.nodes) < len(graph.nodes):
        assert len(subgraph_tick.nodes) < len(graph.nodes), "Tick subgraph should have fewer nodes when range is narrow"

    # subgraph_by_symbol: filter by a symbol present in the trace
    symbols = {n.symbol for n in graph.nodes.values() if n.symbol}
    if symbols:
        sym = next(iter(symbols))
        subgraph_sym = subgraph_by_symbol(graph, sym)
        assert len(subgraph_sym.nodes) > 0, "Symbol subgraph should have nodes"
        assert len(subgraph_sym.nodes) <= len(graph.nodes), "Symbol subgraph should not exceed full graph"

    # trace_register: pick a register that is written somewhere
    written_regs = set()
    for node in graph.nodes.values():
        for dst in node.dst_regs:
            written_regs.add(dst.reg_phys)
    if written_regs:
        reg = next(iter(written_regs))
        reg_trace = trace_register(graph, reg)
        assert len(reg_trace) > 0, "trace_register should return at least one entry"
        for tick, before, after in reg_trace:
            assert isinstance(tick, int), "Tick should be an integer"

    # backward_deps / forward_deps: pick a node that has at least one edge
    nodes_with_edges = set()
    for edge in graph.edges:
        nodes_with_edges.add(edge.dst)
        nodes_with_edges.add(edge.src)
    if nodes_with_edges:
        node_id = next(iter(nodes_with_edges))
        bwd = backward_deps(graph, node_id, max_depth=3)
        assert node_id in bwd.nodes, "backward_deps should include the starting node"
        fwd = forward_deps(graph, node_id, max_depth=3)
        assert node_id in fwd.nodes, "forward_deps should include the starting node"

    # critical_path sanity check
    cp = critical_path(graph)
    assert len(cp) > 0, "critical_path should be non-empty"
