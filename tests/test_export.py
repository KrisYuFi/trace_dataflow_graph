#!/usr/bin/env python3
"""Test export functions with small sample graph."""

import tempfile
import os
from ..models import DataflowGraph, Node, Edge, EdgeType, RegAccess
from ..export import export_dot, export_json, export_chrome_trace


def create_test_graph():
    """Create a small test graph with two nodes and one RAW edge."""
    graph = DataflowGraph()
    
    # Add first node
    node1 = Node(
        id=1,
        tick=150000000000,
        pc=0x10000,
        symbol="test_func",
        mnemonic="add",
        operands="x1, x2, x3",
        is_load=False,
        is_store=False
    )
    node1.dst_regs.append(RegAccess(1, "x1", "int", 0x1234))
    graph.add_node(node1)
    
    # Add second node
    node2 = Node(
        id=2,
        tick=150001000000,
        pc=0x10004,
        symbol="test_func",
        mnemonic="mul",
        operands="x4, x1, x5",
        is_load=False,
        is_store=False
    )
    node2.src_regs.append(RegAccess(1, "x1", "int", 0x1234))
    graph.add_node(node2)
    
    # Add RAW edge
    edge = Edge(src=1, dst=2, edge_type=EdgeType.REG_RAW, label="x1", value=0x1234)
    graph.add_edge(edge)
    
    # Add WAW edge
    node3 = Node(
        id=3,
        tick=150002000000,
        pc=0x10008,
        symbol="test_func",
        mnemonic="sub",
        operands="x1, x6, x7",
        is_load=False,
        is_store=False
    )
    node3.dst_regs.append(RegAccess(1, "x1", "int", 0x5678))
    graph.add_node(node3)
    
    edge_waw = Edge(src=1, dst=3, edge_type=EdgeType.REG_WAW, label="x1", value=0x5678)
    graph.add_edge(edge_waw)
    
    return graph


def test_exports():
    """Test all export functions work correctly."""
    graph = create_test_graph()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Test DOT export
        dot_path = os.path.join(tmpdir, "test.dot")
        export_dot(graph, dot_path)
        assert os.path.exists(dot_path)
        with open(dot_path, 'r') as f:
            content = f.read()
        assert "digraph dataflow" in content
        assert "node_1" in content
        assert "node_2" in content
        assert "x1" in content
        assert "WAW" in content
        print("✓ DOT export passed")
        
        # Test DOT export without WAW
        dot_path_nowaw = os.path.join(tmpdir, "test_nowaw.dot")
        export_dot(graph, dot_path_nowaw, show_waw=False)
        with open(dot_path_nowaw, 'r') as f:
            content = f.read()
        assert "WAW" not in content
        print("✓ DOT export (no WAW) passed")
        
        # Test JSON export
        json_path = os.path.join(tmpdir, "test.json")
        export_json(graph, json_path)
        assert os.path.exists(json_path)
        print("✓ JSON export passed")
        
        # Test Chrome Trace export
        trace_path = os.path.join(tmpdir, "test.json")
        export_chrome_trace(graph, trace_path)
        assert os.path.exists(trace_path)
        with open(trace_path, 'r') as f:
            content = f.read()
        assert "REG_RAW" in content
        assert "REG_WAW" in content
        print("✓ Chrome Trace export passed")
    
    print("\nAll tests passed!")


if __name__ == "__main__":
    test_exports()
