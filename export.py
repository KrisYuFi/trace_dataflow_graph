import json
from typing import Optional
from .models import DataflowGraph, Node, Edge, EdgeType


def _escape_dot_label(text: Optional[str]) -> str:
    """Escape special characters for DOT label."""
    if text is None:
        return ""
    text = text.replace("\\", "\\\\")
    text = text.replace("\"", "\\\"")
    text = text.replace("\n", "\\n")
    return text


def export_dot(graph: DataflowGraph, filepath: str, show_waw: bool = True) -> None:
    """Export dataflow graph to Graphviz DOT format.
    
    Args:
        graph: The dataflow graph to export.
        filepath: Output file path.
        show_waw: Whether to show WAW edges (dashed gray). Defaults to True.
    """
    with open(filepath, 'w') as f:
        f.write("digraph dataflow {\n")
        f.write("    rankdir=TB;\n")
        f.write("    node [shape=record];\n\n")

        for node_id, node in graph.nodes.items():
            if node.symbol is not None:
                symbol_line = node.symbol
            else:
                symbol_line = f"0x{node.pc:x}"
            
            mnemonic_operands = ""
            if node.mnemonic and node.operands:
                mnemonic_operands = f"{node.mnemonic} {node.operands}"
            elif node.mnemonic:
                mnemonic_operands = node.mnemonic
            elif node.operands:
                mnemonic_operands = node.operands
            
            label_parts = [
                symbol_line,
                mnemonic_operands,
                f"tick={node.tick}"
            ]
            label = _escape_dot_label("\\n".join(label_parts))
            
            f.write(f'    node_{node_id} [label="{label}"];\n')
        
        f.write("\n")
        
        for edge in graph.edges:
            if edge.edge_type == EdgeType.REG_WAW and not show_waw:
                continue
            
            src_id = edge.src
            dst_id = edge.dst
            label = _escape_dot_label(edge.label)
            
            if edge.edge_type == EdgeType.REG_RAW:
                attrs = f'label="{label}", color=black, style=solid'
            else:
                attrs = f'label="WAW {label}", color=gray, style=dashed'
            
            f.write(f'    node_{src_id} -> node_{dst_id} [{attrs}];\n')
        
        f.write("}\n")


def export_json(graph: DataflowGraph, filepath: str) -> None:
    """Export dataflow graph to JSON using built-in serialization.
    
    Args:
        graph: The dataflow graph to export.
        filepath: Output file path.
    """
    graph.to_json(filepath)


def export_chrome_trace(graph: DataflowGraph, filepath: str) -> None:
    """Export dataflow graph to Chrome Trace Event format for Perfetto.
    
    Args:
        graph: The dataflow graph to export.
        filepath: Output file path.
    """
    trace_events = []
    flow_id = 0

    for node_id, node in graph.nodes.items():
        ts = node.tick // 1000000
        
        name_parts = []
        if node.symbol:
            name_parts.append(node.symbol)
        if node.mnemonic:
            name_parts.append(node.mnemonic)
        name = " ".join(name_parts) if name_parts else f"0x{node.pc:x}"
        
        args = {
            "pc": f"0x{node.pc:x}"
        }
        if node.raw_bytes is not None:
            args["raw"] = node.raw_bytes.hex()
        if node.operands:
            args["operands"] = node.operands
        
        trace_events.append({
            "ph": "X",
            "name": name,
            "ts": ts,
            "dur": 1,
            "pid": 0,
            "tid": 0,
            "args": args
        })

    for edge in graph.edges:
        src_node = graph.nodes.get(edge.src)
        if not src_node:
            continue
        
        src_ts = src_node.tick // 1000000
        flow_id += 1
        category = "REG_RAW" if edge.edge_type == EdgeType.REG_RAW else "REG_WAW"
        
        args = {}
        if edge.value is not None:
            args["value"] = f"0x{edge.value:x}"
        
        trace_events.append({
            "ph": "f",
            "name": edge.label or "",
            "bp": "e",
            "cat": category,
            "ts": src_ts,
            "pid": 0,
            "tid": 0,
            "id": flow_id,
            "args": args
        })
    
    with open(filepath, 'w') as f:
        json.dump(trace_events, f, indent=2)
