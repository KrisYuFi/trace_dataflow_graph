#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from trace_dataflow_graph.elf_reader import ElfReader
from trace_dataflow_graph.event_merger import EventMerger
from trace_dataflow_graph.graph_builder import GraphBuilder
from trace_dataflow_graph.trace_parser import TraceParser


def build_graph(trace_path: str, elf_path: str):
    elf_reader = ElfReader(elf_path)
    parser = TraceParser(trace_path)
    merger = EventMerger(elf_reader)
    builder = GraphBuilder()
    return builder.build(merger.merge(parser.parse()))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pre-build a trace dataflow graph JSON cache for the MCP server"
    )
    parser.add_argument("--trace", required=True, help="Path to gem5 execution trace log")
    parser.add_argument("--elf", required=True, help="Path to the traced program ELF")
    parser.add_argument(
        "--output",
        default="graph_cache.json",
        help="Output JSON cache path (default: graph_cache.json)",
    )
    args = parser.parse_args()

    graph = build_graph(args.trace, args.elf)
    graph.to_json(args.output)

    output_path = Path(args.output)
    file_size = output_path.stat().st_size
    print(f"Graph cache written to: {output_path}")
    print(f"Nodes: {len(graph.nodes):,}")
    print(f"Edges: {len(graph.edges):,}")
    print(f"File size: {file_size:,} bytes")


if __name__ == "__main__":
    main()
