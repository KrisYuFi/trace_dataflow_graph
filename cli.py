#!/usr/bin/env python3
import argparse
import sys
from typing import Optional

from . import trace_parser
from . import event_merger
from . import graph_builder
from . import query
from . import export


def main():
    parser = argparse.ArgumentParser(
        description="Trace Dataflow Graph - Build and export data dependency graphs from gem5 execution traces"
    )
    
    # Required arguments
    parser.add_argument("--trace", required=True, help="Path to gem5 execution trace log")
    parser.add_argument("--elf", required=True, help="Path to the ELF executable of the traced program")
    
    # Export options
    parser.add_argument(
        "--export", 
        choices=["dot", "json", "chrome", "html"], 
        help="Export format (dot: Graphviz, json: serialized graph, chrome: Chrome Trace Event format, html: interactive vis.js graph)"
    )
    parser.add_argument("--output", help="Output file path (defaults to stdout or auto-generated name)")
    
    # Query options
    parser.add_argument("--critical-path", action="store_true", help="Compute and print the critical path (longest dependency chain)")
    parser.add_argument("--subgraph-tick", nargs=2, type=int, metavar=("START", "END"), help="Extract subgraph with ticks in [START, END]")
    parser.add_argument("--subgraph-symbol", help="Extract subgraph with nodes containing symbol pattern (substring match)")
    parser.add_argument("--show-waw", action="store_true", default=True, help="Show WAW dependencies (default: True)")
    parser.add_argument("--no-waw", dest="show_waw", action="store_false", help="Hide WAW dependencies")
    
    args = parser.parse_args()
    
    # Handle ELF reader import error gracefully
    try:
        from .elf_reader import ElfReader
    except ImportError:
        print(
            "ERROR: pyelftools is required to read ELF files but is not installed.\n"
            "Install it with: pip install pyelftools\n",
            file=sys.stderr
        )
        sys.exit(1)
    
    # Step 1: Create ELF reader
    elf_reader = ElfReader(args.elf)
    
    # Step 2: Create trace parser and parse events
    parser = trace_parser.TraceParser(args.trace)
    raw_events = parser.parse()
    
    # Step 3: Merge events with ELF info
    merger = event_merger.EventMerger(elf_reader)
    inst_events = merger.merge(raw_events)
    
    # Step 4: Build graph
    builder = graph_builder.GraphBuilder()
    graph = builder.build(inst_events)
    
    # Step 5: Apply filters/queries
    if args.subgraph_tick:
        start, end = args.subgraph_tick
        graph = query.subgraph_by_tick(graph, start, end)
    
    if args.subgraph_symbol:
        graph = query.subgraph_by_symbol(graph, args.subgraph_symbol)
    
    if args.critical_path:
        path = query.critical_path(graph)
        print(f"Critical path length: {len(path)} instructions")
        print("-" * 80)
        for i, node in enumerate(path):
            symbol = node.symbol or f"0x{node.pc:x}"
            inst = f"{node.mnemonic} {node.operands}" if node.mnemonic else ""
            print(f"{i+1:4d}: tick={node.tick:8d}  {symbol:30}  {inst}")
        print("-" * 80)
    
    # Step 6: Export if requested
    if args.export:
        # Determine output path
        output_path = args.output
        if not output_path:
            # Auto-generate filename
            ext_map = {
                "dot": "dot",
                "json": "json", 
                "chrome": "json",
                "html": "html"
            }
            ext = ext_map[args.export]
            output_path = f"dataflow_graph.{ext}"
        
        if args.export == "dot":
            export.export_dot(graph, output_path, show_waw=args.show_waw)
        elif args.export == "json":
            export.export_json(graph, output_path)
        elif args.export == "chrome":
            export.export_chrome_trace(graph, output_path)
        elif args.export == "html":
            export.export_html(graph, output_path, show_waw=args.show_waw)
        
        print(f"Exported graph to: {output_path}")
    
    # If no export and no critical path requested, just print stats
    elif not args.critical_path:
        print(f"Graph built successfully: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
        if not args.output:
            print("Use --export to save to file")


if __name__ == "__main__":
    main()
