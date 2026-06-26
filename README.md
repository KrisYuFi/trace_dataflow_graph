# Trace Dataflow Graph

## Project Overview

Trace Dataflow Graph builds dynamic dataflow graphs from gem5 execution traces. It combines instruction execution events, register access events, and optional raw machine bytes from the traced ELF binary so you can inspect register dependencies, extract subgraphs, and export results for graph or timeline tools.

## Architecture

The package has four layers: input readers, event normalization, graph construction, and query/export tools.

```text
ELF Binary ──→ ELF Reader ──→ raw_bytes ──┐
                                          ├──→ Event Merger ──→ Graph Builder ──→ Query/Export
Trace Log ──→ Trace Parser ──→ RawEvents ─┘
```

1. `ElfReader` reads the traced ELF executable and can attach raw instruction bytes from the `.text` section.
2. `TraceParser` streams gem5 trace lines and yields `RawEvent` objects for instruction execution, register reads, and register writes.
3. `EventMerger` groups raw register events with the following instruction event and produces `InstructionEvent` objects.
4. `GraphBuilder` creates a `DataflowGraph` with instruction nodes plus register RAW and WAW dependency edges, then `query` and `export` functions analyze or save the graph.

## Installation

From the gem5 repository root:

```bash
pip install -e tools/trace_dataflow_graph/
pip install pyelftools  # optional, for raw machine bytes
```

`pyelftools` is needed when you use the CLI with `--elf`, or when your Python code creates an `ElfReader`. Pass `elf_reader=None` to `EventMerger` if you only need trace based graph construction and want to skip raw machine bytes.

## CLI Usage

Run the package with `python -m trace_dataflow_graph`. The CLI requires a gem5 trace log and the ELF executable that produced the trace.

```bash
# Basic: build graph and export as DOT
python -m trace_dataflow_graph \
    --trace output/m5out/trace_softmax.log \
    --elf programs/softmax_256/softmax_256.riscv \
    --export dot --output graph.dot
```

```bash
# Critical path analysis
python -m trace_dataflow_graph \
    --trace output/m5out/trace_softmax.log \
    --elf programs/softmax_256/softmax_256.riscv \
    --critical-path
```

```bash
# Extract expf subgraph and export as Chrome Trace
python -m trace_dataflow_graph \
    --trace output/m5out/trace_softmax.log \
    --elf programs/softmax_256/softmax_256.riscv \
    --subgraph-symbol expf --export chrome --output expf_trace.json
```

Other useful options:

```bash
# Export a JSON graph
python -m trace_dataflow_graph \
    --trace output/m5out/trace_softmax.log \
    --elf programs/softmax_256/softmax_256.riscv \
    --export json --output graph.json

# Extract a tick range
python -m trace_dataflow_graph \
    --trace output/m5out/trace_softmax.log \
    --elf programs/softmax_256/softmax_256.riscv \
    --subgraph-tick 1000000 2000000 \
    --export dot --output tick_range.dot

# Hide WAW edges in DOT output
python -m trace_dataflow_graph \
    --trace output/m5out/trace_softmax.log \
    --elf programs/softmax_256/softmax_256.riscv \
    --export dot --output graph_no_waw.dot --no-waw
```

## Python API

Import the implementation classes from their submodules. This example skips ELF lookup, so it only needs a trace file and doesn't require `pyelftools`.

```python
from trace_dataflow_graph.trace_parser import TraceParser
from trace_dataflow_graph.event_merger import EventMerger
from trace_dataflow_graph.graph_builder import GraphBuilder
from trace_dataflow_graph.query import critical_path, subgraph_by_symbol
from trace_dataflow_graph.export import export_dot

# Parse and build
parser = TraceParser("trace.log")
merger = EventMerger(elf_reader=None)  # None means skip raw bytes
builder = GraphBuilder()
graph = builder.build(merger.merge(parser.parse()))

# Query
path = critical_path(graph)
expf = subgraph_by_symbol(graph, "expf")

# Export
export_dot(expf, "expf_graph.dot")

print(f"critical path length: {len(path)}")
print(f"expf subgraph: {len(expf.nodes)} nodes, {len(expf.edges)} edges")
```

Use `ElfReader` when you want raw instruction bytes attached to graph nodes.

```python
from trace_dataflow_graph.elf_reader import ElfReader
from trace_dataflow_graph.trace_parser import TraceParser
from trace_dataflow_graph.event_merger import EventMerger
from trace_dataflow_graph.graph_builder import GraphBuilder
from trace_dataflow_graph.export import export_json

elf = ElfReader("programs/softmax_256/softmax_256.riscv")
parser = TraceParser("output/m5out/trace_softmax.log")
merger = EventMerger(elf_reader=elf)

graph = GraphBuilder().build(merger.merge(parser.parse()))
export_json(graph, "graph.json")
```

The `query` module also includes helpers for common slices and dependency walks:

```python
from trace_dataflow_graph.query import (
    backward_deps,
    forward_deps,
    subgraph_by_pc,
    subgraph_by_tick,
    trace_register,
)

window = subgraph_by_tick(graph, 1000000, 2000000)
pc_hits = subgraph_by_pc(graph, 0x10144)
producers = backward_deps(graph, node_id=42, max_depth=3)
consumers = forward_deps(graph, node_id=42, max_depth=3)
writes_to_a0 = trace_register(graph, reg_phys=10)
```

## Trace Format Requirements

Generate traces from gem5 with instruction execution, result, symbol, user mode, integer register, and floating point register debug output enabled:

```text
--debug-flags=ExecEnable,ExecResult,ExecSymbol,ExecUser,IntRegs,FloatRegs
```

At minimum, graph construction needs instruction execution lines and register access lines. Use these flags when you only need the smallest trace for dependency edges:

```text
--debug-flags=ExecEnable,ExecUser,ExecResult
```

Add `IntRegs` and `FloatRegs` to capture register reads and writes. Add `ExecSymbol` when you want symbol names in parsed instruction events, `--subgraph-symbol` queries, DOT labels, JSON, and Chrome Trace output.

The parser currently recognizes lines shaped like these gem5 debug records:

```text
12345: ... Reading integer reg x[10] (10) as 0x1.
12345: ... Setting floating_point register f[10] (10) to 0x3f800000.
12345: ... 0x10144 @expf : fadd.s fa0, fa0, fa1 : D=0x3f800000
```

## Output Formats

* DOT, Graphviz input from `export_dot` or `--export dot`. Nodes show symbol or PC, instruction text, and tick. RAW edges are solid black, WAW edges are dashed gray unless hidden with `--no-waw`.
* JSON, full serialized graph from `export_json` or `--export json`. This includes nodes, edges, register accesses, raw bytes when present, and load/store flags.
* Chrome Trace, Perfetto compatible trace events from `export_chrome_trace` or `--export chrome`. Instruction nodes become timeline events and dependency edges become flow events.

## Known Limitations

* No memory dependency analysis, including load/store aliasing.
* Single-core SE mode only.
* RISC-V ISA only initially.
* Requires `pyelftools` for raw machine bytes.
