from typing import Dict, List, Optional, Tuple

from .models import DataflowGraph, Edge, EdgeType, Node


def _build_edge_index(graph: DataflowGraph) -> Tuple[Dict[int, List[Edge]], Dict[int, List[Edge]]]:
    """Build and cache edge indices for fast lookup."""
    if hasattr(graph, "_edge_index_built"):
        return graph._edges_by_src, graph._edges_by_dst

    edges_by_src: Dict[int, List[Edge]] = {}
    edges_by_dst: Dict[int, List[Edge]] = {}

    for edge in graph.edges:
        edges_by_src.setdefault(edge.src, []).append(edge)
        edges_by_dst.setdefault(edge.dst, []).append(edge)

    graph._edges_by_src = edges_by_src
    graph._edges_by_dst = edges_by_dst
    graph._edge_index_built = True
    return edges_by_src, edges_by_dst


def _build_subgraph(graph: DataflowGraph, node_ids: set) -> DataflowGraph:
    """Build a new DataflowGraph containing only the given node_ids and edges
    where both src and dst are in the set."""
    subgraph = DataflowGraph()
    for nid in node_ids:
        if nid in graph.nodes:
            subgraph.add_node(graph.nodes[nid])
    for edge in graph.edges:
        if edge.src in node_ids and edge.dst in node_ids:
            subgraph.add_edge(edge)
    return subgraph


def subgraph_by_tick(graph: DataflowGraph, start: int, end: int) -> DataflowGraph:
    """Return a subgraph with nodes whose tick is in [start, end] (inclusive)."""
    filtered = {
        node.id for node in graph.nodes.values()
        if start <= node.tick <= end
    }
    return _build_subgraph(graph, filtered)


def subgraph_by_symbol(graph: DataflowGraph, pattern: str) -> DataflowGraph:
    """Return a subgraph with nodes whose symbol contains *pattern* (substring match)."""
    filtered = {
        node.id for node in graph.nodes.values()
        if node.symbol is not None and pattern in node.symbol
    }
    return _build_subgraph(graph, filtered)


def subgraph_by_pc(graph: DataflowGraph, pc: int) -> DataflowGraph:
    """Return a subgraph with nodes at the given PC (multiple dynamic instances)."""
    filtered = {
        node.id for node in graph.nodes.values()
        if node.pc == pc
    }
    return _build_subgraph(graph, filtered)


def critical_path(graph: DataflowGraph) -> List[Node]:
    """Return the longest chain of REG_RAW dependencies using topological DP.

    Nodes are already in topological order by their sequential ids.
    dp[node] = 1 + max(dp[producer] for REG_RAW producers).
    """
    if not graph.nodes:
        return []

    edges_by_src, edges_by_dst = _build_edge_index(graph)

    producers: Dict[int, List[int]] = {}
    for edge in graph.edges:
        if edge.edge_type == EdgeType.REG_RAW:
            producers.setdefault(edge.dst, []).append(edge.src)

    sorted_nodes = sorted(graph.nodes.keys())

    dp: Dict[int, int] = {}
    pred: Dict[int, Optional[int]] = {}

    for nid in sorted_nodes:
        prod_list = producers.get(nid, [])
        if not prod_list:
            dp[nid] = 1
            pred[nid] = None
        else:
            best_p = max(prod_list, key=lambda p: dp[p])
            dp[nid] = dp[best_p] + 1
            pred[nid] = best_p

    max_node = max(dp, key=dp.get)

    path: List[int] = []
    cur: Optional[int] = max_node
    while cur is not None:
        path.append(cur)
        cur = pred[cur]
    path.reverse()

    return [graph.nodes[nid] for nid in path]


def trace_register(graph: DataflowGraph, reg_phys: int) -> List[Tuple[int, Optional[int], int]]:
    """Return [(tick, before_value, after_value)] for every node that writes *reg_phys*."""
    results: List[Tuple[int, Optional[int], int]] = []
    for node in graph.nodes.values():
        for dst_reg in node.dst_regs:
            if dst_reg.reg_phys == reg_phys:
                results.append((node.tick, dst_reg.before_value, dst_reg.value))
    results.sort(key=lambda x: x[0])
    return results


def backward_deps(graph: DataflowGraph, node_id: int, max_depth: int) -> DataflowGraph:
    """BFS backward through REG_RAW edges, returning a subgraph of reached nodes."""
    if node_id not in graph.nodes:
        return DataflowGraph()

    edges_by_src, edges_by_dst = _build_edge_index(graph)
    collected: set = {node_id}
    frontier = {node_id}

    for _ in range(max_depth):
        if not frontier:
            break
        next_frontier: set = set()
        for nid in frontier:
            for edge in edges_by_dst.get(nid, []):
                if edge.edge_type == EdgeType.REG_RAW and edge.src not in collected:
                    collected.add(edge.src)
                    next_frontier.add(edge.src)
        frontier = next_frontier

    return _build_subgraph(graph, collected)


def forward_deps(graph: DataflowGraph, node_id: int, max_depth: int) -> DataflowGraph:
    """BFS forward through REG_RAW edges, returning a subgraph of reached nodes."""
    if node_id not in graph.nodes:
        return DataflowGraph()

    edges_by_src, edges_by_dst = _build_edge_index(graph)
    collected: set = {node_id}
    frontier = {node_id}

    for _ in range(max_depth):
        if not frontier:
            break
        next_frontier: set = set()
        for nid in frontier:
            for edge in edges_by_src.get(nid, []):
                if edge.edge_type == EdgeType.REG_RAW and edge.dst not in collected:
                    collected.add(edge.dst)
                    next_frontier.add(edge.dst)
        frontier = next_frontier

    return _build_subgraph(graph, collected)
