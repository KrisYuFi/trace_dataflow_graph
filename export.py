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


def _format_html_value(value: Optional[int]) -> Optional[str]:
    if value is None:
        return None
    return f"0x{value:x}"


def _symbol_prefix(symbol: Optional[str]) -> str:
    if not symbol:
        return "unknown"
    prefix = symbol.split("+", 1)[0]
    prefix = prefix.split(":", 1)[0]
    prefix = prefix.split()[0]
    return prefix or symbol


def _palette_color(symbol: Optional[str]) -> str:
    palette = [
        "#60a5fa", "#34d399", "#fbbf24", "#f87171", "#a78bfa",
        "#22d3ee", "#fb7185", "#c084fc", "#4ade80", "#f97316",
    ]
    key = _symbol_prefix(symbol)
    hash_value = 5381
    for char in key:
        hash_value = ((hash_value << 5) + hash_value) + ord(char)
    return palette[hash_value % len(palette)]


def _reg_access_to_html_dict(reg) -> dict:
    return {
        "reg_phys": f"0x{reg.reg_phys:x}",
        "reg_abi": reg.reg_abi,
        "reg_type": reg.reg_type,
        "value": _format_html_value(reg.value),
        "before_value": _format_html_value(reg.before_value),
    }


def _node_title(node: Node) -> str:
    def reg_line(reg) -> str:
        before = ""
        if reg.before_value is not None:
            before = f" before={_format_html_value(reg.before_value)}"
        return f"{reg.reg_abi}({reg.reg_type})={_format_html_value(reg.value)}{before}"

    lines = [
        f"tick: {node.tick}",
        f"pc: 0x{node.pc:x}",
        f"raw_bytes: {node.raw_bytes.hex() if node.raw_bytes is not None else ''}",
        "src_regs:",
    ]
    lines.extend(f"  {reg_line(reg)}" for reg in node.src_regs)
    lines.append("dst_regs:")
    lines.extend(f"  {reg_line(reg)}" for reg in node.dst_regs)
    return "\n".join(lines)


def _html_graph_payload(graph: DataflowGraph, show_waw: bool) -> dict:
    nodes = []
    edges = []

    for node_id, node in graph.nodes.items():
        symbol_or_pc = node.symbol or f"0x{node.pc:x}"
        instruction = " ".join(
            part for part in [node.mnemonic, node.operands] if part
        )
        label = f"{symbol_or_pc}\n{instruction}" if instruction else symbol_or_pc
        color = _palette_color(node.symbol)
        nodes.append({
            "id": node_id,
            "label": label,
            "shape": "box",
            "size": 20,
            "font": {"face": "monospace", "size": 12, "color": "#0f172a"},
            "color": {
                "background": color,
                "border": "#e2e8f0",
                "highlight": {"background": "#facc15", "border": "#fde68a"},
            },
            "baseColor": color,
            "title": _node_title(node),
            "searchText": f"{node.symbol or ''} 0x{node.pc:x}".lower(),
            "details": {
                "id": node.id,
                "tick": node.tick,
                "pc": f"0x{node.pc:x}",
                "raw_bytes": node.raw_bytes.hex() if node.raw_bytes is not None else "",
                "symbol": node.symbol,
                "symbol_prefix": _symbol_prefix(node.symbol),
                "mnemonic": node.mnemonic,
                "operands": node.operands,
                "src_regs": [_reg_access_to_html_dict(reg) for reg in node.src_regs],
                "dst_regs": [_reg_access_to_html_dict(reg) for reg in node.dst_regs],
                "is_load": node.is_load,
                "is_store": node.is_store,
            },
        })

    for edge in graph.edges:
        if edge.edge_type == EdgeType.REG_WAW and not show_waw:
            continue
        if edge.edge_type == EdgeType.REG_RAW:
            color = "#2563eb"
            width = 1.5
            dashes = False
        else:
            color = "#9ca3af"
            width = 0.8
            dashes = True
        edges.append({
            "from": edge.src,
            "to": edge.dst,
            "label": edge.label or "",
            "arrows": "to",
            "color": {"color": color, "highlight": color, "hover": color},
            "font": {"align": "middle", "color": "#e2e8f0", "strokeWidth": 3, "strokeColor": "#0f172a"},
            "width": width,
            "dashes": dashes,
            "edgeType": edge.edge_type.value,
            "value": _format_html_value(edge.value),
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "nodeCount": len(nodes),
        "edgeCount": len(edges),
    }


_HTML_EXPORT_TEMPLATE = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Trace Dataflow Graph - __NODE_COUNT__ nodes, __EDGE_COUNT__ edges</title><link rel="stylesheet" href="https://unpkg.com/vis-network@9.1.6/dist/dist/vis-network.min.css"><style>:root{--bg:#0f172a;--panel:#1e293b;--panel-strong:#111827;--text:#e2e8f0;--muted:#94a3b8;--border:#334155;--accent:#38bdf8;--raw:#2563eb;--waw:#9ca3af;--highlight:#facc15}*{box-sizing:border-box}html,body{width:100%;height:100%;margin:0;overflow:hidden;background:var(--bg);color:var(--text);font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace}body:before{position:fixed;inset:0;z-index:0;pointer-events:none;content:"";background:radial-gradient(circle at 15% 15%,rgba(37,99,235,.24),transparent 30%),radial-gradient(circle at 85% 20%,rgba(56,189,248,.16),transparent 28%),linear-gradient(135deg,rgba(15,23,42,.86),#0f172a)}#app{position:relative;z-index:1;display:grid;grid-template-rows:auto 1fr;width:100vw;height:100vh}.title-bar{display:flex;gap:1rem;align-items:center;justify-content:space-between;min-height:4.5rem;padding:.85rem 1rem;border-bottom:1px solid var(--border);background:rgba(30,41,59,.92);box-shadow:0 16px 40px rgba(2,6,23,.28);backdrop-filter:blur(10px)}.title-copy h1{margin:0;color:var(--text);font-size:clamp(1rem,2vw,1.35rem);font-weight:700;letter-spacing:-.02em}.title-copy p{margin:.25rem 0 0;color:var(--muted);font-size:.78rem}.search-wrap{display:flex;width:min(28rem,42vw);min-width:14rem;align-items:center;border:1px solid var(--border);border-radius:999px;background:rgba(15,23,42,.82);box-shadow:inset 0 1px 0 rgba(226,232,240,.06)}#search{width:100%;border:0;outline:0;padding:.75rem 1rem;background:transparent;color:var(--text);font:inherit;font-size:.85rem}#search::placeholder{color:var(--muted)}#network{width:100%;height:100%;min-height:0}.legend{position:fixed;left:1rem;bottom:1rem;z-index:3;min-width:12rem;padding:.8rem .9rem;border:1px solid var(--border);border-radius:.85rem;background:rgba(30,41,59,.9);box-shadow:0 18px 48px rgba(2,6,23,.4);backdrop-filter:blur(10px)}.legend-title{margin-bottom:.55rem;color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.08em}.legend-row{display:flex;gap:.65rem;align-items:center;margin-top:.35rem;color:var(--text);font-size:.78rem}.legend-line{width:2.75rem;height:0;border-top:2px solid var(--raw)}.legend-line.waw{border-color:var(--waw);border-top-style:dashed}#details{position:fixed;top:4.5rem;right:0;bottom:0;z-index:4;width:min(28rem,92vw);overflow-y:auto;border-left:1px solid var(--border);background:var(--panel);box-shadow:-24px 0 56px rgba(2,6,23,.42);transform:translateX(102%);transition:transform 180ms ease}#details.open{transform:translateX(0)}.detail-card{padding:1rem}.detail-header{display:flex;gap:1rem;align-items:flex-start;justify-content:space-between;padding-bottom:.85rem;border-bottom:1px solid var(--border)}.detail-header h2{margin:0;font-size:1rem;line-height:1.35;word-break:break-word}.detail-subtitle{margin-top:.35rem;color:var(--muted);font-size:.76rem}.close-button{flex:0 0 auto;border:1px solid var(--border);border-radius:999px;padding:.35rem .62rem;background:var(--panel-strong);color:var(--text);cursor:pointer;font:inherit}.detail-section{margin-top:1rem;padding:.85rem;border:1px solid var(--border);border-radius:.85rem;background:rgba(15,23,42,.5)}.detail-section h3{margin:0 0 .7rem;color:var(--accent);font-size:.78rem;letter-spacing:.06em;text-transform:uppercase}.kv{display:grid;grid-template-columns:7rem 1fr;gap:.45rem .75rem;font-size:.78rem}.kv span:nth-child(odd){color:var(--muted)}.kv span:nth-child(even){word-break:break-word}table{width:100%;border-collapse:collapse;font-size:.75rem}th,td{padding:.42rem .35rem;border-bottom:1px solid rgba(51,65,85,.7);text-align:left;vertical-align:top;word-break:break-word}th{color:var(--muted);font-weight:600}.empty{color:var(--muted);font-size:.76rem}@media(max-width:760px){.title-bar{align-items:stretch;flex-direction:column;min-height:7.5rem}.search-wrap{width:100%}#details{top:7.5rem}.legend{right:1rem;min-width:0}}</style></head><body><div id="app"><header class="title-bar"><div class="title-copy"><h1>Trace Dataflow Graph - __NODE_COUNT__ nodes, __EDGE_COUNT__ edges</h1><p>Search symbols or PC addresses, then click an instruction for register details.</p></div><div class="search-wrap"><input id="search" type="search" placeholder="Search symbol or PC hex..." autocomplete="off"></div></header><main id="network" aria-label="Trace dataflow graph"></main></div><aside id="details" aria-live="polite"></aside><div class="legend" aria-label="Edge legend"><div class="legend-title">Dependencies</div><div class="legend-row"><span class="legend-line"></span><span>RAW register flow</span></div><div class="legend-row"><span class="legend-line waw"></span><span>WAW overwrite</span></div></div><script id="graph-data" type="application/json">__GRAPH_JSON__</script><script src="https://unpkg.com/vis-network@9.1.6/dist/vis-network.min.js"></script><script>__GRAPH_SCRIPT__</script></body></html>"""

_JS_EXPORT_SCRIPT = """const graphData=JSON.parse(document.getElementById('graph-data').textContent);const nodeMap=new Map(graphData.nodes.map((node)=>[node.id,node]));const nodes=new vis.DataSet(graphData.nodes);const edges=new vis.DataSet(graphData.edges);const network=new vis.Network(document.getElementById('network'),{nodes,edges},{autoResize:true,layout:{hierarchical:{enabled:true,direction:'RL',sortMethod:'directed',levelSeparation:200,nodeSpacing:150,treeSpacing:200,blockShifting:true,edgeMinimization:true,parentCentralization:false}},physics:{enabled:false},interaction:{hover:true,tooltipDelay:120,navigationButtons:true},nodes:{borderWidth:1,margin:10,shadow:{enabled:true,color:'rgba(2,6,23,.35)',size:10,x:0,y:4}},edges:{smooth:{type:'dynamic'}}});const details=document.getElementById('details');const htmlEscape=(value)=>String(value??'').replace(/[&<>'"]/g,(char)=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));const valueOrDash=(value)=>value===null||value===undefined||value===''?'-':htmlEscape(value);function regTable(rows,columns){if(!rows.length){return '<div class="empty">No registers recorded.</div>'}const header=columns.map((column)=>`<th>${htmlEscape(column.label)}</th>`).join('');const body=rows.map((row)=>`<tr>${columns.map((column)=>`<td>${valueOrDash(row[column.key])}</td>`).join('')}</tr>`).join('');return `<table><thead><tr>${header}</tr></thead><tbody>${body}</tbody></table>`}function showDetails(nodeId){const node=nodeMap.get(nodeId);if(!node){return}const data=node.details;const instruction=[data.mnemonic,data.operands].filter(Boolean).join(' ');details.innerHTML=`<div class="detail-card"><div class="detail-header"><div><h2>${htmlEscape(data.symbol||data.pc)}</h2><div class="detail-subtitle">${htmlEscape(data.symbol_prefix)} - node ${htmlEscape(data.id)}</div></div><button class="close-button" type="button" onclick="document.getElementById('details').classList.remove('open')">Close</button></div><section class="detail-section"><h3>Instruction</h3><div class="kv"><span>PC</span><span>${htmlEscape(data.pc)}</span><span>Tick</span><span>${htmlEscape(data.tick)}</span><span>Mnemonic</span><span>${valueOrDash(data.mnemonic)}</span><span>Operands</span><span>${valueOrDash(data.operands)}</span><span>Instruction</span><span>${valueOrDash(instruction)}</span><span>Raw bytes</span><span>${valueOrDash(data.raw_bytes)}</span><span>is_load</span><span>${htmlEscape(data.is_load)}</span><span>is_store</span><span>${htmlEscape(data.is_store)}</span></div></section><section class="detail-section"><h3>Source registers</h3>${regTable(data.src_regs,[{key:'reg_abi',label:'reg'},{key:'value',label:'value'},{key:'before_value',label:'before'}])}</section><section class="detail-section"><h3>Destination registers</h3>${regTable(data.dst_regs,[{key:'reg_abi',label:'reg'},{key:'before_value',label:'before'},{key:'value',label:'after'}])}</section></div>`;details.classList.add('open')}network.on('click',(params)=>{if(params.nodes.length){showDetails(params.nodes[0])}});document.getElementById('search').addEventListener('input',(event)=>{const query=event.target.value.trim().toLowerCase();const updates=graphData.nodes.map((node)=>{const matches=query&&node.searchText.includes(query);return{id:node.id,color:matches?{background:'#facc15',border:'#fde68a',highlight:{background:'#facc15',border:'#fde68a'}}:node.color,borderWidth:matches?3:1,font:matches?{face:'monospace',size:12,color:'#0f172a',bold:true}:node.font}});nodes.update(updates)});"""


def export_html(graph: DataflowGraph, filepath: str, show_waw: bool = True) -> None:
    payload = _html_graph_payload(graph, show_waw)
    graph_json = json.dumps(payload, separators=(",", ":"))
    graph_json = graph_json.replace("</", "<\\/")
    html = _HTML_EXPORT_TEMPLATE
    html = html.replace("__NODE_COUNT__", str(payload["nodeCount"]))
    html = html.replace("__EDGE_COUNT__", str(payload["edgeCount"]))
    html = html.replace("__GRAPH_JSON__", graph_json)
    html = html.replace("__GRAPH_SCRIPT__", _JS_EXPORT_SCRIPT)
    with open(filepath, 'w') as f:
        f.write(html)
