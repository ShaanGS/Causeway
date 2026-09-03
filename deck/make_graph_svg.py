"""Render the causal graph to a standalone SVG for the deck.

Same layout rules as the console, so the slide and the screen cannot drift apart: time on
x, one lane per machine, process-ancestry edges drawn heavier, the root-cause node ringed.
Regenerating this is the only way a figure in the deck changes.
"""
import sys
sys.path.insert(0, ".")
from causeway.pipeline import Pipeline

SENSOR = {"edr": "#58a6ff", "wazuh": "#a371f7", "suricata": "#d29922", "aminer": "#3fb950"}
W, PAD, LANE, GAP = 1180, 120, 66, 19


def render(g, out):
    H = 44 + len(g["lanes"]) * LANE + 46
    nodes = {n["id"]: n for n in g["nodes"]}
    for n in g["nodes"]:
        n["px"] = PAD + n["x"] * (W - PAD - 52)
    by_lane = {}
    for n in g["nodes"]:
        by_lane.setdefault(n["lane"], []).append(n)
    for lane in by_lane.values():
        lane.sort(key=lambda n: n["px"])
        for i in range(1, len(lane)):
            lane[i]["px"] = max(lane[i]["px"], lane[i - 1]["px"] + GAP)
        over = lane[-1]["px"] - (W - 52)
        if over > 0:
            for n in lane:
                n["px"] -= over
    Y = lambda n: 44 + n["lane"] * LANE

    p = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W*2}" height="{H*2}" '
         f'viewBox="0 0 {W} {H}" font-family="Helvetica,Arial,sans-serif">',
         f'<rect width="{W}" height="{H}" fill="#0b0f16"/>']
    for l in g["lanes"]:
        y = 44 + l["index"] * LANE
        p.append(f'<line x1="{PAD-14}" y1="{y}" x2="{W-30}" y2="{y}" stroke="#242c37" '
                 f'stroke-dasharray="2 5"/>')
        p.append(f'<text x="{PAD-22}" y="{y+4}" fill="#8b949e" font-size="12.5" '
                 f'text-anchor="end" font-family="Menlo,monospace">{l["label"]}</text>')
    for e in g["edges"]:
        a, b = nodes.get(e["src"]), nodes.get(e["dst"])
        if not a or not b:
            continue
        x1, y1, x2, y2 = a["px"], Y(a), b["px"], Y(b)
        mx = (x1 + x2) / 2
        strong = e["rule_id"] == "C-01"
        p.append(f'<path d="M{x1} {y1} C {mx} {y1}, {mx} {y2}, {x2} {y2}" fill="none" '
                 f'stroke="{"#58a6ff" if strong else "#6e7681"}" '
                 f'stroke-width="{2.1 if strong else 1.2}" '
                 f'opacity="{0.9 if strong else 0.5}"/>')
    for n in g["nodes"]:
        import math
        r = 5.5 + min(7.5, math.log2(n["count"] + 1) * 2.2)
        c = SENSOR.get(n["sensor"], "#8b949e")
        if n["is_root"]:
            p.append(f'<circle cx="{n["px"]}" cy="{Y(n)}" r="{r+7}" fill="none" '
                     f'stroke="#f85149" stroke-width="1.8"/>')
            p.append(f'<text x="{n["px"]}" y="{Y(n)-r-13}" fill="#f85149" font-size="12.5" '
                     f'text-anchor="middle">root cause</text>')
        p.append(f'<circle cx="{n["px"]}" cy="{Y(n)}" r="{r}" fill="{c}" fill-opacity="0.85" '
                 f'stroke="{c}" stroke-width="1.3"/>')
    lx, ly = PAD - 22, H - 16
    for i, (s, c) in enumerate(SENSOR.items()):
        p.append(f'<circle cx="{lx + i*112}" cy="{ly-4}" r="5" fill="{c}"/>')
        p.append(f'<text x="{lx + i*112 + 11}" y="{ly}" fill="#8b949e" font-size="12.5">{s}</text>')
    p.append(f'<text x="{W-30}" y="{ly}" fill="#6e7681" font-size="12" text-anchor="end">'
             f'{g["first_seen"]}  →  {g["last_seen"]}</text>')
    p.append("</svg>")
    open(out, "w", encoding="utf-8").write("\n".join(p))
    print(f"wrote {out}  ({len(g['nodes'])} nodes, {len(g['edges'])} edges)")


if __name__ == "__main__":
    pl = Pipeline.from_lab().run()
    big = max(pl.cases, key=lambda c: c.incident.alert_count)
    render(pl.graph(big.incident.id), "deck/causal-graph.svg")
