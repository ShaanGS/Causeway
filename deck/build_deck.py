"""Build the RECURSION deck from the pristine template. Repeatable: run it again after
any content edit rather than hand-patching the unpacked XML.

The one non-obvious step is `connectors_to_rects`. The template draws its logo mark and
footer rules with <p:cxnSp> straightConnector1 shapes. Connectors are *routable*: a viewer
is entitled to recompute their path and their end caps, and some do -- which is how a
0.2in rule inside the logo turns into a full-width line with an arrowhead on it. A
rectangle has no route and no end caps, so it renders the same everywhere.
"""
import re, zipfile
from xml.dom.minidom import parseString

S = 'unpacked/ppt/slides/slide%d.xml'
THIN = 1000          # EMU: below this an axis is the line's thickness, not its length
DEFAULT_W = 12700    # 1pt, if the connector declares no width


def connectors_to_rects(xml: str) -> tuple[str, int]:
    """Rewrite every <p:cxnSp> as an equivalent filled <p:sp> rectangle."""
    out, pos, n = [], 0, 0
    for m in re.finditer(r'<p:cxnSp>.*?</p:cxnSp>', xml, re.S):
        b = m.group(0)
        off = re.search(r'<a:off x="(-?\d+)" y="(-?\d+)"/>', b)
        ext = re.search(r'<a:ext cx="(\d+)" cy="(\d+)"/>', b)
        cid = re.search(r'<p:cNvPr id="(\d+)" name="([^"]*)"', b)
        if not (off and ext and cid):
            continue
        x, y = int(off.group(1)), int(off.group(2))
        cx, cy = int(ext.group(1)), int(ext.group(2))
        wm = re.search(r'<a:ln[^>]*\sw="(\d+)"', b)
        w = int(wm.group(1)) if wm else DEFAULT_W
        col = re.search(r'<a:solidFill><a:srgbClr val="([0-9A-Fa-f]{6})"', b)
        colour = col.group(1) if col else '111111'

        # Give the thin axis the stroke's real width, centred on the original path.
        if cx < THIN:
            x -= w // 2
            cx = w
        if cy < THIN:
            y -= w // 2
            cy = w

        out.append(xml[pos:m.start()])
        out.append(
            f'<p:sp><p:nvSpPr><p:cNvPr id="{cid.group(1)}" name="{cid.group(2)}"/>'
            f'<p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:spPr>'
            f'<a:xfrm><a:off x="{x}" y="{y}"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm>'
            f'<a:prstGeom prst="rect"><a:avLst/></a:prstGeom>'
            f'<a:solidFill><a:srgbClr val="{colour}"/></a:solidFill>'
            f'<a:ln><a:noFill/></a:ln></p:spPr>'
            f'<p:txBody><a:bodyPr/><a:lstStyle/><a:p/></p:txBody></p:sp>'
        )
        pos, n = m.end(), n + 1
    out.append(xml[pos:])
    return ''.join(out), n


def drop_last(path, pattern, keep, label):
    s = open(path, encoding='utf-8').read()
    hits = [m for m in re.finditer(pattern, s, re.S) if '[ Name ]' in m.group(0)]
    assert len(hits) > keep, f'{label}: found {len(hits)}'
    for m in reversed(hits[keep:]):
        s = s[:m.start()] + s[m.end():]
    open(path, 'w', encoding='utf-8').write(s)
    print(f'  {label}: {len(hits)} -> {keep}')


def fill(n, pairs):
    path = S % n
    s = open(path, encoding='utf-8').read()
    for old, new in pairs:
        tag = f'<a:t>{old}</a:t>'
        if tag not in s:
            print(f'  MISSING s{n}: {old[:44]!r}')
            continue
        esc = new.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        s = s.replace(tag, f'<a:t>{esc}</a:t>', 1)
    open(path, 'w', encoding='utf-8').write(s)


TEAM = [("Shaan GS", "9042769952", "shaangurushankar@gmail.com"),
        ("Pradeesh Govindarajan", "+91 93449 11072", "pradeeshgovi@gmail.com"),
        ("Shreyas Gopalika", "+91 91 22 0444 45", "sg8268@srmist.edu.in")]


def main():
    import shutil, os
    shutil.rmtree('unpacked', ignore_errors=True)
    zipfile.ZipFile('template.pptx').extractall('unpacked')

    drop_last(S % 1, r'<p:sp>.*?</p:sp>', 3, 'slide1 name slots')
    drop_last(S % 9, r'<a:tr\b.*?</a:tr>', 3, 'slide9 contact rows')

    fill(1, [('[ Your Project Title Goes Here ]', 'Causeway'),
             ("[ One sentence: what it is and who it's for. ]",
              'For SOC analysts: one incident, with a named cause, from a night of alerts.'),
             ('[ Selected Track ]', 'Cybersecurity — PS2'),
             ('[ Team Name ]', 'Marlloz')] + [('[ Name ]', t[0]) for t in TEAM])

    fill(2, [('[ Who feels this pain, and how often do they feel it? ]',
              'SOC analysts, every shift. One attacker action fires dozens of correct alerts across endpoint, identity, email, firewall and cloud.'),
             ('[ How is this handled today, without your solution? ]',
              'Analysts pivot between consoles by hand, matching timestamps and identities. Tooling dedups by merging alerts whose text looks alike.'),
             ('[ Why does that current approach fall short? ]',
              'Text-merging destroys evidence: two alerts that read alike can be two attack stages. Broad automation isolates hosts on weak grounds.'),
             ('[ What evidence shows this problem is real? Data, quotes, sources. ]',
              'We measured it. On a 938-alert corpus, text dedup buried the successful login that was the root cause and recovered 4 of 9 stages.')])

    fill(3, [('[ Product / System Name ]', 'Causeway'),
             ('[ Plain-language description: what it does, in one or two sentences. ]',
              'Rebuilds the causal incident behind scattered alerts, ranks what to contain, and gates every response on the evidence for it.'),
             ('[ The concrete steps a user takes with it. ]',
              'Open one case instead of hundreds: a causal graph, the ranked root cause, and a recommended action that shows its reasoning.'),
             ("[ What's better than today's alternative, concretely. ]",
              '938 alerts became 17 cases. All nine stages in one incident, recall 1.00, root cause correct. Nothing is deleted.'),
             ('[ Your actual point of difference — be specific. ]',
              'We rank entities, not alerts — nobody contains a row. Confidence stays separate from what the evidence may authorise.')])

    fill(4, [('[ FRONTEND ]', 'RESOLVE + DEDUP'), ('[ API / BACKEND ]', 'CAUSAL EDGES'),
             ('[ MODEL / AWS SERVICE ]', 'EVIDENCE GATE'), ('USER INPUT', 'ALERTS IN'),
             ('OUTPUT', 'CASE + ACTION'),
             ('↑ replace with your real architecture diagram',
              'any product → canonical entities → causal DAG → evidence-gated response'),
             ('[ The decision, and why you made it. ]',
              'No model, no network call in the decision path. Deterministic rules, ~42 ms per run, every refusal explainable in one sentence.'),
             ('[ What was genuinely hard, and how you solved it. ]',
              'Stopping the benign estate collapsing into one incident. Fixed by weighting entities by rarity, so hub entities link nothing.'),
             ('[ Tests or evaluations you ran. ]',
              '27 tests, four configurations. With rarity weighting off precision collapses to 0.13 — the control that proves the design works.')])

    fill(5, [("[ what's in scope ]", 'correlation, entity resolution, reversible dedup, root cause, gated response, console'),
             ("[ what's explicitly not ]", 'we recommend actions, never execute them; no live connectors, no ML model'),
             ('[ What it costs to run — compute, APIs, storage. ]',
              'Effectively zero. Pure Python, no model calls, no external API. 938 alerts in ~42 ms, and it runs fully on-premise.'),
             ('[ What could break, and your fallback plan. ]',
              'Precision on real telemetry. We tested on the public AIT corpus: dedup transferred, correlation did not. Reported, not hidden.'),
             ('[ Where this goes next — roadmap. ]',
              "Learn entity rarity from an environment's own baseline, then add live connectors.")])

    fill(6, [('[ 00% ]', '98%'),
             ('[ one line: what this figure means ]', 'fewer queue items — 938 alerts became 17 cases'),
             ('[ show your working — estimate is acceptable ]',
              '938-alert corpus, labelled 9-stage intrusion. Cases = 17. Recall 1.00 and zero evidence-erasing suppressions.'),
             ('[ The concrete before/after change. ]', 'Analysts open 17 cases, not 938 rows, with the root cause named.'),
             ('[ Other beneficiaries beyond your primary user. ]', 'MSSPs, cloud-security teams, and regulated environments needing an audit trail.'),
             ('[ Realistic misuse or failure case. ]', 'Over-trust: a confident graph could persuade an analyst to skip verification.'),
             ('[ Your mitigation for the above. ]', 'Nothing is deleted; every suppression is reversible. Destructive actions need a human.')])

    rows = [('[ Author, “Title,” Year ]', 'Landauer et al., “A New Alert Data Set for Multi-Step Attack Analysis”, CSET ’24', 'Alert-level corpus design; multi-step framing', 'borrowed — cited', 'ACM, cited'),
            ('[ Repo name / org ]', 'Ventriloquist — our own EDGE NOVA’26 provenance gateway', 'Lineage closure, blast radius, audit chain, policy engine', 'yours', 'own work'),
            ('[ Docs source ]', 'FastAPI · Starlette · Uvicorn · PyYAML', 'HTTP surface and YAML policy loading', 'borrowed', 'MIT / BSD-3'),
            ('[ Dataset name ]', 'AIT Alert Data Set — doi 10.5281/zenodo.8263181', '45,544 real labelled alerts, 3 detectors', 'borrowed', 'CC-BY-4.0'),
            ('[ Model name ]', 'None — no ML model or pretrained weights', 'Correlation is deterministic; no inference step', 'n/a', 'n/a')]
    pairs = []
    for ph, src, gave, own, lic in rows:
        pairs += [(ph, src), ('[ what it gave you ]', gave), ('[ borrowed / yours ]', own), ('[ licence ]', lic)]
    fill(7, pairs)

    fill(8, [('EXTRA SLIDE', 'THE CONSOLE'),
             ('[ optional space · demo link · screenshots · github · qr code ]',
              'One reconstructed incident: 938 alerts in, ranked root cause, gated response.')])

    contact = [('[ Team Name ]', 'Marlloz')]
    for nm, ph, em in TEAM:
        contact += [('[ Name ]', nm), ('[ phone number ]', ph), ('[ email address ]', em)]
    fill(9, contact)

    # checklist sticker: the template's own notes say to remove it
    p = S % 8
    x = open(p, encoding='utf-8').read()
    sps = [(m.start(), m.end(), m.group(0)) for m in re.finditer(r'<p:sp>.*?</p:sp>', x, re.S)]
    i = next(k for k, (s, e, b) in enumerate(sps) if 'BEFORE YOU SUBMIT' in b)
    open(p, 'w', encoding='utf-8').write(x[:sps[i - 1][0]] + x[sps[i][1]:])

    # contact table shrank; its black backing plate has to shrink with it
    p = S % 9
    x = open(p, encoding='utf-8').read()
    m = re.search(r'<p:sp>(?:(?!</p:sp>).)*?name="Google Shape;316;p9".*?</p:sp>', x, re.S)
    b = m.group(0)
    e = re.search(r'<a:ext cx="(\d+)" cy="(\d+)"', b)
    x = x[:m.start()] + b[:e.start(2)] + '2194579' + b[e.end(2):] + x[m.end():]
    open(p, 'w', encoding='utf-8').write(x)

    total = 0
    for n in range(1, 10):
        x = open(S % n, encoding='utf-8').read()
        x, c = connectors_to_rects(x)
        total += c
        open(S % n, 'w', encoding='utf-8').write(x)
        parseString(x)
    print(f'  connectors -> rectangles: {total}')
    print('  all 9 slides well-formed')


if __name__ == '__main__':
    main()
