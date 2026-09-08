"""Figure 2 - one mechanism, five consequences, one boundary.

    python tools/figure_consequence_spine.py

Hand-authored SVG rather than matplotlib: this is a diagram, not a plot, and
matplotlib fights that shape. The layout is written by hand; the **numbers are
derived** from the frozen graph and `results/h5_h6.json`, so the figure cannot
drift from the results it summarises.

Greyscale is handled by hand for the same reason it is inherited elsewhere.
Majority and boundary rows are distinguished by **marker shape and hatching,
never by hue**: solid square plus tinted panel for majority, open circle plus
rule-hatched panel for boundary. Printed in black and white, nothing is lost.

The top band states the **cause**, not the modal share. Four access-control types
produce one detection signature; the 79.4% is what that does to the graph a
planner sees. Leading with the share would assert precisely the conflation
`test_modal_class_membership_is_five_types_but_four_share_the_signature` exists
to separate.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
import math
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from stealthpath.ad_schema import DEFAULT_TRAVERSAL_SET  # noqa: E402
from stealthpath.graph import AttackGraph  # noqa: E402
from stealthpath.risk import PROVISIONAL_WEIGHTS  # noqa: E402

OUT = ROOT / "results" / "figures" / "fig2_consequence_spine.svg"

W, H = 1000, 698
INK, MID, SOFT = "#1a1a1a", "#4a4a4a", "#8a8a8a"
PANEL_MAJ, PANEL_BND, LINE = "#ededed", "#ffffff", "#c9c9c9"
SERIF = "Georgia, Times New Roman, serif"
MONO = "Consolas, Menlo, monospace"

SHAPE_D = ("WriteDacl", "WriteOwner", "GenericAll", "GenericWrite")


def derive() -> dict:
    graph = AttackGraph.load(ROOT / "data" / "goad_graph.json")
    walk = [e for e in graph.edges if e.rel_type in DEFAULT_TRAVERSAL_SET]
    counts = Counter(e.rel_type for e in walk)
    modal = sum(counts[t] for t in counts if PROVISIONAL_WEIGHTS[t].weight == 4.0)
    res = json.loads((ROOT / "results" / "h5_h6.json").read_text(encoding="utf-8"))
    r = res["results"]
    tywin = "TYWIN.LANNISTER@SEVENKINGDOMS"
    return {
        "modal_pct": modal / len(walk) * 100,
        "n_shape_d": len(SHAPE_D),
        "acl_weight": PROVISIONAL_WEIGHTS["GenericWrite"].weight,
        "tywin_static": r["planners_base"][tywin]["weighted_astar"]["cost_display"],
        "tywin_history": r["h5_rl_no_retraining"][tywin]["optimum_base"]["cost_display"],
        "hops_before": r["planners_base"][tywin]["weighted_astar"]["hops"],
        "hops_after": r["planners_perturbed"][tywin]["weighted_astar"]["hops"],
    }



def _hatch(x0: float, y0: float, w: float, h: float,
           spacing: float = 7.0, colour: str = "#e4e4e4",
           width: float = 1.7) -> list:
    """Diagonal 45-degree rules filling a rectangle, as plain <line> elements.

    Replaces `<pattern patternTransform="rotate(45)">`. The family is x + y = c;
    perpendicular spacing `spacing` means stepping c by spacing * sqrt(2). Each
    line is clipped to the rectangle analytically rather than with <clipPath>,
    because a converter that drops <pattern> may well drop <clipPath> too.
    """
    x1, y1 = x0 + w, y0 + h
    step = spacing * math.sqrt(2)
    out = []
    c = x0 + y0
    while c <= x1 + y1:
        ax = max(x0, c - y1)
        bx = min(x1, c - y0)
        if bx > ax:
            out.append('<line x1="{:.2f}" y1="{:.2f}" x2="{:.2f}" y2="{:.2f}" '
                       'stroke="{}" stroke-width="{}"/>'
                       .format(ax, c - ax, bx, c - bx, colour, width))
        c += step
    return out



def _write_png(svg_path: Path, dpi: int = 300) -> Path | None:
    """Rasterise the SVG for templates that cannot place vector art.

    SVG is the source; the PNG is derived from it and never edited. The route is
    svglib -> PDF -> PyMuPDF, chosen because PyMuPDF alone renders this file's
    boundary rows as solid black. Optional on purpose: the figure's own
    correctness does not depend on the raster, so a missing converter prints a
    note rather than failing the build.
    """
    try:
        import pymupdf
        from reportlab.graphics import renderPDF
        from svglib.svglib import svg2rlg
    except ImportError:
        print("  (PNG skipped: pip install -r requirements-figures.txt)")
        return None

    import tempfile
    drawing = svg2rlg(str(svg_path))
    png = svg_path.with_suffix(".png")
    with tempfile.TemporaryDirectory() as tmp:
        pdf = Path(tmp) / "fig.pdf"
        renderPDF.drawToFile(drawing, str(pdf))
        # Closed explicitly: PyMuPDF keeps the file handle open, and on Windows
        # the TemporaryDirectory cleanup then fails with a sharing violation.
        doc = pymupdf.open(pdf)
        try:
            doc[0].get_pixmap(dpi=dpi).save(png)
        finally:
            doc.close()
    return png


def main() -> None:
    d = derive()

    # (n, who, claim, detail, value, hypothesis, is_majority)
    # Rows 1 and 2 carry no value on purpose: they report absences, and a figure
    # cannot show an absence with a number.
    rows = [
        ("1", "SAMWELL", "Risk-weighting has nothing to choose",
         "Both planners return the same route at the same cost",
         "", "H2", True),
        ("2", "H1", "No hops-versus-risk frontier exists",
         "Hop counts identical on all three entry points",
         "", "H1", True),
        ("3", "TYWIN", "History-dependence has nothing to re-rank",
         "Cost moves, route does not - and still does not at k = 10",
         "{:g} -> {:g}".format(d["tywin_static"], d["tywin_history"]), "H3", True),
        ("4", "SQL_SVC", "Sensitivity is set by a minority-class edge",
         "Threshold is GenericWrite, not DCSync - the collapsed value",
         "threshold = {:g}".format(d["acl_weight"]), "H4", False),
        ("5", "P1 / P2", "Only the minority perturbation re-ranks",
         "ACL edge inside the majority: nothing. Membership edge outside it: moves",
         "{}h -> {}h".format(d["hops_before"], d["hops_after"]), "H5/H6", False),
    ]

    s = []
    s.append('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {} {}" '
             'width="{}" height="{}" font-family="{}">'.format(W, H, W, H, SERIF))
    s.append('<rect width="{}" height="{}" fill="#ffffff"/>'.format(W, H))
    # Hatching is drawn as explicit lines rather than as an SVG <pattern>.
    #
    # The pattern version rendered correctly in browsers and was silently
    # dropped by every SVG-to-PNG converter tried: PyMuPDF filled the boundary
    # rows solid black, making their text unreadable, and svglib filled them
    # white, losing the hatch while keeping the caption's claim that it is
    # there. Since the footnote states that hatching is one of the two
    # redundant encodings that survive black-and-white printing, a raster export
    # without it contradicts the figure's own accessibility argument.
    #
    # Primitives every renderer supports keep the SVG and the PNG identical.

    s.append('<text x="40" y="42" font-size="17" font-weight="bold" fill="{}">'
             'One mechanism, five consequences, one boundary</text>'.format(INK))

    s.append('<rect x="40" y="60" width="{}" height="82" rx="4" fill="{}"/>'
             .format(W - 80, INK))
    s.append('<text x="62" y="88" font-size="13.5" fill="#ffffff" font-weight="bold">'
             'MECHANISM &#8212; {} access-control edge types produce '
             '<tspan font-style="italic">one</tspan> detection signature</text>'
             .format(d["n_shape_d"]))
    s.append('<text x="62" y="110" font-size="12" fill="#d6d6d6">'
             'under the stated telemetry baseline, so {:.1f}% of walkable edges carry '
             'a single derived cost,</text>'.format(d["modal_pct"]))
    s.append('<text x="62" y="129" font-size="12" fill="#d6d6d6">'
             'leaving no gradient for a cost-aware planner to climb.</text>')

    y = 174
    for i, (num, who, claim, detail, value, hyp, majority) in enumerate(rows):
        if not majority and rows[i - 1][6]:
            # The 12px inter-row gap cannot hold both a label and a divider, so
            # the boundary transition claims its own band of clearance.
            y += 34
            s.append('<text x="{}" y="{}" font-size="10" fill="{}" text-anchor="end" '
                     'letter-spacing="1.3">BOUNDARY &#8212; DISCRIMINATION SURVIVES '
                     'OUTSIDE THE COLLAPSED CLASS</text>'.format(W - 40, y - 30, MID))
            s.append('<line x1="40" y1="{}" x2="{}" y2="{}" stroke="{}" '
                     'stroke-width="1" stroke-dasharray="5 4"/>'
                     .format(y - 16, W - 40, y - 16, SOFT))

        s.append('<rect x="40" y="{}" width="{}" height="72" rx="3" fill="{}" '
                 'stroke="{}" stroke-width="1"/>'
                 .format(y, W - 80, PANEL_MAJ if majority else PANEL_BND, LINE))
        if not majority:
            s.extend(_hatch(40, y, W - 80, 72))

        if majority:
            s.append('<rect x="54" y="{}" width="17" height="17" fill="{}"/>'
                     .format(y + 27, INK))
        else:
            s.append('<circle cx="62.5" cy="{}" r="8.5" fill="#ffffff" stroke="{}" '
                     'stroke-width="2.2"/>'.format(y + 35.5, INK))

        s.append('<text x="88" y="{}" font-size="11" fill="{}" font-weight="bold">'
                 '{}</text>'.format(y + 27, SOFT, num))
        s.append('<text x="108" y="{}" font-size="12.5" fill="{}" font-weight="bold" '
                 'font-family="{}">{}</text>'.format(y + 27, INK, MONO, escape(who)))
        s.append('<text x="88" y="{}" font-size="13.5" fill="{}">{}</text>'
                 .format(y + 47, INK, escape(claim)))
        s.append('<text x="88" y="{}" font-size="11" fill="{}">{}</text>'
                 .format(y + 64, MID, escape(detail)))
        if value:
            s.append('<text x="{}" y="{}" font-size="14" fill="{}" text-anchor="end" '
                     'font-weight="bold" font-family="{}">{}</text>'
                     .format(W - 62, y + 48, INK, MONO, escape(value)))
        s.append('<text x="{}" y="{}" font-size="10" fill="{}" text-anchor="end" '
                 'letter-spacing="0.8">{}</text>'.format(W - 62, y + 25, SOFT, hyp))
        y += 84

    s.append('<text x="40" y="{}" font-size="10" fill="{}">Rows 1 and 2 carry no '
             'value: they report absences, and a figure cannot show an absence with a '
             'number. Majority rows are solid-marked, boundary rows open-marked and '
             'hatched - no information is carried by hue.</text>'.format(H - 16, SOFT))
    s.append('</svg>')

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(s) + "\n", encoding="utf-8", newline="\n")
    print("wrote {}".format(OUT.relative_to(ROOT)))
    png = _write_png(OUT)
    if png is not None:
        print("wrote {}".format(png.relative_to(ROOT)))
    print("  derived: modal {:.1f}%, TYWIN {:g}->{:g}, {}h->{}h, threshold {:g}"
          .format(d["modal_pct"], d["tywin_static"], d["tywin_history"],
                  d["hops_before"], d["hops_after"], d["acl_weight"]))


if __name__ == "__main__":
    main()
