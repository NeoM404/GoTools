"""Tiny draw.io writer: official AWS (mxgraph.aws4) and Azure (azure2) icons,
AWS-style groups, labelled edges and numbered step badges."""
import html, subprocess, os

CAT = {  # AWS category colours (Architecture Icons guidelines)
    "compute": "#ED7100", "containers": "#ED7100", "mgmt": "#E7157B",
    "security": "#DD344C", "storage": "#7AA116", "network": "#8C4FFF",
}
INK, QUIET, BLUE, ORANGE, RED = "#232F3E", "#5A6B7B", "#2F5FD0", "#F08A24", "#C53030"


class Diagram:
    def __init__(self, name, w, h):
        self.name, self.w, self.h, self.cells, self.n = name, w, h, [], 0

    def _id(self):
        self.n += 1
        return f"n{self.n}"

    def _add(self, style, value, x, y, w, h, vertex=True, extra=""):
        i = self._id()
        v = html.escape(value, quote=True)
        kind = 'vertex="1"' if vertex else 'edge="1"'
        self.cells.append(f'<mxCell id="{i}" value="{v}" style="{style}" {kind} parent="1"{extra}>'
                          f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')
        return i

    # --- icons ---------------------------------------------------------
    def aws(self, res, label, x, y, cat="compute", size=64):
        st = (f"sketch=0;points=[];outlineConnect=0;fontColor={INK};fillColor={CAT[cat]};strokeColor=#ffffff;dashed=0;"
              "verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=14;fontStyle=0;aspect=fixed;"
              f"shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.{res};")
        return self._add(st, label, x, y, size, size)

    def awsres(self, shape, label, x, y, size=56, color=INK):
        st = (f"sketch=0;outlineConnect=0;fontColor={INK};gradientColor=none;fillColor={color};strokeColor=none;dashed=0;"
              "verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=14;aspect=fixed;"
              f"shape=mxgraph.aws4.{shape};")
        return self._add(st, label, x, y, size, size)

    def azure(self, path, label, x, y, size=64):
        st = ("image;aspect=fixed;html=1;points=[];align=center;fontSize=14;verticalLabelPosition=bottom;verticalAlign=top;"
              f"fontColor={INK};image=img/lib/azure2/{path};")
        return self._add(st, label, x, y, size, size)

    # --- groups & boxes ----------------------------------------------
    def group(self, kind, label, x, y, w, h):
        g = {
            "cloud": ("group_aws_cloud_alt", "#232F3E", "#232F3E", "none", 0),
            "account": ("group_account", "#CD2264", "#CD2264", "none", 0),
            "region": ("group_region", "#00A4A6", "#147EBA", "none", 1),
            "vpc": ("group_vpc2", "#8C4FFF", "#8C4FFF", "none", 0),
            "private": ("group_private_subnet", "#00A4A6", "#147EBA", "#E6F6F7", 0),
            "onprem": ("group_corporate_data_center", "#7D8998", "#5A6B7B", "none", 0),
        }[kind]
        st = (f"points=[];outlineConnect=0;gradientColor=none;html=1;whiteSpace=wrap;fontSize=15;fontStyle=1;container=0;"
              f"pointerEvents=0;collapsible=0;recursiveResize=0;shape=mxgraph.aws4.group;grIcon=mxgraph.aws4.{g[0]};"
              f"strokeColor={g[1]};fillColor={g[3]};verticalAlign=top;align=left;spacingLeft=30;fontColor={g[2]};dashed={g[4]};")
        return self._add(st, label, x, y, w, h)

    def azgroup(self, label, x, y, w, h, color="#0078D4"):
        st = (f"rounded=1;arcSize=3;whiteSpace=wrap;html=1;fillColor=none;strokeColor={color};strokeWidth=2;dashed=0;"
              f"verticalAlign=top;align=left;spacingLeft=12;spacingTop=6;fontSize=15;fontStyle=1;fontColor={color};")
        return self._add(st, label, x, y, w, h)

    def box(self, label, x, y, w, h, fill="#FFFFFF", stroke="#9AA5B4", font=14, bold=False, color=INK, align="center", dashed=0):
        st = (f"rounded=1;arcSize=8;whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};fontSize={font};"
              f"fontColor={color};fontStyle={1 if bold else 0};align={align};verticalAlign=middle;spacing=8;dashed={dashed};")
        return self._add(st, label, x, y, w, h)

    def text(self, label, x, y, w, h, font=14, color=QUIET, bold=False, align="left"):
        st = (f"text;html=1;whiteSpace=wrap;fontSize={font};fontColor={color};fontStyle={1 if bold else 0};"
              f"align={align};verticalAlign=top;")
        return self._add(st, label, x, y, w, h)

    def badge(self, n, x, y, color=BLUE):
        st = (f"ellipse;whiteSpace=wrap;html=1;aspect=fixed;fillColor={color};strokeColor=none;fontColor=#FFFFFF;"
              "fontSize=15;fontStyle=1;")
        return self._add(st, str(n), x, y, 30, 30)

    # --- edges ----------------------------------------------------------
    def edge(self, src, dst, label="", color=BLUE, dashed=0, both=False, width=2, exit=None, entry=None, pts=None):
        st = (f"edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;endArrow=block;endFill=1;strokeWidth={width};"
              f"strokeColor={color};fontSize=13;fontColor={INK};labelBackgroundColor=#FFFFFF;dashed={dashed};")
        if both:
            st += "startArrow=block;startFill=1;"
        if exit:
            st += f"exitX={exit[0]};exitY={exit[1]};exitDx=0;exitDy=0;"
        if entry:
            st += f"entryX={entry[0]};entryY={entry[1]};entryDx=0;entryDy=0;"
        i = self._id()
        geo = '<mxGeometry relative="1" as="geometry">'
        if pts:
            geo += '<Array as="points">' + "".join(f'<mxPoint x="{px}" y="{py}"/>' for px, py in pts) + "</Array>"
        geo += "</mxGeometry>"
        self.cells.append(f'<mxCell id="{i}" value="{html.escape(label, quote=True)}" style="{st}" edge="1" parent="1" '
                          f'source="{src}" target="{dst}">{geo}</mxCell>')
        return i

    def save(self, outdir):
        os.makedirs(outdir, exist_ok=True)
        bg = ('<mxCell id="bg" value="" style="rounded=0;fillColor=#FFFFFF;strokeColor=none;" vertex="1" parent="1">'
              f'<mxGeometry x="0" y="0" width="{self.w}" height="{self.h}" as="geometry"/></mxCell>')
        xml = (f'<mxfile host="nedctl"><diagram name="{self.name}"><mxGraphModel dx="{self.w}" dy="{self.h}" grid="0" '
               f'page="1" pageWidth="{self.w}" pageHeight="{self.h}" background="#FFFFFF"><root><mxCell id="0"/>'
               f'<mxCell id="1" parent="0"/>{bg}' + "".join(self.cells) + "</root></mxGraphModel></diagram></mxfile>")
        src = os.path.join(outdir, self.name + ".drawio")
        open(src, "w").write(xml)
        png = os.path.join(outdir, self.name + ".png")
        subprocess.run(["drawio", "--export", "--format", "png", "--scale", "2", "--border", "0", "-o", png, src],
                       check=True, capture_output=True)
        return src, png
