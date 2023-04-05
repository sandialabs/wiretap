#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import sys

# XPath attribute matching expression
# path elements that match this expression will be animated
MATCH="[@stroke-dasharray='9 9'][@stroke-width='3']"
# Animation class
ANIMATION="""
.mxEdgeFlow {
    animation: mxEdgeFlow 0.5s linear;
    animation-iteration-count: infinite;
}
@keyframes mxEdgeFlow {
    to {
        stroke-dashoffset: -18;
    }
}
"""

if len(sys.argv) != 3:
    print("Usage: python3 animate_svg.py input.svg output.svg")
    exit(0)

tree = ET.parse(sys.argv[1])
root = tree.getroot()


child = ET.Element("style")
child.set("type", "text/css")
child.text = ANIMATION

animate = tree.findall(".//{http://www.w3.org/2000/svg}path"+MATCH)

for a in animate:
    print("Animating element", a)
    a.set("class", "mxEdgeFlow")

root.insert(0, child)

tree = ET.ElementTree(root)

# Write modified tree to file with custom namespace prefix
namespace = "http://www.w3.org/2000/svg"
ET.register_namespace("", namespace)
tree.write(sys.argv[2])
