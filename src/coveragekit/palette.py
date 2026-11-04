"""Level colours shared by the report, the SVG heat map, the Navigator layer and the web app.

A soft traffic light: uncovered in light red, Low amber, Medium green, High dark green. Checked with a CVD
validator; amber and green sit at the protan floor, so every place that shows a level also shows a
secondary mark (the dots below, or the level name).
"""

LEVEL_FILL = {0: "#f6d5d0", 1: "#dc9a2a", 2: "#4a9e5c", 3: "#1e6e42"}
LEVEL_INK = {0: "#8a2318", 1: "#0b0b0b", 2: "#ffffff", 3: "#ffffff"}  # text on top of each fill
LEVEL_MARK = {0: "", 1: "●", 2: "●●", 3: "●●●"}
