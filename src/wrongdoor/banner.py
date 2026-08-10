"""
WrongDoor CLI banner - v7.
Compact portrait door with a legible case-sensitive "WrongDoor" wordmark
(bigger W/D, smaller lowercase, tight letter spacing). "Wr" sits inside
the door with visible door frame/panel around it, the rest of the word
emerges from the door's right edge into open space. Knob stays on the
left. Textured with 0s (door) / 1s (word). No tagline, no external font -
every character here is explainable.
"""


def rgb(hexcode: str) -> str:
    hexcode = hexcode.lstrip('#')
    r, g, b = int(hexcode[0:2], 16), int(hexcode[2:4], 16), int(hexcode[4:6], 16)
    return f"\033[38;2;{r};{g};{b}m"


RESET = "\033[0m"
DIM = "\033[2m"

FRAME_C = rgb("5A2720")
BODY_C = rgb("7A4231")
PANEL_C = rgb("8B4F3B")
KNOB_C = rgb("F5C9B8")
WORD_C = rgb("2171B5")

# ---------- Base 5-row font ----------
_BASE_FONT = {
    'W': ["█   █", "█   █", "█ █ █", "██ ██", "█   █"],
    'R': ["████ ", "█   █", "████ ", "█  █ ", "█   █"],
    'O': [" ███ ", "█   █", "█   █", "█   █", " ███ "],
    'N': ["█   █", "██  █", "█ █ █", "█  ██", "█   █"],
    'G': [" ███ ", "█    ", "█  ██", "█   █", " ███ "],
    'D': ["████ ", "█   █", "█   █", "█   █", "████ "],
}


def _scale_font(font: dict, new_h: int, new_w: int) -> dict:
    scaled = {}
    for ch, rows in font.items():
        old_h, old_w = len(rows), len(rows[0])
        new_rows = []
        for r in range(new_h):
            src_r = min(old_h - 1, int(r * old_h / new_h))
            row_src = rows[src_r]
            new_row = ""
            for c in range(new_w):
                src_c = min(old_w - 1, int(c * old_w / new_w))
                new_row += row_src[src_c]
            new_rows.append(new_row)
        scaled[ch] = new_rows
    return scaled


# Capitals scaled up modestly for weight; lowercase kept at its ORIGINAL
# resolution (unscaled) so letter shapes stay fully legible.
_UPPER_H, _UPPER_W = 7, 6
_LOWER_H, _LOWER_W = 5, 5

_UPPER_FONT = _scale_font(_BASE_FONT, _UPPER_H, _UPPER_W)
_LOWER_FONT = _BASE_FONT
_CANVAS_H = _UPPER_H


def _render_mixed_case(word: str, gap: int = 1) -> list:
    rows = ["" for _ in range(_CANVAS_H)]
    for ch in word:
        is_upper = ch.isupper()
        glyph = _UPPER_FONT[ch.upper()] if is_upper else _LOWER_FONT[ch.upper()]
        h = _UPPER_H if is_upper else _LOWER_H
        pad_top = _CANVAS_H - h
        glyph_w = len(glyph[0])
        for i in range(_CANVAS_H):
            if i < pad_top:
                rows[i] += " " * glyph_w + " " * gap
            else:
                rows[i] += glyph[i - pad_top] + " " * gap
    return rows


def print_banner(version: str = "0.1.0") -> None:
    word_rows = _render_mixed_case("WrongDoor")
    word_h, word_w = len(word_rows), len(word_rows[0])
    w_width = _UPPER_W + 1 + _LOWER_W  # "W" + gap + "r"

    door_w, door_h = 16, 14
    canvas_h = max(door_h, word_h + 4)
    canvas_w = door_w + word_w - w_width + 4

    grid = [[(' ', None) for _ in range(canvas_w)] for _ in range(canvas_h)]

    door_top = (canvas_h - door_h) // 2
    door_bottom = door_top + door_h - 1
    door_left = 0
    door_right = door_w - 1

    for row in range(door_top, door_bottom + 1):
        for col in range(door_left, door_right + 1):
            if row in (door_top, door_bottom) or col in (door_left, door_right):
                grid[row][col] = ('0', FRAME_C)
            else:
                grid[row][col] = ('0', BODY_C)

    panel_top, panel_bottom = door_top + 2, door_bottom - 2
    panel_left, panel_right = door_left + 2, door_right - 2
    for row in range(panel_top, panel_bottom + 1):
        for col in range(panel_left, panel_right + 1):
            if row in (panel_top, panel_bottom) or col in (panel_left, panel_right):
                grid[row][col] = ('0', FRAME_C)
            else:
                grid[row][col] = ('0', PANEL_C)

    # Word starts with a small margin so the door frame is still visible
    # around "Wr", rest of the word emerges into open space on the right
    start_row = (canvas_h - word_h) // 2
    start_col = 4

    for r in range(word_h):
        for c in range(word_w):
            if word_rows[r][c] == '█':
                rr, cc = start_row + r, start_col + c
                if 0 <= rr < canvas_h and 0 <= cc < canvas_w:
                    grid[rr][cc] = ('1', WORD_C)

    knob_row = door_top + door_h // 2
    knob_col = door_left + 1
    grid[knob_row][knob_col] = ('o', KNOB_C)

    print()
    for row in grid:
        line = ""
        for ch, color in row:
            line += (color + ch + RESET) if color else " "
        print(line)
    print()
    print(DIM + "  Dynamic Authorization Testing Engine" + RESET)
    print(DIM + "  v" + version + RESET)
    print()


if __name__ == "__main__":
    print_banner()
