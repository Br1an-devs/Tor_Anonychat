"""
securechat/ui.py
────────────────
Full-featured curses terminal UI.

Layout (80×24 minimum recommended)
  ┌──────────────────────────────────────────────────────┐
  │  SECURECHAT  ●  Connected  │  host  │  14:23:01       │  ← header
  ├──────────────────────────────────────────────────────┤
  │                                                       │
  │  [14:23:05]  Peer: hello                             │  ← message
  │  [14:23:08]  You : hi there                          │  ← message
  │  [14:23:10]  ⚙  Peer is typing...                   │  ← sys
  │                                                       │
  │                                                       │
  ├──────────────────────────────────────────────────────┤
  │  ›  _                                                 │  ← input
  ├──────────────────────────────────────────────────────┤
  │  /quit  close  │  /help  commands  │  AES-256-GCM    │  ← footer
  └──────────────────────────────────────────────────────┘

Key bindings
  Enter       – send message
  Ctrl-W      – clear input line
  Ctrl-C / /quit – close session
  ↑ / ↓      – scroll history
"""

import curses
import threading
import time
from collections import deque
from typing import List, Optional
import textwrap

from .protocol import Message, MsgType
from .session import Session


# ── Colour pair indices ───────────────────────────────────────────────────────
CP_HEADER   = 1    # header bar
CP_FOOTER   = 2    # footer bar
CP_YOU      = 3    # your own messages
CP_PEER     = 4    # peer messages
CP_SYS      = 5    # system notices
CP_TIME     = 6    # timestamp dimmed
CP_STATUS   = 7    # "Connected" green
CP_WARN     = 8    # warnings / errors
CP_BORDER   = 9    # separator lines
CP_INPUT    = 10   # input line


MAX_HISTORY = 500   # keep last N messages in memory
MAX_INPUT   = 512   # characters


def _ts(epoch: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(epoch))


class ChatUI:
    """
    Blocking curses UI. Call .run() from the main thread.
    Receives messages via .push_message() (thread-safe).
    Sends messages via the injected Session object.
    """

    def __init__(
        self,
        session: Session,
        role: str,
        you_label: str = "You",
        peer_label: str = "Peer",
        via_tor: bool = False,
    ):
        self._session     = session
        self._role        = role
        self._peer_label  = peer_label
        self._via_tor     = via_tor
        self._you_label   = you_label

        self._messages: deque = deque(maxlen=MAX_HISTORY)
        self._msg_lock  = threading.Lock()
        self._scroll    = 0           # lines scrolled up from bottom
        self._dirty     = threading.Event()
        self._dirty.set()

        self._input_buf : List[str] = []
        self._cursor    = 0

        self._closed    = False
        self._close_msg = ""

        self._stdscr    = None

    # ── Thread-safe message ingestion ────────────────────────────────────────

    def push_message(self, msg: Message) -> None:
        with self._msg_lock:
            self._messages.append(msg)
        self._dirty.set()

    def push_system(self, text: str) -> None:
        self.push_message(Message(MsgType.SYS, text))

    def signal_closed(self, reason: str) -> None:
        self._closed    = True
        self._close_msg = reason
        self._dirty.set()

    # ── Main entry point ─────────────────────────────────────────────────────

    def run(self) -> None:
        curses.wrapper(self._main)

    def _main(self, stdscr) -> None:
        self._stdscr = stdscr
        self._init_colors()
        curses.curs_set(1)

        stdscr.nodelay(False)
        stdscr.timeout(200)     # ms — poll so we can repaint on push_message

        while True:
            if self._dirty.is_set():
                self._dirty.clear()
                self._repaint()

            key = stdscr.getch()

            if key == curses.ERR:
                # timeout — loop again (allows repaint from push_message)
                continue

            action = self._handle_key(key)
            if action == "quit":
                break

            self._repaint()

        # Orderly shutdown
        if not self._closed:
            self._session.close("User quit")

    # ── Key handling ─────────────────────────────────────────────────────────

    def _handle_key(self, key: int) -> Optional[str]:
        if key in (curses.KEY_ENTER, 10, 13):
            return self._handle_enter()

        elif key in (curses.KEY_BACKSPACE, 127, 8):
            if self._cursor > 0:
                self._input_buf.pop(self._cursor - 1)
                self._cursor -= 1

        elif key == curses.KEY_LEFT:
            self._cursor = max(0, self._cursor - 1)

        elif key == curses.KEY_RIGHT:
            self._cursor = min(len(self._input_buf), self._cursor + 1)

        elif key == curses.KEY_HOME:
            self._cursor = 0

        elif key == curses.KEY_END:
            self._cursor = len(self._input_buf)

        elif key == curses.KEY_UP:
            self._scroll += 1
            self._dirty.set()

        elif key == curses.KEY_DOWN:
            self._scroll = max(0, self._scroll - 1)
            self._dirty.set()

        elif key == 23:   # Ctrl-W — clear line
            self._input_buf.clear()
            self._cursor = 0

        elif key == 3:    # Ctrl-C
            return "quit"

        elif key == curses.KEY_DC:   # Delete
            if self._cursor < len(self._input_buf):
                self._input_buf.pop(self._cursor)

        elif 32 <= key <= 126:       # printable ASCII
            if len(self._input_buf) < MAX_INPUT:
                self._input_buf.insert(self._cursor, chr(key))
                self._cursor += 1

        return None

    def _handle_enter(self) -> Optional[str]:
        text = "".join(self._input_buf).strip()
        if not text:
            return None

        self._input_buf.clear()
        self._cursor = 0

        if text.lower() in ("/quit", "/exit", "/q"):
            return "quit"

        if text.lower() == "/help":
            self.push_system(
                "Commands: /quit  /clear  /help  |  ↑↓ scroll  |  Ctrl-W clear input"
            )
            return None

        if text.lower() == "/clear":
            with self._msg_lock:
                self._messages.clear()
            self._scroll = 0
            self._dirty.set()
            return None

        # Regular chat message
        if self._session.is_alive:
            try:
                self._session.send_text(text)
                # Echo locally as "You"
                self.push_message(Message(MsgType.MSG, text, time.time()))
            except Exception as e:
                self.push_system(f"Send error: {e}")
        else:
            self.push_system("Session is closed — cannot send messages.")

        return None

    # ── Rendering ─────────────────────────────────────────────────────────────

    def _repaint(self) -> None:
        try:
            self._stdscr.erase()
            h, w = self._stdscr.getmaxyx()

            if h < 8 or w < 40:
                self._stdscr.addstr(0, 0, "Terminal too small — resize to 80x24+")
                self._stdscr.refresh()
                return

            self._draw_header(w)
            self._draw_footer(h, w)
            self._draw_input(h, w)
            self._draw_messages(h, w)
            self._draw_cursor(h, w)

            self._stdscr.refresh()
        except curses.error:
            pass

    def _draw_header(self, w: int) -> None:
        scr = self._stdscr
        scr.attron(curses.color_pair(CP_HEADER) | curses.A_BOLD)
        scr.addstr(0, 0, " " * w)
        scr.attroff(curses.color_pair(CP_HEADER) | curses.A_BOLD)

        # Left: app name
        left = "  ◈ SECURECHAT"
        scr.attron(curses.color_pair(CP_HEADER) | curses.A_BOLD)
        scr.addstr(0, 0, left[:w-1])
        scr.attroff(curses.color_pair(CP_HEADER) | curses.A_BOLD)

        # Centre: status
        if self._closed:
            status = "● DISCONNECTED"
            cp = CP_WARN
        elif self._session.is_alive:
            status = "● Connected"
            cp = CP_STATUS
        else:
            status = "○ Closed"
            cp = CP_WARN

        cx = max(0, w // 2 - len(status) // 2)
        scr.attron(curses.color_pair(cp) | curses.A_BOLD)
        try:
            scr.addstr(0, cx, status[:w - cx - 1])
        except curses.error:
            pass
        scr.attroff(curses.color_pair(cp) | curses.A_BOLD)

        # Right: [TOR] badge (if applicable) + role + time
        tor_badge    = " [TOR]" if self._via_tor else ""
        right_suffix = f" {self._role}  {time.strftime('%H:%M:%S')}  "
        right = tor_badge + right_suffix
        rx = max(0, w - len(right) - 1)
        if self._via_tor:
            try:
                scr.attron(curses.color_pair(CP_WARN) | curses.A_BOLD)
                scr.addstr(0, rx, tor_badge[:w - rx - 1])
                scr.attroff(curses.color_pair(CP_WARN) | curses.A_BOLD)
                scr.attron(curses.color_pair(CP_HEADER))
                scr.addstr(0, rx + len(tor_badge), right_suffix[:w - rx - len(tor_badge) - 1])
                scr.attroff(curses.color_pair(CP_HEADER))
            except curses.error:
                pass
        else:
            scr.attron(curses.color_pair(CP_HEADER))
            try:
                scr.addstr(0, rx, right[:w - rx - 1])
            except curses.error:
                pass
            scr.attroff(curses.color_pair(CP_HEADER))

        # Separator
        scr.attron(curses.color_pair(CP_BORDER))
        try:
            scr.addstr(1, 0, "─" * (w - 1))
        except curses.error:
            pass
        scr.attroff(curses.color_pair(CP_BORDER))

    def _draw_footer(self, h: int, w: int) -> None:
        scr = self._stdscr
        # Separator above footer
        scr.attron(curses.color_pair(CP_BORDER))
        try:
            scr.addstr(h - 3, 0, "─" * (w - 1))
        except curses.error:
            pass
        scr.attroff(curses.color_pair(CP_BORDER))

        # Footer bar
        scr.attron(curses.color_pair(CP_FOOTER))
        try:
            scr.addstr(h - 1, 0, " " * (w - 1))
        except curses.error:
            pass

        footer = "  /quit  │  /help  │  /clear  │  ↑↓ scroll  │  AES-256-GCM  "
        if self._closed:
            footer = f"  SESSION ENDED: {self._close_msg[:w-4]}  "
        try:
            scr.addstr(h - 1, 0, footer[:w - 1])
        except curses.error:
            pass
        scr.attroff(curses.color_pair(CP_FOOTER))

    def _draw_input(self, h: int, w: int) -> None:
        scr = self._stdscr
        prompt = "›  "
        row    = h - 2
        scr.attron(curses.color_pair(CP_INPUT))
        try:
            scr.addstr(row, 0, " " * (w - 1))
        except curses.error:
            pass

        scr.attron(curses.color_pair(CP_YOU) | curses.A_BOLD)
        try:
            scr.addstr(row, 0, prompt)
        except curses.error:
            pass
        scr.attroff(curses.color_pair(CP_YOU) | curses.A_BOLD)

        visible_w  = w - len(prompt) - 2
        buf_str    = "".join(self._input_buf)
        # Scroll the input if the cursor is near the right edge
        view_start = max(0, self._cursor - visible_w + 1)
        visible    = buf_str[view_start:view_start + visible_w]
        scr.attron(curses.color_pair(CP_INPUT))
        try:
            scr.addstr(row, len(prompt), visible)
        except curses.error:
            pass
        scr.attroff(curses.color_pair(CP_INPUT))

    def _draw_cursor(self, h: int, w: int) -> None:
        prompt_len = 3   # "›  "
        row = h - 2
        col = min(prompt_len + self._cursor, w - 2)
        try:
            self._stdscr.move(row, col)
        except curses.error:
            pass

    def _draw_messages(self, h: int, w: int) -> None:
        """Render the message history in the viewport between header and input."""
        # Usable rows: from row 2 (after header+separator) to h-4 (above input sep)
        top_row   = 2
        bot_row   = h - 4       # inclusive
        viewport  = bot_row - top_row + 1
        if viewport <= 0:
            return

        with self._msg_lock:
            msgs = list(self._messages)

        # Render each message into a list of (attr, text) lines
        lines = []
        for msg in msgs:
            lines.extend(self._render_message(msg, w))

        # Apply scroll offset
        total = len(lines)
        if self._scroll > total - viewport:
            self._scroll = max(0, total - viewport)

        # Slice the visible window
        start = max(0, total - viewport - self._scroll)
        end   = start + viewport
        visible = lines[start:end]

        for i, (attr, text) in enumerate(visible):
            row = top_row + i
            if row > bot_row:
                break
            try:
                self._stdscr.attron(attr)
                self._stdscr.addstr(row, 1, text[:w - 2])
                self._stdscr.attroff(attr)
            except curses.error:
                pass

        # Scroll indicator
        if self._scroll > 0:
            indicator = f" ↑ {self._scroll} lines above "
            col = max(0, w - len(indicator) - 2)
            try:
                self._stdscr.attron(curses.color_pair(CP_WARN) | curses.A_BOLD)
                self._stdscr.addstr(top_row, col, indicator[:w-col-1])
                self._stdscr.attroff(curses.color_pair(CP_WARN) | curses.A_BOLD)
            except curses.error:
                pass

    def _render_message(self, msg: Message, w: int) -> list:
        """Convert a Message into a list of (curses_attr, str) display lines."""
        max_w = max(10, w - 20)   # leave room for prefix
        ts    = _ts(msg.ts)

        if msg.mtype == MsgType.SYS:
            text = msg.body or ""
            prefix = f"[{ts}]  ⚙  "
            attr   = curses.color_pair(CP_SYS)
            lines  = textwrap.wrap(text, width=max_w) or [""]
            result = []
            for i, line in enumerate(lines):
                p = prefix if i == 0 else " " * len(prefix)
                result.append((attr, p + line))
            return result

        elif msg.mtype == MsgType.MSG:
            # Decide who sent it: if we echoed it ourselves, body is added by _handle_enter
            # We tag "You" messages with a special attribute check
            # We can't know for sure here — use a side-channel: messages pushed via
            # push_message from _handle_enter already carry "You" context.
            # For simplicity, we store sender info in the body prefix when echoing.
            body = msg.body or ""
            if body.startswith("\x01"):
                # Outgoing message sentinel
                label  = self._you_label
                attr   = curses.color_pair(CP_YOU) | curses.A_BOLD
                body   = body[1:]
            else:
                label  = self._peer_label
                attr   = curses.color_pair(CP_PEER) | curses.A_BOLD

            prefix = f"[{ts}]  {label:<10}: "
            lines  = textwrap.wrap(body, width=max_w) or [""]
            result = []
            for i, line in enumerate(lines):
                p = prefix if i == 0 else " " * len(prefix)
                result.append((attr, p + line))
            return result

        return []

    # ── Colour init ───────────────────────────────────────────────────────────

    def _init_colors(self) -> None:
        curses.start_color()
        curses.use_default_colors()
        bg = -1   # transparent / terminal default

        curses.init_pair(CP_HEADER, curses.COLOR_BLACK,  curses.COLOR_CYAN)
        curses.init_pair(CP_FOOTER, curses.COLOR_BLACK,  curses.COLOR_WHITE)
        curses.init_pair(CP_YOU,    curses.COLOR_GREEN,  bg)
        curses.init_pair(CP_PEER,   curses.COLOR_CYAN,   bg)
        curses.init_pair(CP_SYS,    curses.COLOR_YELLOW, bg)
        curses.init_pair(CP_TIME,   curses.COLOR_WHITE,  bg)
        curses.init_pair(CP_STATUS, curses.COLOR_GREEN,  bg)
        curses.init_pair(CP_WARN,   curses.COLOR_RED,    bg)
        curses.init_pair(CP_BORDER, curses.COLOR_WHITE,  bg)
        curses.init_pair(CP_INPUT,  curses.COLOR_WHITE,  bg)


# ── Tweak: sentinel for outgoing messages ────────────────────────────────────
# The UI echoes "You:" messages locally by injecting them with a sentinel byte.
# This avoids a separate flag on Message (keeping the protocol clean).
_OUTGOING_SENTINEL = "\x01"


def make_outgoing_msg(text: str) -> Message:
    from .protocol import MsgType, Message
    import time
    return Message(mtype=MsgType.MSG, body=_OUTGOING_SENTINEL + text, ts=time.time())
