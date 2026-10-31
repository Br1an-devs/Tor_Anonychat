"""
securechat/ui.py
────────────────
Curses-based chat UI supporting both 2-user and multi-user (group) modes.

In multi-user (host) mode, the UI surfaces a pending-requests panel so the
host can type /admit <nick> or /deny <nick> to manage join requests without
leaving the chat screen.
"""

import curses
import threading
import time
from collections import deque
from typing import List, Optional
import textwrap

from .protocol import Message, MsgType
from .session import Session

CP_HEADER   = 1
CP_FOOTER   = 2
CP_YOU      = 3
CP_PEER     = 4
CP_SYS      = 5
CP_TIME     = 6
CP_STATUS   = 7
CP_WARN     = 8
CP_BORDER   = 9
CP_INPUT    = 10
CP_PENDING  = 11   # pending join requests highlight


MAX_HISTORY = 500
MAX_INPUT   = 512


def _ts(epoch: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(epoch))


class ChatUI:
    """
    Blocking curses UI.  Call .run() from the main thread.
    Receives messages via .push_message() (thread-safe).
    Sends messages via the injected session object (Session or GroupSession).
    """

    def __init__(
        self,
        session,                # Session or GroupSession
        role: str,
        you_label: str = "You",
        peer_label: str = "Peer",
        via_tor: bool = False,
        ft=None,
        is_group: bool = False,
        host_nickname: str = None,
    ):
        self._session      = session
        self._role         = role
        self._peer_label   = peer_label
        self._via_tor      = via_tor
        self._you_label    = you_label
        self._ft           = ft
        self._is_group     = is_group
        self._host_nickname = host_nickname or you_label

        self._messages: deque = deque(maxlen=MAX_HISTORY)
        self._msg_lock  = threading.Lock()
        self._scroll    = 0
        self._dirty     = threading.Event()
        self._dirty.set()

        self._input_buf: List[str] = []
        self._cursor    = 0

        self._closed    = False
        self._close_msg = ""

        # Pending join requests (host only): list of nick strings
        self._pending: List[str] = []
        self._pending_lock = threading.Lock()

        self._stdscr = None

    # ── Thread-safe external API ──────────────────────────────────────────────

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

    def add_pending_request(self, nickname: str) -> None:
        """Called by GroupSession when a guest is waiting for approval."""
        with self._pending_lock:
            if nickname not in self._pending:
                self._pending.append(nickname)
        self.push_system(
            f"🔔  Join request from '{nickname}' — type /admit {nickname} or /deny {nickname}"
        )
        self._dirty.set()

    def remove_pending(self, nickname: str) -> None:
        with self._pending_lock:
            try:
                self._pending.remove(nickname)
            except ValueError:
                pass
        self._dirty.set()

    # ── Main entry ────────────────────────────────────────────────────────────

    def run(self) -> None:
        curses.wrapper(self._main)

    def _main(self, stdscr) -> None:
        self._stdscr = stdscr
        self._init_colors()
        curses.curs_set(1)
        stdscr.nodelay(False)
        stdscr.timeout(200)

        while True:
            if self._dirty.is_set():
                self._dirty.clear()
                self._repaint()

            key = stdscr.getch()
            if key == curses.ERR:
                continue

            action = self._handle_key(key)
            if action == "quit":
                break

            self._repaint()

        if not self._closed:
            self._session.close("User quit")

    # ── Key handling ──────────────────────────────────────────────────────────

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
        elif key == 23:   # Ctrl-W
            self._input_buf.clear()
            self._cursor = 0
        elif key == 3:    # Ctrl-C
            return "quit"
        elif key == curses.KEY_DC:
            if self._cursor < len(self._input_buf):
                self._input_buf.pop(self._cursor)
        elif 32 <= key <= 126:
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

        low = text.lower()

        # ── Universal commands ────────────────────────────────────────────────
        if low in ("/quit", "/exit", "/q"):
            return "quit"

        if low == "/help":
            self.push_system(
                "Commands: /quit  /clear  /help  |  ↑↓ scroll  |  Ctrl-W clear input"
            )
            self.push_system(
                "File transfer: /sendfile <path>   /accept   /reject"
            )
            if self._is_group:
                self.push_system(
                    "Group (host): /admit <nick>  /deny <nick>  /kick <nick>  /who"
                )
            return None

        if low == "/clear":
            with self._msg_lock:
                self._messages.clear()
            self._scroll = 0
            self._dirty.set()
            return None

        # ── File transfer ─────────────────────────────────────────────────────
        if low.startswith("/sendfile"):
            if self._ft is None:
                self.push_system("File transfer is unavailable.")
                return None
            parts = text.split(None, 1)
            if len(parts) < 2 or not parts[1].strip():
                self.push_system("Usage: /sendfile <path>")
                return None
            if not self._session.is_alive:
                self.push_system("Session is closed — cannot send files.")
                return None
            self._ft.send_file(parts[1].strip())
            return None

        if low in ("/accept", "/accept file"):
            if self._ft is None:
                self.push_system("File transfer is unavailable.")
                return None
            if not self._ft.has_pending_offer():
                self.push_system("No pending file offer to accept.")
                return None
            self._ft.accept_offer()
            return None

        if low.startswith("/reject"):
            if self._ft is None:
                self.push_system("File transfer is unavailable.")
                return None
            if not self._ft.has_pending_offer():
                self.push_system("No pending file offer to reject.")
                return None
            parts  = text.split(None, 1)
            reason = parts[1].strip() if len(parts) > 1 else "declined"
            self._ft.reject_offer(reason)
            return None

        # ── Group / host-only commands ────────────────────────────────────────
        if self._is_group and low.startswith("/admit"):
            parts = text.split(None, 1)
            if len(parts) < 2:
                self.push_system("Usage: /admit <nickname>")
                return None
            nick = parts[1].strip()
            ok = self._session.admit_pending(nick)
            if ok:
                self.remove_pending(nick)
                self.push_system(f"✔  Admitted '{nick}' to the room.")
            else:
                self.push_system(f"No pending request from '{nick}'.")
            return None

        if self._is_group and low.startswith("/deny"):
            parts = text.split(None, 1)
            if len(parts) < 2:
                self.push_system("Usage: /deny <nickname>  [reason]")
                return None
            rest   = parts[1].strip()
            tokens = rest.split(None, 1)
            nick   = tokens[0]
            reason = tokens[1] if len(tokens) > 1 else "Request denied by host"
            ok = self._session.deny_pending(nick, reason)
            if ok:
                self.remove_pending(nick)
                self.push_system(f"✘  Denied '{nick}'.")
            else:
                self.push_system(f"No pending request from '{nick}'.")
            return None

        if self._is_group and low.startswith("/kick"):
            parts = text.split(None, 1)
            if len(parts) < 2:
                self.push_system("Usage: /kick <nickname>")
                return None
            nick = parts[1].strip()
            # Find and close the guest handle
            with self._session._guests_lock:
                handle = self._session._guests.pop(nick, None)
            if handle:
                handle.close("Kicked by host")
                self.push_system(f"⟵  Kicked '{nick}' from the room.")
                self._session._broadcast_system(f"⟵  {nick} was removed by the host.")
                self._session._on_message(
                    Message(MsgType.SYS, f"⟵  {nick} was removed by the host."), "system"
                )
            else:
                self.push_system(f"No connected user named '{nick}'.")
            return None

        if self._is_group and low == "/who":
            nicks = self._session.admitted_nicknames()
            pending = self._session.pending_nicknames()
            self.push_system(
                f"Room: {self._host_nickname} (host), "
                + (", ".join(nicks) if nicks else "(no guests yet)")
            )
            if pending:
                self.push_system(f"Waiting: {', '.join(pending)}")
            return None

        # ── Regular chat message ──────────────────────────────────────────────
        if self._session.is_alive:
            try:
                if self._is_group:
                    self._session.send_text(text)
                    # Host message is already echoed inside GroupSession.send_text
                else:
                    self._session.send_text(text)
                    self.push_message(make_outgoing_msg(text))
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
            self._draw_pending_bar(h, w)          # only in group/host mode
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

        left = "  ◈ SECURECHAT"
        if self._is_group:
            left += " [GROUP]"
        scr.attron(curses.color_pair(CP_HEADER) | curses.A_BOLD)
        scr.addstr(0, 0, left[:w-1])
        scr.attroff(curses.color_pair(CP_HEADER) | curses.A_BOLD)

        # Centre status
        if self._closed:
            status = "● DISCONNECTED"
            cp = CP_WARN
        elif self._session.is_alive:
            if self._is_group:
                gc = self._session.guest_count
                status = f"● {gc} guest{'s' if gc != 1 else ''} connected"
            else:
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

        # Right side
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

    def _pending_bar_height(self) -> int:
        """Number of rows taken by the pending requests bar (0 if none)."""
        if not self._is_group:
            return 0
        with self._pending_lock:
            n = len(self._pending)
        return 0 if n == 0 else 2   # 1 label row + 1 separator

    def _draw_pending_bar(self, h: int, w: int) -> None:
        """Draw pending-requests bar just below the header separator."""
        if not self._is_group:
            return
        with self._pending_lock:
            pending = list(self._pending)
        if not pending:
            return

        row = 2   # right below the separator at row 1
        bar = "  🔔 Waiting: " + "  |  ".join(pending)
        bar = bar[:w - 2]

        try:
            self._stdscr.attron(curses.color_pair(CP_PENDING) | curses.A_BOLD)
            self._stdscr.addstr(row, 0, bar + " " * (w - len(bar) - 1))
            self._stdscr.attroff(curses.color_pair(CP_PENDING) | curses.A_BOLD)
        except curses.error:
            pass

        # Separator below pending bar
        try:
            self._stdscr.attron(curses.color_pair(CP_BORDER))
            self._stdscr.addstr(row + 1, 0, "─" * (w - 1))
            self._stdscr.attroff(curses.color_pair(CP_BORDER))
        except curses.error:
            pass

    def _draw_footer(self, h: int, w: int) -> None:
        scr = self._stdscr
        scr.attron(curses.color_pair(CP_BORDER))
        try:
            scr.addstr(h - 3, 0, "─" * (w - 1))
        except curses.error:
            pass
        scr.attroff(curses.color_pair(CP_BORDER))

        scr.attron(curses.color_pair(CP_FOOTER))
        try:
            scr.addstr(h - 1, 0, " " * (w - 1))
        except curses.error:
            pass

        if self._closed:
            footer = f"  SESSION ENDED: {self._close_msg[:w-4]}  "
        elif self._is_group:
            footer = "  /quit  │  /help  │  /admit <nick>  /deny <nick>  /kick <nick>  /who  │  AES-256-GCM  "
        else:
            footer = "  /quit  │  /help  │  /sendfile <path>  │  /accept  /reject  │  AES-256-GCM  "
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
        view_start = max(0, self._cursor - visible_w + 1)
        visible    = buf_str[view_start:view_start + visible_w]
        scr.attron(curses.color_pair(CP_INPUT))
        try:
            scr.addstr(row, len(prompt), visible)
        except curses.error:
            pass
        scr.attroff(curses.color_pair(CP_INPUT))

    def _draw_cursor(self, h: int, w: int) -> None:
        prompt_len = 3
        row = h - 2
        col = min(prompt_len + self._cursor, w - 2)
        try:
            self._stdscr.move(row, col)
        except curses.error:
            pass

    def _msg_area_top(self) -> int:
        """First row of the message area (depends on pending bar)."""
        base = 2   # below header + separator
        ph = self._pending_bar_height()
        return base + ph

    def _draw_messages(self, h: int, w: int) -> None:
        top_row  = self._msg_area_top()
        bot_row  = h - 4
        viewport = bot_row - top_row + 1
        if viewport <= 0:
            return

        with self._msg_lock:
            msgs = list(self._messages)

        lines = []
        for msg in msgs:
            lines.extend(self._render_message(msg, w))

        total = len(lines)
        if self._scroll > total - viewport:
            self._scroll = max(0, total - viewport)

        start   = max(0, total - viewport - self._scroll)
        end     = start + viewport
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
        max_w = max(10, w - 22)
        ts    = _ts(msg.ts)

        if msg.mtype == MsgType.SYS:
            text   = msg.body or ""
            prefix = f"[{ts}]  ⚙  "
            attr   = curses.color_pair(CP_SYS)
            lines  = textwrap.wrap(text, width=max_w) or [""]
            result = []
            for i, line in enumerate(lines):
                p = prefix if i == 0 else " " * len(prefix)
                result.append((attr, p + line))
            return result

        elif msg.mtype == MsgType.MSG:
            body = msg.body or ""

            if body.startswith("\x01"):
                # Outgoing echo (non-group mode)
                label = self._you_label
                attr  = curses.color_pair(CP_YOU) | curses.A_BOLD
                body  = body[1:]
            elif msg.sender:
                # Multi-user: use sender field
                if msg.sender == self._host_nickname and self._is_group:
                    label = f"{msg.sender} (host)"
                    attr  = curses.color_pair(CP_YOU) | curses.A_BOLD
                else:
                    label = msg.sender
                    # Cycle through a palette based on nickname hash
                    attr  = self._nick_color(msg.sender)
            else:
                label = self._peer_label
                attr  = curses.color_pair(CP_PEER) | curses.A_BOLD

            prefix = f"[{ts}]  {label:<14}: "
            lines  = textwrap.wrap(body, width=max_w) or [""]
            result = []
            for i, line in enumerate(lines):
                p = prefix if i == 0 else " " * len(prefix)
                result.append((attr, p + line))
            return result

        return []

    def _nick_color(self, nickname: str) -> int:
        """Pick a stable color pair for a nickname."""
        # CP_PEER=4, CP_YOU=3, CP_SYS=5, CP_STATUS=7
        palette = [CP_PEER, CP_STATUS, CP_SYS]
        idx = hash(nickname) % len(palette)
        return curses.color_pair(palette[idx]) | curses.A_BOLD

    def _init_colors(self) -> None:
        curses.start_color()
        curses.use_default_colors()
        bg = -1

        curses.init_pair(CP_HEADER,  curses.COLOR_BLACK,  curses.COLOR_CYAN)
        curses.init_pair(CP_FOOTER,  curses.COLOR_BLACK,  curses.COLOR_WHITE)
        curses.init_pair(CP_YOU,     curses.COLOR_GREEN,  bg)
        curses.init_pair(CP_PEER,    curses.COLOR_CYAN,   bg)
        curses.init_pair(CP_SYS,     curses.COLOR_YELLOW, bg)
        curses.init_pair(CP_TIME,    curses.COLOR_WHITE,  bg)
        curses.init_pair(CP_STATUS,  curses.COLOR_GREEN,  bg)
        curses.init_pair(CP_WARN,    curses.COLOR_RED,    bg)
        curses.init_pair(CP_BORDER,  curses.COLOR_WHITE,  bg)
        curses.init_pair(CP_INPUT,   curses.COLOR_WHITE,  bg)
        curses.init_pair(CP_PENDING, curses.COLOR_BLACK,  curses.COLOR_YELLOW)


_OUTGOING_SENTINEL = "\x01"


def make_outgoing_msg(text: str) -> Message:
    import time
    return Message(mtype=MsgType.MSG, body=_OUTGOING_SENTINEL + text, ts=time.time())
