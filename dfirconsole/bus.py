"""Broadcasting pipeline events to connected clients.

A ring buffer keeps the most recent events so that a reopened tab finds a
populated console instead of a blank screen.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any

# Hayabusa and THOR colour their output; ANSI sequences pollute the browser
# just as much as the log file.
ANSI = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\[[0-9]{1,3}(?:;[0-9]{1,3}){0,4}m")


def strip_ansi(text: str) -> str:
    return ANSI.sub("", text)


class EventBus:
    def __init__(self, history: int = 2000) -> None:
        self._subscribers: set[asyncio.Queue] = set()
        self._history: deque[dict] = deque(maxlen=history)
        self._seq = 0
        self._logfile: Path | None = None

    # -- on-disk log -------------------------------------------------------
    def attach_file(self, path: Path) -> None:
        """Everything crossing the bus is also written to disk.

        The interface only shows a sample when output is massive; the file
        keeps all of it. That file is what explains, after the fact, why a
        step stalled.
        """
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._logfile = path
            self._write(f"\n===== Session opened {datetime.now():%Y-%m-%d %H:%M:%S} =====")
        except OSError:
            self._logfile = None

    @property
    def logfile(self) -> Path | None:
        return self._logfile

    def _write(self, line: str) -> None:
        if self._logfile is None:
            return
        try:
            with self._logfile.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError:
            pass

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    def backlog(self) -> list[dict]:
        return list(self._history)

    def emit(self, kind: str, **payload: Any) -> dict:
        self._seq += 1
        event = {"seq": self._seq, "kind": kind, "ts": time.time(), **payload}
        if kind in ("log", "step"):
            self._history.append(event)
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # Slow client: let it drop rather than stall the running
                # collection.
                self.unsubscribe(queue)
        return event

    def log(self, message: str, level: str = "info", step: str | None = None,
            ui: bool = True) -> None:
        """`ui=False`: recorded on disk without being pushed to the browser."""
        message = strip_ansi(message)
        stamp = datetime.now().strftime("%H:%M:%S")
        self._write(f"{stamp} [{level:5}] {step or '-':10} {message}")
        if ui:
            self.emit("log", message=message, level=level, step=step)

    def clear_history(self) -> None:
        self._history.clear()
