"""Independent blocking readers, consumed fairly by the single decision thread."""

import logging
import queue
import threading
import time


def stream_collector_events(sources):
    stop = threading.Event()
    queues = {name: queue.Queue(maxsize=1024) for name in sources}

    def collect(name, factory):
        while not stop.is_set():
            try:
                for event in factory():
                    while not stop.is_set():
                        try:
                            queues[name].put(event, timeout=0.2)
                            break
                        except queue.Full:
                            continue
                    if stop.is_set():
                        return
            except Exception:
                logging.exception("[%s] Collector failed; retrying independently", name)
            stop.wait(1)

    workers = [threading.Thread(target=collect, args=(name, factory), daemon=True,
                                name=f"minifw-{name}") for name, factory in sources.items()]
    for worker in workers:
        worker.start()
    next_tick = time.monotonic()
    try:
        while True:
            available = False
            for name, events in queues.items():
                try:
                    event = events.get_nowait()
                except queue.Empty:
                    continue
                available = True
                yield name, event
            if time.monotonic() >= next_tick:
                yield "tick", None
                next_tick = time.monotonic() + 0.25
            if not available:
                stop.wait(0.05)
    finally:
        stop.set()
        for worker in workers:
            worker.join(timeout=0.2)
