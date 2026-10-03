"""
SlidingWindow - remembers recent events per key and expires old ones.
Cooldown      - stops the same alert from firing over and over.

Both keep their memory bounded, so a flood of spoofed source IPs can't
make Horus eat RAM.
"""
from collections import Counter, OrderedDict, deque
from datetime import timedelta


class SlidingWindow:
    def __init__(self, window: timedelta, max_keys: int = 50_000):
        self.window = window
        self.max_keys = max_keys
        self._events = OrderedDict()   # key -> deque[(timestamp, value)]
        self._values = {}              # key -> Counter of values in the window
        self._last_sweep = None

    def add(self, key, timestamp, value=None):
        # record an event for `key`, dropping entries older than the window."""
        self._expire(key, timestamp)

        if key not in self._events:
            self._events[key] = deque()
            self._values[key] = Counter()
            # hard cap: if too many keys are tracked, forget the oldest one
            if len(self._events) > self.max_keys:
                old_key, _ = self._events.popitem(last=False)
                del self._values[old_key]

        self._events[key].append((timestamp, value))
        self._values[key][value] += 1
        self._sweep(timestamp)

    def count(self, key) -> int:
        """Events currently inside the window for `key`."""
        events = self._events.get(key)
        return len(events) if events else 0

    def distinct(self, key) -> int:
        """Distinct values currently inside the window for `key`."""
        return len(self._values.get(key, ()))

    def values(self, key) -> set:
        """The distinct values currently inside the window for `key`."""
        return set(self._values.get(key, ()))

    def clear(self):
        self._events.clear()
        self._values.clear()
        self._last_sweep = None

    def __len__(self):
        return len(self._events)

    def _expire(self, key, now):
        events = self._events.get(key)
        if not events:
            return
        values = self._values[key]
        while events and now - events[0][0] > self.window:
            _, value = events.popleft()
            values[value] -= 1
            if values[value] <= 0:
                del values[value]
        if not events:                 # nothing left: forget the key entirely
            del self._events[key]
            del self._values[key]

    def _sweep(self, now):
        """Once per window, expire every key (idle sources never get touched otherwise)."""
        if self._last_sweep is None:
            self._last_sweep = now
            return
        if now - self._last_sweep < self.window:
            return
        self._last_sweep = now
        for key in list(self._events):
            self._expire(key, now)


class Cooldown:
    """allow(key, now) is True at most once per `period` for each key."""

    def __init__(self, period: timedelta, max_keys: int = 50_000):
        self.period = period
        self.max_keys = max_keys
        self._last = OrderedDict()     # key -> time of last alert, oldest first

    def allow(self, key, now) -> bool:
        last = self._last.get(key)
        if last is not None and now - last < self.period:
            return False

        self._last[key] = now
        self._last.move_to_end(key)
        self._prune(now)
        return True

    def clear(self):
        self._last.clear()

    def _prune(self, now):
        # oldest entries are first: drop the ones that have expired anyway,
        # and anything beyond the hard cap
        while self._last:
            _, oldest = next(iter(self._last.items()))
            if now - oldest >= self.period or len(self._last) > self.max_keys:
                self._last.popitem(last=False)
            else:
                break