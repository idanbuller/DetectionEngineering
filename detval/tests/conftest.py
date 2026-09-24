from datetime import datetime, timedelta, timezone

import pytest


class FakeClock:
    """A clock that only moves when sleep() is called, so polling loops are deterministic."""

    def __init__(self, start=None):
        self.t = start or datetime(2026, 1, 5, 12, 0, 0, tzinfo=timezone.utc)

    def now(self):
        return self.t

    def sleep(self, seconds):
        self.t += timedelta(seconds=seconds)


@pytest.fixture
def clock():
    return FakeClock()


class FakeSearch:
    """A search function whose rows can depend on how much fake time has passed."""

    def __init__(self, clock, appear_at=None, rows_by_marker=None):
        self.clock = clock
        self.start = clock.now()
        self.appear_at = appear_at or {}  # marker substring -> timedelta after which rows appear
        self.rows = rows_by_marker or {}  # marker substring -> rows to return
        self.calls = []

    def __call__(self, spl, earliest, latest):
        self.calls.append((spl, earliest, latest))
        for marker, rows in self.rows.items():
            if marker in spl:
                delay = self.appear_at.get(marker)
                if delay is None or self.clock.now() - self.start >= delay:
                    return [dict(r) for r in rows]
        return []


@pytest.fixture
def make_search(clock):
    def _make(**kw):
        return FakeSearch(clock, **kw)

    return _make
