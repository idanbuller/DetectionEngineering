from datetime import timedelta

from detval.casespec import Check
from detval.verify import row_matches, verify_check


def check(**kw):
    base = dict(
        name="c",
        kind="telemetry",
        search="index=edr",
        min_rows=1,
        match={},
        window=timedelta(minutes=10),
        settle=timedelta(0),
        poll=timedelta(seconds=30),
    )
    base.update(kw)
    return Check(**base)


def test_row_matches_with_substitutions():
    row = {"dest": "canary-01", "user": ["a", "bob"]}
    assert row_matches(row, {"dest": "{target}"}, {"target": "canary-01"})
    assert row_matches(row, {"user": "bob"}, {})
    assert not row_matches(row, {"dest": "other"}, {})


def test_detected_immediately(clock, make_search):
    search = make_search(rows_by_marker={"edr": [{"_time": str(int(clock.now().timestamp())), "dest": "c1"}]})
    r = verify_check(
        check(match={"dest": "{target}"}), clock.now(), search, {"target": "c1"}, now=clock.now, sleep=clock.sleep
    )
    assert r.detected and r.rows == 1 and r.polls == 1 and r.latency_seconds == 0.0


def test_appears_after_polling(clock, make_search):
    started = clock.now()
    search = make_search(
        appear_at={"edr": timedelta(minutes=3)},
        rows_by_marker={"edr": [{"_time": str(int(started.timestamp()) + 200)}]},
    )
    r = verify_check(check(poll=timedelta(minutes=1)), started, search, now=clock.now, sleep=clock.sleep)
    assert r.detected and r.polls >= 3


def test_never_appears_times_out(clock, make_search):
    r = verify_check(
        check(window=timedelta(minutes=5), poll=timedelta(minutes=1)),
        clock.now(),
        make_search(),
        now=clock.now,
        sleep=clock.sleep,
    )
    assert not r.detected and r.rows == 0
    assert r.polls <= 7  # bounded by window/poll + slack


def test_settle_delays_first_poll(clock, make_search):
    started = clock.now()
    search = make_search(rows_by_marker={"edr": [{"_time": str(int(started.timestamp()))}]})
    verify_check(check(settle=timedelta(minutes=2)), started, search, now=clock.now, sleep=clock.sleep)
    assert (clock.now() - started).total_seconds() >= 120


def test_min_rows(clock, make_search):
    search = make_search(rows_by_marker={"edr": [{"a": 1}]})
    r = verify_check(
        check(min_rows=3, window=timedelta(minutes=2), poll=timedelta(minutes=1)),
        clock.now(),
        search,
        now=clock.now,
        sleep=clock.sleep,
    )
    assert not r.detected and r.rows == 1


def test_search_error_fails_only_that_check(clock):
    def boom(spl, e, latest):
        raise RuntimeError("bad search")

    r = verify_check(check(), clock.now(), boom, now=clock.now, sleep=clock.sleep)
    assert not r.detected and "bad search" in r.error
