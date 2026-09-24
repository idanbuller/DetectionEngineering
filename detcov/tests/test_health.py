import json

from detcov.health import HEALTHY, MISSING, STALE, UNKNOWN, empty, load_health_file


def write(tmp_path, obj):
    p = tmp_path / "h.json"
    p.write_text(json.dumps(obj))
    return str(p)


def test_status_from_list(tmp_path):
    now = 1_000_000.0
    h = load_health_file(
        write(
            tmp_path,
            [
                {"index": "edr", "sourcetype": "edr:process", "last_seen": now, "events": 10},
                {"index": "proxy", "sourcetype": "proxy:web", "last_seen": now - 100000, "events": 5},
                {"index": "dead", "sourcetype": "x", "last_seen": now, "events": 0},
            ],
        ),
        freshness_seconds=3600,
        now=now,
    )
    assert h.status(("edr", "edr:process")) == HEALTHY
    assert h.status(("proxy", "proxy:web")) == STALE
    assert h.status(("dead", "x")) == MISSING
    assert h.status(("nope", "x")) == MISSING  # data exists, this source doesn't
    assert h.status(("edr", "other")) == HEALTHY  # falls back to index-level health


def test_mapping_form_and_index_fallback(tmp_path):
    now = 1_000_000.0
    h = load_health_file(write(tmp_path, {"edr::edr:process": {"last_seen": now, "events": 3}}), 3600, now)
    assert h.status(("edr", "edr:process")) == HEALTHY
    assert h.status(("edr", None)) == HEALTHY


def test_worst_across_pairs(tmp_path):
    now = 1_000_000.0
    h = load_health_file(
        write(
            tmp_path,
            [
                {"index": "edr", "sourcetype": "a", "last_seen": now, "events": 1},
                {"index": "edr", "sourcetype": "b", "last_seen": now - 99999, "events": 1},
            ],
        ),
        3600,
        now,
    )
    assert h.worst({("edr", "a"), ("edr", "b")}) == STALE
    assert h.worst(set()) == UNKNOWN


def test_empty_health_is_unknown():
    h = empty()
    assert h.status(("edr", "x")) == UNKNOWN and not h.has_data
