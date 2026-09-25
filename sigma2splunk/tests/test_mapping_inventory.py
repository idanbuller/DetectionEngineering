import yaml

from sigma2splunk.inventory import load_inventory
from sigma2splunk.mapping import default_mapping, load_mapping
from sigma2splunk.sigma import LogSource


def test_default_mapping_specificity():
    m = default_mapping()
    # sysmon service should beat the generic windows entry
    sysmon = m.resolve(LogSource(product="windows", service="sysmon"))
    assert "Sysmon" in sysmon.sourcetype
    generic = m.resolve(LogSource(product="windows"))
    assert generic.index == "windows"
    proc = m.resolve(LogSource(product="windows", category="process_creation"))
    assert proc.base == "EventCode=4688"


def test_custom_mapping_and_field_map(tmp_path):
    p = tmp_path / "m.yml"
    p.write_text(
        yaml.safe_dump(
            {
                "defaults": {"field_map": {"User": "user"}},
                "logsources": [
                    {
                        "match": {"product": "windows", "category": "process_creation"},
                        "index": "win",
                        "sourcetype": "wineventlog",
                        "field_map": {"Image": "process"},
                    },
                ],
            }
        )
    )
    m = load_mapping(str(p))
    res = m.resolve(LogSource(product="windows", category="process_creation"))
    assert res.index == "win"
    assert m.map_field("Image", res) == "process"
    assert m.map_field("User", res) == "user"  # from defaults
    assert m.map_field("Other", res) == "Other"


def test_unmatched_logsource_is_empty():
    res = default_mapping().resolve(LogSource(product="macos"))
    assert res.index is None and res.sourcetype is None


def test_inventory_availability(tmp_path):
    p = tmp_path / "inv.json"
    p.write_text(
        yaml.safe_dump(
            [
                {"index": "edr", "sourcetype": "sysmon"},
                {"index": "os"},
            ]
        )
    )
    inv = load_inventory(str(p))
    assert inv.available("edr", "sysmon")
    assert inv.available("edr", "other")  # index-level fallback
    assert inv.available("os", "linux")  # only index listed
    assert not inv.available("proxy", "web")
    assert inv.available(None, None)  # nothing to check -> not filtered


def test_inventory_mapping_form(tmp_path):
    p = tmp_path / "inv.json"
    p.write_text(yaml.safe_dump({"edr::sysmon": {"events": 10}, "os": {}}))
    inv = load_inventory(str(p))
    assert inv.available("edr", "sysmon") and inv.available("os", None)
    assert not inv.available("dns", None)


def test_mapping_loads_extract(tmp_path):
    import yaml as _yaml

    from sigma2splunk.mapping import load_mapping
    from sigma2splunk.sigma import LogSource

    p = tmp_path / "m.yml"
    p.write_text(
        _yaml.safe_dump(
            {
                "defaults": {"extract": {"user": "tgt.process.user"}},
                "logsources": [
                    {
                        "match": {"product": "macos"},
                        "index": "edr",
                        "sourcetype": "s1",
                        "extract": {"process": "tgt.process.image.path"},
                    }
                ],
            }
        )
    )
    res = load_mapping(str(p)).resolve(LogSource(product="macos"))
    assert res.extract == {"user": "tgt.process.user", "process": "tgt.process.image.path"}  # defaults + logsource
