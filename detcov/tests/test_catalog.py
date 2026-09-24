from detcov.catalog import TECHNIQUE, extract_data, load_catalog, load_detection


def write(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(body)
    return str(p)


def test_technique_regex_handles_dots_underscores_and_bad_ids():
    assert TECHNIQUE.findall("T1003.001_LSASS.YML") == ["T1003.001"]
    assert TECHNIQUE.findall("attack.t1059.001".upper()) == ["T1059.001"]
    assert TECHNIQUE.findall("T1110 and T1059.003") == ["T1110", "T1059.003"]
    assert TECHNIQUE.findall("T10591") == []  # not a real 4-digit id


def test_extract_index_and_sourcetype_from_spl():
    idx, st, macro = extract_data('index=os sourcetype=linux_secure "Failed password" | stats count')
    assert idx == {"os"} and st == {"linux_secure"} and not macro


def test_extract_handles_in_clause_and_wildcards():
    idx, st, _ = extract_data("index IN (edr, os) sourcetype=* | stats count")
    assert idx == {"edr", "os"} and st == set()  # * is ignored


def test_extract_flags_macro_index():
    idx, st, macro = extract_data("`my_index` sourcetype=edr:file | stats count")
    assert idx == set() and macro is True


def test_extract_reads_tstats():
    idx, st, _ = extract_data("| tstats count where index=firewall by dest")
    assert idx == {"firewall"}


def test_load_detection_pulls_techniques_from_field_and_name(tmp_path):
    p = write(
        tmp_path, "T1110.001_brute.yml", "name: Brute\nmitre: [T1110.001]\nsearch: index=os sourcetype=linux_secure x\n"
    )
    [det] = load_detection(p)
    assert det.techniques == ["T1110.001"]  # not duplicated as T1110
    assert det.data_pairs == {("os", "linux_secure")}


def test_load_detection_from_tags_and_spl_file(tmp_path):
    y = write(tmp_path, "d.yml", "name: X\ntags: [attack.t1003.001, persistence]\nsearch: index=edr foo\n")
    assert load_detection(y)[0].techniques == ["T1003.001"]
    s = write(tmp_path, "T1486_ransom.spl", "index=edr sourcetype=edr:file | stats count")
    assert load_detection(s)[0].techniques == ["T1486"]


def test_load_catalog_skips_test_and_case_files(tmp_path):
    write(tmp_path, "T1.yml", "mitre: [T1059]\nsearch: index=a b\n")
    write(tmp_path, "x.test.yml", "detection: y\n")
    write(tmp_path, "y.case.yml", "technique: T1\n")
    cat = load_catalog([str(tmp_path)])
    assert len(cat) == 1
