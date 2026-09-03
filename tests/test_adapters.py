"""Adapters are where a corpus lies to the pipeline, so each one is tested against the exact
row shapes it was written from -- not against a hand-simplified version of them."""

from __future__ import annotations

import json

import pytest

from causeway import corpus
from causeway.adapters import ait
from causeway.adapters.lab import GROUND_TRUTH_ROOT_REF, generate
from causeway.entities import EntityResolver

# -- AIT: the three shapes a Wazuh row comes in -----------------------------------------

EVE_ROW = {
    "@timestamp": "2022-01-21T00:14:21.351Z",
    "agent": {"ip": "10.143.0.103", "name": "wazuh-client", "id": "16"},
    "predecoder": {"hostname": "intranet-server"},
    "rule": {"level": 3, "id": "86601", "description": "Suricata: Alert - ET POLICY ..."},
    "data": {
        "event_type": "alert", "flow_id": "114520921835946.000000", "app_proto": "http",
        "src_ip": "10.143.0.103", "src_port": "44510", "dest_ip": "91.189.95.85",
        "dest_port": "80",
        "alert": {"severity": "3", "signature_id": "2013504",
                  "signature": "ET POLICY GNU/Linux APT User-Agent Outbound"},
    },
}

FASTLOG_ROW = {
    "@timestamp": "2022-01-21T00:14:21.351Z",
    "agent": {"ip": "10.143.0.103", "name": "wazuh-client", "id": "16"},
    "predecoder": {"timestamp": "01/21/2022-00:14:21.351932"},
    "decoder": {"parent": "snort", "name": "snort"},
    "rule": {"level": 8, "id": "20100", "description": "First time this IDS alert is generated."},
    "data": {"srcip": "10.143.0.103", "dstip": "91.189.95.85:80", "id": "1:2013504:6"},
    "location": "/var/log/suricata/fast.log",
}

WAZUH_ROW = {
    "@timestamp": "2022-01-21T03:05:00.000Z",
    "agent": {"ip": "172.19.128.1", "name": "wazuh-client", "id": "22"},
    "predecoder": {"hostname": "mail", "program_name": "sshd"},
    "rule": {"level": 10, "id": "5710",
             "description": "sshd: Attempt to login using a non-existent user"},
    "data": {"srcip": "172.19.130.4", "srcuser": "admin"},
}

AMINER_ROW = {
    "AnalysisComponent": {"AnalysisComponentType": "NewMatchPathDetector",
                          "AnalysisComponentName": "AMiner: New event type."},
    "LogData": {"RawLogData": ["Jan 21 00:00:01 cloud-share CRON[4388]: pam_unix(cron:session)"],
                "Timestamps": [1642723201]},
    "AMiner": {"ID": "10.143.2.4"},
}


def test_eve_json_relayed_by_wazuh_is_credited_to_suricata():
    parsed = ait._parse_wazuh(EVE_ROW)
    assert parsed is not None
    assert parsed["sensor"] == "suricata"
    assert parsed["rule_id"] == "2013504"
    assert parsed["severity"] == ait.SURICATA_SEVERITY["3"]
    assert parsed["entities"] == {"host": "intranet-server", "src_ip": "10.143.0.103",
                                  "dst_ip": "91.189.95.85"}


def test_fast_log_relay_is_the_same_finding_with_the_same_rule_id():
    """The two encodings of one Suricata alert must dedup against each other."""
    eve, fast = ait._parse_wazuh(EVE_ROW), ait._parse_wazuh(FASTLOG_ROW)
    assert fast is not None and eve is not None
    assert fast["sensor"] == eve["sensor"] == "suricata"
    assert fast["rule_id"] == eve["rule_id"]
    assert fast["entities"]["dst_ip"] == "91.189.95.85", "the port must be stripped"


def test_generic_agent_name_is_not_a_host():
    parsed = ait._parse_wazuh(FASTLOG_ROW)
    assert parsed is not None
    assert "host" not in parsed["entities"]


def test_wazuh_native_row():
    parsed = ait._parse_wazuh(WAZUH_ROW)
    assert parsed is not None
    assert parsed["sensor"] == "wazuh"
    assert parsed["rule_id"] == "5710"
    assert parsed["severity"] == int(10 * ait.WAZUH_LEVEL_SCALE)
    assert parsed["entities"] == {"host": "mail", "src_ip": "172.19.130.4", "user": "admin"}


def test_aminer_row_takes_host_from_the_syslog_header():
    parsed = ait._parse_aminer(AMINER_ROW)
    assert parsed is not None
    assert parsed["sensor"] == "aminer"
    assert parsed["rule_name"] == "New event type."
    assert parsed["entities"] == {"host": "cloud-share", "src_ip": "10.143.2.4"}


def test_rows_without_a_timestamp_are_skipped():
    assert ait._parse_wazuh({"rule": {}}) is None
    assert ait._parse_aminer({"LogData": {}}) is None


def test_stage_lookup_uses_the_published_windows():
    windows = [ait.Window("s", "recon", 100.0, 200.0), ait.Window("s", "exfil", 300.0, 400.0)]
    assert ait.stage_at(windows, 50) == ""
    assert ait.stage_at(windows, 150) == "recon"
    assert ait.stage_at(windows, 250) == ""      # a gap between stages is background
    assert ait.stage_at(windows, 400) == "exfil"


def test_parse_lines_labels_and_numbers_alerts():
    # EVE_ROW is stamped 00:14:21 on 2022-01-21, i.e. epoch 1642724061; WAZUH_ROW is later.
    windows = [ait.Window("demo", "recon", 1642724000.0, 1642724100.0)]
    lines = [json.dumps(EVE_ROW), "", "not json", json.dumps(WAZUH_ROW)]
    alerts = ait.parse_lines(lines, "wazuh", scenario="demo", windows=windows)
    assert [a.id for a in alerts] == ["ait-demo-0000001", "ait-demo-0000002"]
    assert alerts[0].stage == "recon" and alerts[1].stage == ""


def test_missing_archive_says_where_to_get_it(tmp_path):
    labels = tmp_path / "labels.csv"
    labels.write_text("scenario,attack,start,end\ndemo,recon,1,2\n")
    with pytest.raises(FileNotFoundError, match="zenodo"):
        ait.load("demo", path=tmp_path / "nope.zip", labels=labels)


# -- corpus contract ---------------------------------------------------------------------

def test_lab_scenario_carries_its_answer_key():
    scn = generate()
    assert scn.name == "lab"
    assert scn.root_ref == GROUND_TRUTH_ROOT_REF
    assert scn.root_gradable
    assert len(scn.stages) == 9
    assert scn.duplicates and scn.parents


def test_jsonl_round_trip_preserves_alerts_and_labels(tmp_path):
    scn = generate()
    path = tmp_path / "lab.jsonl"
    from causeway.schema import dump_alerts
    dump_alerts(scn.alerts, str(path))
    back = corpus.from_jsonl(path)
    assert back.alerts == scn.alerts
    assert back.truth == scn.truth
    assert not back.root_gradable, "a JSONL file publishes stages, not a root entity"


def test_unknown_corpus_is_refused_loudly():
    with pytest.raises(ValueError, match="unknown corpus"):
        corpus.load("nonsense")


def test_resolver_canonicalises_the_lab_root_ref():
    assert "account:" + EntityResolver().user("CORP\\j.okafor") == GROUND_TRUTH_ROOT_REF
