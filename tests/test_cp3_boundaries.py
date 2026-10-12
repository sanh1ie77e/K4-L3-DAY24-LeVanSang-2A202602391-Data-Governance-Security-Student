"""Kiểm thêm ranh giới dữ liệu và trường hợp OBO không hợp lệ."""
from dataclasses import replace
import json
from pathlib import Path

import pytest

from agent import pii, tools
from agent.llm import MockLLM
from agent.loop import run_once
from agent.policy import PolicyContext, check


def test_labeled_bank_number_wins_overlap_and_offsets_are_exact():
    text = "STK: 012345678912; CCCD: 012345678912; SĐT: 0912-345-678; email: a1@example.vn"
    entities = pii.detect(text)
    assert [(entity["type"], text[entity["start"]:entity["end"]]) for entity in entities] == [
        ("VN_BANK_ACCOUNT", "012345678912"),
        ("VN_CCCD", "012345678912"),
        ("VN_PHONE", "0912-345-678"),
        ("EMAIL", "a1@example.vn"),
    ]
    assert pii.redact(text) == (
        "STK: [REDACTED_VN_BANK_ACCOUNT]; CCCD: [REDACTED_VN_CCCD]; "
        "SĐT: [REDACTED_VN_PHONE]; email: [REDACTED_EMAIL]"
    )


@pytest.mark.parametrize("change", [
    {"data_classification": "unknown"},
    {"request_purpose": "unapproved-purpose"},
    {"agent_scopes": ()},
    {"delegation_depth": 1, "parent_scopes": ()},
    {"delegation_depth": -1},
    {"expires_at": ""},
    {"expires_at": "not-a-date"},
    {"expires_at": "2099-01-01T00:00:00"},
    {"expires_at": "2099-01-01T00:00:00+07:00"},
])
def test_invalid_policy_inputs_are_denied_with_reason(change):
    valid = PolicyContext(
        data_classification="restricted", request_purpose="support-reply",
        agent_owner="test-agent", delegation_depth=0, egress_enabled=False,
        principal_id="dpo", requested_tool="read_customer",
        agent_scopes=("read_customer",), expires_at="2099-01-01T00:00:00Z",
    )
    allow, reason = check(replace(valid, **change))
    assert allow is False and isinstance(reason, str) and reason.strip()


def test_support_is_denied_before_opening_private_store(tmp_path, monkeypatch):
    original = Path.read_text

    def guarded_read(path, *args, **kwargs):
        if path.resolve() == tools.CUSTOMERS_FILE.resolve():
            pytest.fail("support_l1 opened the private store")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read)
    run_once("ticket", mock=True, log_dir=tmp_path, principal_id="support_l1")
    entries = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text(encoding="utf-8").splitlines()]
    assert any(entry["tool"] == "read_customer" and entry["decision"] == "deny" for entry in entries)


def test_unknown_principal_cannot_search_docs(tmp_path, monkeypatch):
    monkeypatch.setattr(tools, "search_docs", lambda *args, **kwargs: pytest.fail("Unauthorized search"))
    run_once("ticket", mock=True, log_dir=tmp_path, principal_id="nobody")
    entries = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(entries) == 1 and entries[0]["decision"] == "deny"


def test_llm_and_ledger_do_not_receive_raw_ticket_pii(tmp_path, monkeypatch):
    text = "CCCD 012345678912, SĐT 0912345678, STK 12345678901234, email lab@example.vn"
    secrets = ("012345678912", "0912345678", "12345678901234", "lab@example.vn")
    monkeypatch.setattr(tools, "search_docs", lambda message: [{"id": "ticket-001.md", "text": text}])
    seen = []

    class SpyLLM(MockLLM):
        def find_injection(self, value):
            seen.append(value)
            return super().find_injection(value)

        def summarize(self, docs):
            seen.extend(doc["text"] for doc in docs)
            return super().summarize(docs)

    from agent.runner import handle
    handle("ticket", SpyLLM(), log_dir=tmp_path, principal_id="support_l1")
    assert len(seen) == 2
    evidence = (tmp_path / "ledger.jsonl").read_text(encoding="utf-8")
    assert all(secret not in value for secret in secrets for value in [*seen, evidence])
