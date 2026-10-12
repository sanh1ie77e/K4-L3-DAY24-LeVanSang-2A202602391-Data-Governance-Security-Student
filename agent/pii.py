"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


# Nhãn tài khoản giúp phân biệt STK 12 số với CCCD 12 số.
# Chỉ lấy span của nhóm value, không che luôn nhãn STK.
_BANK = re.compile(
    r"\b(?:STK|số\s+tài\s+khoản|so\s+tai\s+khoan|bank_account)\b"
    r"[ \t]*(?::|=)?[ \t]*(?P<value>[0-9]{8,16})(?!\w)",
    re.IGNORECASE,
)
_PATTERNS = (
    ("EMAIL", re.compile(r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
                         r"@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
                         r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+")),
    ("VN_CCCD", re.compile(r"(?<!\w)[0-9]{12}(?!\w)")),
    ("VN_PHONE", re.compile(r"(?<!\w)0(?:[ \t-]?[0-9]){9,10}(?!\w)")),
)


def detect(text: str) -> list[dict]:
    candidates = []
    for match in _BANK.finditer(text):
        candidates.append((0, "VN_BANK_ACCOUNT", *match.span("value")))
    for priority, (entity_type, pattern) in enumerate(_PATTERNS, 1):
        for match in pattern.finditer(text):
            candidates.append((priority, entity_type, *match.span()))

    # Ưu tiên nhãn STK, email, CCCD rồi điện thoại; mỗi vùng chỉ giữ một loại.
    entities = []
    for _, entity_type, start, end in sorted(candidates):
        if any(start < item["end"] and item["start"] < end for item in entities):
            continue
        entities.append({"type": entity_type, "start": start, "end": end})
    return sorted(entities, key=lambda item: item["start"])


def redact(text: str) -> str:
    for entity in reversed(detect(text)):
        start, end = entity["start"], entity["end"]
        text = text[:start] + f"[REDACTED_{entity['type']}]" + text[end:]
    return text
