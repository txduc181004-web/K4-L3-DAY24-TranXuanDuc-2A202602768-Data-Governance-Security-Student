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

# Thứ tự ưu tiên quan trọng: recognizer đứng trước "giữ" span, recognizer sau
# bỏ qua mọi match chồng lên span đã giữ. Nhờ vậy 12 chữ số đứng sau "STK"
# là VN_BANK_ACCOUNT chứ không bị nhận nhầm thành VN_CCCD.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# STK có ngữ cảnh: "STK", "số tài khoản", "tài khoản" (có hoặc không dấu),
# cho phép ":"/"là"/"số" xen giữa. Chỉ group 1 (dãy số) là entity.
_BANK_CONTEXT_RE = re.compile(
    r"(?i)(?:\bSTK|s[ốo]\s+t[àa]i\s+kho[ảa]n|t[àa]i\s+kho[ảa]n|account(?:\s+number)?)"
    r"\s*(?:là|la|:|số|so|no\.?)?\s*:?\s*(\d{8,16})(?!\d)"
)

# CCCD: đúng 12 chữ số liên tiếp, không dính chữ số hai bên.
_CCCD_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")

# SĐT: 0xx hoặc +84xx, cho phép dấu cách/chấm/gạch ngang giữa các nhóm.
# Độ dài kiểm thêm sau khi bỏ dấu phân cách (0 + 9-10 chữ số).
_PHONE_RE = re.compile(r"(?<![\d+])(?:\+84|0)\d{2,3}(?:[\s.-]?\d{3}){2}\d{0,1}(?!\d)")

# Fallback fail-safe: dãy 8-16 chữ số không thuộc loại nào ở trên vẫn bị coi
# là STK. Che thừa một mã số vô hại rẻ hơn để lọt một STK không có ngữ cảnh.
_LONG_DIGITS_RE = re.compile(r"(?<!\d)\d{8,16}(?!\d)")


def _phone_ok(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if digits.startswith("84"):
        return len(digits) == 11
    return digits.startswith("0") and len(digits) in (10, 11)


def detect(text: str) -> list[dict]:
    spans: list[dict] = []

    def _free(start: int, end: int) -> bool:
        return all(end <= s["start"] or start >= s["end"] for s in spans)

    def _add(kind: str, start: int, end: int) -> None:
        if _free(start, end):
            spans.append({"type": kind, "start": start, "end": end})

    for m in _EMAIL_RE.finditer(text):
        _add("EMAIL", m.start(), m.end())
    for m in _BANK_CONTEXT_RE.finditer(text):
        _add("VN_BANK_ACCOUNT", m.start(1), m.end(1))
    for m in _CCCD_RE.finditer(text):
        _add("VN_CCCD", m.start(), m.end())
    for m in _PHONE_RE.finditer(text):
        if _phone_ok(m.group()):
            _add("VN_PHONE", m.start(), m.end())
    for m in _LONG_DIGITS_RE.finditer(text):
        _add("VN_BANK_ACCOUNT", m.start(), m.end())

    return sorted(spans, key=lambda s: s["start"])


def redact(text: str) -> str:
    # Thay từ cuối về đầu để offset của các entity phía trước không bị lệch.
    for entity in sorted(detect(text), key=lambda s: s["start"], reverse=True):
        text = text[: entity["start"]] + f"[REDACTED_{entity['type']}]" + text[entity["end"] :]
    return text
