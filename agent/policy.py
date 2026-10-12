"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"

KNOWN_CLASSIFICATIONS = {"public", "internal", "restricted"}

# Data minimisation: đọc dữ liệu restricted phải có mục đích nghiệp vụ cụ thể.
# "summarize-tickets" không đủ lý do để mở hồ sơ chứa CCCD/STK.
RESTRICTED_PURPOSES = {"support-reply", "billing-reconciliation", "privacy-audit"}


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict:
    # Đọc lại mỗi lần check: thu hồi quyền trong principals.json có hiệu lực ngay.
    return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))


def _parse_expiry(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    return parsed if parsed.tzinfo is not None else None


def check(context: PolicyContext) -> tuple[bool, str]:
    """Default deny: chỉ allow khi qua hết mọi rule; mỗi nhánh có reason riêng."""
    c = context
    tool = c.requested_tool or "<unspecified>"

    # Rule tối thiểu, đứng đầu để không điều kiện OBO nào "mở" được nó.
    if c.data_classification == "restricted" and c.egress_enabled:
        return False, (f"deny {tool}: dữ liệu restricted không được đi kèm egress "
                       f"(rule tối thiểu restricted+egress)")
    if c.data_classification not in KNOWN_CLASSIFICATIONS:
        return False, f"deny {tool}: classification không hợp lệ {c.data_classification!r}"

    principals = _load_principals()
    principal = principals.get(c.principal_id)
    if principal is None:
        return False, f"deny {tool}: principal {c.principal_id!r} không có trong principals.json"
    if not c.requested_tool:
        return False, "deny: thiếu requested_tool, không xác định được quyền cần kiểm"

    # Quyền hiệu lực = principal ∩ agent_scopes (∩ parent_scopes nếu được ủy quyền).
    if c.requested_tool not in principal.get("allowed_tools", []):
        return False, f"deny {tool}: principal {c.principal_id!r} không được cấp tool này"
    if c.requested_tool not in c.agent_scopes:
        return False, f"deny {tool}: ngoài agent_scopes của {c.agent_owner!r} {list(c.agent_scopes)}"
    if c.delegation_depth < 0:
        return False, f"deny {tool}: delegation_depth âm ({c.delegation_depth})"
    if c.delegation_depth > 0 and c.requested_tool not in c.parent_scopes:
        return False, (f"deny {tool}: agent con (depth={c.delegation_depth}) không được "
                       f"vượt parent_scopes {list(c.parent_scopes)}")

    if c.request_purpose not in principal.get("purposes", []):
        return False, f"deny {tool}: purpose {c.request_purpose!r} không thuộc purposes của {c.principal_id!r}"
    if c.data_classification == "restricted" and c.request_purpose not in RESTRICTED_PURPOSES:
        return False, f"deny {tool}: purpose {c.request_purpose!r} không đủ để đọc dữ liệu restricted"

    expiry = _parse_expiry(c.expires_at)
    if expiry is None:
        return False, f"deny {tool}: expires_at thiếu hoặc không phải ISO-8601 có timezone ({c.expires_at!r})"
    if expiry <= datetime.now(timezone.utc):
        return False, f"deny {tool}: run đã hết hạn lúc {c.expires_at}"

    return True, (f"allow {tool}: {c.principal_id} có quyền, trong scope của {c.agent_owner}, "
                  f"purpose={c.request_purpose}, classification={c.data_classification}, "
                  f"egress={c.egress_enabled}, hạn tới {c.expires_at}")
