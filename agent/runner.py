"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

RUN_TTL = timedelta(minutes=5)

# Orchestrator (depth 0) không bao giờ có http_post; Run A/B là agent con
# (depth 1) nên quyền hiệu lực còn bị giao thêm với ORCHESTRATOR_SCOPES.
ORCHESTRATOR_SCOPES = ("search_docs", "read_customer")
RUN_A_SCOPES = ("search_docs",)
RUN_B_SCOPES = ("read_customer",)

# Chỉ tên file là nguồn đáng tin cho ticket id: "ticket-904b.md" -> 904.
_TICKET_FILE_RE = re.compile(r"^ticket-(\d+)[a-z]?\.md$")


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


class _Run:
    """Một run con: identity riêng, scope riêng, mọi tool call qua PEP + ledger."""

    def __init__(self, name: str, scopes: tuple[str, ...], principal_id: str,
                 expires_at: str, ledger_path: Path):
        self.agent_id = f"lab24-agent/{name}"
        self.run_id = f"{name}-{uuid.uuid4().hex[:12]}"
        self.scopes = scopes
        self.principal_id = principal_id
        self.expires_at = expires_at
        self.ledger_path = ledger_path

    def call(self, tool: str, args: dict, *, classification: str, purpose: str,
             egress: bool, execute):
        """PEP: policy.check -> ledger.append (allow lẫn deny) -> chỉ chạy khi allow.

        Trả về (allowed, result). Ledger ghi xong mới execute, nên một call
        đã chạy luôn có dòng allow tương ứng; ledger lỗi thì tool không chạy.
        """
        ctx = policy.PolicyContext(
            data_classification=classification,
            request_purpose=purpose,
            agent_owner=self.agent_id,
            delegation_depth=1,
            egress_enabled=egress,
            principal_id=self.principal_id,
            requested_tool=tool,
            agent_scopes=self.scopes,
            parent_scopes=ORCHESTRATOR_SCOPES,
            expires_at=self.expires_at,
        )
        allowed, reason = policy.check(ctx)
        args_hash = hashlib.sha256(
            json.dumps(args, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": self.agent_id,
            "run_id": self.run_id,
            "on_behalf_of": self.principal_id,
            "expires_at": self.expires_at,
            "tool": tool,
            "args_hash": args_hash,
            "classification": classification,
            "purpose": purpose,
            "egress": egress,
            "delegation_depth": 1,
            "decision": "allow" if allowed else "deny",
            "reason": reason,
        }, self.ledger_path)
        if not allowed:
            return False, None
        return True, execute()


def _ticket_ids(docs: list[dict]) -> list[int]:
    ids = []
    for doc in docs:
        m = _TICKET_FILE_RE.match(doc["id"])
        if m:
            ids.append(int(m.group(1)))
    return sorted(set(ids))


def _customers_for_tickets(ticket_ids: list[int]) -> list[str]:
    """Nguồn tin cậy: related_tickets trong customers.json, không phải free text."""
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    wanted = set(ticket_ids)
    return [c["customer_id"] for c in customers if wanted & set(c.get("related_tickets", []))]


def _run_a(message: str, llm, run: _Run) -> tuple[list[dict], list[int]]:
    """Run A: chỉ chạm untrusted content. Không private data, không egress."""
    allowed, docs = run.call(
        "search_docs", {"query": message},
        classification="internal", purpose="summarize-tickets", egress=False,
        execute=lambda: tools.search_docs(message),
    )
    if not allowed:
        return [], []

    # PII gate: text vào context của LLM chỉ là bản đã redact.
    clean_docs = [{"id": d["id"], "text": pii.redact(d["text"])} for d in docs]

    # Mock/LLM có thể bị injection điều khiển. Mọi tool call nó "đề xuất" vẫn
    # phải qua PEP trong scope của Run A, nên bị deny và để lại dấu vết ledger.
    injected = llm.find_injection("\n\n".join(d["text"] for d in clean_docs))
    if injected is not None:
        for customer_id in injected.customer_ids:
            run.call("read_customer", {"customer_id": customer_id},
                     classification="restricted", purpose="summarize-tickets", egress=False,
                     execute=lambda cid=customer_id: tools.read_customer(cid))
        run.call("http_post", {"url": injected.target_url, "customer_ids": injected.customer_ids},
                 classification="restricted", purpose="summarize-tickets", egress=True,
                 execute=lambda: tools.http_post(injected.target_url, {"records": []}))

    # Thứ DUY NHẤT đi qua boundary sang Run B: list[int] lấy từ tên file.
    return clean_docs, _ticket_ids(docs)


def _run_b(ticket_ids: list[int], run: _Run) -> list[str]:
    """Run B: đọc private data cho ticket hợp lệ. Không thấy free text, không egress."""
    served = []
    for customer_id in _customers_for_tickets(ticket_ids):
        allowed, record = run.call(
            "read_customer", {"customer_id": customer_id},
            classification="restricted", purpose="support-reply", egress=False,
            execute=lambda cid=customer_id: tools.read_customer(cid),
        )
        if allowed and record:
            served.append(record["customer_id"])
    return served


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = Path(log_dir) / "ledger.jsonl" if log_dir else DEFAULT_LEDGER_PATH
    expires_at = (datetime.now(timezone.utc) + RUN_TTL).isoformat()

    run_a = _Run("run-a", RUN_A_SCOPES, principal_id, expires_at, ledger_path)
    docs, ticket_ids = _run_a(message, llm, run_a)

    run_b = _Run("run-b", RUN_B_SCOPES, principal_id, expires_at, ledger_path)
    served = _run_b(ticket_ids, run_b)

    answer = llm.summarize(docs)
    if served:
        # Chỉ trả customer_id, không trả PII của hồ sơ ra màn hình.
        answer += f"\nĐã đối chiếu hồ sơ {len(served)} khách hàng gắn với ticket: {', '.join(served)}."
    return answer
